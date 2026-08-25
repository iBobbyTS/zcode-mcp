use crate::{
    PolicyCapabilities, PolicyLauncher, PolicyMode, PreparationError, PreparationResult,
    PreparedCommand, PreparedWorktree, WorktreeManager,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
    sync::Mutex,
};

pub const GENERAL_TASK_SCHEMA: &str = "zcode-general-task/v1";
const MAX_PROMPT_BYTES: usize = 256 * 1024;
const MAX_CONTEXT_HINTS: usize = 128;
const MAX_ATTACHMENTS: usize = 32;
const MAX_ATTACHMENT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_ATTACHMENTS_BYTES: u64 = 32 * 1024 * 1024;
static GENERAL_PREPARATION_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneralProfile {
    AnalysisReadonly,
    ImplementationWorktree,
    TestRunner,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetLimits {
    pub wall_time_ms: u64,
    pub max_turns: u64,
    pub max_tool_calls: u64,
    pub max_context_bytes: u64,
    pub max_result_bytes: u64,
    pub max_artifact_bytes: u64,
}

impl GeneralProfile {
    pub fn default_budget(self) -> BudgetLimits {
        match self {
            Self::AnalysisReadonly => BudgetLimits {
                wall_time_ms: 600_000,
                max_turns: 12,
                max_tool_calls: 80,
                max_context_bytes: 2_000_000,
                max_result_bytes: 256_000,
                max_artifact_bytes: 2_000_000,
            },
            Self::ImplementationWorktree => BudgetLimits {
                wall_time_ms: 1_800_000,
                max_turns: 32,
                max_tool_calls: 240,
                max_context_bytes: 4_000_000,
                max_result_bytes: 512_000,
                max_artifact_bytes: 16_000_000,
            },
            Self::TestRunner => BudgetLimits {
                wall_time_ms: 900_000,
                max_turns: 16,
                max_tool_calls: 120,
                max_context_bytes: 2_000_000,
                max_result_bytes: 512_000,
                max_artifact_bytes: 8_000_000,
            },
        }
    }
}

fn hard_budget_cap() -> BudgetLimits {
    BudgetLimits {
        wall_time_ms: 86_400_000,
        max_turns: 1_024,
        max_tool_calls: 4_096,
        max_context_bytes: 16_777_216,
        max_result_bytes: 16_777_216,
        max_artifact_bytes: 268_435_456,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentInput {
    pub logical_name: String,
    pub source_path: PathBuf,
    pub allowed_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralTaskManifest {
    pub schema: String,
    pub task_id: String,
    pub repository: PathBuf,
    pub base_ref: String,
    pub profile: GeneralProfile,
    pub prompt: String,
    #[serde(default)]
    pub repo_context: Vec<PathBuf>,
    #[serde(default)]
    pub attachments: Vec<AttachmentInput>,
    #[serde(default)]
    pub write_manifest: Vec<PathBuf>,
    pub scratch_root: PathBuf,
    pub artifact_root: PathBuf,
    #[serde(default, deserialize_with = "deserialize_budget")]
    pub budget: Option<BudgetLimits>,
    #[serde(default)]
    pub validation_commands: BTreeMap<String, crate::ValidationCommand>,
    #[serde(default)]
    pub retain_partial: bool,
    pub idempotency_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedAttachment {
    pub logical_name: String,
    pub prepared_path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
}
impl PreparedAttachment {
    pub fn public_projection(&self) -> PublicAttachment {
        PublicAttachment {
            logical_name: self.logical_name.clone(),
            sha256: self.sha256.clone(),
            size_bytes: self.size_bytes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicAttachment {
    pub logical_name: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedGeneralTask {
    pub schema: String,
    pub task_id: String,
    pub repository: PathBuf,
    pub base_sha: String,
    pub profile: GeneralProfile,
    pub prompt_path: PathBuf,
    pub prompt_sha256: String,
    pub context_paths: Vec<PathBuf>,
    pub attachments: Vec<PreparedAttachment>,
    pub write_manifest: Vec<PathBuf>,
    pub worktree: PreparedWorktree,
    pub scratch_root: PathBuf,
    pub artifact_root: PathBuf,
    pub effective_budget: BudgetLimits,
    pub validation_commands: BTreeMap<String, PreparedCommand>,
    pub retain_partial: bool,
    pub idempotency_key: String,
    pub manifest_sha256: String,
    pub prepared_sha256: String,
}

impl PreparedGeneralTask {
    pub fn validate_digest(&self) -> PreparationResult<()> {
        let expected = self.prepared_sha256.clone();
        let mut unsigned = self.clone();
        unsigned.prepared_sha256.clear();
        if hash(&serde_json::to_vec(&unsigned)?) != expected {
            return Err(PreparationError::InvalidManifest(
                "prepared general task digest mismatch".into(),
            ));
        }
        Ok(())
    }
    pub fn launcher(&self) -> PreparationResult<PolicyLauncher> {
        self.validate_digest()?;
        let mut inputs = vec![self.prompt_path.clone()];
        inputs.extend(self.attachments.iter().map(|a| a.prepared_path.clone()));
        inputs.extend(
            self.context_paths
                .iter()
                .map(|p| self.worktree.path.join(p)),
        );
        let mode = match self.profile {
            GeneralProfile::AnalysisReadonly => PolicyMode::GeneralReadonly,
            GeneralProfile::TestRunner => PolicyMode::GeneralTest,
            GeneralProfile::ImplementationWorktree => PolicyMode::GeneralImplementation {
                tracked_write_roots: self.write_manifest.clone(),
            },
        };
        PolicyLauncher::for_general(
            self.worktree.path.clone(),
            self.scratch_root.clone(),
            self.artifact_root.join("result.json"),
            inputs,
            self.validation_commands.clone(),
            PolicyCapabilities::default(),
            mode,
        )
    }
}

pub struct GeneralTaskPreparer {
    attachment_roots: Vec<PathBuf>,
}
impl GeneralTaskPreparer {
    pub fn new(attachment_roots: Vec<PathBuf>) -> PreparationResult<Self> {
        let mut attachment_roots = attachment_roots
            .into_iter()
            .map(fs::canonicalize)
            .collect::<Result<Vec<_>, _>>()?;
        if attachment_roots.iter().any(|root| !root.is_dir()) {
            return Err(PreparationError::InvalidManifest(
                "attachment roots must be directories".into(),
            ));
        }
        attachment_roots.sort();
        attachment_roots.dedup();
        Ok(Self { attachment_roots })
    }

    pub fn prepare(
        &self,
        manifest: &GeneralTaskManifest,
    ) -> PreparationResult<PreparedGeneralTask> {
        let _guard = GENERAL_PREPARATION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        validate_manifest(manifest)?;
        let repository = canonical_repository(&manifest.repository)?;
        let base_sha = resolve_commit(&repository, &manifest.base_ref)?;
        let effective_budget = manifest
            .budget
            .clone()
            .unwrap_or_else(|| manifest.profile.default_budget());
        validate_budget(&effective_budget)?;
        let context_paths = manifest
            .repo_context
            .iter()
            .map(|p| confined_relative(p))
            .collect::<PreparationResult<Vec<_>>>()?;
        let mut context_bytes = manifest.prompt.len() as u64;
        for path in &context_paths {
            reject_protected(path)?;
            let full = reject_symlink_path(&repository, path)?;
            if !full.is_file() {
                return Err(PreparationError::MissingInput(full));
            }
            if secret_type(&full) {
                return Err(PreparationError::CredentialInput(full));
            }
            context_bytes = context_bytes.saturating_add(fs::metadata(full)?.len());
        }
        if context_bytes > effective_budget.max_context_bytes {
            return Err(PreparationError::InvalidManifest(
                "context byte limit exceeded".into(),
            ));
        }
        let write_manifest = manifest
            .write_manifest
            .iter()
            .map(|p| confined_relative(p))
            .collect::<PreparationResult<Vec<_>>>()?;
        if manifest.profile == GeneralProfile::ImplementationWorktree && write_manifest.is_empty() {
            return Err(PreparationError::InvalidManifest(
                "implementation_worktree requires write_manifest".into(),
            ));
        }
        if manifest.profile != GeneralProfile::ImplementationWorktree && !write_manifest.is_empty()
        {
            return Err(PreparationError::InvalidManifest(
                "write_manifest is implementation-only".into(),
            ));
        }
        for path in &write_manifest {
            reject_protected(path)?;
        }
        require_private_root(&manifest.scratch_root, "scratch")?;
        require_private_root(&manifest.artifact_root, "artifacts")?;
        if manifest
            .artifact_root
            .file_name()
            .and_then(|name| name.to_str())
            != Some(manifest.task_id.as_str())
        {
            return Err(PreparationError::InvalidPath {
                path: manifest.artifact_root.clone(),
                reason: "artifact root must be bound to task_id".into(),
            });
        }
        let scratch_parent = canonical_existing_parent(&repository, &manifest.scratch_root)?;
        let artifact_root = canonical_directory(&repository, &manifest.artifact_root)?;
        let manifest_sha256 = hash(&serde_json::to_vec(manifest)?);
        let key = hash(format!("{}:{}", repository.display(), manifest.idempotency_key).as_bytes());
        let job_root = scratch_parent.join(&key);
        fs::create_dir_all(&job_root)?;
        let job_root = fs::canonicalize(job_root)?;
        let prepared_path = job_root.join("prepared-general.json");
        if prepared_path.is_file() {
            let existing: PreparedGeneralTask = serde_json::from_slice(&fs::read(prepared_path)?)?;
            existing.validate_digest()?;
            if existing.manifest_sha256 != manifest_sha256 {
                return Err(PreparationError::IdempotencyConflict(
                    "key already owns a different immutable general task".into(),
                ));
            }
            return Ok(existing);
        }
        let manager = WorktreeManager::new(repository.clone(), job_root.clone())?;
        let worktree = manager.create(&base_sha, &key)?;
        let built = (|| {
            let private_root = create_dir(&job_root, "private-inputs")?;
            let prompt_path = private_root.join("prompt.txt");
            atomic_write(&prompt_path, manifest.prompt.as_bytes())?;
            let prompt_path = fs::canonicalize(prompt_path)?;
            let attachments_root = create_dir(&private_root, "attachments")?;
            let attachments = snapshot_attachments(
                &manifest.attachments,
                &attachments_root,
                &effective_budget,
                context_bytes,
                &self.attachment_roots,
            )?;
            let scratch_root = create_dir(&job_root, "scratch")?;
            let validation_commands = manifest
                .validation_commands
                .iter()
                .map(|(id, c)| {
                    let cwd = worktree.path.join(confined_relative(&c.cwd)?);
                    crate::policy::prepare_command(
                        &c.program,
                        &c.args,
                        &cwd,
                        &worktree.path,
                        &scratch_root,
                        (c.timeout_ms, c.max_output_bytes, false),
                    )
                    .map(|v| (id.clone(), v))
                })
                .collect::<PreparationResult<BTreeMap<_, _>>>()?;
            let mut prepared = PreparedGeneralTask {
                schema: manifest.schema.clone(),
                task_id: manifest.task_id.clone(),
                repository: repository.clone(),
                base_sha: base_sha.clone(),
                profile: manifest.profile,
                prompt_path,
                prompt_sha256: hash(manifest.prompt.as_bytes()),
                context_paths,
                attachments,
                write_manifest,
                worktree: worktree.clone(),
                scratch_root,
                artifact_root,
                effective_budget,
                validation_commands,
                retain_partial: manifest.retain_partial,
                idempotency_key: manifest.idempotency_key.clone(),
                manifest_sha256,
                prepared_sha256: String::new(),
            };
            prepared.prepared_sha256 = hash(&serde_json::to_vec(&prepared)?);
            prepared.validate_digest()?;
            atomic_write(
                &job_root.join("prepared-general.json"),
                &serde_json::to_vec_pretty(&prepared)?,
            )?;
            Ok(prepared)
        })();
        match built {
            Ok(prepared) => Ok(prepared),
            Err(error) => {
                let cleanup = manager
                    .capture_integrity(&worktree)
                    .and_then(|diagnostics| manager.persist_integrity(&worktree, diagnostics))
                    .and_then(|record| manager.cleanup_from_record(&record).map(|_| ()));
                if let Err(cleanup) = cleanup {
                    return Err(PreparationError::Worktree(format!(
                        "general preparation failed ({error}); cleanup failed ({cleanup})"
                    )));
                }
                Err(error)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompletionOutcome {
    Succeeded,
    Blocked,
    Failed,
    Cancelled,
    TimedOut,
    BudgetExhausted,
    RuntimeLost,
    ResultInvalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub artifact_id: String,
    pub kind: GeneralArtifactKind,
    pub sha256: String,
    pub size_bytes: u64,
    pub partial: bool,
    pub head_commit: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneralArtifactKind {
    ReportMarkdown,
    ChangesPatch,
    CheckReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralCompletion {
    pub outcome: CompletionOutcome,
    pub reason_code: Option<String>,
    pub artifact: Option<ArtifactMetadata>,
    pub cleaned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralCompletionSubmission {
    pub requested_outcome: CompletionOutcome,
    pub summary: String,
    #[serde(default)]
    pub checks: Vec<String>,
    #[serde(default)]
    pub residual_gaps: Vec<String>,
}

pub struct GeneralFinalizer;
impl GeneralFinalizer {
    pub fn finalize_submission(
        prepared: &PreparedGeneralTask,
        submission: &GeneralCompletionSubmission,
    ) -> GeneralCompletion {
        if !matches!(
            submission.requested_outcome,
            CompletionOutcome::Succeeded | CompletionOutcome::Blocked
        ) {
            return invalid_completion(prepared, "COMPLETION_OUTCOME_NOT_REQUESTABLE");
        }
        let encoded = serde_json::to_vec(submission).unwrap_or_default();
        if encoded.len() as u64 > prepared.effective_budget.max_result_bytes {
            return invalid_completion(prepared, "RESULT_TOO_LARGE");
        }
        Self::finalize(prepared, submission.requested_outcome)
    }

    pub fn finalize(
        prepared: &PreparedGeneralTask,
        requested: CompletionOutcome,
    ) -> GeneralCompletion {
        match Self::try_finalize(prepared, requested) {
            Ok(v) => v,
            Err(code) => GeneralCompletion {
                outcome: CompletionOutcome::ResultInvalid,
                reason_code: Some(code),
                artifact: None,
                cleaned: cleanup_after_failure(prepared),
            },
        }
    }
    fn try_finalize(
        prepared: &PreparedGeneralTask,
        requested: CompletionOutcome,
    ) -> Result<GeneralCompletion, String> {
        prepared
            .validate_digest()
            .map_err(|_| "PREPARED_TASK_INVALID".to_owned())?;
        let manager = manager(prepared).map_err(|_| "WORKTREE_IDENTITY_INVALID".to_owned())?;
        let mut artifact = None;
        match prepared.profile {
            GeneralProfile::AnalysisReadonly | GeneralProfile::TestRunner => {
                let d = manager
                    .capture_integrity(&prepared.worktree)
                    .map_err(|_| "WORKTREE_INTEGRITY_FAILED".to_owned())?;
                if !d.worktree_clean {
                    return Err("READONLY_PROFILE_MODIFIED_TRACKED_STATE".into());
                }
            }
            GeneralProfile::ImplementationWorktree => {
                let retain = matches!(
                    requested,
                    CompletionOutcome::Succeeded | CompletionOutcome::Blocked
                ) || (prepared.retain_partial
                    && matches!(
                        requested,
                        CompletionOutcome::Failed
                            | CompletionOutcome::Cancelled
                            | CompletionOutcome::TimedOut
                            | CompletionOutcome::BudgetExhausted
                    ));
                if retain {
                    artifact = finalize_patch(prepared, requested != CompletionOutcome::Succeeded)?;
                }
            }
        }
        let mut cleanup_worktree = prepared.worktree.clone();
        if let Some(a) = &artifact {
            if let Some(head) = &a.head_commit {
                cleanup_worktree.head_sha = head.clone();
            }
        }
        let diagnostics = manager
            .capture_integrity(&cleanup_worktree)
            .map_err(|_| "WORKTREE_INTEGRITY_FAILED".to_owned())?;
        if !diagnostics.source_integrity_preserved() {
            return Err("SOURCE_INTEGRITY_FAILED".into());
        }
        let record = manager
            .persist_integrity(&cleanup_worktree, diagnostics)
            .map_err(|_| "CLEANUP_RECORD_FAILED".to_owned())?;
        manager
            .cleanup_from_record(&record)
            .map_err(|_| "WORKTREE_CLEANUP_FAILED".to_owned())?;
        cleanup_scratch(prepared).map_err(|_| "SCRATCH_CLEANUP_FAILED".to_owned())?;
        Ok(GeneralCompletion {
            outcome: requested,
            reason_code: None,
            artifact,
            cleaned: true,
        })
    }
}

fn invalid_completion(prepared: &PreparedGeneralTask, code: &str) -> GeneralCompletion {
    GeneralCompletion {
        outcome: CompletionOutcome::ResultInvalid,
        reason_code: Some(code.into()),
        artifact: None,
        cleaned: cleanup_after_failure(prepared),
    }
}

fn finalize_patch(
    prepared: &PreparedGeneralTask,
    partial: bool,
) -> Result<Option<ArtifactMetadata>, String> {
    let status = git_bytes(
        &prepared.worktree.path,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    let paths = parse_status_paths(&status)?;
    if paths.is_empty() {
        return if partial {
            Ok(None)
        } else {
            Err("IMPLEMENTATION_HAS_NO_CHANGES".into())
        };
    }
    for path in &paths {
        let relative =
            confined_relative(Path::new(path)).map_err(|_| "CHANGED_PATH_INVALID".to_owned())?;
        reject_protected(&relative).map_err(|_| "PROTECTED_PATH_CHANGED".to_owned())?;
        if !prepared
            .write_manifest
            .iter()
            .any(|root| relative.starts_with(root))
        {
            return Err("CHANGED_PATH_NOT_ALLOWLISTED".into());
        }
    }
    let mut add = Command::new("git");
    add.current_dir(&prepared.worktree.path).args(["add", "--"]);
    for p in &paths {
        add.arg(p);
    }
    let out = add.output().map_err(|_| "GIT_STAGE_FAILED".to_owned())?;
    if !out.status.success() {
        return Err("GIT_STAGE_FAILED".into());
    }
    let out = Command::new("git")
        .current_dir(&prepared.worktree.path)
        .args([
            "-c",
            "user.name=zcode-reviewd",
            "-c",
            "user.email=zcode-reviewd@localhost",
            "commit",
            "-m",
            "chore(agent): finalize bounded task result",
        ])
        .output()
        .map_err(|_| "GIT_COMMIT_FAILED".to_owned())?;
    if !out.status.success() {
        return Err("GIT_COMMIT_FAILED".into());
    }
    let head = String::from_utf8(git_bytes(&prepared.worktree.path, &["rev-parse", "HEAD"])?)
        .map_err(|_| "GIT_HEAD_INVALID".to_owned())?
        .trim()
        .to_owned();
    let patch = git_bytes(
        &prepared.worktree.path,
        &["diff", "--binary", &prepared.base_sha, &head],
    )?;
    if patch.len() as u64 > prepared.effective_budget.max_artifact_bytes {
        return Err("ARTIFACT_LIMIT_EXCEEDED".into());
    }
    let path = prepared.artifact_root.join("changes.patch");
    atomic_write(&path, &patch).map_err(|_| "ARTIFACT_WRITE_FAILED".to_owned())?;
    let digest = hash(&patch);
    let metadata = ArtifactMetadata {
        artifact_id: hash(format!("{}:{}", prepared.task_id, digest).as_bytes()),
        kind: GeneralArtifactKind::ChangesPatch,
        sha256: digest,
        size_bytes: patch.len() as u64,
        partial,
        head_commit: Some(head),
    };
    atomic_write(
        &prepared.artifact_root.join("changes.manifest.json"),
        &serde_json::to_vec_pretty(&metadata).map_err(|_| "ARTIFACT_MANIFEST_FAILED".to_owned())?,
    )
    .map_err(|_| "ARTIFACT_MANIFEST_FAILED".to_owned())?;
    Ok(Some(metadata))
}

fn validate_manifest(m: &GeneralTaskManifest) -> PreparationResult<()> {
    if m.schema != GENERAL_TASK_SCHEMA {
        return Err(PreparationError::InvalidManifest(
            "unsupported general task schema".into(),
        ));
    }
    if m.task_id.is_empty()
        || m.idempotency_key.is_empty()
        || m.task_id.len() > 256
        || m.idempotency_key.len() > 512
        || !m.task_id.bytes().all(identifier_byte)
        || !m.idempotency_key.bytes().all(identifier_byte)
        || m.prompt.trim().is_empty()
        || m.prompt.len() > MAX_PROMPT_BYTES
        || m.prompt.contains('\0')
    {
        return Err(PreparationError::InvalidManifest(
            "invalid task identity or prompt".into(),
        ));
    }
    if m.repo_context.len() > MAX_CONTEXT_HINTS || m.attachments.len() > MAX_ATTACHMENTS {
        return Err(PreparationError::InvalidManifest(
            "context item count exceeded".into(),
        ));
    }
    ensure_unique_paths(&m.repo_context, "repo_context")?;
    ensure_unique_paths(&m.write_manifest, "write_manifest")?;
    Ok(())
}
fn identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
}

fn deserialize_budget<'de, D>(deserializer: D) -> Result<Option<BudgetLimits>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    BudgetLimits::deserialize(deserializer).map(Some)
}

fn ensure_unique_paths(paths: &[PathBuf], name: &str) -> PreparationResult<()> {
    let mut seen = std::collections::HashSet::new();
    if paths.iter().any(|path| !seen.insert(path)) {
        return Err(PreparationError::InvalidManifest(format!(
            "{name} contains duplicates"
        )));
    }
    Ok(())
}
fn validate_budget(v: &BudgetLimits) -> PreparationResult<()> {
    let cap = hard_budget_cap();
    let vals = [
        (v.wall_time_ms, cap.wall_time_ms),
        (v.max_turns, cap.max_turns),
        (v.max_tool_calls, cap.max_tool_calls),
        (v.max_context_bytes, cap.max_context_bytes),
        (v.max_result_bytes, cap.max_result_bytes),
        (v.max_artifact_bytes, cap.max_artifact_bytes),
    ];
    if vals.iter().any(|(v, c)| *v == 0 || v > c) {
        return Err(PreparationError::InvalidManifest(
            "budget must be positive and at or below hard cap".into(),
        ));
    }
    Ok(())
}
fn canonical_repository(path: &Path) -> PreparationResult<PathBuf> {
    if !path.is_absolute() {
        return Err(PreparationError::InvalidPath {
            path: path.into(),
            reason: "repository must be absolute".into(),
        });
    }
    let p = fs::canonicalize(path)?;
    if !p.join(".git").exists() {
        return Err(PreparationError::InvalidPath {
            path: p,
            reason: "repository is not a Git worktree".into(),
        });
    }
    Ok(p)
}
fn resolve_commit(repo: &Path, r: &str) -> PreparationResult<String> {
    if r.len() != 40 || !r.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PreparationError::MutableReference(r.into()));
    }
    let out = Command::new("git")
        .current_dir(repo)
        .args(["rev-parse", "--verify", &format!("{r}^{{commit}}")])
        .output()?;
    if !out.status.success() {
        return Err(PreparationError::Git("base commit unavailable".into()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().into())
}
fn confined_relative(path: &Path) -> PreparationResult<PathBuf> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(PreparationError::InvalidPath {
            path: path.into(),
            reason: "path must be canonical repository-relative".into(),
        });
    }
    Ok(path.components().collect())
}
fn reject_protected(path: &Path) -> PreparationResult<()> {
    if path.components().any(|c| {
        c.as_os_str() == ".git" || c.as_os_str() == ".agent-work" || c.as_os_str() == ".gitmodules"
    }) {
        return Err(PreparationError::Policy(
            "protected Git/agent metadata path".into(),
        ));
    }
    Ok(())
}
fn require_private_root(path: &Path, kind: &str) -> PreparationResult<()> {
    let expected = Path::new(".agent-work").join(kind);
    if !path.starts_with(&expected) || path == expected {
        return Err(PreparationError::InvalidPath {
            path: path.into(),
            reason: format!(
                "{kind} root must be a task-confined child of {}",
                expected.display()
            ),
        });
    }
    Ok(())
}
fn reject_symlink_path(root: &Path, relative: &Path) -> PreparationResult<PathBuf> {
    let mut p = root.to_owned();
    for c in relative.components() {
        p.push(c);
        if fs::symlink_metadata(&p)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(PreparationError::SymlinkInput(p));
        }
    }
    let c = fs::canonicalize(&p)?;
    if !c.starts_with(root) {
        return Err(PreparationError::PathEscape {
            path: c,
            root: root.into(),
        });
    }
    Ok(c)
}
fn canonical_existing_parent(repo: &Path, relative: &Path) -> PreparationResult<PathBuf> {
    let r = confined_relative(relative)?;
    let p = repo.join(r);
    reject_existing_symlinks(repo, &p)?;
    fs::create_dir_all(&p)?;
    let c = fs::canonicalize(p)?;
    if !c.starts_with(repo) {
        return Err(PreparationError::PathEscape {
            path: c,
            root: repo.into(),
        });
    }
    Ok(c)
}
fn canonical_directory(repo: &Path, relative: &Path) -> PreparationResult<PathBuf> {
    canonical_existing_parent(repo, relative)
}
fn create_dir(root: &Path, name: &str) -> PreparationResult<PathBuf> {
    let p = root.join(name);
    fs::create_dir_all(&p)?;
    Ok(fs::canonicalize(p)?)
}
fn snapshot_attachments(
    inputs: &[AttachmentInput],
    root: &Path,
    budget: &BudgetLimits,
    base_bytes: u64,
    approved_roots: &[PathBuf],
) -> PreparationResult<Vec<PreparedAttachment>> {
    let mut total = 0;
    let mut seen = std::collections::HashSet::new();
    inputs
        .iter()
        .enumerate()
        .map(|(i, a)| {
            if a.logical_name.is_empty()
                || a.logical_name.contains('/')
                || a.logical_name.contains('\0')
                || !seen.insert(a.logical_name.clone())
            {
                return Err(PreparationError::InvalidManifest(
                    "invalid or duplicate attachment logical name".into(),
                ));
            }
            let allowed = fs::canonicalize(&a.allowed_root)?;
            if !approved_roots.contains(&allowed) {
                return Err(PreparationError::Policy(
                    "attachment root is not owner-approved".into(),
                ));
            }
            let source = fs::canonicalize(&a.source_path)?;
            if !source.starts_with(&allowed)
                || fs::symlink_metadata(&a.source_path)?
                    .file_type()
                    .is_symlink()
                || !source.is_file()
            {
                return Err(PreparationError::PathEscape {
                    path: source,
                    root: allowed,
                });
            }
            if secret_type(&source) {
                return Err(PreparationError::CredentialInput(source));
            }
            let bytes = fs::read(&source)?;
            let size = bytes.len() as u64;
            total += size;
            if size > MAX_ATTACHMENT_BYTES
                || total > MAX_ATTACHMENTS_BYTES
                || base_bytes.saturating_add(total) > budget.max_context_bytes
            {
                return Err(PreparationError::InvalidManifest(
                    "attachment byte limit exceeded".into(),
                ));
            }
            let dest = root.join(format!("{i:03}.bin"));
            atomic_write(&dest, &bytes)?;
            Ok(PreparedAttachment {
                logical_name: a.logical_name.clone(),
                prepared_path: fs::canonicalize(dest)?,
                sha256: hash(&bytes),
                size_bytes: size,
            })
        })
        .collect()
}
fn secret_type(path: &Path) -> bool {
    if path.components().any(|component| {
        matches!(
            component
                .as_os_str()
                .to_str()
                .map(|value| value.to_ascii_lowercase())
                .as_deref(),
            Some(".env" | "credentials" | "secrets" | "auth.json" | "id_rsa" | "id_ed25519")
        )
    }) || path
        .components()
        .collect::<Vec<_>>()
        .windows(2)
        .any(|parts| parts[0].as_os_str() == ".agent-work" && parts[1].as_os_str() == "reviews")
    {
        return true;
    }
    matches!(
        path.extension()
            .and_then(|v| v.to_str())
            .map(|v| v.to_ascii_lowercase())
            .as_deref(),
        Some("pem" | "key" | "p12" | "pfx" | "kdbx" | "env" | "credentials")
    )
}
fn atomic_write(path: &Path, bytes: &[u8]) -> PreparationResult<()> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)?;
    Ok(())
}
fn reject_existing_symlinks(root: &Path, target: &Path) -> PreparationResult<()> {
    let relative = target
        .strip_prefix(root)
        .map_err(|_| PreparationError::PathEscape {
            path: target.into(),
            root: root.into(),
        })?;
    let mut cursor = root.to_owned();
    for part in relative.components() {
        cursor.push(part);
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(PreparationError::SymlinkInput(cursor));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn manager(p: &PreparedGeneralTask) -> PreparationResult<WorktreeManager> {
    let root = p
        .worktree
        .scratch_worktrees_root
        .parent()
        .ok_or_else(|| PreparationError::Worktree("missing job root".into()))?;
    WorktreeManager::new(p.repository.clone(), root.into())
}
fn cleanup_after_failure(prepared: &PreparedGeneralTask) -> bool {
    let Ok(manager) = manager(prepared) else {
        return false;
    };
    if !prepared.worktree.path.exists() {
        return true;
    }
    let Ok(head) = git_bytes(&prepared.worktree.path, &["rev-parse", "HEAD"]) else {
        return false;
    };
    let Ok(head) = String::from_utf8(head) else {
        return false;
    };
    let mut worktree = prepared.worktree.clone();
    worktree.head_sha = head.trim().into();
    let Ok(diagnostics) = manager.capture_integrity(&worktree) else {
        return false;
    };
    let Ok(record) = manager.persist_integrity(&worktree, diagnostics) else {
        return false;
    };
    manager.cleanup_from_record(&record).is_ok() && cleanup_scratch(prepared).is_ok()
}
fn cleanup_scratch(prepared: &PreparedGeneralTask) -> PreparationResult<()> {
    if !prepared.scratch_root.exists() {
        return Ok(());
    }
    let scratch = fs::canonicalize(&prepared.scratch_root)?;
    let job_root = prepared
        .worktree
        .scratch_worktrees_root
        .parent()
        .ok_or_else(|| PreparationError::Worktree("missing job root".into()))?;
    if scratch == job_root || !scratch.starts_with(job_root) || scratch.file_name().is_none() {
        return Err(PreparationError::PathEscape {
            path: scratch,
            root: job_root.into(),
        });
    }
    fs::remove_dir_all(scratch)?;
    Ok(())
}
fn git_bytes(repo: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("git")
        .current_dir(repo)
        .args(args)
        .output()
        .map_err(|_| "GIT_COMMAND_FAILED".to_owned())?;
    if !out.status.success() {
        return Err("GIT_COMMAND_FAILED".into());
    }
    Ok(out.stdout)
}
fn parse_status_paths(bytes: &[u8]) -> Result<Vec<String>, String> {
    let fields = bytes
        .split(|b| *b == 0)
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>();
    let mut result = Vec::new();
    let mut i = 0;
    while i < fields.len() {
        let field =
            String::from_utf8(fields[i].to_vec()).map_err(|_| "GIT_STATUS_INVALID".to_owned())?;
        if field.len() < 4 {
            return Err("GIT_STATUS_INVALID".into());
        }
        let code = &field[..2];
        result.push(field[3..].to_owned());
        i += 1;
        if code.starts_with('R') || code.starts_with('C') {
            if i >= fields.len() {
                return Err("GIT_STATUS_INVALID".into());
            }
            result.push(
                String::from_utf8(fields[i].to_vec())
                    .map_err(|_| "GIT_STATUS_INVALID".to_owned())?,
            );
            i += 1;
        }
    }
    result.sort();
    result.dedup();
    Ok(result)
}
