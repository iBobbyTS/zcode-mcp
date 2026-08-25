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
pub struct PreparedContext {
    pub repository_relative: PathBuf,
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
    pub context: Vec<PreparedContext>,
    pub attachments: Vec<PreparedAttachment>,
    pub write_manifest: Vec<PathBuf>,
    pub worktree: PreparedWorktree,
    pub scratch_root: PathBuf,
    pub artifact_root: PathBuf,
    pub artifact_targets: BTreeMap<GeneralArtifactKind, PathBuf>,
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
    pub fn validate_prepared_content(&self) -> PreparationResult<()> {
        let job_root = self
            .worktree
            .scratch_worktrees_root
            .parent()
            .ok_or_else(|| PreparationError::Worktree("missing job root".into()))?;
        verify_confined_file(job_root, &self.prompt_path, &self.prompt_sha256, None)?;
        for attachment in &self.attachments {
            verify_confined_file(
                job_root,
                &attachment.prepared_path,
                &attachment.sha256,
                Some(attachment.size_bytes),
            )?;
        }
        for context in &self.context {
            let path = reject_symlink_path(&self.worktree.path, &context.repository_relative)?;
            verify_file(&path, &context.sha256, Some(context.size_bytes))?;
        }
        Ok(())
    }
    pub fn launcher(&self) -> PreparationResult<PolicyLauncher> {
        self.validate_digest()?;
        self.validate_prepared_content()?;
        let mut inputs = vec![self.prompt_path.clone()];
        inputs.extend(self.attachments.iter().map(|a| a.prepared_path.clone()));
        inputs.extend(
            self.context
                .iter()
                .map(|context| self.worktree.path.join(&context.repository_relative)),
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
            let existing_bytes = fs::read(&prepared_path)?;
            let existing = serde_json::from_slice::<PreparedGeneralTask>(&existing_bytes)
                .map_err(PreparationError::from);
            let manager = WorktreeManager::new(repository.clone(), job_root.clone())?;
            let reusable = existing.and_then(|existing| {
                validate_reusable_prepared(
                    &existing,
                    &manifest_sha256,
                    &repository,
                    &base_sha,
                    &manager,
                )
                .map(|()| existing)
            });
            return match reusable {
                Ok(existing) => Ok(existing),
                Err(error @ PreparationError::IdempotencyConflict(_)) => Err(error),
                Err(error) => {
                    let cleanup = cleanup_stale_record(&manager, &job_root, &existing_bytes);
                    match cleanup {
                        Ok(()) => Err(error),
                        Err(cleanup) => Err(PreparationError::Worktree(format!(
                            "stale prepared record rejected ({error}); cleanup unresolved ({cleanup})"
                        ))),
                    }
                }
            };
        }
        let manager = WorktreeManager::new(repository.clone(), job_root.clone())?;
        let expected_worktree_path = job_root.join("worktrees").join(&key);
        let worktree = match manager.create(&base_sha, &key) {
            Ok(worktree) => worktree,
            Err(error) => {
                let cleanup =
                    bounded_cleanup_unregistered(&manager, &expected_worktree_path, &job_root);
                return match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(PreparationError::Worktree(format!(
                        "general worktree creation failed ({error}); cleanup unresolved ({cleanup})"
                    ))),
                };
            }
        };
        let built = (|| {
            let (context, context_bytes) = prepare_context(
                &worktree.path,
                &context_paths,
                manifest.prompt.len() as u64,
                effective_budget.max_context_bytes,
            )?;
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
            let artifact_targets = BTreeMap::from([
                (
                    GeneralArtifactKind::ReportMarkdown,
                    scratch_root.join("agent-artifacts/report.md"),
                ),
                (
                    GeneralArtifactKind::CheckReport,
                    scratch_root.join("agent-artifacts/check-report.json"),
                ),
                (
                    GeneralArtifactKind::ChangesPatch,
                    artifact_root.join("changes.patch"),
                ),
            ]);
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
                context,
                attachments,
                write_manifest,
                worktree: worktree.clone(),
                scratch_root,
                artifact_root,
                artifact_targets,
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
                let cleanup = bounded_cleanup_worktree(&manager, &worktree, &job_root);
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
    pub base_sha: String,
    pub changed_paths: Vec<String>,
    pub diff_stat: Option<String>,
    pub media_type: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeneralArtifactKind {
    ReportMarkdown,
    ChangesPatch,
    CheckReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralArtifactIntent {
    pub kind: GeneralArtifactKind,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralCompletion {
    pub outcome: CompletionOutcome,
    pub reason_code: Option<String>,
    pub summary: String,
    pub checks: Vec<String>,
    pub residual_gaps: Vec<String>,
    pub artifacts: Vec<ArtifactMetadata>,
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
    #[serde(default)]
    pub artifact_intents: Vec<GeneralArtifactIntent>,
}

pub struct GeneralFinalizer;
impl GeneralFinalizer {
    pub fn retry_cleanup(
        prepared: &PreparedGeneralTask,
        persisted: &GeneralCompletion,
    ) -> GeneralCompletion {
        let mut completion = persisted.clone();
        completion.cleaned = cleanup_if_trusted(prepared);
        completion
    }

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
        if submission.summary.trim().is_empty()
            || submission.summary.contains('\0')
            || submission.checks.len() > 128
            || submission.residual_gaps.len() > 128
            || submission
                .checks
                .iter()
                .chain(&submission.residual_gaps)
                .any(|value| value.contains('\0'))
            || submission.artifact_intents.iter().any(|intent| {
                intent.sha256.as_ref().is_some_and(|digest| {
                    digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                }) || intent.size_bytes == Some(0)
            })
        {
            return invalid_completion(prepared, "COMPLETION_METADATA_INVALID");
        }
        let encoded = serde_json::to_vec(submission).unwrap_or_default();
        if encoded.len() as u64 > prepared.effective_budget.max_result_bytes {
            return invalid_completion(prepared, "RESULT_TOO_LARGE");
        }
        Self::finish(
            prepared,
            submission.requested_outcome,
            submission.summary.clone(),
            submission.checks.clone(),
            submission.residual_gaps.clone(),
            &submission.artifact_intents,
        )
    }

    pub fn finalize(
        prepared: &PreparedGeneralTask,
        requested: CompletionOutcome,
    ) -> GeneralCompletion {
        Self::finish(
            prepared,
            requested,
            String::new(),
            Vec::new(),
            Vec::new(),
            &[],
        )
    }

    fn finish(
        prepared: &PreparedGeneralTask,
        requested: CompletionOutcome,
        summary: String,
        checks: Vec<String>,
        residual_gaps: Vec<String>,
        intents: &[GeneralArtifactIntent],
    ) -> GeneralCompletion {
        match Self::try_finalize(
            prepared,
            requested,
            summary.clone(),
            checks.clone(),
            residual_gaps.clone(),
            intents,
        ) {
            Ok(mut completion) => {
                completion.cleaned = cleanup_after_failure(prepared);
                if !completion.cleaned {
                    completion.outcome = CompletionOutcome::ResultInvalid;
                    completion.reason_code = Some("TASK_ROOT_CLEANUP_FAILED".into());
                }
                completion
            }
            Err(code) => {
                if code != "ARTIFACT_ROOT_NOT_EMPTY" {
                    cleanup_failed_artifact_outputs(prepared);
                }
                GeneralCompletion {
                    outcome: CompletionOutcome::ResultInvalid,
                    reason_code: Some(code),
                    summary,
                    checks,
                    residual_gaps,
                    artifacts: Vec::new(),
                    artifact: None,
                    cleaned: cleanup_if_trusted(prepared),
                }
            }
        }
    }
    fn try_finalize(
        prepared: &PreparedGeneralTask,
        requested: CompletionOutcome,
        summary: String,
        checks: Vec<String>,
        residual_gaps: Vec<String>,
        intents: &[GeneralArtifactIntent],
    ) -> Result<GeneralCompletion, String> {
        prepared
            .validate_digest()
            .map_err(|_| "PREPARED_TASK_INVALID".to_owned())?;
        prepared
            .validate_prepared_content()
            .map_err(|_| "PREPARED_CONTENT_INVALID".to_owned())?;
        let manager = manager(prepared).map_err(|_| "WORKTREE_IDENTITY_INVALID".to_owned())?;
        prefinalization_integrity(prepared, &manager)?;
        let mut artifacts = collect_declared_artifacts(prepared, intents)?;
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
                    if let Some(patch) = &artifact {
                        validate_patch_intent(intents, patch)?;
                        artifacts.push(patch.clone());
                    } else if intents
                        .iter()
                        .any(|intent| intent.kind == GeneralArtifactKind::ChangesPatch)
                    {
                        return Err("DECLARED_ARTIFACT_MISSING".into());
                    }
                }
            }
        }
        if artifacts
            .iter()
            .map(|artifact| artifact.size_bytes)
            .sum::<u64>()
            > prepared.effective_budget.max_artifact_bytes
        {
            return Err("ARTIFACT_LIMIT_EXCEEDED".into());
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
        persist_artifact_inventory(prepared, &artifacts)?;
        Ok(GeneralCompletion {
            outcome: requested,
            reason_code: None,
            summary,
            checks,
            residual_gaps,
            artifacts,
            artifact,
            cleaned: false,
        })
    }
}

fn invalid_completion(prepared: &PreparedGeneralTask, code: &str) -> GeneralCompletion {
    GeneralCompletion {
        outcome: CompletionOutcome::ResultInvalid,
        reason_code: Some(code.into()),
        summary: String::new(),
        checks: Vec::new(),
        residual_gaps: Vec::new(),
        artifacts: Vec::new(),
        artifact: None,
        cleaned: cleanup_if_trusted(prepared),
    }
}

fn cleanup_failed_artifact_outputs(prepared: &PreparedGeneralTask) {
    for name in [
        "report.md",
        "check-report.json",
        "changes.patch",
        "changes.manifest.json",
        "artifacts.manifest.json",
    ] {
        let path = prepared.artifact_root.join(name);
        if path.parent() == Some(prepared.artifact_root.as_path()) {
            let _ = fs::remove_file(path);
        }
    }
}

fn prefinalization_integrity(
    prepared: &PreparedGeneralTask,
    manager: &WorktreeManager,
) -> Result<(), String> {
    reject_unsafe_repository_config(&prepared.worktree.path)?;
    let diagnostics = manager
        .capture_integrity(&prepared.worktree)
        .map_err(|_| "PREFINALIZATION_HEAD_INVALID".to_owned())?;
    if !diagnostics.source_integrity_preserved()
        || !diagnostics.detached_head_unchanged
        || diagnostics.observed_head.as_deref() != Some(prepared.base_sha.as_str())
        || prepared.worktree.head_sha != prepared.base_sha
        || !diagnostics.staged_diff.is_empty()
    {
        return Err("PREFINALIZATION_HEAD_INVALID".into());
    }
    Ok(())
}

fn reject_unsafe_repository_config(repository: &Path) -> Result<(), String> {
    let output = safe_git_output(
        repository,
        &["config", "--local", "--get-regexp", "^(filter\\.|diff\\.)"],
    )?;
    if output.status.success() && !output.stdout.is_empty() {
        return Err("UNSAFE_GIT_CONFIG".into());
    }
    if !output.status.success() && output.status.code() != Some(1) {
        return Err("GIT_CONFIG_CHECK_FAILED".into());
    }
    let fsmonitor = safe_git_output(
        repository,
        &["config", "--local", "--get", "core.fsmonitor"],
    )?;
    if fsmonitor.status.success() && !fsmonitor.stdout.is_empty() {
        return Err("UNSAFE_GIT_CONFIG".into());
    }
    if !fsmonitor.status.success() && fsmonitor.status.code() != Some(1) {
        return Err("GIT_CONFIG_CHECK_FAILED".into());
    }
    Ok(())
}

fn collect_declared_artifacts(
    prepared: &PreparedGeneralTask,
    intents: &[GeneralArtifactIntent],
) -> Result<Vec<ArtifactMetadata>, String> {
    if intents.iter().enumerate().any(|(index, intent)| {
        intents[..index]
            .iter()
            .any(|other| other.kind == intent.kind)
    }) {
        return Err("DUPLICATE_ARTIFACT_INTENT".into());
    }
    ensure_directory_empty(&prepared.artifact_root, "ARTIFACT_ROOT_NOT_EMPTY")?;
    let output_root = prepared
        .artifact_targets
        .get(&GeneralArtifactKind::ReportMarkdown)
        .and_then(|path| path.parent())
        .ok_or("ARTIFACT_TARGET_INVALID")?
        .to_path_buf();
    let expected_files = intents
        .iter()
        .filter_map(|intent| match intent.kind {
            GeneralArtifactKind::ReportMarkdown => Some("report.md"),
            GeneralArtifactKind::CheckReport => Some("check-report.json"),
            GeneralArtifactKind::ChangesPatch => None,
        })
        .collect::<Vec<_>>();
    if output_root.exists() {
        let metadata =
            fs::symlink_metadata(&output_root).map_err(|_| "ARTIFACT_INVENTORY_INVALID")?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("ARTIFACT_INVENTORY_INVALID".into());
        }
        for entry in fs::read_dir(&output_root).map_err(|_| "ARTIFACT_INVENTORY_INVALID")? {
            let entry = entry.map_err(|_| "ARTIFACT_INVENTORY_INVALID")?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("ARTIFACT_INVENTORY_INVALID")?;
            if !expected_files.contains(&name) {
                return Err("UNDECLARED_ARTIFACT".into());
            }
        }
    } else if !expected_files.is_empty() {
        return Err("DECLARED_ARTIFACT_MISSING".into());
    }

    let mut artifacts = Vec::new();
    for intent in intents {
        let (source_name, destination_name) = match intent.kind {
            GeneralArtifactKind::ReportMarkdown => ("report.md", "report.md"),
            GeneralArtifactKind::CheckReport => ("check-report.json", "check-report.json"),
            GeneralArtifactKind::ChangesPatch => {
                if prepared.profile != GeneralProfile::ImplementationWorktree {
                    return Err("CHANGES_PATCH_PROFILE_INVALID".into());
                }
                continue;
            }
        };
        let expected_hash = intent.sha256.as_deref().ok_or("ARTIFACT_HASH_REQUIRED")?;
        let expected_size = intent.size_bytes.ok_or("ARTIFACT_SIZE_REQUIRED")?;
        let source = prepared
            .artifact_targets
            .get(&intent.kind)
            .ok_or("ARTIFACT_TARGET_INVALID")?
            .clone();
        verify_file(&source, expected_hash, Some(expected_size))
            .map_err(|_| "DECLARED_ARTIFACT_INVALID".to_owned())?;
        let bytes = fs::read(&source).map_err(|_| "DECLARED_ARTIFACT_INVALID")?;
        let destination = prepared.artifact_root.join(destination_name);
        atomic_write(&destination, &bytes).map_err(|_| "ARTIFACT_WRITE_FAILED")?;
        verify_file(&destination, expected_hash, Some(expected_size))
            .map_err(|_| "AUTHORITATIVE_ARTIFACT_INVALID".to_owned())?;
        artifacts.push(ArtifactMetadata {
            artifact_id: hash(
                format!("{}:{}:{expected_hash}", prepared.task_id, source_name).as_bytes(),
            ),
            kind: intent.kind,
            sha256: expected_hash.into(),
            size_bytes: expected_size,
            partial: false,
            head_commit: None,
            base_sha: prepared.base_sha.clone(),
            changed_paths: Vec::new(),
            diff_stat: None,
            media_type: match intent.kind {
                GeneralArtifactKind::ReportMarkdown => "text/markdown; charset=utf-8",
                GeneralArtifactKind::CheckReport => "application/json",
                GeneralArtifactKind::ChangesPatch => unreachable!(),
            }
            .into(),
        });
    }
    if artifacts
        .iter()
        .map(|artifact| artifact.size_bytes)
        .sum::<u64>()
        > prepared.effective_budget.max_artifact_bytes
    {
        return Err("ARTIFACT_LIMIT_EXCEEDED".into());
    }
    Ok(artifacts)
}

fn validate_patch_intent(
    intents: &[GeneralArtifactIntent],
    patch: &ArtifactMetadata,
) -> Result<(), String> {
    let Some(intent) = intents
        .iter()
        .find(|intent| intent.kind == GeneralArtifactKind::ChangesPatch)
    else {
        return Ok(());
    };
    if intent
        .sha256
        .as_deref()
        .is_some_and(|value| value != patch.sha256)
        || intent
            .size_bytes
            .is_some_and(|value| value != patch.size_bytes)
    {
        return Err("CHANGES_PATCH_INTENT_MISMATCH".into());
    }
    Ok(())
}

fn persist_artifact_inventory(
    prepared: &PreparedGeneralTask,
    artifacts: &[ArtifactMetadata],
) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(artifacts)
        .map_err(|_| "ARTIFACT_INVENTORY_INVALID".to_owned())?;
    let path = prepared.artifact_root.join("artifacts.manifest.json");
    atomic_write(&path, &bytes).map_err(|_| "ARTIFACT_INVENTORY_WRITE_FAILED".to_owned())?;
    verify_file(&path, &hash(&bytes), Some(bytes.len() as u64))
        .map_err(|_| "ARTIFACT_INVENTORY_INVALID".to_owned())
}

fn reject_gitlinks(repository: &Path) -> Result<(), String> {
    let raw = git_bytes(
        repository,
        &[
            "diff",
            "--cached",
            "--raw",
            "-z",
            "--no-ext-diff",
            "--no-textconv",
        ],
    )?;
    if raw
        .windows(b"160000".len())
        .any(|window| window == b"160000")
    {
        return Err("GITLINK_CHANGE_DENIED".into());
    }
    Ok(())
}

fn validate_final_commit(repository: &Path, base: &str, head: &str) -> Result<(), String> {
    let parents = String::from_utf8(git_bytes(
        repository,
        &["rev-list", "--parents", "-n", "1", head],
    )?)
    .map_err(|_| "FINAL_COMMIT_INVALID".to_owned())?;
    let fields = parents.split_whitespace().collect::<Vec<_>>();
    if fields != [head, base] {
        return Err("FINAL_COMMIT_LINEAGE_INVALID".into());
    }
    let symbolic = safe_git_output(repository, &["symbolic-ref", "-q", "HEAD"])?;
    if symbolic.status.success() || symbolic.status.code() != Some(1) {
        return Err("FINAL_HEAD_NOT_DETACHED".into());
    }
    Ok(())
}

fn ensure_directory_empty(path: &Path, code: &'static str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|_| code.to_owned())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(code.into());
    }
    if fs::read_dir(path)
        .map_err(|_| code.to_owned())?
        .next()
        .is_some()
    {
        return Err(code.into());
    }
    Ok(())
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
    let mut add_args = vec!["add", "--"];
    add_args.extend(paths.iter().map(String::as_str));
    let out = safe_git_output(&prepared.worktree.path, &add_args)
        .map_err(|_| "GIT_STAGE_FAILED".to_owned())?;
    if !out.status.success() {
        return Err("GIT_STAGE_FAILED".into());
    }
    reject_gitlinks(&prepared.worktree.path)?;
    let out = safe_git_output(
        &prepared.worktree.path,
        &[
            "-c",
            "user.name=zcode-reviewd",
            "-c",
            "user.email=zcode-reviewd@localhost",
            "-c",
            "commit.gpgSign=false",
            "commit",
            "--no-verify",
            "--no-gpg-sign",
            "-m",
            "chore(agent): finalize bounded task result",
        ],
    )
    .map_err(|_| "GIT_COMMIT_FAILED".to_owned())?;
    if !out.status.success() {
        return Err("GIT_COMMIT_FAILED".into());
    }
    let head = String::from_utf8(git_bytes(&prepared.worktree.path, &["rev-parse", "HEAD"])?)
        .map_err(|_| "GIT_HEAD_INVALID".to_owned())?
        .trim()
        .to_owned();
    validate_final_commit(&prepared.worktree.path, &prepared.base_sha, &head)?;
    let patch = git_bytes(
        &prepared.worktree.path,
        &[
            "diff",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            &prepared.base_sha,
            &head,
        ],
    )?;
    let repeated = git_bytes(
        &prepared.worktree.path,
        &[
            "diff",
            "--binary",
            "--no-ext-diff",
            "--no-textconv",
            &prepared.base_sha,
            &head,
        ],
    )?;
    if patch != repeated {
        return Err("PATCH_NOT_DETERMINISTIC".into());
    }
    if patch.len() as u64 > prepared.effective_budget.max_artifact_bytes {
        return Err("ARTIFACT_LIMIT_EXCEEDED".into());
    }
    let path = prepared
        .artifact_targets
        .get(&GeneralArtifactKind::ChangesPatch)
        .ok_or("ARTIFACT_TARGET_INVALID")?;
    atomic_write(path, &patch).map_err(|_| "ARTIFACT_WRITE_FAILED".to_owned())?;
    let digest = hash(&patch);
    verify_file(path, &digest, Some(patch.len() as u64))
        .map_err(|_| "AUTHORITATIVE_ARTIFACT_INVALID".to_owned())?;
    let diff_stat = String::from_utf8(git_bytes(
        &prepared.worktree.path,
        &[
            "diff",
            "--stat",
            "--no-ext-diff",
            "--no-textconv",
            &prepared.base_sha,
            &head,
        ],
    )?)
    .map_err(|_| "DIFF_STAT_INVALID".to_owned())?;
    let metadata = ArtifactMetadata {
        artifact_id: hash(format!("{}:{}", prepared.task_id, digest).as_bytes()),
        kind: GeneralArtifactKind::ChangesPatch,
        sha256: digest,
        size_bytes: patch.len() as u64,
        partial,
        head_commit: Some(head),
        base_sha: prepared.base_sha.clone(),
        changed_paths: paths,
        diff_stat: Some(diff_stat),
        media_type: "application/vnd.git-diff".into(),
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
fn prepare_context(
    worktree: &Path,
    paths: &[PathBuf],
    prompt_bytes: u64,
    max_context_bytes: u64,
) -> PreparationResult<(Vec<PreparedContext>, u64)> {
    let mut total = prompt_bytes;
    let context = paths
        .iter()
        .map(|relative| {
            reject_protected(relative)?;
            let path = reject_symlink_path(worktree, relative)?;
            if !path.is_file() {
                return Err(PreparationError::MissingInput(path));
            }
            if secret_type(&path) {
                return Err(PreparationError::CredentialInput(path));
            }
            let bytes = fs::read(&path)?;
            total = total.saturating_add(bytes.len() as u64);
            if total > max_context_bytes {
                return Err(PreparationError::InvalidManifest(
                    "context byte limit exceeded".into(),
                ));
            }
            Ok(PreparedContext {
                repository_relative: relative.clone(),
                sha256: hash(&bytes),
                size_bytes: bytes.len() as u64,
            })
        })
        .collect::<PreparationResult<Vec<_>>>()?;
    Ok((context, total))
}

fn verify_file(
    path: &Path,
    expected_hash: &str,
    expected_size: Option<u64>,
) -> PreparationResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PreparationError::SymlinkInput(path.into()));
    }
    let bytes = fs::read(path)?;
    if expected_size.is_some_and(|size| size != bytes.len() as u64) || hash(&bytes) != expected_hash
    {
        return Err(PreparationError::InvalidManifest(format!(
            "prepared content integrity changed: {}",
            path.display()
        )));
    }
    Ok(())
}
fn verify_confined_file(
    root: &Path,
    path: &Path,
    expected_hash: &str,
    expected_size: Option<u64>,
) -> PreparationResult<()> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| PreparationError::PathEscape {
            path: path.into(),
            root: root.into(),
        })?;
    let mut cursor = root.to_path_buf();
    for component in relative.components() {
        cursor.push(component);
        if fs::symlink_metadata(&cursor)?.file_type().is_symlink() {
            return Err(PreparationError::SymlinkInput(cursor));
        }
    }
    if fs::canonicalize(path)? != path {
        return Err(PreparationError::PathEscape {
            path: path.into(),
            root: root.into(),
        });
    }
    verify_file(path, expected_hash, expected_size)
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
    if prepared.worktree.path.exists() {
        let Ok(head) = git_bytes(&prepared.worktree.path, &["rev-parse", "HEAD"]) else {
            return false;
        };
        let Ok(head) = String::from_utf8(head) else {
            return false;
        };
        if safe_git_output(&prepared.worktree.path, &["symbolic-ref", "-q", "HEAD"])
            .is_ok_and(|output| output.status.success())
            && !safe_git_output(
                &prepared.worktree.path,
                &["checkout", "--detach", head.trim()],
            )
            .is_ok_and(|output| output.status.success())
        {
            return false;
        }
        let mut worktree = prepared.worktree.clone();
        worktree.head_sha = head.trim().into();
        let Ok(diagnostics) = manager.capture_integrity(&worktree) else {
            return false;
        };
        let Ok(record) = manager.persist_integrity(&worktree, diagnostics) else {
            return false;
        };
        if manager.cleanup_from_record(&record).is_err() {
            return false;
        }
    }
    let Some(job_root) = prepared.worktree.scratch_worktrees_root.parent() else {
        return false;
    };
    if !job_root.exists() {
        return manager
            .verify_registration_absent(&prepared.worktree.path)
            .is_ok();
    }
    if !prepared.worktree.path.exists()
        && manager
            .verify_registration_absent(&prepared.worktree.path)
            .is_ok()
    {
        return cleanup_job_root_path(job_root).is_ok();
    }
    if manager.verify_worktree_absent(&prepared.worktree).is_err() {
        return false;
    }
    cleanup_job_root_path(job_root).is_ok()
}

fn bounded_cleanup_worktree(
    manager: &WorktreeManager,
    worktree: &PreparedWorktree,
    job_root: &Path,
) -> PreparationResult<()> {
    let mut last_error = None;
    for _ in 0..3 {
        match manager
            .capture_integrity(worktree)
            .and_then(|diagnostics| manager.persist_integrity(worktree, diagnostics))
            .and_then(|record| manager.cleanup_from_record(&record).map(|_| ()))
            .and_then(|_| manager.verify_worktree_absent(worktree))
            .and_then(|_| cleanup_job_root_path(job_root))
        {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| PreparationError::Worktree("cleanup retry exhausted".into())))
}

fn bounded_cleanup_unregistered(
    manager: &WorktreeManager,
    worktree_path: &Path,
    job_root: &Path,
) -> PreparationResult<()> {
    let mut last_error = None;
    for _ in 0..3 {
        match manager
            .verify_path_absent(worktree_path)
            .and_then(|_| cleanup_job_root_path(job_root))
        {
            Ok(()) => return Ok(()),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| PreparationError::Worktree("cleanup retry exhausted".into())))
}

fn validate_reusable_prepared(
    prepared: &PreparedGeneralTask,
    manifest_sha256: &str,
    repository: &Path,
    base_sha: &str,
    manager: &WorktreeManager,
) -> PreparationResult<()> {
    prepared.validate_digest()?;
    if prepared.manifest_sha256 != manifest_sha256
        || prepared.repository != repository
        || prepared.base_sha != base_sha
    {
        return Err(PreparationError::IdempotencyConflict(
            "key already owns a different immutable general task".into(),
        ));
    }
    prepared.validate_prepared_content()?;
    let diagnostics = manager.capture_integrity(&prepared.worktree)?;
    if diagnostics.has_policy_violation()
        || diagnostics.observed_head.as_deref() != Some(base_sha)
        || !diagnostics.detached_head_unchanged
    {
        return Err(PreparationError::Worktree(
            "prepared record worktree is stale or no longer detached at base".into(),
        ));
    }
    Ok(())
}

fn cleanup_stale_record(
    manager: &WorktreeManager,
    job_root: &Path,
    _record_bytes: &[u8],
) -> PreparationResult<()> {
    // A record that already failed digest/content/owner validation is never
    // authority for deletion, even when its JSON shape remains parseable.
    // Enumerate only manager-bound registrations under the canonical job root.
    manager.cleanup_registered_under_job_root(job_root)?;
    cleanup_job_root_path(job_root)
}
fn cleanup_if_trusted(prepared: &PreparedGeneralTask) -> bool {
    prepared.validate_digest().is_ok() && cleanup_after_failure(prepared)
}
fn cleanup_job_root_path(job_root: &Path) -> PreparationResult<()> {
    if !job_root.exists() {
        return Ok(());
    }
    let root = fs::canonicalize(job_root)?;
    let parent = root
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| PreparationError::Worktree("job root has no parent".into()))?;
    let repository = root
        .ancestors()
        .find(|candidate| candidate.join(".git").exists())
        .ok_or_else(|| PreparationError::Worktree("job root has no repository ancestor".into()))?;
    let allowed = repository.join(".agent-work/scratch");
    if root.file_name().is_none()
        || root == parent
        || !root.starts_with(&allowed)
        || root
            .components()
            .any(|component| component.as_os_str() == ".git")
    {
        return Err(PreparationError::PathEscape {
            path: root,
            root: parent,
        });
    }
    fs::remove_dir_all(&root)?;
    if root.exists() {
        return Err(PreparationError::Worktree(
            "job root remains after cleanup".into(),
        ));
    }
    Ok(())
}
fn git_bytes(repo: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let out = safe_git_output(repo, args)?;
    if !out.status.success() {
        return Err("GIT_COMMAND_FAILED".into());
    }
    Ok(out.stdout)
}
fn safe_git_output(repo: &Path, args: &[&str]) -> Result<std::process::Output, String> {
    Command::new("git")
        .current_dir(repo)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", "/var/empty")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PAGER", "cat")
        .env_remove("GIT_EXTERNAL_DIFF")
        .args(["-c", "core.hooksPath=/dev/null", "-c", "core.pager=cat"])
        .args(args)
        .output()
        .map_err(|_| "GIT_COMMAND_FAILED".to_owned())
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
