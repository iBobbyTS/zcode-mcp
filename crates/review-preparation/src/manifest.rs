use crate::{
    policy::{is_credential_path, is_prior_review_artifact, prepare_command},
    PolicyCapabilities, PolicyLauncher, PreparationError, PreparationResult, PreparedCommand,
    PreparedWorktree, WorktreeManager,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs,
    path::{Component, Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Mutex,
};

pub const MANIFEST_SCHEMA: &str = "sectioned-zcode-review/v1";
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_IDEMPOTENCY_KEY_BYTES: usize = 512;
static PREPARATION_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewKind {
    Plan,
    Code,
}

impl ReviewKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Code => "code",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RoundKind {
    PlanReview,
    InitialBounded,
    RepairDelta,
    FinalBounded,
}

impl RoundKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlanReview => "PLAN_REVIEW",
            Self::InitialBounded => "INITIAL_BOUNDED",
            Self::RepairDelta => "REPAIR_DELTA",
            Self::FinalBounded => "FINAL_BOUNDED",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    Deny,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScratchPolicy {
    Isolated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationCommand {
    pub id: String,
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewManifest {
    pub schema: String,
    pub review_kind: ReviewKind,
    pub feature_id: String,
    pub section_id: String,
    pub round_kind: RoundKind,
    pub repository: PathBuf,
    pub base_ref: String,
    pub head_ref: String,
    pub plan_path: PathBuf,
    pub context_paths: Vec<PathBuf>,
    pub scope_paths: Vec<PathBuf>,
    pub forbidden_input_globs: Vec<String>,
    pub validation_commands: Vec<ValidationCommand>,
    pub report_target: PathBuf,
    pub scratch_root: PathBuf,
    #[serde(default)]
    pub model: Option<String>,
    pub fresh_session: bool,
    pub network_policy: NetworkPolicy,
    pub scratch_policy: ScratchPolicy,
    pub idempotency_key: String,
}

impl ReviewManifest {
    pub fn from_json(bytes: &[u8]) -> PreparationResult<Self> {
        let manifest = serde_json::from_slice(bytes)?;
        validate_manifest_fields(&manifest)?;
        Ok(manifest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputArtifact {
    pub source_path: PathBuf,
    pub prepared_path: PathBuf,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedScopePath {
    pub repository_relative: PathBuf,
    pub worktree_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedLaunchSpec {
    pub schema: String,
    pub review_kind: ReviewKind,
    pub feature_id: String,
    pub section_id: String,
    pub round_kind: RoundKind,
    pub repository: PathBuf,
    pub base_sha: String,
    pub head_sha: String,
    pub worktree: PreparedWorktree,
    pub plan: InputArtifact,
    pub context: Vec<InputArtifact>,
    pub scope: Vec<PreparedScopePath>,
    pub forbidden_input_globs: Vec<String>,
    pub validation_commands: Vec<PreparedCommand>,
    pub report_target: PathBuf,
    pub scratch_root: PathBuf,
    pub manifest_provenance_path: PathBuf,
    pub manifest_sha256: String,
    pub prepared_sha256: String,
    pub model: Option<String>,
    pub fresh_session: bool,
    pub network_policy: NetworkPolicy,
    pub scratch_policy: ScratchPolicy,
    pub idempotency_key: String,
    pub capabilities: PolicyCapabilities,
}

impl PreparedLaunchSpec {
    pub fn canonical_json(&self) -> PreparationResult<String> {
        Ok(serde_json::to_string(self)?)
    }

    pub fn validate_digest(&self) -> PreparationResult<()> {
        if !self.fresh_session {
            return Err(PreparationError::InvalidManifest(
                "prepared counted review must use a fresh session".into(),
            ));
        }
        let mut unsigned = self.clone();
        let expected = unsigned.prepared_sha256.clone();
        unsigned.prepared_sha256.clear();
        let actual = sha256(&serde_json::to_vec(&unsigned)?);
        if actual != expected {
            return Err(PreparationError::InvalidManifest(
                "prepared launch digest does not match its canonical fields".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_for_launch(&self) -> PreparationResult<()> {
        self.validate_digest()?;
        let job_root = self
            .worktree
            .scratch_worktrees_root
            .parent()
            .ok_or_else(|| PreparationError::Worktree("worktree root has no job root".into()))?;
        let manager = WorktreeManager::new(self.repository.clone(), job_root.to_path_buf())?;
        let diagnostics = manager.capture_integrity(&self.worktree)?;
        if diagnostics.has_policy_violation() {
            return Err(PreparationError::Worktree(
                "prepared launch integrity changed before runtime start".into(),
            ));
        }
        Ok(())
    }

    pub fn launcher(&self) -> PreparationResult<PolicyLauncher> {
        self.validate_digest()?;
        let mut readable_inputs = Vec::with_capacity(self.context.len() + 1);
        readable_inputs.push(self.plan.prepared_path.clone());
        readable_inputs.extend(
            self.context
                .iter()
                .map(|artifact| artifact.prepared_path.clone()),
        );
        PolicyLauncher::new(
            self.worktree.path.clone(),
            self.scratch_root.clone(),
            self.report_target.clone(),
            readable_inputs,
            self.validation_commands.clone(),
            self.network_policy == NetworkPolicy::Allow,
            self.capabilities.clone(),
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReviewPreparer;

impl ReviewPreparer {
    pub fn prepare(&self, manifest: &ReviewManifest) -> PreparationResult<PreparedLaunchSpec> {
        let _guard = PREPARATION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        validate_manifest_fields(manifest)?;
        let repository = canonical_repository(&manifest.repository)?;
        let base_sha = resolve_commit(&repository, &manifest.base_ref)?;
        let head_sha = resolve_commit(&repository, &manifest.head_ref)?;
        ensure_ancestor(&repository, &base_sha, &head_sha)?;

        let plan_source = canonical_input(&repository, &manifest.plan_path, true)?;
        validate_allowed_input(
            &repository,
            &plan_source,
            &manifest.plan_path,
            &manifest.forbidden_input_globs,
        )?;
        let mut context_sources = Vec::with_capacity(manifest.context_paths.len());
        for context in &manifest.context_paths {
            let source = canonical_input(&repository, context, true)?;
            validate_allowed_input(
                &repository,
                &source,
                context,
                &manifest.forbidden_input_globs,
            )?;
            context_sources.push(source);
        }
        let scope_relative = manifest
            .scope_paths
            .iter()
            .map(|scope| validated_relative(scope))
            .collect::<PreparationResult<Vec<_>>>()?;
        for scope in &scope_relative {
            validate_scope_policy(scope, &manifest.forbidden_input_globs)?;
            ensure_source_scope_clean(&repository, scope)?;
        }

        let scratch_root = canonical_scratch_root(&repository, &manifest.scratch_root)?;
        let report_target = canonical_report_target(&repository, &manifest.report_target)?;
        let normalized_manifest = serde_json::to_vec_pretty(manifest)?;
        let manifest_sha256 = sha256(&normalized_manifest);
        let preparation_key = sha256(
            serde_json::to_string(&(
                repository.to_string_lossy().as_ref(),
                manifest.idempotency_key.as_str(),
            ))?
            .as_bytes(),
        );
        let job_root = create_confined_directory(&scratch_root, &preparation_key)?;
        let finalized_spec_path = job_root.join("provenance/prepared-launch.json");
        if finalized_spec_path.is_file() {
            reject_symlink_components(&finalized_spec_path)?;
            let existing: PreparedLaunchSpec =
                serde_json::from_slice(&fs::read(&finalized_spec_path)?)?;
            existing.validate_digest()?;
            if existing.manifest_sha256 != manifest_sha256
                || existing.repository != repository
                || existing.idempotency_key != manifest.idempotency_key
            {
                return Err(PreparationError::IdempotencyConflict(
                    "key already owns a different canonical manifest".into(),
                ));
            }
            return Ok(existing);
        }
        let manager = WorktreeManager::new(repository.clone(), job_root.clone())?;
        let worktree = manager.create(&head_sha, &preparation_key)?;
        let built = (|| {
            let inputs_root = create_confined_directory(&job_root, "inputs")?;
            let provenance_root = create_confined_directory(&job_root, "provenance")?;
            let writable_scratch = create_confined_directory(&job_root, "scratch")?;
            let plan = snapshot_input(&plan_source, &inputs_root, 0)?;
            let context = context_sources
                .iter()
                .enumerate()
                .map(|(index, path)| snapshot_input(path, &inputs_root, index + 1))
                .collect::<PreparationResult<Vec<_>>>()?;
            let scope = scope_relative
                .iter()
                .cloned()
                .map(|relative| {
                    let worktree_path = canonical_input(&worktree.path, &relative, false)?;
                    validate_allowed_input(
                        &worktree.path,
                        &worktree_path,
                        &relative,
                        &manifest.forbidden_input_globs,
                    )?;
                    Ok(PreparedScopePath {
                        repository_relative: relative,
                        worktree_path,
                    })
                })
                .collect::<PreparationResult<Vec<_>>>()?;
            let validation_commands = prepare_commands(
                &manifest.validation_commands,
                &worktree.path,
                &writable_scratch,
                manifest.network_policy == NetworkPolicy::Allow,
            )?;
            let provenance_path = provenance_root.join("review-manifest.json");
            atomic_write(&provenance_path, &normalized_manifest)?;
            let provenance_path = fs::canonicalize(provenance_path)?;

            let mut spec = PreparedLaunchSpec {
                schema: manifest.schema.clone(),
                review_kind: manifest.review_kind,
                feature_id: manifest.feature_id.clone(),
                section_id: manifest.section_id.clone(),
                round_kind: manifest.round_kind,
                repository: repository.clone(),
                base_sha: base_sha.clone(),
                head_sha: head_sha.clone(),
                worktree: worktree.clone(),
                plan,
                context,
                scope,
                forbidden_input_globs: manifest.forbidden_input_globs.clone(),
                validation_commands,
                report_target: report_target.clone(),
                scratch_root: writable_scratch,
                manifest_provenance_path: provenance_path,
                manifest_sha256,
                prepared_sha256: String::new(),
                model: manifest.model.clone(),
                fresh_session: manifest.fresh_session,
                network_policy: manifest.network_policy,
                scratch_policy: manifest.scratch_policy,
                idempotency_key: manifest.idempotency_key.clone(),
                capabilities: PolicyCapabilities::for_network(
                    manifest.network_policy == NetworkPolicy::Allow,
                ),
            };
            spec.prepared_sha256 = sha256(&serde_json::to_vec(&spec)?);
            spec.validate_digest()?;
            atomic_write(
                &provenance_root.join("prepared-launch.json"),
                &serde_json::to_vec_pretty(&spec)?,
            )?;
            Ok(spec)
        })();
        match built {
            Ok(spec) => Ok(spec),
            Err(error) => {
                if let Err(cleanup) = cleanup_failed_preparation(&manager, &worktree) {
                    return Err(PreparationError::Worktree(format!(
                        "preparation failed ({error}); verified cleanup failed ({cleanup})"
                    )));
                }
                Err(error)
            }
        }
    }
}

fn cleanup_failed_preparation(
    manager: &WorktreeManager,
    worktree: &PreparedWorktree,
) -> PreparationResult<()> {
    let diagnostics = manager.capture_integrity(worktree)?;
    let record = manager.persist_integrity(worktree, diagnostics)?;
    manager.cleanup_from_record(&record)?;
    Ok(())
}

fn validate_manifest_fields(manifest: &ReviewManifest) -> PreparationResult<()> {
    if manifest.schema != MANIFEST_SCHEMA {
        return Err(PreparationError::InvalidManifest(format!(
            "unsupported schema {}",
            manifest.schema
        )));
    }
    validate_identifier("feature_id", &manifest.feature_id, MAX_IDENTIFIER_BYTES)?;
    validate_identifier("section_id", &manifest.section_id, MAX_IDENTIFIER_BYTES)?;
    validate_identifier(
        "idempotency_key",
        &manifest.idempotency_key,
        MAX_IDEMPOTENCY_KEY_BYTES,
    )?;
    ensure_unique("context_paths", &manifest.context_paths)?;
    ensure_unique("scope_paths", &manifest.scope_paths)?;
    ensure_unique("forbidden_input_globs", &manifest.forbidden_input_globs)?;
    if manifest
        .forbidden_input_globs
        .iter()
        .any(|pattern| pattern.is_empty())
    {
        return Err(PreparationError::InvalidManifest(
            "forbidden_input_globs cannot contain an empty pattern".into(),
        ));
    }
    if !manifest.fresh_session {
        return Err(PreparationError::InvalidManifest(
            "counted review requires fresh_session=true".into(),
        ));
    }
    if manifest.scope_paths.is_empty() {
        return Err(PreparationError::InvalidManifest(
            "scope_paths cannot be empty".into(),
        ));
    }
    if manifest
        .model
        .as_ref()
        .is_some_and(|model| model.trim().is_empty())
    {
        return Err(PreparationError::InvalidManifest(
            "model cannot be empty when supplied".into(),
        ));
    }
    let mut command_ids = HashSet::new();
    for command in &manifest.validation_commands {
        validate_identifier("validation command id", &command.id, MAX_IDENTIFIER_BYTES)?;
        if !command_ids.insert(command.id.as_str()) {
            return Err(PreparationError::InvalidManifest(format!(
                "duplicate validation command id {}",
                command.id
            )));
        }
        if command.timeout_ms == 0
            || command.timeout_ms > 3_600_000
            || command.max_output_bytes == 0
            || command.max_output_bytes > 16 * 1024 * 1024
        {
            return Err(PreparationError::InvalidManifest(format!(
                "validation command {} has invalid bounds",
                command.id
            )));
        }
    }
    Ok(())
}

fn validate_identifier(name: &str, value: &str, max_bytes: usize) -> PreparationResult<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        return Err(PreparationError::InvalidManifest(format!(
            "{name} has an invalid format"
        )));
    }
    Ok(())
}

fn ensure_unique<T>(name: &str, values: &[T]) -> PreparationResult<()>
where
    T: Eq + std::hash::Hash,
{
    let mut unique = HashSet::with_capacity(values.len());
    if values.iter().all(|value| unique.insert(value)) {
        Ok(())
    } else {
        Err(PreparationError::InvalidManifest(format!(
            "{name} cannot contain duplicates"
        )))
    }
}

fn validate_scope_policy(scope: &Path, forbidden_globs: &[String]) -> PreparationResult<()> {
    if is_credential_path(scope) {
        return Err(PreparationError::CredentialInput(scope.to_path_buf()));
    }
    let normalized = scope.to_string_lossy().replace('\\', "/");
    if is_prior_review_artifact(scope)
        || forbidden_globs
            .iter()
            .any(|pattern| wildcard_match(pattern, &normalized))
    {
        return Err(PreparationError::ForbiddenInput(scope.to_path_buf()));
    }
    Ok(())
}

fn ensure_source_scope_clean(repository: &Path, scope: &Path) -> PreparationResult<()> {
    for cached in [false, true] {
        let mut command = Command::new("git");
        command.arg("-C").arg(repository).arg("diff");
        if cached {
            command.arg("--cached");
        }
        let status = command
            .args(["--quiet", "--no-ext-diff", "--no-textconv", "--"])
            .arg(scope)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("GIT_LITERAL_PATHSPECS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        match status.code() {
            Some(0) => {}
            Some(1) => {
                return Err(PreparationError::Worktree(format!(
                    "source scope {} has tracked {} changes",
                    scope.display(),
                    if cached { "staged" } else { "unstaged" }
                )));
            }
            _ => {
                return Err(PreparationError::Git(format!(
                    "could not inspect tracked changes for source scope {}",
                    scope.display()
                )));
            }
        }
    }
    Ok(())
}

fn canonical_repository(path: &Path) -> PreparationResult<PathBuf> {
    if !path.is_absolute() {
        return Err(PreparationError::InvalidPath {
            path: path.to_path_buf(),
            reason: "repository must be absolute".into(),
        });
    }
    reject_symlink_components(path)?;
    let canonical = fs::canonicalize(path)?;
    let root = git_text(&canonical, &["rev-parse", "--show-toplevel"])?;
    let root = fs::canonicalize(root)?;
    if canonical != root {
        return Err(PreparationError::InvalidPath {
            path: canonical,
            reason: "repository must identify the Git top level".into(),
        });
    }
    Ok(root)
}

fn resolve_commit(repository: &Path, reference: &str) -> PreparationResult<String> {
    if reference.len() != 40 || !reference.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PreparationError::MutableReference(reference.into()));
    }
    let expected = reference.to_ascii_lowercase();
    let resolved = git_text(
        repository,
        &["rev-parse", "--verify", &format!("{expected}^{{commit}}")],
    )?;
    if resolved != expected {
        return Err(PreparationError::MutableReference(reference.into()));
    }
    Ok(resolved)
}

fn ensure_ancestor(repository: &Path, base: &str, head: &str) -> PreparationResult<()> {
    let output = git(repository, &["merge-base", "--is-ancestor", base, head])?;
    if !output.status.success() {
        return Err(PreparationError::InvalidManifest(
            "base commit is not an ancestor of head commit".into(),
        ));
    }
    Ok(())
}

fn canonical_input(
    repository: &Path,
    relative: &Path,
    require_file: bool,
) -> PreparationResult<PathBuf> {
    let relative = validated_relative(relative)?;
    let candidate = repository.join(relative);
    reject_symlink_components(&candidate)?;
    let canonical = fs::canonicalize(&candidate)
        .map_err(|_| PreparationError::MissingInput(candidate.clone()))?;
    if !canonical.starts_with(repository) {
        return Err(PreparationError::PathEscape {
            path: canonical,
            root: repository.to_path_buf(),
        });
    }
    if require_file && !canonical.is_file() {
        return Err(PreparationError::InvalidPath {
            path: canonical,
            reason: "input must be a regular file".into(),
        });
    }
    Ok(canonical)
}

fn validate_allowed_input(
    repository: &Path,
    canonical: &Path,
    original: &Path,
    forbidden_globs: &[String],
) -> PreparationResult<()> {
    if is_credential_path(canonical) {
        return Err(PreparationError::CredentialInput(canonical.to_path_buf()));
    }
    let relative =
        canonical
            .strip_prefix(repository)
            .map_err(|_| PreparationError::PathEscape {
                path: canonical.to_path_buf(),
                root: repository.to_path_buf(),
            })?;
    let normalized = relative.to_string_lossy().replace('\\', "/");
    if is_prior_review_artifact(canonical)
        || forbidden_globs
            .iter()
            .any(|pattern| wildcard_match(pattern, &normalized))
    {
        return Err(PreparationError::ForbiddenInput(original.to_path_buf()));
    }
    Ok(())
}

fn canonical_scratch_root(repository: &Path, path: &Path) -> PreparationResult<PathBuf> {
    let allowed_root = repository.join(".agent-work").join("scratch");
    reject_symlink_components(&allowed_root)?;
    let candidate = if path.is_absolute() {
        reject_parent_components(path)?;
        path.to_path_buf()
    } else {
        repository.join(validated_relative(path)?)
    };
    ensure_lexically_confined(&candidate, &allowed_root, false)?;
    reject_symlink_components(&candidate)?;
    fs::create_dir_all(&allowed_root)?;
    let allowed_root = fs::canonicalize(allowed_root)?;
    fs::create_dir_all(&candidate)?;
    let canonical = fs::canonicalize(&candidate)?;
    if canonical == allowed_root || !canonical.starts_with(&allowed_root) {
        return Err(PreparationError::PathEscape {
            path: canonical,
            root: allowed_root,
        });
    }
    Ok(canonical)
}

fn canonical_report_target(repository: &Path, path: &Path) -> PreparationResult<PathBuf> {
    let allowed_root = repository.join(".agent-work").join("reviews");
    reject_symlink_components(&allowed_root)?;
    let candidate = if path.is_absolute() {
        reject_parent_components(path)?;
        path.to_path_buf()
    } else {
        repository.join(validated_relative(path)?)
    };
    let filename = candidate
        .file_name()
        .ok_or_else(|| PreparationError::InvalidPath {
            path: candidate.clone(),
            reason: "report target has no file name".into(),
        })?
        .to_owned();
    let parent = candidate
        .parent()
        .ok_or_else(|| PreparationError::InvalidPath {
            path: candidate.clone(),
            reason: "report target has no parent".into(),
        })?;
    ensure_lexically_confined(parent, &allowed_root, true)?;
    reject_symlink_components(&candidate)?;
    reject_symlink_components(parent)?;
    fs::create_dir_all(&allowed_root)?;
    let allowed_root = fs::canonicalize(allowed_root)?;
    fs::create_dir_all(parent)?;
    let parent = fs::canonicalize(parent)?;
    if parent != allowed_root && !parent.starts_with(&allowed_root) {
        return Err(PreparationError::PathEscape {
            path: parent,
            root: allowed_root,
        });
    }
    Ok(parent.join(filename))
}

fn snapshot_input(source: &Path, root: &Path, index: usize) -> PreparationResult<InputArtifact> {
    let name = source
        .file_name()
        .ok_or_else(|| PreparationError::InvalidPath {
            path: source.to_path_buf(),
            reason: "input has no file name".into(),
        })?;
    let target = root.join(format!("{index:04}-{}", name.to_string_lossy()));
    let bytes = fs::read(source)?;
    atomic_write(&target, &bytes)?;
    let target = fs::canonicalize(target)?;
    Ok(InputArtifact {
        source_path: source.to_path_buf(),
        prepared_path: target,
        sha256: sha256(&bytes),
        bytes: u64::try_from(bytes.len())
            .map_err(|_| PreparationError::InvalidManifest("input artifact is too large".into()))?,
    })
}

fn prepare_commands(
    commands: &[ValidationCommand],
    worktree: &Path,
    scratch_root: &Path,
    network_allowed: bool,
) -> PreparationResult<Vec<PreparedCommand>> {
    commands
        .iter()
        .map(|command| {
            let relative_cwd = validated_relative(&command.cwd)?;
            prepare_command(
                &command.id,
                &command.program,
                &command.args,
                &worktree.join(relative_cwd),
                worktree,
                scratch_root,
                (
                    command.timeout_ms,
                    command.max_output_bytes,
                    network_allowed,
                ),
            )
        })
        .collect()
}

fn validated_relative(path: &Path) -> PreparationResult<PathBuf> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(PreparationError::InvalidPath {
            path: path.to_path_buf(),
            reason: "path must be non-empty and repository-relative".into(),
        });
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(PreparationError::InvalidPath {
            path: path.to_path_buf(),
            reason: "path traversal is forbidden".into(),
        });
    }
    Ok(path.to_path_buf())
}

fn create_confined_directory(root: &Path, name: &str) -> PreparationResult<PathBuf> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || matches!(name, "." | "..") {
        return Err(PreparationError::InvalidManifest(
            "scratch directory name is invalid".into(),
        ));
    }
    let path = root.join(name);
    ensure_lexically_confined(&path, root, false)?;
    reject_symlink_components(&path)?;
    fs::create_dir_all(&path)?;
    let path = fs::canonicalize(path)?;
    if path == root || !path.starts_with(root) {
        return Err(PreparationError::PathEscape {
            path,
            root: root.to_path_buf(),
        });
    }
    Ok(path)
}

fn ensure_lexically_confined(path: &Path, root: &Path, allow_root: bool) -> PreparationResult<()> {
    reject_parent_components(path)?;
    if (!allow_root && path == root) || !path.starts_with(root) {
        return Err(PreparationError::PathEscape {
            path: path.to_path_buf(),
            root: root.to_path_buf(),
        });
    }
    Ok(())
}

fn reject_parent_components(path: &Path) -> PreparationResult<()> {
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(PreparationError::InvalidPath {
            path: path.to_path_buf(),
            reason: "path traversal is forbidden".into(),
        });
    }
    Ok(())
}

fn reject_symlink_components(path: &Path) -> PreparationResult<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current.exists() && fs::symlink_metadata(&current)?.file_type().is_symlink() {
            return Err(PreparationError::SymlinkInput(current));
        }
    }
    Ok(())
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern = pattern.replace("**", "*");
    let (mut pattern_index, mut value_index) = (0usize, 0usize);
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut star, mut star_value) = (None, 0usize);
    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            star = Some(pattern_index);
            pattern_index += 1;
            star_value = value_index;
        } else if let Some(star_index) = star {
            pattern_index = star_index + 1;
            star_value += 1;
            value_index = star_value;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn atomic_write(path: &Path, bytes: &[u8]) -> PreparationResult<()> {
    let parent = path.parent().ok_or_else(|| PreparationError::InvalidPath {
        path: path.to_path_buf(),
        reason: "output path has no parent".into(),
    })?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(".{}.tmp", std::process::id()));
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn git_text(path: &Path, arguments: &[&str]) -> PreparationResult<String> {
    let output = git(path, arguments)?;
    if !output.status.success() {
        return Err(PreparationError::Git(
            String::from_utf8_lossy(&output.stderr).trim().into(),
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().into())
}

fn git(path: &Path, arguments: &[&str]) -> PreparationResult<Output> {
    Ok(Command::new("git")
        .arg("-C")
        .arg(path)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .output()?)
}
