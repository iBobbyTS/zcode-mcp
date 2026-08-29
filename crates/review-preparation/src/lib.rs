mod general;
mod manifest;
mod policy;
mod worktree;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, fs, path::PathBuf};

/// Version and descriptor digest of the plugin-supplied conservative review Bash policy.
/// The daemon exposes these alongside review provenance so policy decisions are auditable.
pub const REVIEW_BASH_POLICY_VERSION: &str = "zcode-readonly-bash/v1.0.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewHookProvenance {
    pub daemon_policy_version: String,
    pub daemon_policy_sha256: String,
    pub expected_hook_version: String,
    pub expected_hook_sha256: String,
    pub effective_hook_version: Option<String>,
    pub effective_hook_sha256: Option<String>,
    #[serde(default)]
    pub effective_hook_path: Option<String>,
    pub hook_activation_verified: bool,
    pub activation_method: Option<String>,
    pub activation_generation: Option<String>,
}

impl Default for ReviewHookProvenance {
    fn default() -> Self {
        review_bash_hook_provenance()
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn review_bash_daemon_policy_sha256() -> String {
    sha256_bytes(include_bytes!("policy.rs"))
}

pub fn review_bash_hook_sha256() -> String {
    sha256_bytes(include_bytes!(
        "../../../plugins/zcode-subagent-mcp-v2/review-bash-hook/lib/readonly-bash-policy.mjs"
    ))
}

pub fn review_bash_hook_provenance() -> ReviewHookProvenance {
    let daemon_policy_version = REVIEW_BASH_POLICY_VERSION.to_owned();
    let daemon_policy_sha256 = review_bash_daemon_policy_sha256();
    let expected_hook_version = REVIEW_BASH_POLICY_VERSION.to_owned();
    let expected_hook_sha256 = review_bash_hook_sha256();
    let unverified = || ReviewHookProvenance {
        daemon_policy_version: daemon_policy_version.clone(),
        daemon_policy_sha256: daemon_policy_sha256.clone(),
        expected_hook_version: expected_hook_version.clone(),
        expected_hook_sha256: expected_hook_sha256.clone(),
        effective_hook_version: None,
        effective_hook_sha256: None,
        effective_hook_path: None,
        hook_activation_verified: false,
        activation_method: None,
        activation_generation: None,
    };
    let Some(path) = std::env::var_os("ZCODE_REVIEW_HOOK_PROVENANCE") else {
        return unverified();
    };
    let Ok(bytes) = fs::read(path) else {
        return unverified();
    };
    let Ok(record) = serde_json::from_slice::<ReviewHookProvenance>(&bytes) else {
        return unverified();
    };
    let service_generation = std::env::var("ZCODE_REVIEW_SERVICE_GENERATION").ok();
    let artifact_matches = record
        .effective_hook_path
        .as_deref()
        .and_then(|path| fs::read(path).ok())
        .is_some_and(|bytes| Some(sha256_bytes(&bytes)) == record.effective_hook_sha256);
    let verified = record.hook_activation_verified
        && record.daemon_policy_version == daemon_policy_version
        && record.daemon_policy_sha256 == daemon_policy_sha256
        && record.expected_hook_version == expected_hook_version
        && record.expected_hook_sha256 == expected_hook_sha256
        && record.effective_hook_version.as_deref() == Some(expected_hook_version.as_str())
        && record.effective_hook_sha256.as_deref() == Some(expected_hook_sha256.as_str())
        && artifact_matches
        && record
            .activation_method
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        && record
            .activation_generation
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        && record.activation_generation.as_deref() == service_generation.as_deref();
    if verified {
        record
    } else {
        unverified()
    }
}

/// Digest of both decision owners that make up the shipped review Bash policy.
///
/// The Rust source governs daemon permission preview/effective decisions, while
/// the plugin JavaScript governs the ZCode hook. Embedding both source files
/// prevents provenance from silently identifying only one half of the policy.
pub fn review_bash_policy_sha256() -> String {
    let mut digest = Sha256::new();
    for (label, source) in [
        ("daemon-rust-policy", include_bytes!("policy.rs").as_slice()),
        (
            "plugin-js-policy",
            include_bytes!(
                "../../../plugins/zcode-subagent-mcp-v2/review-bash-hook/lib/readonly-bash-policy.mjs"
            )
            .as_slice(),
        ),
    ] {
        digest.update((label.len() as u64).to_be_bytes());
        digest.update(label.as_bytes());
        digest.update((source.len() as u64).to_be_bytes());
        digest.update(source);
    }
    format!("{:x}", digest.finalize())
}

pub use general::{
    canonical_general_repository, general_control_header, general_launch_prompt,
    validate_general_named_command, ArtifactMetadata, AttachmentInput, BudgetLimits,
    CompletionOutcome, GeneralArtifactIntent, GeneralArtifactKind, GeneralCompletion,
    GeneralCompletionSubmission, GeneralFinalizer, GeneralNamedCommand, GeneralProfile,
    GeneralTaskManifest, GeneralTaskPreparer, PreparedAttachment, PreparedContext,
    PreparedGeneralTask, PublicAttachment, GENERAL_COMPLETE_TOOL_NAME, GENERAL_CONTROL_SCHEMA,
    GENERAL_RUN_CHECK_TOOL_NAME, GENERAL_TASK_SCHEMA,
};

pub use manifest::{
    InputArtifact, NetworkPolicy, PreparedLaunchSpec, PreparedScopePath, ReviewKind,
    ReviewManifest, ReviewPreparer, RoundKind, ScratchPolicy, ValidationCommand,
    MAX_VALIDATION_COMMAND_TIMEOUT_MS,
};
pub use policy::{
    ExternalDecision, PermissionDecision, PermissionRequest, PolicyCapabilities, PolicyLauncher,
    PolicyMode, PreparedCommand, SandboxEnforcement, ValidationOutput,
};
pub use worktree::{CleanupRecord, IntegrityDiagnostics, PreparedWorktree, WorktreeManager};

#[derive(Debug)]
pub enum PreparationError {
    InvalidManifest(String),
    InvalidPath { path: PathBuf, reason: String },
    PathEscape { path: PathBuf, root: PathBuf },
    SymlinkInput(PathBuf),
    MissingInput(PathBuf),
    MutableReference(String),
    ForbiddenInput(PathBuf),
    CredentialInput(PathBuf),
    Git(String),
    Worktree(String),
    Policy(String),
    IdempotencyConflict(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl PreparationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidManifest(_) => "INVALID_MANIFEST",
            Self::InvalidPath { .. } => "INVALID_PATH",
            Self::PathEscape { .. } => "PATH_ESCAPE",
            Self::SymlinkInput(_) => "SYMLINK_INPUT",
            Self::MissingInput(_) => "MISSING_INPUT",
            Self::MutableReference(_) => "MUTABLE_REFERENCE",
            Self::ForbiddenInput(_) => "FORBIDDEN_INPUT",
            Self::CredentialInput(_) => "CREDENTIAL_INPUT",
            Self::Git(_) => "GIT_ERROR",
            Self::Worktree(_) => "WORKTREE_ERROR",
            Self::Policy(_) => "POLICY_DENIED",
            Self::IdempotencyConflict(_) => "IDEMPOTENCY_CONFLICT",
            Self::Io(_) => "IO_ERROR",
            Self::Json(_) => "JSON_ERROR",
        }
    }
}

impl fmt::Display for PreparationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest(message) => write!(formatter, "invalid manifest: {message}"),
            Self::InvalidPath { path, reason } => {
                write!(formatter, "invalid path {}: {reason}", path.display())
            }
            Self::PathEscape { path, root } => write!(
                formatter,
                "path {} escapes allowed root {}",
                path.display(),
                root.display()
            ),
            Self::SymlinkInput(path) => {
                write!(formatter, "symlink input is forbidden: {}", path.display())
            }
            Self::MissingInput(path) => write!(formatter, "input is missing: {}", path.display()),
            Self::MutableReference(reference) => {
                write!(
                    formatter,
                    "Git reference is not an immutable commit SHA: {reference}"
                )
            }
            Self::ForbiddenInput(path) => {
                write!(
                    formatter,
                    "prior review input is forbidden: {}",
                    path.display()
                )
            }
            Self::CredentialInput(path) => {
                write!(
                    formatter,
                    "credential input is forbidden: {}",
                    path.display()
                )
            }
            Self::Git(message) => write!(formatter, "Git operation failed: {message}"),
            Self::Worktree(message) => write!(formatter, "worktree operation failed: {message}"),
            Self::Policy(message) => write!(formatter, "policy denied request: {message}"),
            Self::IdempotencyConflict(message) => {
                write!(formatter, "idempotency conflict: {message}")
            }
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::Json(error) => write!(formatter, "JSON error: {error}"),
        }
    }
}

impl std::error::Error for PreparationError {}

impl From<std::io::Error> for PreparationError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for PreparationError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

pub type PreparationResult<T> = Result<T, PreparationError>;
