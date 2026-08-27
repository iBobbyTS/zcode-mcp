mod general;
mod manifest;
mod policy;
mod worktree;

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

use std::{fmt, path::PathBuf};

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
