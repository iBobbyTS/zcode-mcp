mod general;
mod manifest;
mod policy;
mod worktree;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

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
    #[serde(default)]
    pub effective_config_path: Option<String>,
    #[serde(default)]
    pub effective_config_sha256: Option<String>,
    #[serde(default)]
    pub effective_guard_wrapper_path: Option<String>,
    #[serde(default)]
    pub effective_guard_wrapper_sha256: Option<String>,
    #[serde(default)]
    pub effective_audit_wrapper_path: Option<String>,
    #[serde(default)]
    pub effective_audit_wrapper_sha256: Option<String>,
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
        effective_config_path: None,
        effective_config_sha256: None,
        effective_guard_wrapper_path: None,
        effective_guard_wrapper_sha256: None,
        effective_audit_wrapper_path: None,
        effective_audit_wrapper_sha256: None,
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
    let artifact_matches = file_hash_matches(
        record.effective_hook_path.as_deref(),
        record.effective_hook_sha256.as_deref(),
    );
    // `activation_generation` identifies the installed/preflighted hook
    // artifact. The daemon's restart-scoped service generation is a separate
    // process identity and is intentionally not coupled to this record.
    let verified = record.hook_activation_verified
        && record.daemon_policy_version == daemon_policy_version
        && record.daemon_policy_sha256 == daemon_policy_sha256
        && record.expected_hook_version == expected_hook_version
        && record.expected_hook_sha256 == expected_hook_sha256
        && record.effective_hook_version.as_deref() == Some(expected_hook_version.as_str())
        && record.effective_hook_sha256.as_deref() == Some(expected_hook_sha256.as_str())
        && artifact_matches
        && effective_config_references_hook(&record)
        && record
            .activation_method
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        && record
            .activation_generation
            .as_deref()
            .is_some_and(|value| !value.is_empty());
    if verified {
        record
    } else {
        unverified()
    }
}

fn file_hash_matches(path: Option<&str>, expected: Option<&str>) -> bool {
    match (path, expected) {
        (Some(path), Some(expected)) => fs::read(path)
            .ok()
            .is_some_and(|bytes| sha256_bytes(&bytes) == expected),
        _ => false,
    }
}

fn effective_config_references_hook(record: &ReviewHookProvenance) -> bool {
    let (
        Some(config_path),
        Some(config_sha256),
        Some(guard_path),
        Some(guard_sha256),
        Some(audit_path),
        Some(audit_sha256),
    ) = (
        record.effective_config_path.as_deref(),
        record.effective_config_sha256.as_deref(),
        record.effective_guard_wrapper_path.as_deref(),
        record.effective_guard_wrapper_sha256.as_deref(),
        record.effective_audit_wrapper_path.as_deref(),
        record.effective_audit_wrapper_sha256.as_deref(),
    )
    else {
        return false;
    };
    if !file_hash_matches(Some(config_path), Some(config_sha256))
        || !file_hash_matches(Some(guard_path), Some(guard_sha256))
        || !file_hash_matches(Some(audit_path), Some(audit_sha256))
    {
        return false;
    }
    let Some(hook_root) = PathBuf::from(guard_path)
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
    else {
        return false;
    };
    if Path::new(audit_path) != hook_root.join("hooks/audit-bash-result.mjs")
        || record.effective_hook_path.as_deref()
            != hook_root.join("lib/readonly-bash-policy.mjs").to_str()
    {
        return false;
    }
    let Ok(config) = fs::read(config_path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .ok_or(())
    else {
        return false;
    };
    if config
        .pointer("/hooks/enabled")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return false;
    }
    [
        ("PreToolUse", guard_path),
        ("PostToolUse", audit_path),
        ("PostToolUseFailure", audit_path),
    ]
    .into_iter()
    .all(|(event, expected_path)| config_event_references(&config, event, expected_path))
}

fn config_event_references(config: &serde_json::Value, event: &str, expected_path: &str) -> bool {
    config
        .pointer(&format!("/hooks/events/{event}"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                let hook = entry
                    .get("hooks")
                    .and_then(serde_json::Value::as_array)
                    .filter(|hooks| hooks.len() == 1)
                    .and_then(|hooks| hooks.first());
                let command = hook
                    .and_then(|hook| hook.get("command"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(|command| {
                        PathBuf::from(command)
                            .file_name()
                            .map(|name| name.to_owned())
                    });
                entry.get("matcher").and_then(serde_json::Value::as_str) == Some("Bash")
                    && entry.get("description").and_then(serde_json::Value::as_str)
                        == Some(&format!("review-bash-hook:{event}"))
                    && hook
                        .and_then(|hook| hook.get("type"))
                        .and_then(serde_json::Value::as_str)
                        == Some("process")
                    && hook
                        .and_then(|hook| hook.get("timeoutMs"))
                        .and_then(serde_json::Value::as_u64)
                        == Some(5_000)
                    && command.as_deref().is_some_and(|name| name == "node")
                    && hook
                        .and_then(|hook| hook.get("args"))
                        .and_then(serde_json::Value::as_array)
                        .filter(|args| args.len() == 1)
                        .and_then(|args| args.first())
                        .and_then(serde_json::Value::as_str)
                        == Some(expected_path)
            })
        })
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
