mod general;
mod manifest;
mod policy;
mod worktree;

pub use general::PermissionMode;
pub use policy::AGENT_BASH_COMMAND_FAMILIES;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

/// Version and descriptor digest of the plugin-supplied conservative Bash policy.
/// The daemon exposes these alongside agent-hook provenance so policy decisions are auditable.
pub const AGENT_BASH_POLICY_VERSION: &str = "zcode-agent-bash/v1.0.0";
pub const AGENT_FILE_POLICY_VERSION: &str = "zcode-agent-file-policy/v1.0.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentHookProvenance {
    pub daemon_policy_version: String,
    pub daemon_policy_sha256: String,
    pub expected_hook_version: String,
    pub expected_hook_sha256: String,
    pub effective_hook_version: Option<String>,
    pub effective_hook_sha256: Option<String>,
    #[serde(default)]
    pub effective_file_policy_version: Option<String>,
    #[serde(default)]
    pub effective_file_policy_sha256: Option<String>,
    #[serde(default)]
    pub effective_file_policy_path: Option<String>,
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
    #[serde(default)]
    pub effective_file_wrapper_path: Option<String>,
    #[serde(default)]
    pub effective_file_wrapper_sha256: Option<String>,
    pub hook_activation_verified: bool,
    pub activation_method: Option<String>,
    pub activation_generation: Option<String>,
    /// Binds this installed hook record to the generic daemon configuration.
    /// The daemon supplies the expected value at startup; it is not inferred
    /// from the activation artifact itself.
    #[serde(default)]
    pub service_generation: Option<String>,
}

impl Default for AgentHookProvenance {
    fn default() -> Self {
        agent_bash_hook_provenance()
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn agent_bash_daemon_policy_sha256() -> String {
    sha256_bytes(include_bytes!("policy.rs"))
}

pub fn agent_bash_hook_sha256() -> String {
    sha256_bytes(include_bytes!(
        "../../../plugins/zcode-subagent-mcp/lib/bash-policy.mjs"
    ))
}

pub fn agent_bash_hook_provenance() -> AgentHookProvenance {
    let expected_service_generation = std::env::var("ZCODE_AGENT_SERVICE_GENERATION").ok();
    agent_bash_hook_provenance_for_service_generation(expected_service_generation.as_deref())
}

/// Load and verify the installed hook record against the daemon generation.
/// A missing expected generation intentionally fails closed, while callers
/// that do not yet have a daemon identity can use the legacy-shaped helper
/// only for untrusted diagnostics.
pub fn agent_bash_hook_provenance_for_service_generation(
    expected_service_generation: Option<&str>,
) -> AgentHookProvenance {
    let daemon_policy_version = AGENT_BASH_POLICY_VERSION.to_owned();
    let daemon_policy_sha256 = agent_bash_daemon_policy_sha256();
    let expected_hook_version = AGENT_BASH_POLICY_VERSION.to_owned();
    let expected_hook_sha256 = agent_bash_hook_sha256();
    let unverified = || AgentHookProvenance {
        daemon_policy_version: daemon_policy_version.clone(),
        daemon_policy_sha256: daemon_policy_sha256.clone(),
        expected_hook_version: expected_hook_version.clone(),
        expected_hook_sha256: expected_hook_sha256.clone(),
        effective_hook_version: None,
        effective_hook_sha256: None,
        effective_file_policy_version: None,
        effective_file_policy_sha256: None,
        effective_file_policy_path: None,
        effective_hook_path: None,
        effective_config_path: None,
        effective_config_sha256: None,
        effective_guard_wrapper_path: None,
        effective_guard_wrapper_sha256: None,
        effective_audit_wrapper_path: None,
        effective_audit_wrapper_sha256: None,
        effective_file_wrapper_path: None,
        effective_file_wrapper_sha256: None,
        hook_activation_verified: false,
        activation_method: None,
        activation_generation: None,
        service_generation: None,
    };
    let Some(path) = std::env::var_os("ZCODE_AGENT_HOOK_PROVENANCE") else {
        return unverified();
    };
    let Ok(bytes) = fs::read(path) else {
        return unverified();
    };
    let Ok(record) = serde_json::from_slice::<AgentHookProvenance>(&bytes) else {
        return unverified();
    };
    let artifact_matches = file_hash_matches(
        record.effective_hook_path.as_deref(),
        record.effective_hook_sha256.as_deref(),
    );
    let file_policy_matches = file_hash_matches(
        record.effective_file_policy_path.as_deref(),
        record.effective_file_policy_sha256.as_deref(),
    );
    let verified = record.hook_activation_verified
        && record.daemon_policy_version == daemon_policy_version
        && record.daemon_policy_sha256 == daemon_policy_sha256
        && record.expected_hook_version == expected_hook_version
        && record.expected_hook_sha256 == expected_hook_sha256
        && record.effective_hook_version.as_deref() == Some(expected_hook_version.as_str())
        && record.effective_hook_sha256.as_deref() == Some(expected_hook_sha256.as_str())
        && artifact_matches
        && record.effective_file_policy_version.as_deref() == Some(AGENT_FILE_POLICY_VERSION)
        && file_policy_matches
        && effective_config_references_hook(&record)
        && record
            .activation_method
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        && record
            .activation_generation
            .as_deref()
            .is_some_and(|value| !value.is_empty())
        && expected_service_generation
            .filter(|value| !value.is_empty())
            .is_some_and(|expected| record.service_generation.as_deref() == Some(expected));
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

fn effective_config_references_hook(record: &AgentHookProvenance) -> bool {
    let (
        Some(config_path),
        Some(config_sha256),
        Some(guard_path),
        Some(guard_sha256),
        Some(audit_path),
        Some(audit_sha256),
        Some(file_policy_path),
        Some(file_wrapper_path),
        Some(file_wrapper_sha256),
    ) = (
        record.effective_config_path.as_deref(),
        record.effective_config_sha256.as_deref(),
        record.effective_guard_wrapper_path.as_deref(),
        record.effective_guard_wrapper_sha256.as_deref(),
        record.effective_audit_wrapper_path.as_deref(),
        record.effective_audit_wrapper_sha256.as_deref(),
        record.effective_file_policy_path.as_deref(),
        record.effective_file_wrapper_path.as_deref(),
        record.effective_file_wrapper_sha256.as_deref(),
    )
    else {
        return false;
    };
    if !file_hash_matches(Some(config_path), Some(config_sha256))
        || !file_hash_matches(Some(guard_path), Some(guard_sha256))
        || !file_hash_matches(Some(audit_path), Some(audit_sha256))
        || !file_hash_matches(
            Some(file_policy_path),
            record.effective_file_policy_sha256.as_deref(),
        )
        || !file_hash_matches(Some(file_wrapper_path), Some(file_wrapper_sha256))
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
        || record.effective_hook_path.as_deref() != hook_root.join("lib/bash-policy.mjs").to_str()
        || Path::new(file_policy_path) != hook_root.join("lib/agent-file-policy.mjs")
        || Path::new(file_wrapper_path) != hook_root.join("hooks/check-agent-files.mjs")
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
    .all(|(event, expected_path)| config_event_references(&config, event, "Bash", expected_path))
        && config_event_references(
            &config,
            "PreToolUse",
            "^(Read|Grep|Glob|Write|Edit|Delete|Move)$",
            file_wrapper_path,
        )
}

fn config_event_references(
    config: &serde_json::Value,
    event: &str,
    matcher: &str,
    expected_path: &str,
) -> bool {
    config
        .pointer(&format!("/hooks/events/{event}"))
        .and_then(serde_json::Value::as_array)
        .is_some_and(|entries| {
            let bash_entries = entries
                .iter()
                .filter(|entry| {
                    entry.get("matcher").and_then(serde_json::Value::as_str) == Some(matcher)
                })
                .collect::<Vec<_>>();
            bash_entries.len() == 1
                && bash_entries.into_iter().all(|entry| {
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
                    entry.get("description").is_none()
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

#[cfg(test)]
mod provenance_tests {
    use super::agent_bash_hook_provenance_for_service_generation;

    #[test]
    fn missing_record_cannot_verify_against_a_daemon_generation() {
        let provenance = agent_bash_hook_provenance_for_service_generation(Some("daemon-test"));
        assert!(!provenance.hook_activation_verified);
        assert!(provenance.service_generation.is_none());
    }
}

/// Digest of both decision owners that make up the shipped agent Bash policy.
///
/// The Rust source governs daemon permission preview/effective decisions, while
/// the plugin JavaScript governs the ZCode hook. Embedding both source files
/// prevents provenance from silently identifying only one half of the policy.
pub fn agent_bash_policy_sha256() -> String {
    let mut digest = Sha256::new();
    for (label, source) in [
        ("daemon-rust-policy", include_bytes!("policy.rs").as_slice()),
        (
            "plugin-js-policy",
            include_bytes!("../../../plugins/zcode-subagent-mcp/lib/bash-policy.mjs").as_slice(),
        ),
        (
            "plugin-js-file-policy",
            include_bytes!("../../../plugins/zcode-subagent-mcp/lib/agent-file-policy.mjs")
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
    validate_general_named_command, AccessMode, AttachmentInput, BudgetLimits, ChangesPatch,
    CompletionOutcome, GeneralCompletion, GeneralFinalizer, GeneralNamedCommand,
    GeneralTaskManifest, GeneralTaskPreparer, PreparedAttachment, PreparedContext,
    PreparedGeneralTask, PublicAttachment, GENERAL_CONTROL_SCHEMA, GENERAL_TASK_SCHEMA,
};

pub use manifest::{ValidationCommand, MAX_VALIDATION_COMMAND_TIMEOUT_MS};
pub use policy::{
    ExternalDecision, PermissionDecision, PermissionRequest, PolicyCapabilities, PolicyLauncher,
    PreparedCommand, SandboxEnforcement, ValidatedPermissionDenial, ValidationOutput,
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
                    "forbidden agent metadata input is forbidden: {}",
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

#[cfg(test)]
mod hook_config_tests {
    use super::config_event_references;
    use serde_json::json;

    fn event_entry(path: &str) -> serde_json::Value {
        json!({
            "matcher": "Bash",
            "hooks": [{
                "type": "process",
                "command": "node",
                "args": [path],
                "timeoutMs": 5000
            }]
        })
    }

    #[test]
    fn accepts_zcode_016_description_free_single_bash_entry() {
        let config = json!({
            "hooks": {"events": {
                "PreToolUse": [
                    {"matcher": "Other", "hooks": []},
                    event_entry("/hooks/check-bash-readonly.mjs")
                ]
            }}
        });
        assert!(config_event_references(
            &config,
            "PreToolUse",
            "Bash",
            "/hooks/check-bash-readonly.mjs"
        ));
    }

    #[test]
    fn rejects_description_or_duplicate_bash_entries() {
        let mut described = event_entry("/hooks/check-bash-readonly.mjs");
        described["description"] = json!("agent-hook:PreToolUse");
        let config = json!({"hooks": {"events": {"PreToolUse": [described]}}});
        assert!(!config_event_references(
            &config,
            "PreToolUse",
            "Bash",
            "/hooks/check-bash-readonly.mjs"
        ));

        let config = json!({"hooks": {"events": {"PreToolUse": [
            event_entry("/hooks/check-bash-readonly.mjs"),
            event_entry("/hooks/check-bash-readonly.mjs")
        ]}}});
        assert!(!config_event_references(
            &config,
            "PreToolUse",
            "Bash",
            "/hooks/check-bash-readonly.mjs"
        ));
    }
}
