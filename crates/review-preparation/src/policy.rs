use crate::{PreparationError, PreparationResult};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs,
    io::{ErrorKind, Read},
    os::unix::process::CommandExt,
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxEnforcement {
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyCapabilities {
    pub exact_command_allowlist: bool,
    pub sanitized_environment: bool,
    pub bounded_time_and_output: bool,
    pub local_hard_deny: bool,
    pub source_integrity_diagnostics: bool,
    pub network_isolation_enforced: bool,
    pub network_control: String,
    pub os_sandbox: SandboxEnforcement,
}

impl Default for PolicyCapabilities {
    fn default() -> Self {
        Self::for_network(false)
    }
}

impl PolicyCapabilities {
    pub(crate) fn for_network(network_allowed: bool) -> Self {
        Self {
            exact_command_allowlist: true,
            sanitized_environment: true,
            bounded_time_and_output: true,
            local_hard_deny: true,
            source_integrity_diagnostics: true,
            network_isolation_enforced: false,
            network_control: if network_allowed {
                "manifest allows network; no network isolation is enforced".into()
            } else {
                "known network clients and URL arguments denied; general network isolation unsupported"
                    .into()
            },
            os_sandbox: SandboxEnforcement::Unsupported,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreparedCommand {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    pub environment: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub readonly_safe: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyMode {
    ReviewReadonly,
    GeneralReadonly,
    GeneralTest,
    GeneralImplementation { tracked_write_roots: Vec<PathBuf> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionRequest {
    Read(PathBuf),
    Write(PathBuf),
    Edit(PathBuf),
    Delete(PathBuf),
    Move {
        source: PathBuf,
        destination: PathBuf,
    },
    Execute {
        program: PathBuf,
        args: Vec<String>,
        cwd: PathBuf,
    },
    Network(String),
    GitRefMutation,
    CredentialRead(PathBuf),
    InternalReviewLedger,
    InternalGeneralCompletion,
    InternalGeneralRunCheck(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDecision {
    pub allowed: bool,
    pub reason: &'static str,
}

macro_rules! define_review_bash_command_families {
    ($($program:literal),+ $(,)?) => {
        /// The command families enforced by the Rust review Bash policy and
        /// projected into task capability guidance.
        pub const REVIEW_BASH_COMMAND_FAMILIES: &[&str] = &[$($program),+];

        fn review_bash_program_allowed(program: &str) -> bool {
            matches!(program, $($program)|+)
        }
    };
}

define_review_bash_command_families!(
    "pwd", "ls", "stat", "wc", "head", "tail", "cat", "grep", "rg", "sed", "find", "git", "shasum",
    "cksum",
);

#[derive(Debug, Clone, PartialEq, Eq)]
struct PermissionDenialSemantics {
    program_family: String,
    category: String,
    reason_code: String,
    operand_class: String,
    retry_class: &'static str,
    recommended_action: &'static str,
}

impl PermissionDenialSemantics {
    fn fingerprint(&self) -> String {
        format!(
            "family={};category={};reason={};operand={}",
            self.program_family, self.category, self.reason_code, self.operand_class
        )
    }

    fn feedback(&self, repeated: bool) -> String {
        if repeated {
            format!(
                "DENY[policy_version={};code=REPEATED_DENIED_OPERATION;retry=do_not_retry_equivalent;next=use_read_or_existing_inputs;original_code={}]",
                crate::REVIEW_BASH_POLICY_VERSION,
                self.reason_code
            )
        } else {
            format!(
                "DENY[policy_version={};code={};retry={};next={}]",
                crate::REVIEW_BASH_POLICY_VERSION,
                self.reason_code,
                self.retry_class,
                self.recommended_action
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationOutput {
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub cancelled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryState {
    Existing,
    Missing,
}

#[derive(Debug, Clone)]
pub struct PolicyLauncher {
    worktree: PathBuf,
    scratch_root: PathBuf,
    report_target: PathBuf,
    readable_inputs: Vec<PathBuf>,
    commands: BTreeMap<String, PreparedCommand>,
    network_allowed: bool,
    capabilities: PolicyCapabilities,
    mode: PolicyMode,
}

impl PolicyLauncher {
    pub fn new(
        worktree: PathBuf,
        scratch_root: PathBuf,
        report_target: PathBuf,
        readable_inputs: Vec<PathBuf>,
        commands: BTreeMap<String, PreparedCommand>,
        network_allowed: bool,
        capabilities: PolicyCapabilities,
    ) -> PreparationResult<Self> {
        let worktree = fs::canonicalize(worktree)?;
        let scratch_root = fs::canonicalize(scratch_root)?;
        let report_parent =
            report_target
                .parent()
                .ok_or_else(|| PreparationError::InvalidPath {
                    path: report_target.clone(),
                    reason: "report target has no parent".into(),
                })?;
        let report_parent = fs::canonicalize(report_parent)?;
        let report_target = report_parent.join(report_target.file_name().ok_or_else(|| {
            PreparationError::InvalidPath {
                path: report_target.clone(),
                reason: "report target has no file name".into(),
            }
        })?);
        let readable_inputs = readable_inputs
            .into_iter()
            .map(|root| fs::canonicalize(&root).map_err(PreparationError::Io))
            .collect::<PreparationResult<Vec<_>>>()?;
        Ok(Self {
            worktree,
            scratch_root,
            report_target,
            readable_inputs,
            commands,
            network_allowed,
            capabilities,
            mode: PolicyMode::ReviewReadonly,
        })
    }

    pub fn for_general(
        worktree: PathBuf,
        scratch_root: PathBuf,
        artifact_target: PathBuf,
        readable_inputs: Vec<PathBuf>,
        commands: BTreeMap<String, PreparedCommand>,
        capabilities: PolicyCapabilities,
        mode: PolicyMode,
    ) -> PreparationResult<Self> {
        let mut launcher = Self::new(
            worktree,
            scratch_root,
            artifact_target,
            readable_inputs,
            commands,
            false,
            capabilities,
        )?;
        launcher.mode = mode;
        if let PolicyMode::GeneralImplementation {
            tracked_write_roots,
        } = &mut launcher.mode
        {
            for root in tracked_write_roots.iter_mut() {
                *root = lexical_confined_path(&launcher.worktree, root)?;
                if protected_worktree_path(&launcher.worktree, root) {
                    return Err(PreparationError::Policy(
                        "tracked write root targets protected metadata".into(),
                    ));
                }
            }
        }
        Ok(launcher)
    }

    pub fn capabilities(&self) -> &PolicyCapabilities {
        &self.capabilities
    }

    /// Returns a machine-parseable denial prefix and an attempt-local semantic
    /// fingerprint for a ZCode permission request. The caller owns only the
    /// transient retry state; policy classification remains in this owner.
    pub fn zcode_denial_feedback(
        params: &serde_json::Value,
        supplied_reason: Option<&str>,
        repeated: bool,
    ) -> Option<(String, String)> {
        let semantics = permission_denial_semantics(params, supplied_reason)?;
        Some((semantics.feedback(repeated), semantics.fingerprint()))
    }

    pub fn decide(
        &self,
        request: &PermissionRequest,
        external: ExternalDecision,
    ) -> PermissionDecision {
        if let Some(reason) = self.hard_deny_reason(request) {
            return PermissionDecision {
                allowed: false,
                reason,
            };
        }
        if external == ExternalDecision::Deny {
            return PermissionDecision {
                allowed: false,
                reason: "external_policy_denied",
            };
        }
        PermissionDecision {
            allowed: true,
            reason: "allowed_by_bounded_policy",
        }
    }

    pub fn decide_zcode_permission(
        &self,
        params: &serde_json::Value,
        external: ExternalDecision,
    ) -> PermissionDecision {
        let Some(tool_name) = params.get("toolName").and_then(serde_json::Value::as_str) else {
            return PermissionDecision {
                allowed: false,
                reason: "permission_tool_missing",
            };
        };
        let input = params.get("input").unwrap_or(&serde_json::Value::Null);
        if tool_name == "Bash" {
            if !matches!(self.mode, PolicyMode::ReviewReadonly) {
                return PermissionDecision {
                    allowed: false,
                    reason: "permission_request_unrecognized",
                };
            }
            return self.decide_review_bash(input, external);
        }
        let request = if tool_name == "mcp__general-completion__zcode_general_complete" {
            Some(PermissionRequest::InternalGeneralCompletion)
        } else if tool_name == "mcp__general-completion__zcode_general_run_check" {
            exact_command_id_input(input).map(PermissionRequest::InternalGeneralRunCheck)
        } else if matches!(
            tool_name,
            "mcp__review-ledger__review_checkpoint"
                | "mcp__review-ledger__review_progress"
                | "mcp__review-ledger__review_finding_upsert"
                | "mcp__review-ledger__review_validation_record"
                | "mcp__review-ledger__review_finalize"
        ) {
            Some(PermissionRequest::InternalReviewLedger)
        } else {
            match tool_name.to_ascii_lowercase().as_str() {
                "read" | "grep" | "glob" => input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .map(|path| PermissionRequest::Read(self.resolve_job_path(path))),
                "write" => input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .map(|path| PermissionRequest::Write(self.resolve_job_path(path))),
                "edit" => input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .map(|path| PermissionRequest::Edit(self.resolve_job_path(path))),
                "delete" => input
                    .get("path")
                    .and_then(serde_json::Value::as_str)
                    .map(|path| PermissionRequest::Delete(self.resolve_job_path(path))),
                "move" => {
                    let source = input
                        .get("source")
                        .and_then(serde_json::Value::as_str)
                        .map(|path| self.resolve_job_path(path));
                    let destination = input
                        .get("destination")
                        .and_then(serde_json::Value::as_str)
                        .map(|path| self.resolve_job_path(path));
                    match (source, destination) {
                        (Some(source), Some(destination)) => Some(PermissionRequest::Move {
                            source,
                            destination,
                        }),
                        _ => None,
                    }
                }
                "network" => input
                    .get("target")
                    .and_then(serde_json::Value::as_str)
                    .map(|target| PermissionRequest::Network(target.into())),
                "git_ref_mutation" => Some(PermissionRequest::GitRefMutation),
                "execute" | "terminal" => {
                    let program = input
                        .get("program")
                        .and_then(serde_json::Value::as_str)
                        .map(PathBuf::from);
                    let args = input
                        .get("args")
                        .and_then(serde_json::Value::as_array)
                        .and_then(|values| {
                            values
                                .iter()
                                .map(|value| value.as_str().map(str::to_owned))
                                .collect::<Option<Vec<_>>>()
                        });
                    let cwd = input
                        .get("cwd")
                        .and_then(serde_json::Value::as_str)
                        .map(|path| self.resolve_job_path(path));
                    match (program, args, cwd) {
                        (Some(program), Some(args), Some(cwd)) => {
                            Some(PermissionRequest::Execute { program, args, cwd })
                        }
                        _ => None,
                    }
                }
                _ => None,
            }
        };
        match request {
            Some(request) => self.decide(&request, external),
            None => PermissionDecision {
                allowed: false,
                reason: "permission_request_unrecognized",
            },
        }
    }

    fn decide_review_bash(
        &self,
        input: &serde_json::Value,
        external: ExternalDecision,
    ) -> PermissionDecision {
        if external == ExternalDecision::Deny {
            return PermissionDecision {
                allowed: false,
                reason: "external_policy_denied",
            };
        }
        let Some(command) = input.get("command").and_then(serde_json::Value::as_str) else {
            return PermissionDecision {
                allowed: false,
                reason: "bash_command_missing",
            };
        };
        let cwd = input
            .get("cwd")
            .and_then(serde_json::Value::as_str)
            .map(PathBuf::from)
            .unwrap_or_else(|| self.worktree.clone());
        let cwd = match fs::canonicalize(&cwd) {
            Ok(path) if self.is_review_root(&path) => path,
            _ => {
                return PermissionDecision {
                    allowed: false,
                    reason: "cwd_outside_review_roots",
                }
            }
        };
        let Some(argv) = tokenize_review_bash(command) else {
            return PermissionDecision {
                allowed: false,
                reason: "shell_composition_or_expansion_denied",
            };
        };
        let program = argv.first().map(String::as_str).unwrap_or_default();
        if !review_bash_program_allowed(program) {
            return PermissionDecision {
                allowed: false,
                reason: "command_not_allowlisted",
            };
        }
        if program == "sed" && !valid_review_sed(&argv[1..]) {
            return PermissionDecision {
                allowed: false,
                reason: "sed_form_not_bounded",
            };
        }
        if program == "git"
            && argv[2..].iter().any(|arg| {
                is_credential_path(Path::new(arg)) || is_prior_review_artifact(Path::new(arg))
            })
        {
            return PermissionDecision {
                allowed: false,
                reason: "git_sensitive_path_denied",
            };
        }
        if program == "git" && !valid_review_git(&argv[1..]) {
            return PermissionDecision {
                allowed: false,
                reason: "git_option_or_mutation_denied",
            };
        }
        let path_args = match review_bash_path_operands(program, &argv[1..]) {
            Some(paths) => paths,
            None => {
                return PermissionDecision {
                    allowed: false,
                    reason: "command_option_not_allowlisted",
                }
            }
        };
        let require_file = matches!(
            program,
            "cat" | "wc" | "head" | "tail" | "sed" | "shasum" | "cksum"
        );
        if path_args.iter().any(|path| path == "-") {
            return PermissionDecision {
                allowed: false,
                reason: "stdin_input_denied",
            };
        }
        if !self.review_paths_confined(&path_args, &cwd, require_file) {
            return PermissionDecision {
                allowed: false,
                reason: "path_outside_review_roots",
            };
        }
        PermissionDecision {
            allowed: true,
            reason: "review_bash_allowlisted",
        }
    }

    fn is_review_root(&self, path: &Path) -> bool {
        path.starts_with(&self.worktree)
            || self
                .readable_inputs
                .iter()
                .any(|root| path.starts_with(root))
    }

    fn review_paths_confined(&self, args: &[String], cwd: &Path, require_file: bool) -> bool {
        args.iter().all(|arg| {
            let path = Path::new(arg);
            if arg == "-"
                || arg.starts_with('~')
                || path
                    .components()
                    .any(|component| component == Component::ParentDir)
                || is_credential_path(path)
                || is_prior_review_artifact(path)
            {
                return false;
            }
            let candidate = if path.is_absolute() {
                path.to_path_buf()
            } else {
                cwd.join(path)
            };
            let Ok(real) = fs::canonicalize(candidate) else {
                return false;
            };
            if !self.is_review_root(&real)
                || is_credential_path(&real)
                || is_prior_review_artifact(&real)
            {
                return false;
            }
            !require_file || real.is_file()
        })
    }

    pub fn run(&self, command_id: &str) -> PreparationResult<ValidationOutput> {
        let cancellation = AtomicBool::new(false);
        self.run_cancellable(
            command_id,
            Instant::now() + Duration::from_secs(86_400),
            &cancellation,
        )
    }

    pub fn run_cancellable(
        &self,
        command_id: &str,
        attempt_deadline: Instant,
        cancellation: &AtomicBool,
    ) -> PreparationResult<ValidationOutput> {
        let prepared = self.commands.get(command_id).ok_or_else(|| {
            PreparationError::Policy(format!(
                "command {command_id} is not in the exact allowlist"
            ))
        })?;
        if fs::canonicalize(&self.worktree)? != self.worktree
            || fs::canonicalize(&prepared.cwd)? != prepared.cwd
            || !prepared.cwd.starts_with(&self.worktree)
            || fs::canonicalize(&prepared.program)? != prepared.program
            || !prepared.program.is_file()
        {
            return Err(PreparationError::Policy(
                "named command path identity is no longer valid".into(),
            ));
        }
        let request = PermissionRequest::Execute {
            program: prepared.program.clone(),
            args: prepared.args.clone(),
            cwd: prepared.cwd.clone(),
        };
        let decision = self.decide(&request, ExternalDecision::Allow);
        if !decision.allowed {
            return Err(PreparationError::Policy(decision.reason.into()));
        }
        execute(prepared, attempt_deadline, cancellation)
    }

    fn hard_deny_reason(&self, request: &PermissionRequest) -> Option<&'static str> {
        match request {
            PermissionRequest::Network(_) if !self.network_allowed => {
                Some("network_not_enforced_and_request_denied")
            }
            PermissionRequest::Network(_) => None,
            PermissionRequest::GitRefMutation => Some("git_ref_mutation_denied"),
            PermissionRequest::CredentialRead(_) => Some("credential_read_denied"),
            PermissionRequest::InternalReviewLedger => match self.mode {
                PolicyMode::ReviewReadonly => None,
                _ => Some("review_ledger_unavailable_for_general_task"),
            },
            PermissionRequest::InternalGeneralCompletion => match self.mode {
                PolicyMode::ReviewReadonly => {
                    Some("general_completion_unavailable_for_review_task")
                }
                PolicyMode::GeneralReadonly
                | PolicyMode::GeneralTest
                | PolicyMode::GeneralImplementation { .. } => None,
            },
            PermissionRequest::InternalGeneralRunCheck(command_id) => {
                let Some(command) = self.commands.get(command_id) else {
                    return Some("general_check_command_not_selected");
                };
                match self.mode {
                    PolicyMode::ReviewReadonly => Some("general_check_unavailable_for_review_task"),
                    PolicyMode::GeneralReadonly if !command.readonly_safe => {
                        Some("general_check_not_readonly_safe")
                    }
                    PolicyMode::GeneralReadonly
                    | PolicyMode::GeneralTest
                    | PolicyMode::GeneralImplementation { .. } => None,
                }
            }
            PermissionRequest::Read(path) => {
                if is_credential_path(path) {
                    return Some("credential_read_denied");
                }
                let Ok(path) = fs::canonicalize(path) else {
                    return Some("read_path_unverifiable");
                };
                if is_prior_review_artifact(&path) {
                    return Some("prior_review_artifact_denied");
                }
                if path.starts_with(&self.worktree)
                    || self
                        .readable_inputs
                        .iter()
                        .any(|root| path.starts_with(root))
                {
                    None
                } else {
                    Some("read_path_escape_denied")
                }
            }
            PermissionRequest::Write(path) => self.followed_write_denial(path, false),
            PermissionRequest::Edit(path) => self.followed_write_denial(path, true),
            PermissionRequest::Delete(path) => self.lexical_entry_denial(path, true),
            PermissionRequest::Move {
                source,
                destination,
            } => self
                .lexical_entry_denial(source, true)
                .or_else(|| self.lexical_entry_denial(destination, false)),
            PermissionRequest::Execute { program, args, cwd } => {
                if self.commands.values().any(|command| {
                    &command.program == program && &command.args == args && &command.cwd == cwd
                }) {
                    None
                } else {
                    Some("command_not_allowlisted")
                }
            }
        }
    }

    fn resolve_job_path(&self, value: &str) -> PathBuf {
        let path = Path::new(value);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.worktree.join(path)
        }
    }

    fn followed_write_denial(&self, path: &Path, must_exist: bool) -> Option<&'static str> {
        match self.lexical_entry_state(path, must_exist) {
            Ok(EntryState::Existing) => self.canonical_write_denial(path),
            Ok(EntryState::Missing) => None,
            Err(reason) => Some(reason),
        }
    }

    fn lexical_entry_denial(&self, path: &Path, must_exist: bool) -> Option<&'static str> {
        self.lexical_entry_state(path, must_exist).err()
    }

    fn lexical_entry_state(
        &self,
        path: &Path,
        must_exist: bool,
    ) -> Result<EntryState, &'static str> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| component == Component::ParentDir)
        {
            return Err("write_path_unverifiable");
        }
        if let Some(reason) = self.resolved_write_denial(path) {
            return Err(reason);
        }
        match fs::symlink_metadata(path) {
            Ok(_) => {
                let candidate = self.canonical_parent_entry(path)?;
                if let Some(reason) = self.resolved_write_denial(&candidate) {
                    Err(reason)
                } else {
                    Ok(EntryState::Existing)
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound && !must_exist => {
                let Some(candidate) = self.resolve_nonexistent_entry(path) else {
                    return Err("write_path_unverifiable");
                };
                if let Some(reason) = self.resolved_write_denial(&candidate) {
                    Err(reason)
                } else {
                    Ok(EntryState::Missing)
                }
            }
            Err(_) => Err("write_path_unverifiable"),
        }
    }

    fn canonical_parent_entry(&self, path: &Path) -> Result<PathBuf, &'static str> {
        let parent = path.parent().ok_or("write_path_unverifiable")?;
        let filename = path.file_name().ok_or("write_path_unverifiable")?;
        let canonical_parent = fs::canonicalize(parent).map_err(|_| "write_path_unverifiable")?;
        if !canonical_parent.is_dir() {
            return Err("write_path_unverifiable");
        }
        Ok(canonical_parent.join(filename))
    }

    fn canonical_write_denial(&self, path: &Path) -> Option<&'static str> {
        let Ok(canonical) = fs::canonicalize(path) else {
            return Some("write_path_unverifiable");
        };
        self.resolved_write_denial(&canonical)
    }

    fn resolve_nonexistent_entry(&self, path: &Path) -> Option<PathBuf> {
        let mut current = path.to_path_buf();
        let mut missing = Vec::<OsString>::new();
        loop {
            match fs::symlink_metadata(&current) {
                Ok(_) => {
                    let canonical = fs::canonicalize(&current).ok()?;
                    if !canonical.is_dir() {
                        return None;
                    }
                    let mut candidate = canonical;
                    for component in missing.iter().rev() {
                        candidate.push(component);
                    }
                    return Some(candidate);
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    missing.push(current.file_name()?.to_os_string());
                    if !current.pop() {
                        return None;
                    }
                }
                Err(_) => return None,
            }
        }
    }

    fn resolved_write_denial(&self, target: &Path) -> Option<&'static str> {
        let Some(report_root) = self.report_target.parent() else {
            return Some("write_path_unverifiable");
        };
        if target.starts_with(&self.worktree) {
            if protected_worktree_path(&self.worktree, target) {
                return Some("protected_worktree_metadata_denied");
            }
            return match &self.mode {
                PolicyMode::GeneralImplementation {
                    tracked_write_roots,
                } if tracked_write_roots
                    .iter()
                    .any(|root| target.starts_with(root)) =>
                {
                    None
                }
                PolicyMode::GeneralImplementation { .. } => Some("tracked_path_not_allowlisted"),
                _ => Some("tracked_writes_denied_for_profile"),
            };
        }
        if !matches!(self.mode, PolicyMode::ReviewReadonly) && target.starts_with(report_root) {
            return Some("daemon_artifact_root_denied");
        }
        if target == self.scratch_root
            || target == report_root
            || (!target.starts_with(&self.scratch_root) && !target.starts_with(report_root))
        {
            Some("write_outside_artifact_roots_denied")
        } else {
            None
        }
    }
}

fn valid_review_git_branch(args: &[String]) -> bool {
    if args.is_empty() || args == ["--show-current"] {
        return true;
    }
    let mut list_mode = false;
    for arg in args {
        match arg.as_str() {
            "--list" => list_mode = true,
            "--all" | "--remotes" | "--verbose" | "-a" | "-r" | "-v" | "-vv" => {}
            value if value.starts_with('-') => return false,
            _ if list_mode => {}
            _ => return false,
        }
    }
    true
}

fn unsafe_review_git_object_path(arg: &str) -> bool {
    let Some((_, object_path)) = arg.split_once(':') else {
        return false;
    };
    let path = Path::new(object_path);
    object_path.is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| component == Component::ParentDir)
        || is_credential_path(path)
}

fn safe_review_git_operand(arg: &str) -> bool {
    !arg.is_empty()
        && !arg.starts_with('/')
        && !arg.starts_with('~')
        && !arg
            .split('/')
            .any(|component| component.is_empty() || component == "..")
        && !is_credential_path(Path::new(arg))
        && !is_prior_review_artifact(Path::new(arg))
        && !unsafe_review_git_object_path(arg)
}

fn valid_review_git(args: &[String]) -> bool {
    let mut index = 0;
    if args.first().is_some_and(|arg| arg == "--no-pager") {
        index = 1;
    }
    let Some(subcommand) = args.get(index).map(String::as_str) else {
        return false;
    };
    let sub_args = &args[index + 1..];
    match subcommand {
        "status" => valid_review_git_status(sub_args),
        "diff" | "show" | "log" => valid_review_git_diff_like(subcommand, sub_args),
        "rev-parse" => valid_review_git_rev_parse(sub_args),
        "cat-file" => valid_review_git_cat_file(sub_args),
        "ls-files" => valid_review_git_ls_files(sub_args),
        "branch" => valid_review_git_branch(sub_args),
        _ => false,
    }
}

fn valid_review_git_status(args: &[String]) -> bool {
    args.iter().all(|arg| {
        if arg.starts_with('-') {
            matches!(
                arg.as_str(),
                "--short"
                    | "-s"
                    | "--branch"
                    | "-b"
                    | "--porcelain"
                    | "--long"
                    | "--no-ahead-behind"
                    | "--show-stash"
                    | "--no-renames"
            ) || matches!(arg.strip_prefix("--porcelain="), Some("v1") | Some("v2"))
                || matches!(
                    arg.strip_prefix("--untracked-files="),
                    Some("no") | Some("normal") | Some("all")
                )
        } else {
            false
        }
    })
}

fn valid_review_git_diff_like(subcommand: &str, args: &[String]) -> bool {
    let mut paths_mode = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            paths_mode = true;
            index += 1;
            continue;
        }
        if paths_mode {
            if !safe_review_git_operand(arg) {
                return false;
            }
            index += 1;
            continue;
        }
        if matches!(
            arg.as_str(),
            "--output"
                | "--ext-diff"
                | "--textconv"
                | "--no-index"
                | "--show-signature"
                | "--exec"
                | "--stdin"
        ) || arg.starts_with("--output=")
            || arg.starts_with("--exec=")
            || arg.starts_with("--ext-diff=")
            || arg.starts_with("--textconv=")
            || arg.starts_with("--no-index=")
        {
            return false;
        }
        if arg.starts_with('-') {
            let allowed_boolean = match subcommand {
                "diff" => matches!(
                    arg.as_str(),
                    "--cached"
                        | "--staged"
                        | "--stat"
                        | "--shortstat"
                        | "--numstat"
                        | "--name-only"
                        | "--name-status"
                        | "--check"
                        | "--binary"
                        | "--full-index"
                        | "--no-color"
                        | "--minimal"
                        | "--patience"
                        | "--histogram"
                        | "--ignore-space-change"
                        | "--ignore-all-space"
                        | "--ignore-blank-lines"
                        | "--exit-code"
                        | "--quiet"
                        | "--find-renames"
                        | "--find-copies"
                        | "--relative"
                        | "--merge-base"
                        | "--no-renames"
                        | "--word-diff"
                        | "-p"
                        | "-s"
                ),
                "log" => matches!(
                    arg.as_str(),
                    "--oneline"
                        | "--graph"
                        | "--all"
                        | "--branches"
                        | "--tags"
                        | "--remotes"
                        | "--reverse"
                        | "--topo-order"
                        | "--date-order"
                        | "--author-date-order"
                        | "--first-parent"
                        | "--merges"
                        | "--no-merges"
                        | "--name-only"
                        | "--name-status"
                        | "--stat"
                        | "--shortstat"
                        | "--numstat"
                        | "--patch"
                        | "--no-patch"
                        | "--decorate"
                        | "--no-decorate"
                        | "--full-history"
                        | "--simplify-merges"
                        | "--dense"
                        | "--sparse"
                        | "--boundary"
                        | "--left-right"
                        | "--cherry-pick"
                        | "--cherry-mark"
                        | "--ancestry-path"
                        | "--bisect"
                        | "-p"
                ),
                "show" => matches!(
                    arg.as_str(),
                    "--stat"
                        | "--name-only"
                        | "--name-status"
                        | "--no-color"
                        | "--no-patch"
                        | "-s"
                        | "--oneline"
                        | "--decorate"
                        | "--no-decorate"
                ),
                _ => false,
            };
            if allowed_boolean {
                index += 1;
                continue;
            }
            if subcommand == "log" && (arg == "-n" || arg.starts_with("-n")) {
                let value =
                    if let Some(value) = arg.strip_prefix("-n").filter(|value| !value.is_empty()) {
                        value
                    } else {
                        let Some(value) = args.get(index + 1) else {
                            return false;
                        };
                        index += 1;
                        value.as_str()
                    };
                if !valid_positive_integer(value) {
                    return false;
                }
                index += 1;
                continue;
            }
            let (name, inline_value) = arg
                .split_once('=')
                .map_or((arg.as_str(), None), |(name, value)| (name, Some(value)));
            let value_option = match subcommand {
                "diff" => matches!(
                    name,
                    "--unified"
                        | "--diff-filter"
                        | "--submodule"
                        | "--word-diff"
                        | "--word-diff-regex"
                        | "--find-renames"
                        | "--find-copies"
                        | "--color"
                        | "--src-prefix"
                        | "--dst-prefix"
                        | "--line-prefix"
                        | "--inter-hunk-context"
                ),
                "log" => matches!(
                    name,
                    "--max-count"
                        | "--skip"
                        | "--since"
                        | "--until"
                        | "--after"
                        | "--before"
                        | "--author"
                        | "--committer"
                        | "--grep"
                        | "--pretty"
                        | "--format"
                        | "--date"
                        | "--decorate"
                        | "--diff-filter"
                        | "--unified"
                        | "--color"
                ),
                "show" => matches!(name, "--format" | "--pretty" | "--color"),
                _ => false,
            };
            if !value_option {
                return false;
            }
            if let Some(value) = inline_value {
                if value.is_empty() {
                    return false;
                }
                if (matches!(name, "--max-count" | "--skip") && !valid_positive_integer(value))
                    || (matches!(name, "--unified" | "--inter-hunk-context")
                        && !valid_nonnegative_integer(value))
                {
                    return false;
                }
                index += 1;
            } else {
                let Some(value) = args.get(index + 1) else {
                    return false;
                };
                if value.starts_with('-') || value.is_empty() {
                    return false;
                }
                if (matches!(name, "--max-count" | "--skip") && !valid_positive_integer(value))
                    || (matches!(name, "--unified" | "--inter-hunk-context")
                        && !valid_nonnegative_integer(value))
                {
                    return false;
                }
                index += 2;
            }
            continue;
        }
        if !safe_review_git_operand(arg) {
            return false;
        }
        index += 1;
    }
    true
}

fn valid_review_git_rev_parse(args: &[String]) -> bool {
    if args.is_empty() {
        return false;
    }
    args.iter().all(|arg| {
        if arg.starts_with('-') {
            matches!(
                arg.as_str(),
                "--verify"
                    | "--quiet"
                    | "-q"
                    | "--show-toplevel"
                    | "--show-prefix"
                    | "--is-inside-work-tree"
                    | "--is-bare-repository"
                    | "--is-shallow-repository"
                    | "--show-object-format"
            ) || arg
                .strip_prefix("--short=")
                .is_some_and(|value| value.chars().all(|c| c.is_ascii_digit()))
                || arg == "--short"
        } else {
            safe_review_git_operand(arg)
        }
    })
}

fn valid_review_git_cat_file(args: &[String]) -> bool {
    args.len() == 2
        && matches!(args[0].as_str(), "-e" | "-p" | "-t" | "-s")
        && safe_review_git_operand(&args[1])
}

fn valid_review_git_ls_files(args: &[String]) -> bool {
    let mut paths_mode = false;
    for arg in args {
        if arg == "--" {
            paths_mode = true;
            continue;
        }
        if paths_mode {
            if !safe_review_git_operand(arg) {
                return false;
            }
            continue;
        }
        if matches!(
            arg.as_str(),
            "--cached"
                | "--deleted"
                | "--modified"
                | "--others"
                | "--ignored"
                | "--stage"
                | "--unmerged"
                | "--killed"
                | "--directory"
                | "--empty-directory"
                | "--full-name"
                | "--error-unmatch"
                | "--deduplicate"
                | "-c"
                | "-d"
                | "-m"
                | "-o"
                | "-i"
                | "-u"
                | "-s"
                | "-t"
                | "-k"
        ) {
            continue;
        }
        return false;
    }
    true
}

/// Return only operands that the selected command grammar defines as paths.
///
/// This intentionally does not guess from whether an arbitrary token happens
/// to exist: search patterns, revisions and option values are not paths, while
/// every actual path operand is subsequently canonicalized fail-closed.
fn review_bash_path_operands(program: &str, args: &[String]) -> Option<Vec<String>> {
    match program {
        "pwd" => args
            .iter()
            .all(|arg| matches!(arg.as_str(), "-L" | "-P"))
            .then(Vec::new),
        "ls" => simple_path_operands(
            args,
            &[
                "-a",
                "-A",
                "-l",
                "-d",
                "-h",
                "-n",
                "-i",
                "-1",
                "-G",
                "--all",
                "--almost-all",
                "--directory",
                "--human-readable",
                "--inode",
                "--numeric-uid-gid",
                "--color=never",
                "--group-directories-first",
            ],
            &["--time-style"],
        ),
        "stat" => simple_path_operands(
            args,
            &["-L", "-x", "--dereference", "--file-system", "--terse"],
            &["-f", "-c", "--format", "--printf"],
        ),
        "wc" => required_path_operands(
            args,
            &[
                "-c",
                "-l",
                "-m",
                "-w",
                "-L",
                "--bytes",
                "--chars",
                "--lines",
                "--max-line-length",
                "--words",
            ],
            &[],
        ),
        "head" | "tail" => head_tail_path_operands(program, args),
        "cat" => required_path_operands(
            args,
            &[
                "-A",
                "-b",
                "-E",
                "-n",
                "-s",
                "-t",
                "-T",
                "-u",
                "-v",
                "--number",
                "--number-nonblank",
                "--show-all",
                "--show-ends",
                "--show-tabs",
                "--squeeze-blank",
            ],
            &[],
        ),
        "grep" => grep_like_path_operands(args, false),
        "rg" => grep_like_path_operands(args, true),
        "sed" => valid_review_sed(args).then(|| args[2..].to_vec()),
        "find" => valid_review_find(args),
        "git" => git_path_operands(args),
        "shasum" | "cksum" => required_path_operands(
            args,
            &["-b", "-p", "-t", "-U", "-0", "--tag", "-l"],
            &["-a", "--algorithm", "--length"],
        ),
        _ => None,
    }
}

fn required_path_operands(
    args: &[String],
    boolean_options: &[&str],
    value_options: &[&str],
) -> Option<Vec<String>> {
    let paths = simple_path_operands(args, boolean_options, value_options)?;
    (!paths.is_empty()).then_some(paths)
}

fn simple_path_operands(
    args: &[String],
    boolean_options: &[&str],
    value_options: &[&str],
) -> Option<Vec<String>> {
    let mut paths = Vec::new();
    let mut index = 0;
    let mut options_ended = false;
    while index < args.len() {
        let arg = &args[index];
        if arg == "-" {
            return None;
        }
        if !options_ended && arg == "--" {
            options_ended = true;
        } else if !options_ended
            && (boolean_options.contains(&arg.as_str())
                || value_options
                    .iter()
                    .any(|option| arg.starts_with(&format!("{option}="))))
        {
        } else if !options_ended && value_options.contains(&arg.as_str()) {
            index += 1;
            if index >= args.len() {
                return None;
            }
        } else if !options_ended && arg == "-" {
            paths.push(arg.clone());
        } else if !options_ended && arg.starts_with('-') {
            return None;
        } else {
            paths.push(arg.clone());
        }
        index += 1;
    }
    Some(paths)
}

fn head_tail_path_operands(program: &str, args: &[String]) -> Option<Vec<String>> {
    let mut paths = Vec::new();
    let mut index = 0;
    let mut options_ended = false;
    while index < args.len() {
        let arg = &args[index];
        if !options_ended && arg == "--" {
            options_ended = true;
        } else if !options_ended
            && matches!(
                arg.as_str(),
                "-q" | "-v" | "--quiet" | "--silent" | "--verbose"
            )
        {
        } else if !options_ended
            && program == "tail"
            && matches!(arg.as_str(), "-f" | "-F" | "--follow" | "--retry")
        {
            return None;
        } else if !options_ended
            && (arg.strip_prefix('-').is_some_and(|value| {
                !value.is_empty() && value.chars().all(|character| character.is_ascii_digit())
            }) || ["-n", "--lines", "-c", "--bytes"]
                .iter()
                .any(|option| arg.starts_with(&format!("{option}="))))
        {
        } else if !options_ended && matches!(arg.as_str(), "-n" | "--lines" | "-c" | "--bytes") {
            index += 1;
            if index >= args.len() {
                return None;
            }
        } else if !options_ended && arg.starts_with('-') {
            return None;
        } else {
            paths.push(arg.clone());
        }
        index += 1;
    }
    (!paths.is_empty()).then_some(paths)
}

fn grep_like_path_operands(args: &[String], ripgrep: bool) -> Option<Vec<String>> {
    let boolean_short = if ripgrep {
        "nHhIiSsFUlcvqwo"
    } else {
        "HhIiLnqsvEFPowx"
    };
    let value_short = if ripgrep { "egtmABC" } else { "efmABC" };
    let boolean_long: &[&str] = if ripgrep {
        &[
            "--line-number",
            "--with-filename",
            "--no-filename",
            "--ignore-case",
            "--case-sensitive",
            "--smart-case",
            "--fixed-strings",
            "--files",
            "--files-with-matches",
            "--files-without-match",
            "--count",
            "--count-matches",
            "--only-matching",
            "--word-regexp",
            "--line-regexp",
            "--json",
            "--stats",
            "--heading",
            "--no-heading",
            "--column",
            "--pcre2",
            "--color=never",
        ]
    } else {
        &[
            "--with-filename",
            "--no-filename",
            "--ignore-case",
            "--no-messages",
            "--invert-match",
            "--line-number",
            "--files-with-matches",
            "--files-without-match",
            "--count",
            "--only-matching",
            "--word-regexp",
            "--line-regexp",
            "--fixed-strings",
            "--extended-regexp",
            "--perl-regexp",
            "--binary-files=without-match",
            "--binary-files=text",
            "--color=never",
        ]
    };
    let value_long: &[&str] = if ripgrep {
        &[
            "--regexp",
            "--glob",
            "--type",
            "--type-not",
            "--max-count",
            "--after-context",
            "--before-context",
            "--context",
            "--file",
            "--ignore-file",
            "--encoding",
            "--sort",
            "--sortr",
        ]
    } else {
        &[
            "--regexp",
            "--file",
            "--max-count",
            "--after-context",
            "--before-context",
            "--context",
            "--include",
            "--exclude",
            "--exclude-dir",
            "--exclude-from",
            "--directories",
            "--devices",
        ]
    };
    let mut paths = Vec::new();
    let mut pattern_specified = false;
    let mut files_mode = false;
    let mut options_ended = false;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if !options_ended && arg == "--" {
            options_ended = true;
        } else if !options_ended
            && ripgrep
            && [
                "--pre",
                "--pre-glob",
                "--hostname-bin",
                "--search-zip",
                "--follow",
            ]
            .iter()
            .any(|option| arg == option || arg.starts_with(&format!("{option}=")))
        {
            return None;
        } else if !options_ended && arg.starts_with("--") {
            if boolean_long.contains(&arg.as_str()) {
                files_mode |= arg == "--files";
            } else {
                let option = arg.split_once('=').map_or(arg.as_str(), |(name, _)| name);
                if !value_long.contains(&option) {
                    return None;
                }
                let inline_value = arg.contains('=');
                if !inline_value {
                    index += 1;
                    if index >= args.len() {
                        return None;
                    }
                }
                if matches!(option, "--regexp" | "--file") {
                    pattern_specified = true;
                }
                if matches!(option, "--file" | "--ignore-file" | "--exclude-from") {
                    let value = arg
                        .split_once('=')
                        .map_or(args[index].as_str(), |(_, value)| value);
                    paths.push(value.to_owned());
                }
            }
        } else if !options_ended && arg == "-" {
            paths.push(arg.clone());
        } else if !options_ended && arg.starts_with('-') {
            let cluster = &arg[1..];
            if cluster.len() == 1 && value_short.contains(cluster) {
                index += 1;
                if index >= args.len() {
                    return None;
                }
                if cluster == "e" || cluster == "f" {
                    pattern_specified = true;
                }
                if cluster == "f" {
                    paths.push(args[index].clone());
                }
            } else if !cluster.chars().all(|flag| boolean_short.contains(flag)) {
                return None;
            }
        } else if files_mode || pattern_specified {
            paths.push(arg.clone());
        } else {
            pattern_specified = true;
        }
        index += 1;
    }
    if (!files_mode && !pattern_specified) || (!ripgrep && paths.is_empty()) {
        None
    } else {
        Some(paths)
    }
}

fn git_path_operands(args: &[String]) -> Option<Vec<String>> {
    let command_index = args
        .iter()
        .position(|arg| arg == "--no-pager")
        .map_or(0, |_| 1);
    let subcommand = args.get(command_index)?.as_str();
    let operands = &args[command_index + 1..];
    if let Some(separator) = operands.iter().position(|arg| arg == "--") {
        return Some(operands[separator + 1..].to_vec());
    }
    let _ = subcommand;
    Some(Vec::new())
}

fn valid_review_find(args: &[String]) -> Option<Vec<String>> {
    let mut paths = Vec::new();
    let mut index = 0;
    while index < args.len() && !args[index].starts_with('-') {
        paths.push(args[index].clone());
        index += 1;
    }
    if paths.is_empty() {
        return None;
    }
    while index < args.len() {
        match args[index].as_str() {
            "-L" | "-H" | "-delete" | "-exec" | "-execdir" | "-ok" | "-okdir" | "-prune"
            | "-ls" | "-print" | "-print0" | "-fprint" | "-fprint0" | "-fprintf" | "-fls"
            | "-printf" | "-writable" => return None,
            "-maxdepth" | "-mindepth" => {
                let value = args.get(index + 1)?;
                if value.parse::<u8>().ok().is_none_or(|value| value > 50) {
                    return None;
                }
                index += 2;
            }
            "-type" => {
                let value = args.get(index + 1)?;
                if value.len() != 1
                    || !matches!(
                        value.as_bytes()[0],
                        b'f' | b'd' | b'l' | b'p' | b's' | b'b' | b'c'
                    )
                {
                    return None;
                }
                index += 2;
            }
            "-name" | "-iname" | "-path" | "-ipath" | "-size" | "-mtime" | "-mmin" => {
                let value = args.get(index + 1)?;
                if value.is_empty() || value.starts_with('-') {
                    return None;
                }
                index += 2;
            }
            "-newer" => {
                let value = args.get(index + 1)?;
                if value.is_empty() {
                    return None;
                }
                paths.push(value.clone());
                index += 2;
            }
            "-empty" | "-readable" | "-quit" => index += 1,
            _ => return None,
        }
    }
    Some(paths)
}

fn lexical_confined_path(root: &Path, value: &Path) -> PreparationResult<PathBuf> {
    if value.is_absolute()
        || value
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(PreparationError::InvalidPath {
            path: value.to_path_buf(),
            reason: "path must be repository-relative and confined".into(),
        });
    }
    Ok(root.join(value))
}

fn protected_worktree_path(worktree: &Path, target: &Path) -> bool {
    let Ok(relative) = target.strip_prefix(worktree) else {
        return false;
    };
    relative.components().any(|component| {
        component.as_os_str() == ".git"
            || component.as_os_str() == ".agent-work"
            || component.as_os_str() == ".gitmodules"
    })
}

pub(crate) fn prepare_command(
    program: &Path,
    args: &[String],
    cwd: &Path,
    worktree: &Path,
    scratch_root: &Path,
    bounds: (u64, usize, bool),
) -> PreparationResult<PreparedCommand> {
    let (timeout_ms, max_output_bytes, network_allowed) = bounds;
    if timeout_ms == 0 || max_output_bytes == 0 {
        return Err(PreparationError::InvalidManifest(
            "validation command bounds must be non-zero".into(),
        ));
    }
    let program = fs::canonicalize(program).map_err(|error| PreparationError::InvalidPath {
        path: program.to_path_buf(),
        reason: error.to_string(),
    })?;
    if !program.is_file() {
        return Err(PreparationError::InvalidPath {
            path: program,
            reason: "command is not a regular file".into(),
        });
    }
    let cwd = fs::canonicalize(cwd).map_err(|error| PreparationError::InvalidPath {
        path: cwd.to_path_buf(),
        reason: error.to_string(),
    })?;
    if !cwd.starts_with(worktree) {
        return Err(PreparationError::PathEscape {
            path: cwd,
            root: worktree.to_path_buf(),
        });
    }
    validate_program_and_args(&program, args, worktree, scratch_root, network_allowed)?;
    let home = scratch_root.join("home");
    let temporary = scratch_root.join("tmp");
    fs::create_dir_all(&home)?;
    fs::create_dir_all(&temporary)?;
    let mut environment = BTreeMap::new();
    environment.insert("HOME".into(), home.to_string_lossy().into_owned());
    environment.insert("TMPDIR".into(), temporary.to_string_lossy().into_owned());
    environment.insert("PATH".into(), "/usr/bin:/bin:/usr/sbin:/sbin".into());
    environment.insert("LANG".into(), "C".into());
    environment.insert("LC_ALL".into(), "C".into());
    Ok(PreparedCommand {
        program,
        args: args.to_vec(),
        cwd,
        timeout_ms,
        max_output_bytes,
        environment,
        readonly_safe: false,
    })
}

fn exact_command_id_input(input: &serde_json::Value) -> Option<String> {
    let object = input.as_object()?;
    if object.len() != 1 {
        return None;
    }
    let command_id = object.get("command_id")?.as_str()?;
    if command_id.is_empty()
        || command_id.len() > 256
        || !command_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return None;
    }
    Some(command_id.to_owned())
}

fn permission_denial_semantics(
    params: &serde_json::Value,
    supplied_reason: Option<&str>,
) -> Option<PermissionDenialSemantics> {
    let tool = params
        .get("toolName")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_ascii_lowercase();
    let input = params.get("input").unwrap_or(&serde_json::Value::Null);
    let supplied_reason = supplied_reason.and_then(normalized_supplied_reason);
    let (program_family, category, inferred_reason, operand_class) = match tool.as_str() {
        "bash" => input
            .get("command")
            .and_then(serde_json::Value::as_str)
            .map(bash_denial_identity)
            .unwrap_or_else(|| {
                (
                    "bash".into(),
                    "command".into(),
                    "bash_command_missing".into(),
                    "missing_command".into(),
                )
            }),
        "read" | "grep" | "glob" => (
            tool.clone(),
            "path".into(),
            "external_policy_denied".into(),
            "unavailable_path".into(),
        ),
        "write" | "edit" | "delete" | "move" => (
            tool.clone(),
            "write".into(),
            "write_denied".into(),
            "mutation".into(),
        ),
        "execute" | "terminal" => {
            let program = input
                .get("program")
                .and_then(serde_json::Value::as_str)
                .and_then(|program| Path::new(program).file_name())
                .and_then(OsStr::to_str)
                .unwrap_or("unknown")
                .to_ascii_lowercase();
            (
                program,
                "execute".into(),
                "command_not_allowlisted".into(),
                "program".into(),
            )
        }
        "network" => (
            "network".into(),
            "network".into(),
            "network_not_enforced_and_request_denied".into(),
            "network".into(),
        ),
        "git_ref_mutation" => (
            "git".into(),
            "ref_mutation".into(),
            "git_ref_mutation_denied".into(),
            "mutation".into(),
        ),
        _ if tool.starts_with("mcp__") => (
            "named_check".into(),
            "named_check".into(),
            "permission_request_unrecognized".into(),
            "named_check".into(),
        ),
        _ => (
            tool.clone(),
            "unknown".into(),
            "permission_request_unrecognized".into(),
            "unknown".into(),
        ),
    };
    let reason_code = supplied_reason.unwrap_or(inferred_reason);
    let (retry_class, recommended_action) =
        denial_recovery(&tool, &program_family, &reason_code, &operand_class);
    Some(PermissionDenialSemantics {
        program_family,
        category,
        reason_code,
        operand_class,
        retry_class,
        recommended_action,
    })
}

fn normalized_supplied_reason(reason: &str) -> Option<String> {
    let trimmed = reason.trim();
    if let Some(metadata) = trimmed
        .strip_prefix("DENY[")
        .and_then(|value| value.split_once(']'))
    {
        let fields = metadata
            .0
            .split(';')
            .filter_map(|field| field.split_once('='));
        let mut code = None;
        let mut original_code = None;
        for (key, value) in fields {
            match key {
                "code" => code = stable_reason_token(value),
                "original_code" => original_code = stable_reason_token(value),
                _ => {}
            }
        }
        return original_code
            .or(code)
            .filter(|value| value != "REPEATED_DENIED_OPERATION")
            .map(canonical_reason_code);
    }
    stable_reason_token(trimmed)
        .filter(|value| value.contains('_'))
        .map(canonical_reason_code)
}

fn stable_reason_token(value: &str) -> Option<String> {
    (!value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    .then(|| value.to_owned())
}

fn canonical_reason_code(value: String) -> String {
    if value.starts_with("shell_") {
        "shell_composition_or_expansion_denied".into()
    } else if value == "git_global_option_denied" {
        "git_option_or_mutation_denied".into()
    } else {
        value
    }
}

fn bash_denial_identity(command: &str) -> (String, String, String, String) {
    let Some(argv) = tokenize_review_bash(command) else {
        let operand_class = if command.contains('\n') || command.contains('\r') {
            "multiline"
        } else {
            "compound_command"
        };
        return (
            "shell".into(),
            "composition".into(),
            "shell_composition_or_expansion_denied".into(),
            operand_class.into(),
        );
    };
    let family = argv
        .first()
        .and_then(|program| Path::new(program).file_name())
        .and_then(OsStr::to_str)
        .unwrap_or("unknown")
        .to_ascii_lowercase();
    if !review_bash_program_allowed(&family) {
        return (
            family,
            "program".into(),
            "command_not_allowlisted".into(),
            "program".into(),
        );
    }
    if family == "git" {
        let category = git_denial_category(&argv[1..]);
        let operand_class = git_denial_operand_class(&argv[1..]);
        let reason = if matches!(operand_class.as_str(), "sensitive_path") {
            "git_sensitive_path_denied"
        } else if matches!(
            operand_class.as_str(),
            "cwd_override" | "config_override" | "repository_override"
        ) {
            "git_option_or_mutation_denied"
        } else {
            "git_option_or_mutation_denied"
        };
        return (family, category, reason.into(), operand_class);
    }
    let operand_class = if argv[1..].iter().any(|value| {
        is_credential_path(Path::new(value)) || is_prior_review_artifact(Path::new(value))
    }) {
        "sensitive_path"
    } else if argv[1..].iter().any(|value| value.starts_with('-')) {
        "option"
    } else if argv.len() <= 1 {
        "missing_path"
    } else {
        "path"
    };
    let inferred_reason = match operand_class {
        "sensitive_path" => "credential_read_denied",
        "missing_path" => "command_option_not_allowlisted",
        _ => "external_policy_denied",
    };
    (
        family.clone(),
        family,
        inferred_reason.into(),
        operand_class.into(),
    )
}

fn git_denial_category(args: &[String]) -> String {
    let mut index = 0;
    while let Some(value) = args.get(index) {
        if matches!(value.as_str(), "-C" | "-c" | "--git-dir" | "--work-tree") {
            index = index.saturating_add(2);
            continue;
        }
        if value.starts_with("--git-dir=")
            || value.starts_with("--work-tree=")
            || value.starts_with("-c")
            || value == "--no-pager"
        {
            index = index.saturating_add(1);
            continue;
        }
        return value.trim_start_matches('-').to_ascii_lowercase();
    }
    "unknown".into()
}

fn git_denial_operand_class(args: &[String]) -> String {
    if args.iter().any(|value| value == "-C") {
        return "cwd_override".into();
    }
    if args
        .iter()
        .any(|value| value == "-c" || value.starts_with("-c"))
    {
        return "config_override".into();
    }
    if args.iter().any(|value| {
        matches!(value.as_str(), "--git-dir" | "--work-tree")
            || value.starts_with("--git-dir=")
            || value.starts_with("--work-tree=")
    }) {
        return "repository_override".into();
    }
    if args.iter().any(|value| {
        matches!(
            value.as_str(),
            "--output" | "--ext-diff" | "--textconv" | "--no-index"
        ) || value.starts_with("--output=")
    }) {
        return "write_option".into();
    }
    if args.iter().any(|value| {
        is_credential_path(Path::new(value)) || is_prior_review_artifact(Path::new(value))
    }) {
        return "sensitive_path".into();
    }
    if args.first().is_some_and(|value| {
        matches!(
            value.as_str(),
            "add"
                | "apply"
                | "branch"
                | "checkout"
                | "clean"
                | "commit"
                | "merge"
                | "mv"
                | "rebase"
                | "reset"
                | "restore"
                | "rm"
                | "switch"
                | "tag"
        )
    }) {
        return "mutation".into();
    }
    "option_or_operand".into()
}

fn denial_recovery(
    tool: &str,
    program_family: &str,
    reason_code: &str,
    operand_class: &str,
) -> (&'static str, &'static str) {
    if reason_code.starts_with("shell_")
        || reason_code.contains("multiline")
        || reason_code == "shell_composition_or_expansion_denied"
    {
        return ("split_once", "split_into_single_commands");
    }
    if tool == "read"
        && matches!(
            reason_code,
            "read_path_unverifiable" | "permission_request_unrecognized"
        )
    {
        return ("simplify_once", "correct_read_path_once");
    }
    if program_family == "git"
        && matches!(
            operand_class,
            "cwd_override" | "config_override" | "repository_override"
        )
    {
        return ("simplify_once", "remove_denied_option_once");
    }
    if reason_code.contains("option_not_allowlisted")
        && !matches!(
            operand_class,
            "write_option" | "mutation" | "sensitive_path"
        )
    {
        return ("simplify_once", "remove_denied_option_once");
    }
    if matches!(
        reason_code,
        "command_not_allowlisted" | "program_not_allowlisted"
    ) {
        if matches!(
            program_family,
            "curl" | "wget" | "ssh" | "scp" | "sftp" | "nc" | "ncat" | "telnet"
        ) {
            return ("do_not_retry_equivalent", "stop_evidence_path");
        }
        if matches!(
            program_family,
            "cargo"
                | "rustc"
                | "npm"
                | "npx"
                | "pnpm"
                | "yarn"
                | "bun"
                | "docker"
                | "make"
                | "cmake"
                | "pytest"
                | "python"
                | "python3"
                | "go"
        ) {
            return ("use_named_check", "use_named_check");
        }
        return ("use_read", "use_read_or_prepared_inputs");
    }
    if reason_code.contains("credential")
        || reason_code.contains("sensitive")
        || reason_code.contains("secret")
        || reason_code.contains("network")
        || reason_code.contains("write")
        || reason_code.contains("mutation")
        || reason_code.contains("outside")
        || reason_code.contains("escape")
        || reason_code.contains("protected")
        || reason_code.contains("prior_review")
        || reason_code == "external_policy_denied"
        || matches!(
            operand_class,
            "write_option" | "mutation" | "sensitive_path" | "outside_scope"
        )
    {
        return ("do_not_retry_equivalent", "stop_evidence_path");
    }
    ("use_read", "use_read_or_prepared_inputs")
}

fn tokenize_review_bash(command: &str) -> Option<Vec<String>> {
    if command.is_empty()
        || command.len() > 16 * 1024
        || command.chars().any(|c| matches!(c, '\n' | '\r'))
    {
        return None;
    }
    let mut result = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for character in command.chars() {
        match quote {
            Some(delimiter) if character == delimiter => quote = None,
            Some(_) => current.push(character),
            None if character == '\'' || character == '"' => quote = Some(character),
            None if character.is_whitespace() => {
                if !current.is_empty() {
                    result.push(std::mem::take(&mut current));
                }
            }
            None if matches!(
                character,
                ';' | '&'
                    | '|'
                    | '>'
                    | '<'
                    | '$'
                    | '`'
                    | '('
                    | ')'
                    | '{'
                    | '}'
                    | '*'
                    | '?'
                    | '['
                    | ']'
                    | '#'
                    | '!'
                    | '\\'
            ) =>
            {
                return None
            }
            None => current.push(character),
        }
    }
    if quote.is_some() {
        return None;
    }
    if !current.is_empty() {
        result.push(current);
    }
    if result.len() > 128 {
        return None;
    }
    (!result.is_empty()).then_some(result)
}

fn valid_review_sed(args: &[String]) -> bool {
    if args.len() < 3 || args[0] != "-n" {
        return false;
    }
    let range = &args[1];
    let valid_number = |value: &str| {
        !value.is_empty()
            && value.chars().all(|c| c.is_ascii_digit())
            && value
                .parse::<u64>()
                .ok()
                .is_some_and(|number| number <= 10_000)
    };
    let mut pieces = range.strip_suffix('p').unwrap_or("").split(',');
    let first = pieces.next().unwrap_or("");
    let second = pieces.next();
    if pieces.next().is_some()
        || !valid_number(first)
        || second.is_some_and(|value| !valid_number(value))
    {
        return false;
    }
    args[2..].iter().all(|arg| !arg.starts_with('-'))
}

fn validate_program_and_args(
    program: &Path,
    args: &[String],
    worktree: &Path,
    scratch_root: &Path,
    network_allowed: bool,
) -> PreparationResult<()> {
    let name = program
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !network_allowed
        && matches!(
            name.as_str(),
            "curl" | "wget" | "ssh" | "scp" | "sftp" | "nc" | "ncat" | "telnet" | "ftp"
        )
    {
        return Err(PreparationError::Policy(
            "known network client is forbidden".into(),
        ));
    }
    if matches!(name.as_str(), "sh" | "bash" | "zsh" | "fish") {
        return Err(PreparationError::Policy(
            "shell interpreters are not validation commands".into(),
        ));
    }
    if name == "env" && !args.is_empty() {
        return Err(PreparationError::Policy(
            "env may inspect the sanitized environment but cannot launch another command".into(),
        ));
    }
    if name == "git" {
        validate_git_args(args, worktree, scratch_root)?;
    }
    for argument in args {
        if argument.contains('\0') || argument.contains('\n') || argument.contains('\r') {
            return Err(PreparationError::Policy(
                "command arguments may not contain control separators".into(),
            ));
        }
        let lowercase = argument.to_ascii_lowercase();
        if !network_allowed
            && (lowercase.contains("http://")
                || lowercase.contains("https://")
                || lowercase.starts_with("ssh://")
                || lowercase.starts_with("git@"))
        {
            return Err(PreparationError::Policy(
                "network-oriented command argument is forbidden".into(),
            ));
        }
        let argument_path = Path::new(argument);
        if argument_path.is_absolute()
            && !argument_path.starts_with(worktree)
            && !argument_path.starts_with(scratch_root)
            && argument_path != program
        {
            return Err(PreparationError::Policy(
                "absolute command argument escapes job roots".into(),
            ));
        }
        if argument_path
            .components()
            .any(|component| component == Component::ParentDir)
        {
            return Err(PreparationError::Policy(
                "parent traversal in command argument is forbidden".into(),
            ));
        }
        if is_credential_path(argument_path) {
            return Err(PreparationError::Policy(
                "credential-oriented command argument is forbidden".into(),
            ));
        }
    }
    Ok(())
}

fn validate_git_args(
    args: &[String],
    worktree: &Path,
    scratch_root: &Path,
) -> PreparationResult<()> {
    let verb = args.first().map(String::as_str).unwrap_or_default();
    if !matches!(verb, "diff" | "status" | "log" | "show" | "rev-parse") {
        return Err(PreparationError::Policy(
            "Git command may read state but may not mutate refs or files".into(),
        ));
    }
    let mut index = 1usize;
    let mut pathspecs = false;
    let mut no_ext_diff = false;
    let mut no_textconv = false;
    while index < args.len() {
        let argument = &args[index];
        if pathspecs {
            validate_git_path_value(argument, worktree, scratch_root)?;
            index += 1;
            continue;
        }
        if argument == "--" {
            pathspecs = true;
            index += 1;
            continue;
        }
        if !argument.starts_with('-') || argument == "-" {
            if verb == "status" {
                return Err(PreparationError::Policy(
                    "Git status pathspecs must follow an explicit -- separator".into(),
                ));
            }
            index += 1;
            continue;
        }
        if argument == "--no-ext-diff" {
            no_ext_diff = true;
        }
        if argument == "--no-textconv" {
            no_textconv = true;
        }
        if git_flag_allowed(verb, argument) {
            index += 1;
            continue;
        }
        if let Some(value) = argument.strip_prefix("--max-count=") {
            if verb == "log" && valid_positive_integer(value) {
                index += 1;
                continue;
            }
        }
        if let Some(value) = argument.strip_prefix("--unified=") {
            if verb == "diff" && valid_nonnegative_integer(value) {
                index += 1;
                continue;
            }
        }
        if let Some(value) = argument
            .strip_prefix("--format=")
            .or_else(|| argument.strip_prefix("--pretty="))
        {
            if matches!(verb, "log" | "show") && !value.is_empty() {
                index += 1;
                continue;
            }
        }
        if let Some(value) = argument.strip_prefix("--color=") {
            if matches!(verb, "diff" | "log" | "show") && value == "never" {
                index += 1;
                continue;
            }
        }
        if let Some(value) = argument.strip_prefix("--porcelain=") {
            if verb == "status" && matches!(value, "v1" | "v2") {
                index += 1;
                continue;
            }
        }
        if let Some(value) = argument.strip_prefix("--untracked-files=") {
            if verb == "status" && matches!(value, "no" | "normal" | "all") {
                index += 1;
                continue;
            }
        }
        if argument == "-n" || argument == "--max-count" {
            let value = args.get(index + 1).ok_or_else(|| {
                PreparationError::Policy("Git max-count option requires a value".into())
            })?;
            if verb == "log" && valid_positive_integer(value) {
                index += 2;
                continue;
            }
        }
        return Err(PreparationError::Policy(format!(
            "Git {verb} option is not in the strict read-only grammar: {argument}"
        )));
    }
    if matches!(verb, "diff" | "log" | "show") && (!no_ext_diff || !no_textconv) {
        return Err(PreparationError::Policy(format!(
            "Git {verb} must explicitly disable external diff and textconv execution"
        )));
    }
    Ok(())
}

fn git_flag_allowed(verb: &str, argument: &str) -> bool {
    match verb {
        "diff" => matches!(
            argument,
            "--no-ext-diff"
                | "--no-textconv"
                | "--cached"
                | "--staged"
                | "--stat"
                | "--name-only"
                | "--name-status"
                | "--check"
                | "--binary"
                | "--full-index"
                | "--no-renames"
                | "--exit-code"
                | "--quiet"
                | "--no-color"
                | "--patch"
                | "--no-patch"
                | "-p"
                | "-s"
        ),
        "status" => matches!(
            argument,
            "--short"
                | "-s"
                | "--branch"
                | "-b"
                | "--porcelain"
                | "--long"
                | "--no-ahead-behind"
                | "--show-stash"
                | "--no-renames"
        ),
        "log" => matches!(
            argument,
            "--no-ext-diff"
                | "--no-textconv"
                | "--stat"
                | "--name-only"
                | "--name-status"
                | "--no-color"
                | "--no-patch"
                | "-s"
                | "--oneline"
                | "--decorate"
                | "--no-decorate"
                | "--first-parent"
                | "--all"
        ),
        "show" => matches!(
            argument,
            "--no-ext-diff"
                | "--no-textconv"
                | "--stat"
                | "--name-only"
                | "--name-status"
                | "--no-color"
                | "--no-patch"
                | "-s"
                | "--oneline"
                | "--decorate"
                | "--no-decorate"
        ),
        "rev-parse" => matches!(
            argument,
            "--verify"
                | "--quiet"
                | "-q"
                | "--short"
                | "--show-toplevel"
                | "--show-prefix"
                | "--is-inside-work-tree"
                | "--is-bare-repository"
                | "--is-shallow-repository"
                | "--show-object-format"
        ),
        _ => false,
    }
}

fn valid_positive_integer(value: &str) -> bool {
    value.parse::<u32>().is_ok_and(|value| value > 0)
}

fn valid_nonnegative_integer(value: &str) -> bool {
    value.parse::<u16>().is_ok()
}

fn validate_git_path_value(
    value: &str,
    worktree: &Path,
    scratch_root: &Path,
) -> PreparationResult<()> {
    if value.is_empty() || value.starts_with('-') {
        return Err(PreparationError::Policy(
            "Git pathspec is empty or option-like".into(),
        ));
    }
    let path = Path::new(value);
    if path.is_absolute() && !path.starts_with(worktree) && !path.starts_with(scratch_root) {
        return Err(PreparationError::Policy(
            "Git pathspec escapes job roots".into(),
        ));
    }
    if path
        .components()
        .any(|component| component == Component::ParentDir)
    {
        return Err(PreparationError::Policy(
            "Git pathspec contains parent traversal".into(),
        ));
    }
    if is_credential_path(path) {
        return Err(PreparationError::Policy(
            "Git credential-oriented pathspec is forbidden".into(),
        ));
    }
    Ok(())
}

fn execute(
    prepared: &PreparedCommand,
    attempt_deadline: Instant,
    cancellation: &AtomicBool,
) -> PreparationResult<ValidationOutput> {
    let mut command = Command::new(&prepared.program);
    command
        .args(&prepared.args)
        .current_dir(&prepared.cwd)
        .env_clear()
        .envs(&prepared.environment)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let pid = i32::try_from(child.id())
        .map_err(|_| PreparationError::Policy("validation command process id is invalid".into()))?;
    let stdout = child.stdout.take().expect("piped validation stdout");
    let stderr = child.stderr.take().expect("piped validation stderr");
    let max_stdout = prepared.max_output_bytes;
    let max_stderr = prepared.max_output_bytes;
    let output_limited = Arc::new(AtomicBool::new(false));
    let stdout_reader = spawn_reader(stdout, max_stdout, Arc::clone(&output_limited));
    let stderr_reader = spawn_reader(stderr, max_stderr, Arc::clone(&output_limited));
    let command_deadline = Instant::now()
        .checked_add(Duration::from_millis(prepared.timeout_ms))
        .unwrap_or(attempt_deadline);
    let deadline = command_deadline.min(attempt_deadline);
    let (status, timed_out, cancelled) = loop {
        if let Some(status) = child.try_wait()? {
            break (status, false, false);
        }
        if cancellation.load(Ordering::Acquire) {
            signal_group(pid, libc::SIGKILL)?;
            let status = child.wait()?;
            break (status, false, true);
        }
        if output_limited.load(Ordering::Acquire) {
            signal_group(pid, libc::SIGKILL)?;
            let status = child.wait()?;
            break (status, false, false);
        }
        if Instant::now() >= deadline {
            signal_group(pid, libc::SIGKILL)?;
            let status = child.wait()?;
            break (status, true, false);
        }
        thread::sleep(Duration::from_millis(2));
    };
    terminate_remaining_group(pid)?;
    let (stdout, stdout_truncated) = receive_reader(stdout_reader, "stdout")?;
    let (stderr, stderr_truncated) = receive_reader(stderr_reader, "stderr")?;
    Ok(ValidationOutput {
        status_code: status.code(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        stdout_truncated,
        stderr_truncated,
        timed_out,
        cancelled,
    })
}

fn spawn_reader(
    reader: impl Read + Send + 'static,
    max_bytes: usize,
    output_limited: Arc<AtomicBool>,
) -> mpsc::Receiver<std::io::Result<(Vec<u8>, bool)>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(read_bounded(reader, max_bytes, &output_limited));
    });
    receiver
}

fn receive_reader(
    receiver: mpsc::Receiver<std::io::Result<(Vec<u8>, bool)>>,
    stream: &str,
) -> PreparationResult<(Vec<u8>, bool)> {
    receiver
        .recv_timeout(Duration::from_secs(1))
        .map_err(|_| {
            PreparationError::Policy(format!(
                "validation {stream} pipe remained open after process-group termination"
            ))
        })?
        .map_err(PreparationError::Io)
}

fn terminate_remaining_group(pgid: i32) -> PreparationResult<()> {
    if !process_group_exists(pgid)? {
        return Ok(());
    }
    signal_group(pgid, libc::SIGTERM)?;
    let term_deadline = Instant::now() + Duration::from_millis(50);
    while process_group_exists(pgid)? && Instant::now() < term_deadline {
        thread::sleep(Duration::from_millis(2));
    }
    if process_group_exists(pgid)? {
        signal_group(pgid, libc::SIGKILL)?;
    }
    let kill_deadline = Instant::now() + Duration::from_secs(1);
    while process_group_exists(pgid)? {
        if Instant::now() >= kill_deadline {
            return Err(PreparationError::Policy(
                "validation process group remained alive after SIGKILL".into(),
            ));
        }
        thread::sleep(Duration::from_millis(2));
    }
    Ok(())
}

fn process_group_exists(pgid: i32) -> PreparationResult<bool> {
    if pgid <= 1 {
        return Err(PreparationError::Policy(
            "validation process group identity is invalid".into(),
        ));
    }
    let result = unsafe { libc::kill(-pgid, 0) };
    if result == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(PreparationError::Io(error)),
    }
}

fn signal_group(pgid: i32, signal: i32) -> PreparationResult<()> {
    if pgid <= 1 {
        return Err(PreparationError::Policy(
            "validation process group identity is invalid".into(),
        ));
    }
    let result = unsafe { libc::kill(-pgid, signal) };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(PreparationError::Io(error))
    }
}

fn read_bounded(
    mut reader: impl Read,
    max_bytes: usize,
    output_limited: &AtomicBool,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::with_capacity(max_bytes.min(8192));
    let mut buffer = [0u8; 8192];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok((retained, truncated));
        }
        let remaining = max_bytes.saturating_sub(retained.len());
        retained.extend_from_slice(&buffer[..count.min(remaining)]);
        truncated |= count > remaining;
        if truncated {
            output_limited.store(true, Ordering::Release);
        }
    }
}

pub(crate) fn is_credential_path(path: &Path) -> bool {
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        matches!(
            value.as_str(),
            ".ssh"
                | ".git"
                | ".env"
                | ".env.local"
                | ".env.production"
                | ".aws"
                | ".gnupg"
                | ".netrc"
                | ".npmrc"
                | "credentials"
                | "credentials.json"
                | "auth.json"
                | "id_rsa"
                | "id_ed25519"
                | "known_hosts"
                | "authorized_keys"
        ) || value.contains("access_token")
            || value.contains("api_key")
            || value.contains("secret_key")
            || value.ends_with(".pem")
            || value.ends_with(".key")
            || value.ends_with(".p12")
            || value.ends_with(".pfx")
            || value.ends_with(".jks")
            || value.ends_with(".kdbx")
    })
}

pub(crate) fn is_prior_review_artifact(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    normalized.contains("/.agent-work/reviews/")
        || normalized.contains("gpt-raw")
        || normalized.contains("gpt-admission")
        || normalized.contains("glm-raw")
        || normalized.contains("glm-admission")
}
