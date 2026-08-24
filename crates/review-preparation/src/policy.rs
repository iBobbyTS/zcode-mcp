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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalDecision {
    Allow,
    Deny,
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionDecision {
    pub allowed: bool,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationOutput {
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
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
        Ok(Self {
            worktree,
            scratch_root,
            report_target,
            readable_inputs,
            commands,
            network_allowed,
            capabilities,
        })
    }

    pub fn capabilities(&self) -> &PolicyCapabilities {
        &self.capabilities
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
        let request = match tool_name.to_ascii_lowercase().as_str() {
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
        };
        match request {
            Some(request) => self.decide(&request, external),
            None => PermissionDecision {
                allowed: false,
                reason: "permission_request_unrecognized",
            },
        }
    }

    pub fn run(&self, command_id: &str) -> PreparationResult<ValidationOutput> {
        let prepared = self.commands.get(command_id).ok_or_else(|| {
            PreparationError::Policy(format!(
                "command {command_id} is not in the exact allowlist"
            ))
        })?;
        let request = PermissionRequest::Execute {
            program: prepared.program.clone(),
            args: prepared.args.clone(),
            cwd: prepared.cwd.clone(),
        };
        let decision = self.decide(&request, ExternalDecision::Allow);
        if !decision.allowed {
            return Err(PreparationError::Policy(decision.reason.into()));
        }
        execute(prepared)
    }

    fn hard_deny_reason(&self, request: &PermissionRequest) -> Option<&'static str> {
        match request {
            PermissionRequest::Network(_) if !self.network_allowed => {
                Some("network_not_enforced_and_request_denied")
            }
            PermissionRequest::Network(_) => None,
            PermissionRequest::GitRefMutation => Some("git_ref_mutation_denied"),
            PermissionRequest::CredentialRead(_) => Some("credential_read_denied"),
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
            PermissionRequest::Write(path) => self.write_path_denial(path, false),
            PermissionRequest::Edit(path) | PermissionRequest::Delete(path) => {
                self.write_path_denial(path, true)
            }
            PermissionRequest::Move {
                source,
                destination,
            } => self
                .write_path_denial(source, true)
                .or_else(|| self.write_path_denial(destination, false)),
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

    fn write_path_denial(&self, path: &Path, must_exist: bool) -> Option<&'static str> {
        if !path.is_absolute()
            || path
                .components()
                .any(|component| component == Component::ParentDir)
        {
            return Some("write_path_unverifiable");
        }
        match fs::symlink_metadata(path) {
            Ok(_) => self.canonical_write_denial(path),
            Err(error) if error.kind() == ErrorKind::NotFound && !must_exist => {
                let Some(candidate) = self.resolve_nonexistent_write_target(path) else {
                    return Some("write_path_unverifiable");
                };
                self.resolved_write_denial(&candidate)
            }
            Err(_) => Some("write_path_unverifiable"),
        }
    }

    fn canonical_write_denial(&self, path: &Path) -> Option<&'static str> {
        let Ok(canonical) = fs::canonicalize(path) else {
            return Some("write_path_unverifiable");
        };
        self.resolved_write_denial(&canonical)
    }

    fn resolve_nonexistent_write_target(&self, path: &Path) -> Option<PathBuf> {
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
        if target.starts_with(&self.worktree)
            || target == self.scratch_root
            || target == report_root
            || (!target.starts_with(&self.scratch_root) && !target.starts_with(report_root))
        {
            Some("write_outside_artifact_roots_denied")
        } else {
            None
        }
    }
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
    })
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

fn execute(prepared: &PreparedCommand) -> PreparationResult<ValidationOutput> {
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
    let stdout_reader = spawn_reader(stdout, max_stdout);
    let stderr_reader = spawn_reader(stderr, max_stderr);
    let deadline = Instant::now() + Duration::from_millis(prepared.timeout_ms);
    let (status, timed_out) = loop {
        if let Some(status) = child.try_wait()? {
            break (status, false);
        }
        if Instant::now() >= deadline {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            let status = child.wait()?;
            break (status, true);
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
    })
}

fn spawn_reader(
    reader: impl Read + Send + 'static,
    max_bytes: usize,
) -> mpsc::Receiver<std::io::Result<(Vec<u8>, bool)>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let _ = sender.send(read_bounded(reader, max_bytes));
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

fn read_bounded(mut reader: impl Read, max_bytes: usize) -> std::io::Result<(Vec<u8>, bool)> {
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
    }
}

pub(crate) fn is_credential_path(path: &Path) -> bool {
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        matches!(
            value.as_str(),
            ".ssh"
                | ".aws"
                | ".gnupg"
                | ".netrc"
                | ".npmrc"
                | "credentials"
                | "credentials.json"
                | "auth.json"
                | "id_rsa"
                | "id_ed25519"
        ) || value.contains("access_token")
            || value.contains("api_key")
            || value.contains("secret_key")
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
