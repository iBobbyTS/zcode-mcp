use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use review_ledger::{
    LedgerManager, REVIEW_CHECKPOINT, REVIEW_FINALIZE, REVIEW_PROGRESS, REVIEW_VALIDATION_RECORD,
};
use review_preparation::{
    CompletionOutcome, GeneralArtifactIntent, GeneralArtifactKind, GeneralCompletionSubmission,
    NetworkPolicy, PreparedGeneralTask, PreparedLaunchSpec, ReviewKind, ReviewManifest, RoundKind,
    ScratchPolicy,
};
use review_store::{LifecycleWrite, Store, TaskOutcome};
use sectioned_shadow::{
    run_shadow_v2, EvidenceClassification, RmcpFacadeClient, ShadowConfig, ShadowMode,
    SHADOW_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    env, io,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier, Mutex,
    },
    thread,
    time::Duration,
};
use zcode_driver::{ChildExit, Inbound, ProcessIdentity, StopOutcome};
use zcode_protocol::{RequestEnvelope, WireId, WireMessage};
use zcode_reviewd::rpc::{RpcServer, RpcService, ServerOptions};
use zcode_reviewd::{
    CommandRuntimeFactory, InternalLedgerMcpConfig, LifecycleRecord, LifecycleSink, ManagedRuntime,
    RuntimeCommandError, RuntimeEvent, RuntimeFactory, RuntimeTerminal, Scheduler, SchedulerConfig,
    SessionReady, TurnBoundary, TurnSnapshot,
};

const OFFICIAL_RUNTIME_SHA256: &str =
    "9318f60fb8c2c3bc83ce62da10220ebcdc9a99786df0a9abb1a4435ba66e4274";

static POLICY_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct PolicyEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    previous: Option<std::ffi::OsString>,
}

impl Drop for PolicyEnvGuard {
    fn drop(&mut self) {
        match self.previous.as_ref() {
            Some(value) => std::env::set_var("ZCODE_REVIEW_HOOK_PROVENANCE", value),
            None => std::env::remove_var("ZCODE_REVIEW_HOOK_PROVENANCE"),
        }
    }
}

fn install_verified_policy(root: &Path) -> PolicyEnvGuard {
    let lock = POLICY_ENV_LOCK.lock().unwrap();
    let previous = std::env::var_os("ZCODE_REVIEW_HOOK_PROVENANCE");
    let config = root.join("policy-config.json");
    let provenance = root.join("policy-provenance.json");
    std::fs::write(&config, "{}\n").unwrap();
    let plugin_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../plugins/zcode-subagent-mcp-v2")
        .canonicalize()
        .unwrap();
    for script in ["install-review-hook.mjs", "preflight-review-hook.mjs"] {
        let output = Command::new("node")
            .arg(plugin_root.join("scripts").join(script))
            .args([
                "--config",
                config.to_str().unwrap(),
                "--provenance",
                provenance.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{script} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::env::set_var("ZCODE_REVIEW_HOOK_PROVENANCE", provenance);
    PolicyEnvGuard {
        _lock: lock,
        previous,
    }
}

fn discover(protocol_version: &str) -> Vec<Value> {
    discover_mode(protocol_version, None)
}

fn discover_mode(protocol_version: &str, mode: Option<&str>) -> Vec<Value> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zcode-review-mcp"));
    command.env(
        "ZCODE_REVIEWD_SOCKET",
        "/tmp/zcode-review-mcp-test-unused.sock",
    );
    if let Some(mode) = mode {
        command.env("ZCODE_PUBLIC_API_MODE", mode);
    }
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":protocol_version,"capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    ] {
        writeln!(stdin, "{request}").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let frames = stdout
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        frames.len(),
        2,
        "stdout must contain only MCP response frames: {stdout}"
    );
    frames
}

struct FacadeProcess {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    stdout: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl FacadeProcess {
    fn start(socket: &Path) -> Self {
        Self::start_mode(socket, None)
    }

    fn start_mode(socket: &Path, mode: Option<&str>) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_zcode-review-mcp"));
        command.env("ZCODE_REVIEWD_SOCKET", socket);
        if let Some(mode) = mode {
            command.env("ZCODE_PUBLIC_API_MODE", mode);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut process = Self {
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        let initialized = process.request("initialize", json!({"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}));
        assert_eq!(initialized["result"]["protocolVersion"], "2026-07-28");
        writeln!(
            process.stdin,
            "{}",
            json!({"jsonrpc":"2.0","method":"notifications/initialized"})
        )
        .unwrap();
        process.stdin.flush().unwrap();
        process
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        writeln!(
            self.stdin,
            "{}",
            json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
        )
        .unwrap();
        self.stdin.flush().unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(response["id"], id);
        response
    }

    fn tool(&mut self, name: &str, arguments: Value) -> Value {
        let response = self.request("tools/call", json!({"name":name,"arguments":arguments}));
        assert!(response.get("error").is_none(), "{name}: {response}");
        assert!(
            response["result"]["content"]
                .as_array()
                .is_some_and(|content| content.iter().any(|item| {
                    item["type"] == "text"
                        && item["text"].as_str().is_some_and(|text| !text.is_empty())
                })),
            "{name} missing text fallback: {response}"
        );
        let structured = response["result"]["structuredContent"].clone();
        assert!(
            !structured.is_null(),
            "{name} missing structured content: {response}"
        );
        structured
    }

    fn tool_error(&mut self, name: &str, arguments: Value) -> String {
        let response = self.request("tools/call", json!({"name":name,"arguments":arguments}));
        assert_eq!(response["result"]["isError"], true, "{response}");
        response["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

impl Drop for FacadeProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn git(repository: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().into()
}

fn official_runtime_path() -> Option<PathBuf> {
    env::var_os("ZCODE_RUNTIME_PATH").map(PathBuf::from)
}

fn verify_official_runtime(path: &Path) {
    assert!(path.is_file(), "ZCODE_RUNTIME_PATH must be a regular file");
    assert_eq!(
        format!("{:x}", Sha256::digest(std::fs::read(path).unwrap())),
        OFFICIAL_RUNTIME_SHA256
    );
}

fn official_runtime_command(path: &Path) -> io::Result<Command> {
    let mut command = Command::new("node");
    command.arg(path).arg("app-server");
    Ok(command)
}

fn wait_official_public_review(
    facade: &mut FacadeProcess,
    agent_id: &str,
    attempt_sequence: u64,
    timeout: Duration,
) -> Value {
    let deadline = std::time::Instant::now() + timeout;
    let mut responded = std::collections::HashSet::new();
    loop {
        let status = facade.tool("zcode_agent_get", json!({"agent_id":agent_id}));
        for request in status["pending_requests"].as_array().unwrap() {
            if request["kind"] == "permission" {
                let request_id = request["request_id"].as_str().unwrap();
                if responded.insert(request_id.to_owned()) {
                    let response = facade.tool(
                        "zcode_agent_respond",
                        json!({
                            "agent_id":agent_id,
                            "request_id":request_id,
                            "decision":"allow",
                            "reason":"bounded official structured review"
                        }),
                    );
                    assert_eq!(response["disposition"], "responded");
                }
            }
        }
        if status["task"]["phase"] == "TERMINAL"
            && status["task"]["attempt_sequence"] == attempt_sequence
        {
            return status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "official public review did not terminalize: {status}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn manifest_fixture(root: &Path) -> PathBuf {
    let repository = root.join("repository");
    std::fs::create_dir_all(repository.join("src")).unwrap();
    std::fs::write(repository.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    git(&repository, &["init"]);
    git(&repository, &["config", "user.name", "S07 Test"]);
    git(
        &repository,
        &["config", "user.email", "s07@example.invalid"],
    );
    git(&repository, &["add", "src/lib.rs"]);
    git(&repository, &["commit", "-m", "fixture"]);
    std::fs::create_dir_all(repository.join(".agent-work/reviews/s07")).unwrap();
    std::fs::create_dir_all(repository.join(".agent-work/scratch/jobs")).unwrap();
    std::fs::write(repository.join(".agent-work/PLAN.md"), "# plan\n").unwrap();
    let head = git(&repository, &["rev-parse", "HEAD"]);
    let manifest = ReviewManifest {
        schema: "sectioned-zcode-review/v1".into(),
        review_kind: ReviewKind::Code,
        feature_id: "s07-public".into(),
        section_id: "S07".into(),
        round_kind: RoundKind::InitialBounded,
        repository: std::fs::canonicalize(&repository).unwrap(),
        base_ref: head.clone(),
        head_ref: head,
        plan_path: ".agent-work/PLAN.md".into(),
        context_paths: vec![],
        scope_paths: vec!["src".into()],
        forbidden_input_globs: vec![],
        validation_commands: Default::default(),
        report_target: ".agent-work/reviews/s07/report.md".into(),
        scratch_root: ".agent-work/scratch/jobs".into(),
        model: None,
        fresh_session: true,
        network_policy: NetworkPolicy::Deny,
        scratch_policy: ScratchPolicy::Isolated,
        idempotency_key: "s07-public-process".into(),
    };
    let path = root.join("review-manifest.json");
    std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    path
}

struct PublicFakeRuntime {
    sink: Arc<dyn LifecycleSink>,
    sequence: AtomicU64,
    terminal: Mutex<Option<RuntimeTerminal>>,
    turn: Mutex<TurnSnapshot>,
    bootstrap_entered: Arc<Barrier>,
    bootstrap_release: Arc<Barrier>,
    readiness: bool,
    emit_unsupported: bool,
}

impl PublicFakeRuntime {
    fn emit(&self, event: RuntimeEvent) {
        self.sink.emit(LifecycleRecord {
            sequence: self.sequence.fetch_add(1, Ordering::AcqRel),
            event,
        });
    }

    fn finish(&self, terminal: RuntimeTerminal) -> RuntimeTerminal {
        let mut current = self.terminal.lock().unwrap();
        if let Some(current) = current.as_ref() {
            return current.clone();
        }
        *current = Some(terminal.clone());
        drop(current);
        self.emit(RuntimeEvent::Terminal(terminal.clone()));
        terminal
    }
}

impl ManagedRuntime for PublicFakeRuntime {
    fn identity(&self) -> Option<ProcessIdentity> {
        None
    }
    fn stop(&self, _grace: Duration) -> RuntimeTerminal {
        self.finish(RuntimeTerminal::Stopped(StopOutcome::AlreadyExited(
            ChildExit::Exited(Some(0)),
        )))
    }
    fn wait_terminal(&self, _timeout: Duration) -> Option<RuntimeTerminal> {
        self.terminal.lock().unwrap().clone()
    }
    fn bootstrap_session(
        &self,
        job: &review_store::Job,
        _timeout: Duration,
    ) -> Result<SessionReady, RuntimeCommandError> {
        if !self.readiness {
            self.bootstrap_entered.wait();
            self.bootstrap_release.wait();
        }
        *self.turn.lock().unwrap() = TurnSnapshot {
            generation: 1,
            active: !self.readiness,
            boundary: self.readiness.then_some(TurnBoundary::Completed),
        };
        if !self.readiness {
            self.emit(RuntimeEvent::Driver(Inbound::Message(
                WireMessage::Request(RequestEnvelope::new(
                    WireId::String("permission-wire".into()),
                    "interaction/requestPermission",
                    json!({"toolCallId":"tool-1","toolName":"git_ref_mutation","input":{}}),
                )),
            )));
            if self.emit_unsupported {
                self.emit(RuntimeEvent::Driver(Inbound::Message(
                    WireMessage::Request(RequestEnvelope::new(
                        WireId::String("input-wire".into()),
                        "interaction/requestUserInput",
                        json!({"question":"private unsupported payload"}),
                    )),
                )));
            }
        }
        Ok(SessionReady {
            session_id: format!("session-{}", job.agent_id),
            initial_turn_id: Some("turn-1".into()),
            observed_model: None,
        })
    }
    fn send_turn(
        &self,
        _session_id: &str,
        _content: &str,
        _timeout: Duration,
    ) -> Result<Option<String>, RuntimeCommandError> {
        Ok(Some("turn-next".into()))
    }
    fn stop_turn(
        &self,
        _session_id: &str,
        _timeout: Duration,
    ) -> Result<TurnSnapshot, RuntimeCommandError> {
        let mut turn = self.turn.lock().unwrap();
        turn.active = false;
        turn.boundary = Some(TurnBoundary::Completed);
        Ok(turn.clone())
    }
    fn respond_request(
        &self,
        _correlation_id: &str,
        _decision: &str,
        _content: Option<&str>,
        _deadline: std::time::Instant,
    ) -> Result<(), RuntimeCommandError> {
        Ok(())
    }
    fn turn_snapshot(&self) -> TurnSnapshot {
        self.turn.lock().unwrap().clone()
    }
}

struct PublicFakeFactory {
    bootstrap_entered: Arc<Barrier>,
    bootstrap_release: Arc<Barrier>,
    runtimes: Mutex<HashMap<String, Arc<PublicFakeRuntime>>>,
    emit_unsupported: bool,
}
impl PublicFakeFactory {
    fn create_runtime(
        &self,
        sink: Arc<dyn LifecycleSink>,
        readiness: bool,
    ) -> Arc<PublicFakeRuntime> {
        Arc::new(PublicFakeRuntime {
            sink,
            sequence: AtomicU64::new(1),
            terminal: Mutex::new(None),
            turn: Mutex::new(TurnSnapshot {
                generation: 0,
                active: false,
                boundary: None,
            }),
            bootstrap_entered: Arc::clone(&self.bootstrap_entered),
            bootstrap_release: Arc::clone(&self.bootstrap_release),
            readiness,
            emit_unsupported: self.emit_unsupported,
        })
    }

    fn runtime(&self, agent_id: &str) -> Arc<PublicFakeRuntime> {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(runtime) = self.runtimes.lock().unwrap().get(agent_id).cloned() {
                return runtime;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "public fake runtime was not spawned"
            );
            thread::sleep(Duration::from_millis(5));
        }
    }
}
impl RuntimeFactory for PublicFakeFactory {
    fn spawn(
        &self,
        job: &review_store::Job,
        sink: Arc<dyn LifecycleSink>,
    ) -> std::io::Result<Arc<dyn ManagedRuntime>> {
        let runtime = self.create_runtime(sink, false);
        self.runtimes
            .lock()
            .unwrap()
            .insert(job.agent_id.clone(), Arc::clone(&runtime));
        Ok(runtime)
    }

    fn spawn_readiness(
        &self,
        _job: &review_store::Job,
        sink: Arc<dyn LifecycleSink>,
        deadline: std::time::Instant,
    ) -> std::io::Result<Arc<dyn ManagedRuntime>> {
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "readiness spawn deadline elapsed",
            ));
        }
        Ok(self.create_runtime(sink, true))
    }
}

fn completed_runtime_terminal() -> RuntimeTerminal {
    RuntimeTerminal::Completed(StopOutcome::AlreadyExited(ChildExit::Exited(Some(0))))
}

fn complete_next_review_attempt(
    store: &Store,
    scheduler: &Scheduler,
    factory: &PublicFakeFactory,
    ledger: &LedgerManager,
    checkpoint_id: &str,
    inject_redacted_progress: bool,
) -> String {
    complete_next_review_attempt_with_terminal(
        store,
        scheduler,
        factory,
        ledger,
        checkpoint_id,
        inject_redacted_progress,
        completed_runtime_terminal(),
    )
}

fn complete_next_review_attempt_with_terminal(
    store: &Store,
    scheduler: &Scheduler,
    factory: &PublicFakeFactory,
    ledger: &LedgerManager,
    checkpoint_id: &str,
    inject_redacted_progress: bool,
    terminal: RuntimeTerminal,
) -> String {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let execution_id = loop {
        let started = scheduler.start_ready().unwrap();
        if let Some(execution_id) = started.into_iter().next() {
            break execution_id;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "review attempt was not submitted"
        );
        thread::sleep(Duration::from_millis(5));
    };
    let progress_identity = store.review_progress(&execution_id).unwrap().unwrap();
    scheduler
        .call_task_review_tool(
            &execution_id,
            REVIEW_PROGRESS,
            json!({
                "attempt_sequence":progress_identity.attempt_sequence,
                "run_idempotency_key":progress_identity.run_idempotency_key,
                "stage":"inspection",
                "summary":"public composition progress",
                "counters":{"files":1,"findings":0}
            }),
        )
        .unwrap();
    if inject_redacted_progress {
        let job = store.get_job(&execution_id).unwrap().unwrap();
        let runtime_agent_id = job.runtime_agent_id.unwrap();
        for (source_sequence, redaction_level) in [
            ((1u64 << 62) + 1, "redacted"),
            ((1u64 << 62) + 2, "bounded"),
        ] {
            store
                .append_lifecycle(&LifecycleWrite {
                    agent_id: execution_id.clone(),
                    runtime_agent_id: runtime_agent_id.clone(),
                    owner_epoch: job.owner_epoch,
                    source_sequence,
                    event_type: "review.progress".into(),
                    turn_id: None,
                    payload_json: json!({
                        "stage":"inspection",
                        "summary":format!("{redaction_level} MCP progress secret"),
                        "counters":{"private":1},
                        "attempt_sequence":1,
                        "updated_at":1
                    })
                    .to_string(),
                    redaction_level: redaction_level.into(),
                    terminal: None,
                    turn_state: None,
                })
                .unwrap();
        }
    }
    ledger
        .call_tool(
            &execution_id,
            REVIEW_CHECKPOINT,
            json!({
                "checkpoint_id":checkpoint_id,
                "stage":"inspection",
                "summary":"public composition inspected",
                "inspected":[{"path":"src/lib.rs","line_ranges":["1"]}],
                "commands":[],
                "open_questions":[],
                "remaining_scope":[]
            }),
        )
        .unwrap();
    ledger
        .call_tool(
            &execution_id,
            REVIEW_VALIDATION_RECORD,
            json!({
                "validation_id":format!("{checkpoint_id}-validation"),
                "command":"cargo test",
                "cwd":"public-composition",
                "exit_code":0,
                "duration_ms":1,
                "stdout_summary":"passed",
                "stderr_summary":"",
                "related_findings":[]
            }),
        )
        .unwrap();
    ledger
        .call_tool(
            &execution_id,
            REVIEW_FINALIZE,
            json!({
                "signal":"no_findings_observed",
                "summary":"public composition finalized",
                "coverage":{"covered":["public facade"],"not_covered":[]},
                "uncertainties":[],
                "recommended_next_actions":[]
            }),
        )
        .unwrap();
    factory.runtime(&execution_id).finish(terminal);
    let terminal_deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if store.task_result(&execution_id).unwrap().is_some() {
            break;
        }
        assert!(
            std::time::Instant::now() < terminal_deadline,
            "review attempt did not terminalize"
        );
        thread::sleep(Duration::from_millis(5));
    }
    execution_id
}

fn wait_public_terminal(
    facade: &mut FacadeProcess,
    agent_id: &str,
    attempt_sequence: u64,
) -> Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let status = facade.tool("zcode_agent_get", json!({"agent_id":agent_id}));
        if status["task"]["phase"] == "TERMINAL"
            && status["task"]["attempt_sequence"] == attempt_sequence
        {
            return status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "public task did not terminalize"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn resolved_property<'a>(schema: &'a Value, field: &str) -> &'a Value {
    let property = &schema["properties"][field];
    match property["$ref"].as_str() {
        Some(reference) => schema
            .pointer(reference.strip_prefix('#').unwrap())
            .unwrap(),
        None => property,
    }
}

fn contains_enum(schema: &Value, expected: &[&str]) -> bool {
    match schema {
        Value::Object(map) => {
            map.get("enum")
                .and_then(Value::as_array)
                .is_some_and(|values| {
                    values
                        == &expected
                            .iter()
                            .map(|value| Value::String((*value).into()))
                            .collect::<Vec<_>>()
                })
                || map.values().any(|value| contains_enum(value, expected))
        }
        Value::Array(values) => values.iter().any(|value| contains_enum(value, expected)),
        _ => false,
    }
}

#[test]
fn stdio_is_clean_and_modern_and_legacy_clients_discover_exact_tools() {
    for version in ["2026-07-28", "2024-11-05"] {
        let frames = discover(version);
        assert_eq!(frames[0]["result"]["protocolVersion"], version);
        let tools = frames[1]["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), zcode_review_mcp::PUBLIC_TOOLS.len());
        let names = tools
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names, zcode_review_mcp::PUBLIC_TOOLS.into_iter().collect());
        for tool in tools {
            assert_eq!(
                tool["inputSchema"]["additionalProperties"], false,
                "{} input must be closed",
                tool["name"]
            );
            assert_eq!(
                tool["outputSchema"]["additionalProperties"], false,
                "{} output must be closed",
                tool["name"]
            );
        }
        let by_name = |name: &str| tools.iter().find(|tool| tool["name"] == name).unwrap();
        for (name, field, minimum, maximum) in [
            ("zcode_review_events", "limit", 1, 100),
            ("zcode_review_wait", "timeout_ms", 1, 5000),
            ("zcode_review_result", "preview_bytes", 0, 8192),
            ("zcode_review_list", "limit", 1, 100),
        ] {
            let schema = resolved_property(&by_name(name)["inputSchema"], field);
            assert_eq!(schema["minimum"], minimum);
            assert_eq!(schema["maximum"], maximum);
        }
        assert_eq!(
            resolved_property(&by_name("zcode_review_message")["inputSchema"], "mode")["enum"],
            json!(["queue", "interrupt_and_continue"])
        );
        assert_eq!(
            resolved_property(&by_name("zcode_review_respond")["inputSchema"], "decision")["enum"],
            json!(["allow", "deny"])
        );
        assert_eq!(
            resolved_property(&by_name("zcode_review_list")["inputSchema"], "scope")["enum"],
            json!(["active", "recent", "all"])
        );
        assert!(contains_enum(
            &by_name("zcode_review_spawn")["outputSchema"],
            &["created", "existing_compatible"]
        ));
        assert!(contains_enum(
            &by_name("zcode_review_status")["outputSchema"],
            &[
                "QUEUED",
                "STARTING",
                "RUNNING",
                "STOPPING",
                "COMPLETED",
                "CANCELLED",
                "FAILED",
                "FAILED_RUNTIME_LOST",
                "ORPHANED",
                "CLOSED"
            ]
        ));
        assert!(contains_enum(
            &by_name("zcode_review_message")["outputSchema"],
            &[
                "queued",
                "delivered",
                "interrupted_then_delivered",
                "already_delivered",
                "failed"
            ]
        ));
        assert!(contains_enum(
            &by_name("zcode_review_respond")["outputSchema"],
            &["responded", "already_responded", "in_flight"]
        ));
        assert!(contains_enum(
            &by_name("zcode_review_respond")["outputSchema"],
            &["allow", "deny"]
        ));
        assert!(contains_enum(
            &by_name("zcode_review_status")["outputSchema"],
            &["permission", "unsupported_input"]
        ));
        assert!(contains_enum(
            &by_name("zcode_review_status")["outputSchema"],
            &[
                "read",
                "write",
                "command",
                "network",
                "git_ref_mutation",
                "user_input",
                "unknown"
            ]
        ));
        assert!(contains_enum(
            &by_name("zcode_review_status")["outputSchema"],
            &["externally_decidable", "hard_deny", "unknown"]
        ));
        assert!(contains_enum(
            &by_name("zcode_review_result")["outputSchema"],
            &[
                "valid",
                "missing",
                "replaced",
                "binary",
                "invalid",
                "legacy_unverified"
            ]
        ));
    }
}

#[test]
fn v2_stdio_discovers_only_the_exact_static_catalog() {
    let frames = discover_mode("2026-07-28", Some("subagent_v2"));
    let tools = frames[1]["result"]["tools"].as_array().unwrap();
    let names = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(names, zcode_review_mcp::V2_PUBLIC_TOOLS);
    assert_eq!(tools.len(), 14);
    assert!(tools.iter().all(|tool| {
        tool["inputSchema"]["additionalProperties"] == false
            && tool["outputSchema"]["additionalProperties"] == false
            && tool["annotations"]["openWorldHint"] == false
    }));
    assert!(!names.contains(&"zcode_review_status"));
    assert!(!names.contains(&"zcode_review_list"));
    let ensure_ready = tools
        .iter()
        .find(|tool| tool["name"] == "zcode_system_ensure_ready")
        .unwrap();
    let readiness_output = &ensure_ready["outputSchema"];
    assert!(contains_enum(
        readiness_output,
        &[
            "READY",
            "CONFIG_INVALID",
            "ZCODE_START_FAILED",
            "RUNTIME_PROTOCOL_FAILED",
            "MODEL_AUTH_FAILED",
            "RUNTIME_FAILED",
            "NOT_OBSERVED_WITHIN_TIMEOUT",
            "CLEANUP_FAILED"
        ]
    ));
    let reason_property = &readiness_output["properties"]["reason_code"];
    let reason_variants = reason_property["anyOf"].as_array().unwrap();
    assert_eq!(reason_variants.len(), 2);
    let reason_enum = reason_variants
        .iter()
        .find_map(|variant| {
            variant["$ref"]
                .as_str()
                .and_then(|reference| readiness_output.pointer(reference.strip_prefix('#')?))
                .filter(|schema| schema.get("enum").is_some())
        })
        .unwrap();
    assert_eq!(
        reason_enum["enum"],
        json!([
            "CONFIG_INVALID",
            "ZCODE_START_FAILED",
            "RUNTIME_PROTOCOL_FAILED",
            "MODEL_AUTH_FAILED",
            "RUNTIME_FAILED",
            "NOT_OBSERVED_WITHIN_TIMEOUT",
            "CLEANUP_FAILED"
        ])
    );
    assert!(reason_variants
        .iter()
        .any(|variant| variant["type"] == "null"));
    let status = tools
        .iter()
        .find(|tool| tool["name"] == "zcode_system_status")
        .unwrap();
    assert!(contains_enum(
        &status["outputSchema"],
        &["beta_ready", "experimental_unverified_runtime"]
    ));
}

#[test]
fn invalid_or_empty_catalog_selector_fails_before_stdio_startup() {
    for selector in ["", "legacy_review_v1,subagent_v2", "unknown"] {
        let output = Command::new(env!("CARGO_BIN_EXE_zcode-review-mcp"))
            .env(
                "ZCODE_REVIEWD_SOCKET",
                "/tmp/zcode-review-mcp-test-unused.sock",
            )
            .env("ZCODE_PUBLIC_API_MODE", selector)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "selector {selector:?} was accepted"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("ZCODE_PUBLIC_API_MODE"), "{stderr}");
        assert!(!stderr.contains("/tmp/zcode-review-mcp-test-unused.sock"));
    }
}

#[test]
fn v2_general_lifecycle_is_scoped_redacted_and_restart_stable() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
    let runtime_factory: Arc<dyn RuntimeFactory> = Arc::new(PublicFakeFactory {
        bootstrap_entered: Arc::new(Barrier::new(2)),
        bootstrap_release: Arc::new(Barrier::new(2)),
        runtimes: Mutex::new(HashMap::new()),
        emit_unsupported: true,
    });
    let scheduler = Scheduler::new(
        "s05-v2-general",
        Arc::clone(&store),
        runtime_factory,
        SchedulerConfig::default(),
    )
    .unwrap();
    let service = Arc::new(RpcService::new(scheduler, Arc::clone(&store)).unwrap());
    let socket = directory.path().join("rpc/review.sock");
    let _server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
    let manifest_path = manifest_fixture(directory.path());
    let manifest: ReviewManifest =
        serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap();

    let mut first = FacadeProcess::start_mode(&socket, Some("subagent_v2"));
    let readiness = first.tool("zcode_system_ensure_ready", json!({"timeout_ms":100}));
    assert_eq!(readiness["ready"], true);
    assert_eq!(readiness["probe_result"], "READY");
    assert_eq!(readiness["reason_code"], Value::Null);
    assert_eq!(
        readiness["status"]["capabilities"]["maturity"],
        json!({
            "analysis_readonly":"experimental_unverified_runtime",
            "implementation_worktree":"experimental_unverified_runtime",
            "structured_review":"beta_ready",
            "test_runner":"experimental_unverified_runtime"
        })
    );
    let spawn_input = json!({
        "repository":manifest.repository,
        "base_ref":manifest.base_ref,
        "profile":"analysis_readonly",
        "prompt":"inspect the repository without modifying it",
        "feature_id":"s05-v2-process",
        "ownership_token":"s05-v2-owner",
        "idempotency_key":"s05-v2-general-process",
        "write_manifest":[],
        "repo_context":["src/lib.rs"],
        "attachments":[],
        "retain_partial":false
    });
    serde_json::from_value::<zcode_review_mcp::v2::AgentSpawnInput>(spawn_input.clone()).unwrap();
    let spawned = first.tool("zcode_agent_spawn", spawn_input);
    let agent_id = spawned["agent_id"].as_str().unwrap().to_owned();
    assert_eq!(spawned["submission_disposition"], "created");
    assert_eq!(spawned["attempt_sequence"], 1);
    assert_eq!(spawned["phase"], "QUEUED");
    drop(first);

    let mut restarted = FacadeProcess::start_mode(&socket, Some("subagent_v2"));
    let task = restarted.tool("zcode_agent_get", json!({"agent_id":agent_id}));
    assert_eq!(task["task"]["agent_id"], agent_id);
    assert_eq!(task["task"]["attempt_sequence"], 1);
    assert!(task["pending_requests"].as_array().unwrap().is_empty());
    let listed = restarted.tool(
        "zcode_agent_list",
        json!({"feature_id":"s05-v2-process","limit":10}),
    );
    assert_eq!(listed["tasks"].as_array().unwrap().len(), 1);
    assert_eq!(listed["tasks"][0]["agent_id"], agent_id);
    let events = restarted.tool(
        "zcode_agent_events",
        json!({"agent_id":agent_id,"after_sequence":0,"limit":100}),
    );
    let next_sequence = events["next_sequence"].as_u64().unwrap();
    let waited = restarted.tool(
        "zcode_agent_wait",
        json!({"agent_id":agent_id,"after_sequence":next_sequence,"timeout_ms":10}),
    );
    assert_eq!(waited["timed_out"], true);
    assert!(waited["next_sequence"].as_u64().unwrap() >= next_sequence);
    let public = serde_json::to_string(&(task, listed, events, waited)).unwrap();
    for forbidden in [
        directory.path().to_string_lossy().as_ref(),
        "s05-v2-owner",
        "inspect the repository",
        "workspace_path",
        "runtime_agent_id",
        "correlation_id",
    ] {
        assert!(!public.contains(forbidden), "leaked {forbidden}: {public}");
    }
    let cancelled = restarted.tool("zcode_agent_cancel", json!({"agent_id":agent_id}));
    assert_eq!(cancelled["task"]["phase"], "TERMINAL");
    assert_eq!(cancelled["task"]["cancel_requested"], true);
    let closed = restarted.tool("zcode_agent_close", json!({"agent_id":agent_id}));
    assert_eq!(closed["task"]["closed"], true);
    assert_eq!(closed["task"]["resources_reaped"], true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_v2_composition_uses_terminal_evidence_and_survives_daemon_restart() {
    let directory = tempfile::tempdir().unwrap();
    let _policy_env = install_verified_policy(directory.path());
    let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
    let factory = Arc::new(PublicFakeFactory {
        bootstrap_entered: Arc::new(Barrier::new(1)),
        bootstrap_release: Arc::new(Barrier::new(1)),
        runtimes: Mutex::new(HashMap::new()),
        emit_unsupported: false,
    });
    let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
    let runtime_factory: Arc<dyn RuntimeFactory> = factory.clone();
    let scheduler = Scheduler::new(
        "s05-v2-composition-first",
        Arc::clone(&store),
        runtime_factory,
        SchedulerConfig::default(),
    )
    .unwrap()
    .with_ledger(
        Arc::clone(&ledger),
        InternalLedgerMcpConfig {
            command: PathBuf::from("/usr/bin/false"),
            socket: directory.path().join("first-ledger.sock"),
            runtime_sha256: None,
        },
    )
    .unwrap();
    let service = Arc::new(RpcService::new(scheduler.clone(), Arc::clone(&store)).unwrap());
    let socket = directory.path().join("rpc/review.sock");
    let server = RpcServer::bind(&socket, Arc::clone(&service), ServerOptions::default()).unwrap();
    let manifest_path = manifest_fixture(directory.path());
    let manifest: ReviewManifest =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    let initial_head = git(&manifest.repository, &["rev-parse", "HEAD"]);
    let initial_status = git(&manifest.repository, &["status", "--porcelain"]);
    let shadow = ShadowConfig {
        schema: SHADOW_SCHEMA.into(),
        manifest_path: manifest_path.clone(),
        artifact_directory: directory.path().join("shadow-artifacts"),
        artifact_stem: "s05-real-public-shadow".into(),
        mode: ShadowMode::Full,
        wait_timeout_ms: 500,
        max_waits: 6,
    };
    let shadow_store = Arc::clone(&store);
    let shadow_scheduler = scheduler.clone();
    let shadow_factory = Arc::clone(&factory);
    let shadow_ledger = Arc::clone(&ledger);
    let review_worker = thread::spawn(move || {
        complete_next_review_attempt_with_terminal(
            &shadow_store,
            &shadow_scheduler,
            &shadow_factory,
            &shadow_ledger,
            "fresh-public-checkpoint",
            true,
            RuntimeTerminal::Exited(ChildExit::Exited(Some(17))),
        )
    });
    let facade =
        RmcpFacadeClient::spawn(Path::new(env!("CARGO_BIN_EXE_zcode-review-mcp")), &socket)
            .await
            .unwrap();
    let shadow_run = run_shadow_v2(&facade, &shadow).await.unwrap();
    facade.shutdown().await.unwrap();
    let shadow_execution = review_worker.join().unwrap();
    let reconciled = store.task_result(&shadow_execution).unwrap().unwrap();
    assert_eq!(reconciled.result.outcome, TaskOutcome::Succeeded);
    assert_eq!(reconciled.result.summary, "REVIEW_FINALIZED");
    assert!(!reconciled.result.partial);
    assert!(reconciled.result.residual_gaps.is_empty());
    assert_eq!(
        shadow_run.provenance.classification,
        EvidenceClassification::IndependentEvidence
    );
    assert!(shadow_run.provenance.fresh_session_observed);
    assert_eq!(shadow_run.provenance.checkpoint_count, 1);
    let shadow_report = std::fs::read(&shadow_run.artifacts.glm_raw).unwrap();
    let shadow_report_sha256 = format!("{:x}", Sha256::digest(&shadow_report));
    assert_eq!(
        shadow_run.provenance.report_sha256.as_deref(),
        Some(shadow_report_sha256.as_str())
    );
    let shadow_prepared: PreparedLaunchSpec = serde_json::from_str(
        store
            .get_job(&shadow_execution)
            .unwrap()
            .unwrap()
            .prepared_launch_json
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert!(!shadow_prepared.worktree.path.exists());

    let shadow_agent_id = shadow_run.provenance.agent_id.clone();
    let mut before_restart = FacadeProcess::start_mode(&socket, Some("subagent_v2"));
    let shadow_status = before_restart.tool("zcode_agent_get", json!({"agent_id":shadow_agent_id}));
    assert_eq!(shadow_status["task"]["attempt_sequence"], 1);
    assert_eq!(shadow_status["task"]["counts_as_independent"], true);
    assert_eq!(shadow_status["task"]["resources_reaped"], true);
    let shadow_events = before_restart.tool(
        "zcode_agent_events",
        json!({"agent_id":shadow_agent_id,"after_sequence":0,"limit":100}),
    );
    let shadow_rows = shadow_events["events"].as_array().unwrap();
    assert!(shadow_rows
        .iter()
        .all(|event| event["attempt_sequence"] == 1));
    let progress = shadow_rows
        .iter()
        .find(|event| event["event_type"] == "review_progress")
        .unwrap();
    assert_eq!(progress["stage"], "inspection");
    assert_eq!(progress["summary"], "public composition progress");
    assert_eq!(progress["counters"], json!({"files":1,"findings":0}));
    assert!(progress["last_progress_at"].as_u64().is_some());
    assert!(progress["semantic_idle_ms"].as_u64().is_some());
    assert_eq!(progress["nudge_sent"], false);
    let fail_closed = shadow_rows
        .iter()
        .filter(|event| event["event_type"] == "review_progress" && event.get("stage").is_none())
        .collect::<Vec<_>>();
    assert_eq!(fail_closed.len(), 2);
    for event in fail_closed {
        let event = event.as_object().unwrap();
        for field in [
            "stage",
            "summary",
            "counters",
            "last_progress_at",
            "semantic_idle_ms",
            "nudge_sent",
        ] {
            assert!(!event.contains_key(field), "MCP event leaked {field}");
        }
    }
    let public = shadow_events.to_string();
    for forbidden in [
        "run_idempotency_key",
        "runtime_agent_id",
        "payload_json",
        "MCP progress secret",
        "private",
    ] {
        assert!(
            !public.contains(forbidden),
            "public event leaked {forbidden}"
        );
    }
    drop(before_restart);
    server.shutdown();
    drop(service);
    drop(scheduler);

    let restarted_factory: Arc<dyn RuntimeFactory> = factory.clone();
    let restarted_scheduler = Scheduler::new(
        "s05-v2-composition-restarted",
        Arc::clone(&store),
        restarted_factory,
        SchedulerConfig::default(),
    )
    .unwrap()
    .with_ledger(
        Arc::clone(&ledger),
        InternalLedgerMcpConfig {
            command: PathBuf::from("/usr/bin/false"),
            socket: directory.path().join("restarted-ledger.sock"),
            runtime_sha256: None,
        },
    )
    .unwrap();
    restarted_scheduler.reconcile_startup().unwrap();
    let restarted_service =
        Arc::new(RpcService::new(restarted_scheduler.clone(), Arc::clone(&store)).unwrap());
    let _restarted_server =
        RpcServer::bind(&socket, restarted_service, ServerOptions::default()).unwrap();
    let mut v2 = FacadeProcess::start_mode(&socket, Some("subagent_v2"));
    assert_eq!(
        v2.tool("zcode_agent_get", json!({"agent_id":shadow_agent_id}))["task"]["resources_reaped"],
        true
    );

    let mut continuation_parent_manifest = manifest.clone();
    continuation_parent_manifest.idempotency_key = "s05-public-continuation-parent".into();
    continuation_parent_manifest.report_target =
        ".agent-work/reviews/s07/continuation-parent.md".into();
    let continuation_parent = v2.tool(
        "zcode_review_spawn",
        json!({
            "review_kind":"initial_bounded",
            "repository":continuation_parent_manifest.repository,
            "base_ref":continuation_parent_manifest.base_ref,
            "head_ref":continuation_parent_manifest.head_ref,
            "scope_manifest":continuation_parent_manifest.scope_paths,
            "requirements_path":continuation_parent_manifest.plan_path,
            "report_path":continuation_parent_manifest.report_target,
            "feature_id":continuation_parent_manifest.feature_id,
            "section_id":continuation_parent_manifest.section_id,
            "ownership_token":"s05-public-continuation-parent-owner",
            "idempotency_key":continuation_parent_manifest.idempotency_key,
            "read_only":true,
            "attachments":[]
        }),
    );
    let public_agent_id = continuation_parent["agent_id"].as_str().unwrap().to_owned();
    let review_id = continuation_parent["review_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(continuation_parent["counts_as_independent"], false);
    let first_execution = complete_next_review_attempt(
        &store,
        &restarted_scheduler,
        &factory,
        &ledger,
        "continuation-parent-checkpoint",
        false,
    );
    let first_status = wait_public_terminal(&mut v2, &public_agent_id, 1);
    assert_eq!(first_status["task"]["counts_as_independent"], true);
    assert_eq!(first_status["task"]["fresh_session_observed"], true);
    let first_prepared: PreparedLaunchSpec = serde_json::from_str(
        store
            .get_job(&first_execution)
            .unwrap()
            .unwrap()
            .prepared_launch_json
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    let first_report = std::fs::read(&first_prepared.report_target).unwrap();
    let first_report_sha256 = format!("{:x}", Sha256::digest(&first_report));
    assert!(!first_prepared.worktree.path.exists());
    let first_events = v2.tool(
        "zcode_agent_events",
        json!({"agent_id":public_agent_id,"after_sequence":0,"limit":100}),
    );
    let first_cursor = first_events["next_sequence"].as_u64().unwrap();
    let first_event_rows = first_events["events"].as_array().unwrap();
    assert!(!first_event_rows.is_empty());
    assert!(first_event_rows
        .iter()
        .all(|event| event["attempt_sequence"] == 1));
    assert_eq!(first_event_rows[0]["sequence"], 1);
    assert!(first_event_rows.iter().all(|event| matches!(
        event["event_type"].as_str(),
        Some(
            "attempt_started"
                | "review_progress"
                | "pending_request"
                | "review_finalized"
                | "terminal"
        )
    )));

    let continuation = v2.tool(
        "zcode_review_continue",
        json!({
            "agent_id":public_agent_id,
            "review_id":review_id,
            "base_ref":manifest.base_ref,
            "head_ref":manifest.head_ref,
            "frozen_finding_ids":[],
            "idempotency_key":"s05-public-continuation",
            "attachments":[],
            "budget":{
                "wall_time_ms":7000,
                "max_turns":12,
                "max_tool_calls":48,
                "max_context_bytes":1048576,
                "max_result_bytes":262144,
                "max_artifact_bytes":2097152
            }
        }),
    );
    assert_eq!(continuation["agent_id"], public_agent_id);
    assert_eq!(continuation["review_id"], review_id);
    assert_eq!(continuation["attempt_sequence"], 2);
    assert_eq!(continuation["counts_as_independent"], false);
    assert_eq!(continuation["effective_budget"]["max_turns"], 12);
    let second_execution = complete_next_review_attempt(
        &store,
        &restarted_scheduler,
        &factory,
        &ledger,
        "continuation-public-checkpoint",
        false,
    );
    let second_status = wait_public_terminal(&mut v2, &public_agent_id, 2);
    assert_eq!(second_status["task"]["counts_as_independent"], false);
    assert_eq!(second_status["task"]["fresh_session_observed"], true);
    let second_prepared: PreparedLaunchSpec = serde_json::from_str(
        store
            .get_job(&second_execution)
            .unwrap()
            .unwrap()
            .prepared_launch_json
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert!(!second_prepared.worktree.path.exists());
    let continuation_events = v2.tool(
        "zcode_agent_events",
        json!({"agent_id":public_agent_id,"after_sequence":0,"limit":100}),
    );
    let continuation_rows = continuation_events["events"].as_array().unwrap();
    assert!(!continuation_rows.is_empty());
    assert_eq!(continuation_rows[0]["sequence"], 1);
    assert_eq!(
        continuation_events["next_sequence"],
        continuation_rows.last().unwrap()["sequence"]
    );
    assert!(continuation_events["next_sequence"].as_u64().unwrap() <= first_cursor);
    assert!(continuation_rows
        .iter()
        .all(|event| event["attempt_sequence"] == 2));

    let selected_first = v2.tool(
        "zcode_agent_result",
        json!({"agent_id":public_agent_id,"attempt_sequence":1}),
    );
    assert_eq!(selected_first["task"]["attempt_sequence"], 1);
    assert_eq!(selected_first["result"]["outcome"], "SUCCEEDED");
    let evidence = &selected_first["result"]["review_evidence"];
    assert_eq!(evidence["final_signal"], "no_findings_observed");
    assert_eq!(evidence["finalized"], true);
    assert_eq!(evidence["counts"]["checkpoints"], 1);
    assert_eq!(evidence["counts"]["validations"], 1);
    assert_eq!(evidence["counts"]["findings"], 0);
    assert_eq!(evidence["independence"]["counts_as_independent"], true);
    assert_eq!(
        evidence["validation_provenance"]["daemon_verification"]["artifact_digest_verified"],
        true
    );
    assert_eq!(
        evidence["validation_provenance"]["model_attestation"]["present"],
        true
    );
    let first_artifact = selected_first["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|artifact| artifact["kind"] == "report_markdown")
        .unwrap();
    assert_eq!(first_artifact["sha256"], first_report_sha256);
    let selected_chunk = v2.tool(
        "zcode_agent_result",
        json!({
            "agent_id":public_agent_id,
            "attempt_sequence":1,
            "artifact_id":first_artifact["artifact_id"],
            "offset_bytes":0,
            "limit_bytes":first_report.len()
        }),
    );
    let selected_bytes = BASE64
        .decode(
            selected_chunk["artifact_chunk"]["bytes_base64"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(selected_bytes, first_report);
    assert_eq!(selected_chunk["artifact_chunk"]["eof"], true);
    let continuation_closed = v2.tool("zcode_agent_close", json!({"agent_id":public_agent_id}));
    assert_eq!(continuation_closed["task"]["resources_reaped"], true);

    let general_spawn = v2.tool(
        "zcode_agent_spawn",
        json!({
            "repository":manifest.repository,
            "base_ref":manifest.base_ref,
            "profile":"analysis_readonly",
            "prompt":"inspect the repository without modifying it",
            "feature_id":"s05-public-composition",
            "ownership_token":"s05-public-owner",
            "idempotency_key":"s05-public-general-completion",
            "write_manifest":[],
            "repo_context":["src/lib.rs"],
            "attachments":[],
            "retain_partial":false
        }),
    );
    let general_agent_id = general_spawn["agent_id"].as_str().unwrap().to_owned();
    let general_execution = store
        .get_task(&general_agent_id)
        .unwrap()
        .unwrap()
        .execution_agent_id;
    assert_eq!(
        restarted_scheduler.start_ready().unwrap(),
        vec![general_execution.clone()]
    );
    let general_pending = v2.tool("zcode_agent_get", json!({"agent_id":general_agent_id}));
    let permission_id = general_pending["pending_requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|request| request["kind"] == "permission")
        .unwrap()["request_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let responded = v2.tool(
        "zcode_agent_respond",
        json!({
            "agent_id":general_agent_id,
            "request_id":permission_id,
            "decision":"allow",
            "reason":"public composition response"
        }),
    );
    assert_eq!(responded["disposition"], "responded");
    assert_eq!(responded["effective_decision"], "deny");
    assert_eq!(responded["policy_overrode"], true);
    let message = v2.tool(
        "zcode_agent_message",
        json!({
            "agent_id":general_agent_id,
            "message_id":"s05-public-message",
            "mode":"queue",
            "content":"record the bounded public composition"
        }),
    );
    assert_eq!(message["disposition"], "queued");
    let general_job = store.get_job(&general_execution).unwrap().unwrap();
    let general_prepared: PreparedGeneralTask =
        serde_json::from_str(general_job.prepared_launch_json.as_deref().unwrap()).unwrap();
    let general_report = b"# General public composition\n\nverified result chunk\n";
    let general_report_path = general_prepared
        .artifact_targets
        .get(&GeneralArtifactKind::ReportMarkdown)
        .unwrap();
    std::fs::create_dir_all(general_report_path.parent().unwrap()).unwrap();
    std::fs::write(general_report_path, general_report).unwrap();
    let general_sha256 = format!("{:x}", Sha256::digest(general_report));
    restarted_scheduler
        .submit_general_completion(
            &general_execution,
            GeneralCompletionSubmission {
                requested_outcome: CompletionOutcome::Succeeded,
                summary: "public general completion succeeded".into(),
                checks: vec!["public composition".into()],
                residual_gaps: Vec::new(),
                artifact_intents: vec![GeneralArtifactIntent {
                    kind: GeneralArtifactKind::ReportMarkdown,
                    sha256: Some(general_sha256.clone()),
                    size_bytes: Some(general_report.len() as u64),
                }],
            },
        )
        .unwrap();
    factory
        .runtime(&general_execution)
        .finish(completed_runtime_terminal());
    let general_terminal = wait_public_terminal(&mut v2, &general_agent_id, 1);
    assert_eq!(general_terminal["task"]["resources_reaped"], false);
    let general_result = v2.tool("zcode_agent_result", json!({"agent_id":general_agent_id}));
    assert_eq!(general_result["result"]["outcome"], "SUCCEEDED");
    let general_artifact = general_result["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|artifact| artifact["kind"] == "report_markdown")
        .unwrap();
    assert_eq!(general_artifact["sha256"], general_sha256);
    let general_chunk = v2.tool(
        "zcode_agent_result",
        json!({
            "agent_id":general_agent_id,
            "artifact_id":general_artifact["artifact_id"],
            "offset_bytes":0,
            "limit_bytes":general_report.len()
        }),
    );
    assert_eq!(
        BASE64
            .decode(
                general_chunk["artifact_chunk"]["bytes_base64"]
                    .as_str()
                    .unwrap()
            )
            .unwrap(),
        general_report
    );
    assert_eq!(general_chunk["artifact_chunk"]["eof"], true);
    assert_eq!(
        v2.tool("zcode_agent_close", json!({"agent_id":general_agent_id}))["task"]
            ["resources_reaped"],
        true
    );
    assert!(!general_prepared.worktree.path.exists());

    let mut legacy = FacadeProcess::start_mode(&socket, Some("legacy_review_v1"));
    assert!(
        legacy.tool("zcode_review_list", json!({"scope":"all","limit":1}))["jobs"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    for agent_id in [&public_agent_id, &general_agent_id] {
        assert!(legacy
            .tool_error("zcode_review_status", json!({"agent_id":agent_id}))
            .starts_with("not_found:"));
    }
    assert_eq!(
        v2.tool("zcode_agent_get", json!({"agent_id":general_agent_id}))["task"]
            ["resources_reaped"],
        true
    );
    assert_eq!(
        git(&manifest.repository, &["rev-parse", "HEAD"]),
        initial_head
    );
    assert_eq!(
        git(&manifest.repository, &["status", "--porcelain"]),
        initial_status
    );
}

#[test]
fn official_public_v2_configured_readiness_is_truthful_bounded_and_reaped() {
    let Some(runtime_path) = official_runtime_path() else {
        eprintln!("skipped: ZCODE_RUNTIME_PATH is unset");
        return;
    };
    verify_official_runtime(&runtime_path);
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(directory.path().join("readiness.sqlite3")).unwrap());
    let factory_path = runtime_path.clone();
    let runtime_factory: Arc<dyn RuntimeFactory> = Arc::new(CommandRuntimeFactory::new(
        move |_job: &review_store::Job| official_runtime_command(&factory_path),
    ));
    let scheduler = Scheduler::new(
        "s05-official-public-readiness",
        Arc::clone(&store),
        runtime_factory,
        SchedulerConfig {
            global_max_agents: 1,
            per_workspace_max_agents: 1,
            stop_grace: Duration::from_secs(1),
            bootstrap_timeout: Duration::from_secs(5),
            control_timeout: Duration::from_secs(5),
        },
    )
    .unwrap();
    let service = Arc::new(RpcService::new(scheduler, Arc::clone(&store)).unwrap());
    let socket = directory.path().join("rpc/review.sock");
    let _server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
    let mut facade = FacadeProcess::start_mode(&socket, Some("subagent_v2"));
    let started = std::time::Instant::now();
    let readiness = facade.tool("zcode_system_ensure_ready", json!({"timeout_ms":5000}));
    assert_eq!(readiness["status"]["components"]["driver"], "READY");
    assert_eq!(readiness["status"]["components"]["runtime"], "READY");
    if readiness["ready"] == true {
        assert_eq!(readiness["probe_result"], "READY");
        assert_eq!(readiness["reason_code"], Value::Null);
        assert_eq!(readiness["status"]["components"]["model_auth"], "READY");
    } else {
        assert_ne!(readiness["probe_result"], "MODEL_AUTH_FAILED");
        assert_eq!(readiness["reason_code"], readiness["probe_result"]);
    }
    assert!(started.elapsed() < Duration::from_secs(6));
    assert!(store.list_jobs(10).unwrap().is_empty());
}

#[test]
fn official_public_v2_general_permission_completion_and_result_are_bounded() {
    const GENERAL_COMPLETION_TOOL: &str = "mcp__general-completion__zcode_general_complete";
    const MAX_PERMISSION_EVIDENCE: usize = 8;
    let Some(runtime_path) = official_runtime_path() else {
        eprintln!("skipped: ZCODE_RUNTIME_PATH is unset");
        return;
    };
    let Some(daemon_program) = env::var_os("ZCODE_REVIEWD_BIN").map(PathBuf::from) else {
        eprintln!("skipped: ZCODE_REVIEWD_BIN is unset");
        return;
    };
    verify_official_runtime(&runtime_path);
    assert!(daemon_program.is_file());
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(directory.path().join("general.sqlite3")).unwrap());
    let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
    let factory_path = runtime_path.clone();
    let runtime_factory: Arc<dyn RuntimeFactory> = Arc::new(CommandRuntimeFactory::new_prepared(
        move |_job: &review_store::Job| official_runtime_command(&factory_path),
    ));
    let socket = directory.path().join("rpc/review.sock");
    let scheduler = Scheduler::new(
        "s05-official-public-general",
        Arc::clone(&store),
        runtime_factory,
        SchedulerConfig {
            global_max_agents: 1,
            per_workspace_max_agents: 1,
            stop_grace: Duration::from_secs(2),
            bootstrap_timeout: Duration::from_secs(30),
            control_timeout: Duration::from_secs(5),
        },
    )
    .unwrap()
    .with_ledger(
        ledger,
        InternalLedgerMcpConfig {
            command: std::fs::canonicalize(daemon_program).unwrap(),
            socket: socket.clone(),
            runtime_sha256: Some(OFFICIAL_RUNTIME_SHA256.into()),
        },
    )
    .unwrap();
    let service = Arc::new(RpcService::new(scheduler.clone(), Arc::clone(&store)).unwrap());
    let _server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
    let manifest_path = manifest_fixture(directory.path());
    let manifest: ReviewManifest =
        serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap();
    let initial_head = git(&manifest.repository, &["rev-parse", "HEAD"]);
    let initial_status = git(&manifest.repository, &["status", "--porcelain"]);
    let denied_target = directory.path().join("must-not-exist.txt");
    let idempotency_key = "s05-official-public-general";
    let completion = json!({
        "requested_outcome":"SUCCEEDED",
        "summary":"official runtime called the private general completion ingress",
        "checks":["typed permission denied"],
        "residual_gaps":[],
        "artifact_intents":[]
    });
    let prompt = format!(
        "Complete this bounded task in order. First use the Bash tool to try to create {} and wait for permission; it will be denied, so continue without retrying it. Then call the injected zcode_general_complete MCP tool exactly once with these arguments: {}. Do not use any other tool and do not stop after a prose answer; completion is valid only after zcode_general_complete returns accepted.",
        denied_target.display(),
        completion
    );
    let mut facade = FacadeProcess::start_mode(&socket, Some("subagent_v2"));
    let spawned = facade.tool(
        "zcode_agent_spawn",
        json!({
            "repository":manifest.repository,
            "base_ref":manifest.base_ref,
            "profile":"analysis_readonly",
            "prompt":prompt,
            "feature_id":"s05-official-public-general",
            "ownership_token":"s05-official-public-general-owner",
            "idempotency_key":idempotency_key,
            "write_manifest":[],
            "repo_context":["src/lib.rs"],
            "attachments":[],
            "retain_partial":false,
            "budget":{
                "wall_time_ms":120000,
                "max_turns":2,
                "max_tool_calls":6,
                "max_context_bytes":1048576,
                "max_result_bytes":262144,
                "max_artifact_bytes":2097152
            }
        }),
    );
    assert_eq!(spawned["effective_budget"]["max_turns"], 2);
    assert_eq!(spawned["effective_budget"]["max_tool_calls"], 6);
    let agent_id = spawned["agent_id"].as_str().unwrap().to_owned();
    let execution_id = store
        .get_task(&agent_id)
        .unwrap()
        .unwrap()
        .execution_agent_id;
    assert_eq!(scheduler.start_ready().unwrap(), vec![execution_id.clone()]);

    let general_job = store.get_job(&execution_id).unwrap().unwrap();
    let prepared: PreparedGeneralTask =
        serde_json::from_str(general_job.prepared_launch_json.as_deref().unwrap()).unwrap();

    let terminal_deadline = std::time::Instant::now() + Duration::from_secs(150);
    let mut responded = std::collections::HashSet::new();
    let mut denied_bash = false;
    let mut permission_evidence = Vec::new();
    let mut permission_evidence_overflow = false;
    let terminal = loop {
        let status = facade.tool("zcode_agent_get", json!({"agent_id":agent_id}));
        for request in status["pending_requests"].as_array().unwrap() {
            if request["kind"] != "permission" {
                continue;
            }
            let request_id = request["request_id"].as_str().unwrap();
            if !responded.insert(request_id.to_owned()) {
                continue;
            }
            let tool_name = request["tool_name"].as_str().unwrap_or_default();
            let deny = tool_name.eq_ignore_ascii_case("bash");
            let response = facade.tool(
                "zcode_agent_respond",
                json!({
                    "agent_id":agent_id,
                    "request_id":request_id,
                    "decision":if deny { "deny" } else { "allow" },
                    "reason":"bounded official runtime general ingress verification"
                }),
            );
            if permission_evidence.len() < MAX_PERMISSION_EVIDENCE {
                permission_evidence.push(json!({
                    "tool_name":request["tool_name"],
                    "policy_preview":request["policy_preview"],
                    "disposition":response["disposition"],
                    "requested_decision":response["requested_decision"],
                    "effective_decision":response["effective_decision"],
                    "policy_overrode":response["policy_overrode"],
                    "policy_reason_code":response["policy_reason_code"]
                }));
            } else {
                permission_evidence_overflow = true;
            }
            if deny {
                denied_bash |= response["effective_decision"] == "deny";
            }
        }
        if status["task"]["phase"] == "TERMINAL" {
            break status;
        }
        assert!(
            std::time::Instant::now() < terminal_deadline,
            "official general task did not terminalize: {status}"
        );
        thread::sleep(Duration::from_millis(50));
    };
    let result = facade.tool("zcode_agent_result", json!({"agent_id":agent_id}));
    let closed = facade.tool("zcode_agent_close", json!({"agent_id":agent_id}));

    assert!(
        denied_bash,
        "official runtime did not preserve the typed deny path"
    );
    assert!(!denied_target.exists());
    assert_eq!(terminal["task"]["attempt_sequence"], 1);
    assert_eq!(terminal["task"]["effective_budget"]["max_turns"], 2);
    assert_eq!(terminal["task"]["effective_budget"]["max_tool_calls"], 6);
    assert_eq!(
        terminal["result"]["result_sha256"],
        result["result"]["result_sha256"]
    );
    assert_eq!(
        result["result"]["result_sha256"].as_str().unwrap().len(),
        64
    );
    assert_eq!(closed["task"]["resources_reaped"], true);
    assert!(!prepared.worktree.path.exists());
    assert_eq!(
        git(&manifest.repository, &["rev-parse", "HEAD"]),
        initial_head
    );
    assert_eq!(
        git(&manifest.repository, &["status", "--porcelain"]),
        initial_status
    );
    assert!(
        !permission_evidence_overflow,
        "official runtime exceeded the bounded public permission evidence envelope"
    );
    for evidence in &permission_evidence {
        let tool_name = evidence["tool_name"]
            .as_str()
            .expect("public pending tool_name must be bounded text");
        let policy_preview = evidence["policy_preview"]
            .as_str()
            .expect("public pending policy_preview must be bounded text");
        let disposition = evidence["disposition"]
            .as_str()
            .expect("public response disposition must be bounded text");
        let requested_decision = evidence["requested_decision"]
            .as_str()
            .expect("public requested_decision must be bounded text");
        let effective_decision = evidence["effective_decision"]
            .as_str()
            .expect("public effective_decision must be bounded text");
        assert!(tool_name.len() <= 256, "unbounded tool_name: {evidence}");
        assert!(
            matches!(
                policy_preview,
                "externally_decidable" | "hard_deny" | "unknown"
            ),
            "invalid policy_preview: {evidence}"
        );
        assert_eq!(disposition, "responded", "{evidence}");
        assert!(
            matches!(requested_decision, "allow" | "deny"),
            "invalid requested_decision: {evidence}"
        );
        assert!(
            matches!(effective_decision, "allow" | "deny"),
            "invalid effective_decision: {evidence}"
        );
        assert!(
            evidence["policy_overrode"].is_boolean(),
            "invalid policy_overrode: {evidence}"
        );
        assert!(
            evidence["policy_reason_code"]
                .as_str()
                .is_none_or(|reason| reason.len() <= 128),
            "unbounded policy_reason_code: {evidence}"
        );
    }
    let completion_permission = permission_evidence
        .iter()
        .find(|evidence| evidence["tool_name"] == GENERAL_COMPLETION_TOOL)
        .unwrap_or_else(|| {
            panic!(
                "official runtime did not request the injected general completion tool; public_permission_evidence={}",
                serde_json::to_string(&permission_evidence).unwrap()
            )
        });
    assert_eq!(
        completion_permission["requested_decision"], "allow",
        "{completion_permission}"
    );
    if completion_permission["policy_preview"] == "hard_deny" {
        assert_eq!(
            completion_permission["effective_decision"], "deny",
            "{completion_permission}"
        );
        assert_eq!(
            completion_permission["policy_overrode"], true,
            "{completion_permission}"
        );
        assert_eq!(
            completion_permission["policy_reason_code"], "permission_request_unrecognized",
            "{completion_permission}"
        );
        panic!(
            "official runtime requested the injected general completion tool but policy hard-denied it as unrecognized: {completion_permission}"
        );
    }
    assert_eq!(
        completion_permission["policy_preview"], "externally_decidable",
        "{completion_permission}"
    );
    assert_eq!(
        completion_permission["effective_decision"], "allow",
        "{completion_permission}"
    );
    assert_eq!(
        completion_permission["policy_overrode"], false,
        "{completion_permission}"
    );
    assert_eq!(
        completion_permission["policy_reason_code"],
        serde_json::Value::Null,
        "{completion_permission}"
    );
    assert_eq!(
        result["result"]["outcome"], "SUCCEEDED",
        "result={result}; public_permission_evidence={permission_evidence:?}"
    );
    assert_eq!(
        result["result"]["summary"],
        "official runtime called the private general completion ingress"
    );
    assert_eq!(
        result["result"]["checks"],
        json!(["typed permission denied"])
    );
    assert_eq!(result["artifacts"], json!([]));
}

#[test]
fn official_public_v2_structured_fresh_and_continuation_finalize_and_reap() {
    let Some(runtime_path) = official_runtime_path() else {
        eprintln!("skipped: ZCODE_RUNTIME_PATH is unset");
        return;
    };
    let Some(daemon_program) = env::var_os("ZCODE_REVIEWD_BIN").map(PathBuf::from) else {
        eprintln!("skipped: ZCODE_REVIEWD_BIN is unset");
        return;
    };
    verify_official_runtime(&runtime_path);
    assert!(daemon_program.is_file());
    let directory = tempfile::tempdir().unwrap();
    let manifest_path = manifest_fixture(directory.path());
    let manifest: ReviewManifest =
        serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap();
    std::fs::write(
        manifest.repository.join(".git/info/exclude"),
        ".agent-work/\n",
    )
    .unwrap();
    let initial_head = git(&manifest.repository, &["rev-parse", "HEAD"]);
    let initial_status = git(&manifest.repository, &["status", "--porcelain"]);
    let store = Arc::new(Store::open(directory.path().join("structured.sqlite3")).unwrap());
    let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
    let factory_path = runtime_path.clone();
    let runtime_factory: Arc<dyn RuntimeFactory> = Arc::new(CommandRuntimeFactory::new_prepared(
        move |_job: &review_store::Job| official_runtime_command(&factory_path),
    ));
    let socket = directory.path().join("rpc/review.sock");
    let scheduler = Scheduler::new(
        "s05-official-public-structured",
        Arc::clone(&store),
        runtime_factory,
        SchedulerConfig {
            global_max_agents: 1,
            per_workspace_max_agents: 1,
            stop_grace: Duration::from_secs(2),
            bootstrap_timeout: Duration::from_secs(90),
            control_timeout: Duration::from_secs(5),
        },
    )
    .unwrap()
    .with_ledger(
        Arc::clone(&ledger),
        InternalLedgerMcpConfig {
            command: std::fs::canonicalize(daemon_program).unwrap(),
            socket: socket.clone(),
            runtime_sha256: Some(OFFICIAL_RUNTIME_SHA256.into()),
        },
    )
    .unwrap();
    let service = Arc::new(RpcService::new(scheduler.clone(), Arc::clone(&store)).unwrap());
    let _server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
    let mut facade = FacadeProcess::start_mode(&socket, Some("subagent_v2"));
    let fresh = facade.tool(
        "zcode_review_spawn",
        json!({
            "review_kind":"initial_bounded",
            "repository":manifest.repository,
            "base_ref":manifest.base_ref,
            "head_ref":manifest.head_ref,
            "scope_manifest":["src/lib.rs"],
            "requirements_path":".agent-work/PLAN.md",
            "report_path":".agent-work/reviews/official-public-fresh.md",
            "feature_id":"s05-official-public-structured",
            "section_id":"S05",
            "ownership_token":"s05-official-public-structured-owner",
            "idempotency_key":"s05-official-public-structured-fresh",
            "read_only":true,
            "attachments":[],
            "model":"zai/glm-5.3",
            "budget":{
                "wall_time_ms":240000,
                "max_turns":4,
                "max_tool_calls":24,
                "max_context_bytes":1048576,
                "max_result_bytes":262144,
                "max_artifact_bytes":2097152
            }
        }),
    );
    assert_eq!(fresh["counts_as_independent"], false);
    assert_eq!(fresh["effective_budget"]["max_turns"], 4);
    assert_eq!(fresh["effective_budget"]["max_tool_calls"], 24);
    let agent_id = fresh["agent_id"].as_str().unwrap().to_owned();
    let review_id = fresh["review_id"].as_str().unwrap().to_owned();
    let fresh_execution = store
        .get_task(&agent_id)
        .unwrap()
        .unwrap()
        .execution_agent_id;
    assert_eq!(
        scheduler.start_ready().unwrap(),
        vec![fresh_execution.clone()]
    );
    let delivered = facade.tool(
        "zcode_agent_message",
        json!({
            "agent_id":agent_id,
            "message_id":"s05-official-public-structured-finalize",
            "mode":"interrupt_and_continue",
            "content":"Continue the bounded review, call each required ledger tool, record validation, and finalize the report."
        }),
    );
    assert_eq!(delivered["disposition"], "interrupted_then_delivered");
    let fresh_terminal =
        wait_official_public_review(&mut facade, &agent_id, 1, Duration::from_secs(240));
    assert_eq!(fresh_terminal["task"]["counts_as_independent"], true);
    assert_eq!(fresh_terminal["task"]["fresh_session_observed"], true);
    assert_eq!(fresh_terminal["task"]["effective_budget"]["max_turns"], 4);
    assert_eq!(
        fresh_terminal["task"]["effective_budget"]["max_tool_calls"],
        24
    );
    let fresh_snapshot = store.review_snapshot(&fresh_execution).unwrap().unwrap();
    assert!(fresh_snapshot.report.finalized);
    assert!(!fresh_snapshot.checkpoints.is_empty());
    assert!(!fresh_snapshot.validations.is_empty());
    let fresh_prepared: PreparedLaunchSpec = serde_json::from_str(
        store
            .get_job(&fresh_execution)
            .unwrap()
            .unwrap()
            .prepared_launch_json
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert!(!fresh_prepared.worktree.path.exists());

    let continuation = facade.tool(
        "zcode_review_continue",
        json!({
            "agent_id":agent_id,
            "review_id":review_id,
            "base_ref":manifest.base_ref,
            "head_ref":manifest.head_ref,
            "frozen_finding_ids":[],
            "idempotency_key":"s05-official-public-structured-continuation",
            "attachments":[],
            "budget":{
                "wall_time_ms":240000,
                "max_turns":3,
                "max_tool_calls":16,
                "max_context_bytes":1048576,
                "max_result_bytes":262144,
                "max_artifact_bytes":2097152
            }
        }),
    );
    assert_eq!(continuation["agent_id"], agent_id);
    assert_eq!(continuation["review_id"], review_id);
    assert_eq!(continuation["attempt_sequence"], 2);
    assert_eq!(continuation["counts_as_independent"], false);
    assert_eq!(continuation["effective_budget"]["max_turns"], 3);
    assert_eq!(continuation["effective_budget"]["max_tool_calls"], 16);
    let continuation_execution = store
        .get_task(&agent_id)
        .unwrap()
        .unwrap()
        .execution_agent_id;
    assert_ne!(continuation_execution, fresh_execution);
    assert_eq!(
        scheduler.start_ready().unwrap(),
        vec![continuation_execution.clone()]
    );
    let continuation_terminal =
        wait_official_public_review(&mut facade, &agent_id, 2, Duration::from_secs(240));
    assert_eq!(
        continuation_terminal["task"]["counts_as_independent"],
        false
    );
    assert_eq!(
        continuation_terminal["task"]["fresh_session_observed"],
        true
    );
    assert_eq!(
        continuation_terminal["task"]["effective_budget"]["max_turns"],
        3
    );
    assert_eq!(
        continuation_terminal["task"]["effective_budget"]["max_tool_calls"],
        16
    );
    let continuation_snapshot = store
        .review_snapshot(&continuation_execution)
        .unwrap()
        .unwrap();
    assert!(continuation_snapshot.report.finalized);
    assert!(!continuation_snapshot.checkpoints.is_empty());
    assert!(!continuation_snapshot.validations.is_empty());
    let continuation_prepared: PreparedLaunchSpec = serde_json::from_str(
        store
            .get_job(&continuation_execution)
            .unwrap()
            .unwrap()
            .prepared_launch_json
            .as_deref()
            .unwrap(),
    )
    .unwrap();
    assert!(!continuation_prepared.worktree.path.exists());

    store.reap_job(&fresh_execution).unwrap();
    for attempt_sequence in [1_u64, 2] {
        let result = facade.tool(
            "zcode_agent_result",
            json!({"agent_id":agent_id,"attempt_sequence":attempt_sequence}),
        );
        assert_eq!(result["result"]["outcome"], "SUCCEEDED", "{result}");
        assert_eq!(result["task"]["attempt_sequence"], attempt_sequence);
        if attempt_sequence == 1 {
            assert_eq!(result["task"]["resources_reaped"], true);
        }
        let artifact = result["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|artifact| artifact["kind"] == "report_markdown")
            .unwrap();
        let chunk = facade.tool(
            "zcode_agent_result",
            json!({
                "agent_id":agent_id,
                "attempt_sequence":attempt_sequence,
                "artifact_id":artifact["artifact_id"],
                "offset_bytes":0,
                "limit_bytes":artifact["size_bytes"]
            }),
        );
        let bytes = BASE64
            .decode(chunk["artifact_chunk"]["bytes_base64"].as_str().unwrap())
            .unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&bytes)), artifact["sha256"]);
        assert!(String::from_utf8(bytes)
            .unwrap()
            .contains("FINALIZED: true"));
    }
    let closed = facade.tool("zcode_agent_close", json!({"agent_id":agent_id}));
    assert_eq!(closed["task"]["resources_reaped"], true);
    assert_eq!(
        git(&manifest.repository, &["rev-parse", "HEAD"]),
        initial_head
    );
    assert_eq!(
        git(&manifest.repository, &["status", "--porcelain"]),
        initial_status
    );
}

#[test]
fn concurrent_v2_facades_use_canonical_identity_and_authoritative_disposition() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
    let runtime_factory: Arc<dyn RuntimeFactory> = Arc::new(PublicFakeFactory {
        bootstrap_entered: Arc::new(Barrier::new(2)),
        bootstrap_release: Arc::new(Barrier::new(2)),
        runtimes: Mutex::new(HashMap::new()),
        emit_unsupported: true,
    });
    let scheduler = Scheduler::new(
        "s05-v2-canonical",
        Arc::clone(&store),
        runtime_factory,
        SchedulerConfig::default(),
    )
    .unwrap();
    let service = Arc::new(RpcService::new(scheduler, Arc::clone(&store)).unwrap());
    let socket = directory.path().join("rpc/review.sock");
    let _server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
    let manifest_path = manifest_fixture(directory.path());
    let manifest: ReviewManifest =
        serde_json::from_slice(&std::fs::read(manifest_path).unwrap()).unwrap();
    let alias = directory.path().join("repository-alias");
    std::os::unix::fs::symlink(&manifest.repository, &alias).unwrap();
    let input_for = |repository: &Path| {
        json!({
            "repository":repository,
            "base_ref":manifest.base_ref,
            "profile":"analysis_readonly",
            "prompt":"inspect the repository without modifying it",
            "feature_id":"s05-v2-canonical",
            "ownership_token":"s05-v2-owner",
            "idempotency_key":"s05-v2-canonical-replay",
            "write_manifest":[],
            "repo_context":["src/lib.rs"],
            "attachments":[],
            "retain_partial":false
        })
    };
    let barrier = Arc::new(Barrier::new(3));
    let responses = thread::scope(|scope| {
        let mut workers = Vec::new();
        for repository in [&manifest.repository, &alias] {
            let socket = socket.clone();
            let barrier = Arc::clone(&barrier);
            let input = input_for(repository);
            workers.push(scope.spawn(move || {
                let mut facade = FacadeProcess::start_mode(&socket, Some("subagent_v2"));
                barrier.wait();
                facade.tool("zcode_agent_spawn", input)
            }));
        }
        barrier.wait();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(responses[0]["agent_id"], responses[1]["agent_id"]);
    let mut dispositions = responses
        .iter()
        .map(|response| response["submission_disposition"].as_str().unwrap())
        .collect::<Vec<_>>();
    dispositions.sort_unstable();
    assert_eq!(dispositions, ["created", "existing"]);

    let mut replay = FacadeProcess::start_mode(&socket, Some("subagent_v2"));
    let replayed = replay.tool("zcode_agent_spawn", input_for(&alias));
    assert_eq!(replayed["agent_id"], responses[0]["agent_id"]);
    assert_eq!(replayed["submission_disposition"], "existing");
    let listed = replay.tool(
        "zcode_agent_list",
        json!({
            "repository":alias,
            "phase":"QUEUED",
            "profile":"analysis_readonly",
            "limit":1
        }),
    );
    assert_eq!(listed["tasks"].as_array().unwrap().len(), 1);
    assert_eq!(listed["tasks"][0]["agent_id"], responses[0]["agent_id"]);
    assert!(listed["next_cursor"].is_null());
    let terminal_only = replay.tool(
        "zcode_agent_list",
        json!({
            "repository":alias,
            "outcome":"SUCCEEDED",
            "limit":1
        }),
    );
    assert!(terminal_only["tasks"].as_array().unwrap().is_empty());
    assert!(terminal_only["next_cursor"].is_null());
    assert_eq!(store.list_jobs(10).unwrap().len(), 1);
}

#[test]
fn public_stdio_submit_returns_before_claim_and_survives_facade_restart() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("review.sqlite3");
    let store = Arc::new(Store::open(&database).unwrap());
    let bootstrap_entered = Arc::new(Barrier::new(2));
    let bootstrap_release = Arc::new(Barrier::new(2));
    let runtime_factory: Arc<dyn RuntimeFactory> = Arc::new(PublicFakeFactory {
        bootstrap_entered: Arc::clone(&bootstrap_entered),
        bootstrap_release: Arc::clone(&bootstrap_release),
        runtimes: Mutex::new(HashMap::new()),
        emit_unsupported: true,
    });
    let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
    let scheduler = Scheduler::new(
        "s07-process",
        Arc::clone(&store),
        runtime_factory,
        SchedulerConfig::default(),
    )
    .unwrap()
    .with_ledger(
        Arc::clone(&ledger),
        InternalLedgerMcpConfig {
            command: PathBuf::from("/usr/bin/false"),
            socket: directory.path().join("internal-ledger.sock"),
            runtime_sha256: None,
        },
    )
    .unwrap();
    let service = Arc::new(RpcService::new(scheduler.clone(), Arc::clone(&store)).unwrap());
    let socket = directory.path().join("rpc/review.sock");
    let _server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
    let manifest = manifest_fixture(directory.path());
    let claim_loop = {
        let scheduler = scheduler.clone();
        std::thread::spawn(move || loop {
            let started = scheduler.start_ready().unwrap();
            if !started.is_empty() {
                return started;
            }
            std::thread::sleep(Duration::from_millis(1));
        })
    };

    let mut first = FacadeProcess::start(&socket);
    assert_eq!(
        first.tool_error(
            "zcode_review_events",
            json!({"agent_id":"missing","after_sequence":0,"limit":0}),
        ),
        "validation: limit must be between 1 and 100"
    );
    assert_eq!(
        first.tool_error("zcode_review_status", json!({"agent_id":"missing"})),
        "not_found: review job was not found"
    );
    let spawned = first.tool("zcode_review_spawn", json!({"manifest_path":manifest}));
    let agent_id = spawned["agent_id"].as_str().unwrap().to_owned();
    assert_eq!(spawned["submission_disposition"], "created");
    assert!(matches!(
        spawned["state"].as_str(),
        Some("QUEUED" | "STARTING")
    ));
    bootstrap_entered.wait();
    assert_eq!(
        store.get_job(&agent_id).unwrap().unwrap().state,
        review_store::JobState::Starting
    );
    assert_eq!(
        scheduler.active_count(),
        0,
        "bootstrap must not register a ready runtime before release"
    );
    let replay = first.tool("zcode_review_spawn", json!({"manifest_path":manifest}));
    assert_eq!(replay["agent_id"], agent_id);
    assert_eq!(replay["submission_disposition"], "existing_compatible");
    drop(first);

    let mut restarted = FacadeProcess::start(&socket);
    let status = restarted.tool("zcode_review_status", json!({"agent_id":agent_id}));
    assert_eq!(status["job"]["state"], "STARTING");
    assert!(serde_json::to_string(&status)
        .unwrap()
        .find(directory.path().to_string_lossy().as_ref())
        .is_none());
    bootstrap_release.wait();
    assert_eq!(claim_loop.join().unwrap(), vec![agent_id.clone()]);
    let queued = restarted.tool(
        "zcode_review_message",
        json!({
            "agent_id":agent_id, "message_id":"public-message", "mode":"queue", "content":"next"
        }),
    );
    assert_eq!(queued["disposition"], "queued");
    let duplicate = restarted.tool(
        "zcode_review_message",
        json!({
            "agent_id":agent_id, "message_id":"public-message", "mode":"queue", "content":"next"
        }),
    );
    assert_eq!(duplicate["disposition"], "queued");
    let conflict = restarted.request("tools/call", json!({"name":"zcode_review_message","arguments":{
        "agent_id":agent_id, "message_id":"public-message", "mode":"queue", "content":"different"
    }}));
    assert_eq!(conflict["result"]["isError"], true);
    assert!(!conflict
        .to_string()
        .contains(directory.path().to_string_lossy().as_ref()));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let pending = loop {
        let pending = store.pending_requests(&agent_id).unwrap();
        if pending.len() == 2 {
            break pending;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "public runtime did not expose requests"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    let permission_id = pending
        .iter()
        .find(|request| request.request_type == "permission")
        .unwrap()
        .request_id
        .clone();
    let responded = restarted.tool("zcode_review_respond", json!({
        "agent_id":agent_id,"request_id":permission_id,"decision":"allow","reason":"external allow"
    }));
    assert_eq!(responded["disposition"], "responded");
    assert_eq!(responded["requested_decision"], "allow");
    assert_eq!(responded["effective_decision"], "deny");
    assert_eq!(responded["policy_overrode"], true);
    assert_eq!(responded["policy_reason_code"], "git_ref_mutation_denied");
    let responded_again = restarted.tool("zcode_review_respond", json!({
        "agent_id":agent_id,"request_id":permission_id,"decision":"allow","reason":"external allow"
    }));
    assert_eq!(responded_again["disposition"], "already_responded");
    assert_eq!(responded_again["effective_decision"], "deny");

    let events = restarted.tool(
        "zcode_review_events",
        json!({"agent_id":agent_id,"after_sequence":0,"limit":100}),
    );
    let event_rows = events["events"].as_array().unwrap();
    assert!(!event_rows.is_empty());
    assert!(event_rows
        .windows(2)
        .all(|pair| pair[0]["sequence"].as_u64() < pair[1]["sequence"].as_u64()));
    assert!(event_rows.iter().all(|event| matches!(
        event["redaction_level"].as_str(),
        Some("allowlisted" | "redacted")
    )));

    let pending = restarted.tool("zcode_review_status", json!({"agent_id":agent_id}));
    let request = pending["pending_requests"]
        .as_array()
        .unwrap()
        .iter()
        .find(|request| request["kind"] == "unsupported_input")
        .unwrap();
    assert_eq!(request["kind"], "unsupported_input");
    assert_eq!(request["respondable"], false);
    let serialized = pending.to_string();
    for forbidden in [
        "input-wire",
        "private unsupported payload",
        "workspace_path",
        "runtime_agent_id",
        "process_group_id",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "public projection leaked {forbidden}"
        );
    }

    let after_sequence = pending["job"]["last_event_sequence"].as_u64().unwrap();
    let waited = restarted.tool(
        "zcode_review_wait",
        json!({"agent_id":agent_id,"after_sequence":after_sequence,"timeout_ms":10}),
    );
    assert_eq!(waited["timed_out"], true);
    let result = restarted.tool(
        "zcode_review_result",
        json!({"agent_id":agent_id,"preview_bytes":4096}),
    );
    assert_eq!(result["report"]["finalized"], false);
    assert_eq!(result["report"]["integrity"], "valid");
    assert_eq!(
        result["report"]["expected_sha256"],
        result["report"]["observed_sha256"]
    );
    ledger
        .call_tool(
            &agent_id,
            REVIEW_CHECKPOINT,
            json!({
                "checkpoint_id":"public-cp","stage":"inspection","summary":"public flow observed",
                "inspected":[{"path":"src/lib.rs","line_ranges":["1"]}],"commands":[],
                "open_questions":[],"remaining_scope":[]
            }),
        )
        .unwrap();
    ledger.call_tool(&agent_id, REVIEW_VALIDATION_RECORD, json!({
        "validation_id":"public-validation","command":"cargo test","cwd":"/prepared/worktree",
        "exit_code":0,"duration_ms":1,"stdout_summary":"passed","stderr_summary":"","related_findings":[]
    })).unwrap();
    ledger.call_tool(&agent_id, REVIEW_FINALIZE, json!({
        "signal":"no_findings_observed","summary":"public fixture finalized",
        "coverage":{"covered":["public facade"],"not_covered":[]},"uncertainties":[],"recommended_next_actions":[]
    })).unwrap();
    let finalized = restarted.tool(
        "zcode_review_result",
        json!({"agent_id":agent_id,"preview_bytes":4096}),
    );
    assert_eq!(finalized["report"]["finalized"], true);
    assert_eq!(finalized["report"]["integrity"], "valid");
    assert_eq!(
        finalized["report"]["expected_sha256"],
        finalized["report"]["observed_sha256"]
    );
    let stopped = restarted.tool("zcode_review_stop", json!({"agent_id":agent_id}));
    assert_eq!(stopped["state"], "CANCELLED");
    assert_eq!(stopped["resources_reaped"], false);
    let closed = restarted.tool("zcode_review_close", json!({"agent_id":agent_id}));
    assert_eq!(closed["state"], "CANCELLED");
    assert_eq!(closed["resources_reaped"], true);
    let closed_again = restarted.tool("zcode_review_close", json!({"agent_id":agent_id}));
    assert_eq!(closed_again["resources_reaped"], true);
}
