use review_ledger::{LedgerManager, REVIEW_CHECKPOINT, REVIEW_FINALIZE, REVIEW_VALIDATION_RECORD};
use review_preparation::{NetworkPolicy, ReviewKind, ReviewManifest, RoundKind, ScratchPolicy};
use review_store::Store;
use serde_json::{json, Value};
use std::{
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use zcode_driver::{ChildExit, Inbound, ProcessIdentity, StopOutcome};
use zcode_protocol::{RequestEnvelope, WireId, WireMessage};
use zcode_reviewd::rpc::{RpcServer, RpcService, ServerOptions};
use zcode_reviewd::{
    InternalLedgerMcpConfig, LifecycleRecord, LifecycleSink, ManagedRuntime, RuntimeCommandError,
    RuntimeEvent, RuntimeFactory, RuntimeTerminal, Scheduler, SchedulerConfig, SessionReady,
    TurnBoundary, TurnSnapshot,
};

fn discover(protocol_version: &str) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zcode-review-mcp"))
        .env(
            "ZCODE_REVIEWD_SOCKET",
            "/tmp/zcode-review-mcp-test-unused.sock",
        )
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
        let mut child = Command::new(env!("CARGO_BIN_EXE_zcode-review-mcp"))
            .env("ZCODE_REVIEWD_SOCKET", socket)
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
        assert!(response.get("error").is_none(), "{response}");
        let structured = response["result"]["structuredContent"].clone();
        assert!(
            !structured.is_null(),
            "missing structured content: {response}"
        );
        structured
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
}

impl PublicFakeRuntime {
    fn emit(&self, event: RuntimeEvent) {
        self.sink.emit(LifecycleRecord {
            sequence: self.sequence.fetch_add(1, Ordering::AcqRel),
            event,
        });
    }
}

impl ManagedRuntime for PublicFakeRuntime {
    fn identity(&self) -> Option<ProcessIdentity> {
        None
    }
    fn stop(&self, _grace: Duration) -> RuntimeTerminal {
        let terminal =
            RuntimeTerminal::Stopped(StopOutcome::AlreadyExited(ChildExit::Exited(Some(0))));
        *self.terminal.lock().unwrap() = Some(terminal.clone());
        self.emit(RuntimeEvent::Terminal(terminal.clone()));
        terminal
    }
    fn wait_terminal(&self, _timeout: Duration) -> Option<RuntimeTerminal> {
        self.terminal.lock().unwrap().clone()
    }
    fn bootstrap_session(
        &self,
        job: &review_store::Job,
        _timeout: Duration,
    ) -> Result<SessionReady, RuntimeCommandError> {
        *self.turn.lock().unwrap() = TurnSnapshot {
            generation: 1,
            active: true,
            boundary: None,
        };
        self.emit(RuntimeEvent::Driver(Inbound::Message(
            WireMessage::Request(RequestEnvelope::new(
                WireId::String("permission-wire".into()),
                "interaction/requestPermission",
                json!({"toolCallId":"tool-1","toolName":"git_ref_mutation","input":{}}),
            )),
        )));
        self.emit(RuntimeEvent::Driver(Inbound::Message(
            WireMessage::Request(RequestEnvelope::new(
                WireId::String("input-wire".into()),
                "interaction/requestUserInput",
                json!({"question":"private unsupported payload"}),
            )),
        )));
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
    ) -> Result<(), RuntimeCommandError> {
        Ok(())
    }
    fn turn_snapshot(&self) -> TurnSnapshot {
        self.turn.lock().unwrap().clone()
    }
}

struct PublicFakeFactory;
impl RuntimeFactory for PublicFakeFactory {
    fn spawn(
        &self,
        _job: &review_store::Job,
        sink: Arc<dyn LifecycleSink>,
    ) -> std::io::Result<Arc<dyn ManagedRuntime>> {
        Ok(Arc::new(PublicFakeRuntime {
            sink,
            sequence: AtomicU64::new(1),
            terminal: Mutex::new(None),
            turn: Mutex::new(TurnSnapshot {
                generation: 0,
                active: false,
                boundary: None,
            }),
        }))
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
fn public_stdio_submit_returns_before_claim_and_survives_facade_restart() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("review.sqlite3");
    let store = Arc::new(Store::open(&database).unwrap());
    let runtime_factory: Arc<dyn RuntimeFactory> = Arc::new(PublicFakeFactory);
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

    let mut first = FacadeProcess::start(&socket);
    let spawned = first.tool("zcode_review_spawn", json!({"manifest_path":manifest}));
    let agent_id = spawned["agent_id"].as_str().unwrap().to_owned();
    assert_eq!(spawned["submission_disposition"], "created");
    assert_eq!(spawned["state"], "QUEUED");
    assert_eq!(
        scheduler.active_count(),
        0,
        "public spawn must not enter runtime bootstrap"
    );
    let replay = first.tool("zcode_review_spawn", json!({"manifest_path":manifest}));
    assert_eq!(replay["agent_id"], agent_id);
    assert_eq!(replay["submission_disposition"], "existing_compatible");
    drop(first);

    let mut restarted = FacadeProcess::start(&socket);
    let status = restarted.tool("zcode_review_status", json!({"agent_id":agent_id}));
    assert_eq!(status["job"]["state"], "QUEUED");
    assert!(serde_json::to_string(&status)
        .unwrap()
        .find(directory.path().to_string_lossy().as_ref())
        .is_none());
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
    assert_eq!(scheduler.start_ready().unwrap(), vec![agent_id.clone()]);
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
