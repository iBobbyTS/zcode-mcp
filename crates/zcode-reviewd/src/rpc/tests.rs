use super::*;
use crate::{
    CommandRuntimeFactory, LifecycleRecord, LifecycleSink, ManagedRuntime, RuntimeCommandError,
    RuntimeEvent, RuntimeFactory, RuntimeOwner, RuntimeTerminal, SchedulerConfig, SessionReady,
    TurnBoundary, TurnSnapshot,
};
use review_store::{Job, LifecycleWrite, MessageState, NewArtifact, PendingRequestState};
use std::{
    collections::HashMap,
    io::{self, Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Barrier, Condvar, Mutex,
    },
};
use zcode_driver::{observe_process_group, ChildExit, Inbound, ProcessIdentity, StopOutcome};

struct FakeRuntime {
    sink: Arc<dyn LifecycleSink>,
    next_sequence: AtomicU64,
    terminal: Mutex<Option<RuntimeTerminal>>,
    changed: Condvar,
    turn: Mutex<TurnSnapshot>,
}

impl FakeRuntime {
    fn new(sink: Arc<dyn LifecycleSink>) -> Self {
        Self {
            sink,
            next_sequence: AtomicU64::new(1),
            terminal: Mutex::new(None),
            changed: Condvar::new(),
            turn: Mutex::new(TurnSnapshot {
                generation: 0,
                active: false,
                boundary: None,
            }),
        }
    }

    fn emit(&self, event: RuntimeEvent) {
        let sequence = self.next_sequence.fetch_add(1, Ordering::AcqRel);
        self.sink.emit(LifecycleRecord { sequence, event });
    }

    fn finish(&self) -> RuntimeTerminal {
        let mut terminal = self.terminal.lock().unwrap();
        if let Some(terminal) = terminal.as_ref() {
            return terminal.clone();
        }
        let outcome =
            RuntimeTerminal::Stopped(StopOutcome::AlreadyExited(ChildExit::Exited(Some(0))));
        self.emit(RuntimeEvent::Terminal(outcome.clone()));
        *terminal = Some(outcome.clone());
        self.changed.notify_all();
        outcome
    }
}

impl ManagedRuntime for FakeRuntime {
    fn identity(&self) -> Option<ProcessIdentity> {
        None
    }

    fn stop(&self, _grace: Duration) -> RuntimeTerminal {
        self.finish()
    }

    fn wait_terminal(&self, timeout: Duration) -> Option<RuntimeTerminal> {
        let terminal = self.terminal.lock().unwrap();
        if terminal.is_some() {
            return terminal.clone();
        }
        self.changed
            .wait_timeout(terminal, timeout)
            .unwrap()
            .0
            .clone()
    }

    fn bootstrap_session(
        &self,
        job: &Job,
        _timeout: Duration,
    ) -> Result<SessionReady, RuntimeCommandError> {
        *self.turn.lock().unwrap() = TurnSnapshot {
            generation: 1,
            active: true,
            boundary: None,
        };
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
        let mut turn = self.turn.lock().unwrap();
        turn.generation = turn.generation.saturating_add(1);
        turn.active = true;
        turn.boundary = None;
        Ok(Some(format!("turn-{}", turn.generation)))
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

#[derive(Default)]
struct FakeFactory {
    runtimes: Mutex<HashMap<String, Arc<FakeRuntime>>>,
    fail_for: Mutex<Vec<String>>,
}

impl FakeFactory {
    fn fail(&self, agent_id: &str) {
        self.fail_for.lock().unwrap().push(agent_id.into());
    }

    fn runtime(&self, agent_id: &str) -> Arc<FakeRuntime> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(runtime) = self.runtimes.lock().unwrap().get(agent_id).cloned() {
                return runtime;
            }
            assert!(Instant::now() < deadline, "runtime was not spawned");
            thread::sleep(Duration::from_millis(5));
        }
    }
}

impl RuntimeFactory for FakeFactory {
    fn spawn(
        &self,
        job: &Job,
        sink: Arc<dyn LifecycleSink>,
    ) -> io::Result<Arc<dyn ManagedRuntime>> {
        if self
            .fail_for
            .lock()
            .unwrap()
            .iter()
            .any(|agent_id| agent_id == &job.agent_id)
        {
            return Err(io::Error::other("scripted runtime failure"));
        }
        let runtime = Arc::new(FakeRuntime::new(sink));
        runtime.emit(RuntimeEvent::Driver(Inbound::Malformed(
            "sensitive runtime text".into(),
        )));
        self.runtimes
            .lock()
            .unwrap()
            .insert(job.agent_id.clone(), Arc::clone(&runtime));
        Ok(runtime)
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    database: PathBuf,
    socket: PathBuf,
    store: Arc<Store>,
    factory: Arc<FakeFactory>,
    service: Arc<RpcService>,
    server: RpcServer,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("review.sqlite3");
    let socket = directory.path().join("rpc").join("review.sock");
    let store = Arc::new(Store::open(&database).unwrap());
    let factory = Arc::new(FakeFactory::default());
    let runtime_factory: Arc<dyn RuntimeFactory> = factory.clone();
    let scheduler = Scheduler::new(
        "rpc-test",
        Arc::clone(&store),
        runtime_factory,
        SchedulerConfig {
            global_max_agents: 4,
            per_workspace_max_agents: 4,
            stop_grace: Duration::from_millis(100),
            command_timeout: Duration::from_secs(1),
        },
    )
    .unwrap();
    let service = Arc::new(RpcService::new(scheduler.clone(), Arc::clone(&store)).unwrap());
    let server = RpcServer::bind(&socket, Arc::clone(&service), ServerOptions::default()).unwrap();
    Fixture {
        _directory: directory,
        database,
        socket,
        store,
        factory,
        service,
        server,
    }
}

fn request(request_id: &str, method: RpcMethod) -> RpcRequest {
    RpcRequest {
        version: RPC_VERSION,
        request_id: request_id.into(),
        method,
    }
}

#[test]
fn private_report_result_keeps_expected_and_observed_integrity_distinct() {
    let view = verified_artifact_view(
        VerifiedArtifact {
            integrity: ArtifactIntegrity::Missing,
            locator: "/prepared/report.md".into(),
            expected_sha256: Some("a".repeat(64)),
            expected_bytes: Some(128),
            actual_sha256: None,
            actual_bytes: None,
            checkpoint_number: 3,
            finalized: false,
            preview: None,
        },
        64,
    );
    assert_eq!(view.integrity, ArtifactIntegrityView::Missing);
    assert_eq!(view.expected_sha256, Some("a".repeat(64)));
    assert_eq!(view.expected_bytes, Some(128));
    assert_eq!(view.observed_sha256, None);
    assert_eq!(view.observed_bytes, None);

    let schema: Value = serde_json::from_str(include_str!(
        "../../../../schemas/review-report.schema.json"
    ))
    .unwrap();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    let mut at_max = serde_json::to_value(view).unwrap();
    at_max["expected_bytes"] = serde_json::json!(u64::MAX);
    at_max["observed_bytes"] = serde_json::json!(u64::MAX);
    at_max["checkpoint_number"] = serde_json::json!(u64::MAX);
    assert!(validator.is_valid(&at_max));
    for field in ["expected_bytes", "observed_bytes", "checkpoint_number"] {
        let mut over_max = at_max.clone();
        over_max[field] = serde_json::from_str("18446744073709551616").unwrap();
        assert!(!validator.is_valid(&over_max), "over-u64 {field}");
    }
}

fn client(path: &Path) -> RpcClient {
    RpcClient::new(path, Duration::from_secs(3))
}

fn success(response: RpcResponse) -> RpcSuccess {
    match response.outcome {
        RpcOutcome::Success { result } => *result,
        RpcOutcome::Error { error } => panic!("unexpected RPC error: {error:?}"),
    }
}

fn error(response: RpcResponse) -> RpcError {
    match response.outcome {
        RpcOutcome::Error { error } => error,
        RpcOutcome::Success { result } => panic!("unexpected RPC success: {result:?}"),
    }
}

fn enqueue_request(agent_id: &str, key: &str) -> RpcMethod {
    RpcMethod::Enqueue {
        job: NewJobInput {
            agent_id: agent_id.into(),
            workspace_path: "/workspace".into(),
            idempotency_key: Some(key.into()),
            parent_agent_id: None,
            review_kind: Some("code".into()),
            feature_id: Some("feature".into()),
            section_id: Some("S02".into()),
            round_kind: Some("INITIAL_BOUNDED".into()),
            report_path: None,
            runtime_hash: Some("runtime-hash".into()),
            initial_prompt: "Begin review.".into(),
        },
    }
}

fn raw_call(path: &Path, frame: &[u8]) -> RpcResponse {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    if let Err(error) = stream.write_all(frame) {
        assert!(matches!(
            error.kind(),
            io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
        ));
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    serde_json::from_slice(&response).unwrap()
}

#[test]
fn typed_protocol_round_trips_every_method_and_outer_error() {
    let methods = vec![
        RpcMethod::SpawnReview {
            manifest: ReviewManifest {
                schema: "sectioned-zcode-review/v1".into(),
                review_kind: review_preparation::ReviewKind::Code,
                feature_id: "feature".into(),
                section_id: "S06".into(),
                round_kind: review_preparation::RoundKind::InitialBounded,
                repository: "/repository".into(),
                base_ref: "a".repeat(40),
                head_ref: "b".repeat(40),
                plan_path: ".agent-work/PLAN.md".into(),
                context_paths: vec![],
                scope_paths: vec!["src".into()],
                forbidden_input_globs: vec![".agent-work/reviews/*".into()],
                validation_commands: Default::default(),
                report_target: ".agent-work/reviews/report.md".into(),
                scratch_root: ".agent-work/scratch/jobs".into(),
                model: None,
                fresh_session: true,
                network_policy: review_preparation::NetworkPolicy::Deny,
                scratch_policy: review_preparation::ScratchPolicy::Isolated,
                idempotency_key: "feature:S06:initial".into(),
            },
        },
        enqueue_request("job-1", "key-1"),
        RpcMethod::Start,
        RpcMethod::Status {
            agent_id: "job-1".into(),
        },
        RpcMethod::Events(EventQuery {
            agent_id: "job-1".into(),
            runtime_agent_id: Some("runtime-1".into()),
            after: 4,
            limit: 10,
        }),
        RpcMethod::Wait(WaitQuery {
            agent_id: "job-1".into(),
            runtime_agent_id: None,
            after: 4,
            timeout_ms: 50,
        }),
        RpcMethod::Message(MessageInput {
            agent_id: "job-1".into(),
            message_id: "msg-1".into(),
            mode: "queue".into(),
            content: "continue".into(),
        }),
        RpcMethod::Respond(RespondInput {
            agent_id: "job-1".into(),
            request_id: "permission-1".into(),
            decision: ResponseDecision::Allow,
            content: None,
        }),
        RpcMethod::Stop {
            agent_id: "job-1".into(),
        },
        RpcMethod::Result(ResultQuery {
            agent_id: "job-1".into(),
            preview_bytes: 64,
        }),
        RpcMethod::List {
            scope: JobListScopeView::Recent,
            limit: 10,
        },
        RpcMethod::Close {
            agent_id: "job-1".into(),
        },
        RpcMethod::Reap {
            agent_id: "job-1".into(),
        },
        RpcMethod::ReviewTool(ReviewToolInput {
            agent_id: "job-1".into(),
            tool: "review_checkpoint".into(),
            arguments: serde_json::json!({"checkpoint_id":"cp-1"}),
        }),
    ];
    for (index, method) in methods.into_iter().enumerate() {
        let request = request(&format!("request-{index}"), method);
        let encoded = serde_json::to_vec(&request).unwrap();
        assert_eq!(
            serde_json::from_slice::<RpcRequest>(&encoded).unwrap(),
            request
        );
    }

    for code in [
        RpcErrorCode::Malformed,
        RpcErrorCode::Oversized,
        RpcErrorCode::UnsupportedVersion,
        RpcErrorCode::UnknownMethod,
        RpcErrorCode::Validation,
        RpcErrorCode::NotFound,
        RpcErrorCode::Conflict,
        RpcErrorCode::Persistence,
        RpcErrorCode::Timeout,
        RpcErrorCode::RuntimeLost,
        RpcErrorCode::Unavailable,
        RpcErrorCode::Internal,
    ] {
        let response = RpcResponse::error(Some("request".into()), RpcError::new(code, "error"));
        let encoded = serde_json::to_vec(&response).unwrap();
        assert_eq!(
            serde_json::from_slice::<RpcResponse>(&encoded).unwrap(),
            response
        );
    }
}

#[test]
fn transport_reports_malformed_oversized_version_method_validation_and_not_found() {
    let fixture = fixture();
    assert_eq!(
        error(raw_call(&fixture.socket, b"{]\n")).code,
        RpcErrorCode::Malformed
    );
    let unsupported = raw_call(
        &fixture.socket,
        b"{\"version\":3,\"request_id\":\"v\",\"method\":\"status\",\"params\":{\"agent_id\":\"job\"}}\n",
    );
    assert_eq!(unsupported.request_id.as_deref(), Some("v"));
    assert_eq!(error(unsupported).code, RpcErrorCode::UnsupportedVersion);
    assert_eq!(
        error(raw_call(
            &fixture.socket,
            b"{\"version\":5,\"request_id\":\"m\",\"method\":\"missing\"}\n"
        ))
        .code,
        RpcErrorCode::UnknownMethod
    );
    assert_eq!(
        error(
            client(&fixture.socket)
                .call(&request(
                    "missing",
                    RpcMethod::Status {
                        agent_id: "none".into()
                    }
                ))
                .unwrap()
        )
        .code,
        RpcErrorCode::NotFound
    );
    assert_eq!(
        error(
            client(&fixture.socket)
                .call(&request(
                    "invalid",
                    RpcMethod::List {
                        scope: JobListScopeView::Recent,
                        limit: 0
                    }
                ))
                .unwrap()
        )
        .code,
        RpcErrorCode::Validation
    );
    let mut oversized = vec![b' '; MAX_FRAME_BYTES + 1];
    oversized.push(b'\n');
    assert_eq!(
        error(raw_call(&fixture.socket, &oversized)).code,
        RpcErrorCode::Oversized
    );

    let near_cap_id = "r".repeat(MAX_FRAME_BYTES - 128);
    let response = client(&fixture.socket)
        .call(&RpcRequest {
            version: RPC_VERSION,
            request_id: near_cap_id,
            method: RpcMethod::Start,
        })
        .unwrap();
    assert_eq!(response.request_id, None);
    assert_eq!(error(response).code, RpcErrorCode::Validation);
}

#[test]
fn rpc_service_rejects_a_store_outside_the_scheduler_owner() {
    let directory = tempfile::tempdir().unwrap();
    let scheduler_store =
        Arc::new(Store::open(directory.path().join("scheduler.sqlite3")).unwrap());
    let other_store = Arc::new(Store::open(directory.path().join("other.sqlite3")).unwrap());
    let factory: Arc<dyn RuntimeFactory> = Arc::new(FakeFactory::default());
    let scheduler = Scheduler::new(
        "rpc-owner",
        scheduler_store,
        factory,
        SchedulerConfig::default(),
    )
    .unwrap();
    assert!(matches!(
        RpcService::new(scheduler, other_store),
        Err(RpcServiceConfigError::MismatchedStore)
    ));
}

#[test]
fn transport_maps_conflict_runtime_loss_and_payload_caps() {
    let fixture = fixture();
    let rpc = client(&fixture.socket);
    success(
        rpc.call(&request("enqueue-1", enqueue_request("job-1", "key-1")))
            .unwrap(),
    );
    assert_eq!(
        error(
            rpc.call(&request(
                "enqueue-conflict",
                enqueue_request("job-1", "key-2"),
            ))
            .unwrap(),
        )
        .code,
        RpcErrorCode::Conflict
    );
    fixture.factory.fail("job-fail");
    success(
        rpc.call(&request(
            "enqueue-fail",
            enqueue_request("job-fail", "key-fail"),
        ))
        .unwrap(),
    );
    assert_eq!(
        error(rpc.call(&request("start", RpcMethod::Start)).unwrap()).code,
        RpcErrorCode::RuntimeLost
    );
    assert!(matches!(
        success(
            rpc.call(&request(
                "failed-status",
                RpcMethod::Status {
                    agent_id: "job-fail".into(),
                },
            ))
            .unwrap(),
        ),
        RpcSuccess::Status { ref job }
            if job.failure_message.as_deref() == Some("[REDACTED]")
    ));

    let job = fixture.store.get_job("job-1").unwrap().unwrap();
    let runtime_agent_id = job.runtime_agent_id.clone().unwrap();
    fixture
        .store
        .append_lifecycle(&LifecycleWrite {
            agent_id: "job-1".into(),
            runtime_agent_id,
            owner_epoch: job.owner_epoch,
            source_sequence: 99,
            event_type: "test.large".into(),
            turn_id: None,
            payload_json: "x".repeat(MAX_EVENT_PAYLOAD_BYTES + 1),
            redaction_level: "redacted".into(),
            terminal: None,
            turn_state: None,
        })
        .unwrap();
    assert_eq!(
        error(
            rpc.call(&request(
                "events-large",
                RpcMethod::Events(EventQuery {
                    agent_id: "job-1".into(),
                    runtime_agent_id: None,
                    after: 1,
                    limit: 10,
                }),
            ))
            .unwrap(),
        )
        .code,
        RpcErrorCode::Oversized
    );
    assert_eq!(
        error(
            rpc.call(&request(
                "preview-large",
                RpcMethod::Result(ResultQuery {
                    agent_id: "job-1".into(),
                    preview_bytes: MAX_PREVIEW_BYTES + 1,
                }),
            ))
            .unwrap(),
        )
        .code,
        RpcErrorCode::Validation
    );
}

#[test]
fn lifecycle_methods_preserve_idempotency_events_wait_result_and_reconnect() {
    let fixture = fixture();
    let rpc = client(&fixture.socket);
    let first_response = rpc
        .call(&request(
            "enqueue-1",
            enqueue_request("job-1", "stable-key"),
        ))
        .unwrap();
    assert_eq!(first_response.request_id.as_deref(), Some("enqueue-1"));
    let first = success(first_response);
    assert!(matches!(
        first,
        RpcSuccess::Enqueued { ref job } if job.agent_id == "job-1"
    ));
    let duplicate = success(
        rpc.call(&request(
            "enqueue-2",
            enqueue_request("different-id", "stable-key"),
        ))
        .unwrap(),
    );
    assert!(matches!(
        duplicate,
        RpcSuccess::Enqueued { ref job } if job.agent_id == "job-1"
    ));
    assert!(matches!(
        success(rpc.call(&request("start", RpcMethod::Start)).unwrap()),
        RpcSuccess::Started { ref agent_ids } if agent_ids == &["job-1"]
    ));

    let runtime = fixture.factory.runtime("job-1");
    runtime.emit(RuntimeEvent::Driver(Inbound::OversizedLine { bytes: 2048 }));
    let page = success(
        rpc.call(&request(
            "events",
            RpcMethod::Events(EventQuery {
                agent_id: "job-1".into(),
                runtime_agent_id: None,
                after: 0,
                limit: 10,
            }),
        ))
        .unwrap(),
    );
    let page = match page {
        RpcSuccess::Events { page } => page,
        other => panic!("unexpected events result: {other:?}"),
    };
    assert_eq!(page.events.len(), 2);
    assert_eq!(page.events[0].redaction_level, "redacted");
    assert!(!page.events[0]
        .payload_json
        .contains("sensitive runtime text"));
    assert!(matches!(
        success(
            rpc.call(&request(
                "events-page",
                RpcMethod::Events(EventQuery {
                    agent_id: "job-1".into(),
                    runtime_agent_id: None,
                    after: 0,
                    limit: 1,
                }),
            ))
            .unwrap(),
        ),
        RpcSuccess::Events { ref page }
            if page.events.len() == 1 && page.has_more && page.next_sequence == 1
    ));

    let message = RpcMethod::Message(MessageInput {
        agent_id: "job-1".into(),
        message_id: "msg-1".into(),
        mode: "queue".into(),
        content: "continue".into(),
    });
    assert!(matches!(
        success(rpc.call(&request("message-1", message.clone())).unwrap()),
        RpcSuccess::Message {
            disposition: MessageDispositionView::Queued
        }
    ));
    assert!(matches!(
        success(rpc.call(&request("message-2", message)).unwrap()),
        RpcSuccess::Message {
            disposition: MessageDispositionView::Queued
        }
    ));
    fixture
        .store
        .insert_pending_request("req-1", "job-1", "corr-1", "permission", "{}")
        .unwrap();
    let respond = RpcMethod::Respond(RespondInput {
        agent_id: "job-1".into(),
        request_id: "req-1".into(),
        decision: ResponseDecision::Allow,
        content: None,
    });
    assert!(matches!(
        success(rpc.call(&request("respond-1", respond.clone())).unwrap()),
        RpcSuccess::Respond {
            outcome: ResponseOutcomeView {
                disposition: ResponseDispositionView::Responded,
                ..
            }
        }
    ));
    assert!(matches!(
        success(rpc.call(&request("respond-2", respond)).unwrap()),
        RpcSuccess::Respond {
            outcome: ResponseOutcomeView {
                disposition: ResponseDispositionView::AlreadyResponded,
                ..
            }
        }
    ));

    let report_path = fixture._directory.path().join("report.md");
    std::fs::write(&report_path, "bounded report preview").unwrap();
    fixture
        .store
        .insert_artifact(&NewArtifact {
            artifact_id: "artifact-1".into(),
            agent_id: "job-1".into(),
            artifact_type: "report".into(),
            path: report_path.to_string_lossy().into_owned(),
            sha256: "a".repeat(64),
            bytes: 22,
            checkpoint_number: Some(1),
        })
        .unwrap();
    let result = success(
        rpc.call(&request(
            "result",
            RpcMethod::Result(ResultQuery {
                agent_id: "job-1".into(),
                preview_bytes: 7,
            }),
        ))
        .unwrap(),
    );
    let artifact = match result {
        RpcSuccess::Result {
            artifact: Some(artifact),
            ..
        } => artifact,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(artifact.preview_state, PreviewState::Unavailable);
    assert_eq!(artifact.preview, None);
    assert_eq!(artifact.integrity, ArtifactIntegrityView::LegacyUnverified);
    assert_eq!(artifact.expected_sha256, Some("a".repeat(64)));
    assert_eq!(artifact.expected_bytes, Some(22));
    assert_eq!(artifact.observed_sha256, None);
    assert_eq!(artifact.observed_bytes, None);
    let schema: Value = serde_json::from_str(include_str!(
        "../../../../schemas/review-report.schema.json"
    ))
    .unwrap();
    jsonschema::draft202012::meta::validate(&schema).unwrap();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    assert!(validator.is_valid(&serde_json::to_value(artifact).unwrap()));

    assert!(matches!(
        success(
            rpc.call(&request(
                "wait-timeout",
                RpcMethod::Wait(WaitQuery {
                    agent_id: "job-1".into(),
                    runtime_agent_id: None,
                    after: page.next_sequence,
                    timeout_ms: 30,
                }),
            ))
            .unwrap()
        ),
        RpcSuccess::Wait { timed_out: true, ref page, .. } if page.events.is_empty()
    ));
    let emit_runtime = Arc::clone(&runtime);
    let emit = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        emit_runtime.emit(RuntimeEvent::Driver(Inbound::OversizedLine { bytes: 4096 }));
    });
    assert!(matches!(success(
            rpc.call(&request(
                "wait-event",
                RpcMethod::Wait(WaitQuery {
                    agent_id: "job-1".into(),
                    runtime_agent_id: None,
                    after: page.next_sequence,
                    timeout_ms: 500,
                }),
            ))
            .unwrap()
        ),
        RpcSuccess::Wait { ref page, .. } if page.events.len() == 1
    ));
    emit.join().unwrap();

    let reconnected = client(&fixture.socket);
    assert!(matches!(
        success(
            reconnected
                .call(&request(
                    "status-reconnected",
                    RpcMethod::Status {
                        agent_id: "job-1".into(),
                    },
                ))
                .unwrap()
        ),
        RpcSuccess::Status { ref job } if job.state == JobStateView::Running
    ));
    assert!(matches!(
        success(rpc.call(&request("list", RpcMethod::List { scope: JobListScopeView::Recent, limit: 10 })).unwrap()),
        RpcSuccess::Listed { ref jobs } if jobs.len() == 1
    ));
}

#[test]
fn forced_persistence_failure_is_typed_without_server_disconnect() {
    let fixture = fixture();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = OFF; DROP TABLE agents;")
        .unwrap();
    let rpc = client(&fixture.socket);
    assert_eq!(
        error(
            rpc.call(&request("persist", enqueue_request("job-1", "key-1")))
                .unwrap()
        )
        .code,
        RpcErrorCode::Persistence
    );
    assert_eq!(
        error(raw_call(&fixture.socket, b"{]\n")).code,
        RpcErrorCode::Malformed
    );
}

#[test]
fn file_backed_server_restart_reconciles_and_retains_partial_events() {
    let fixture = fixture();
    let rpc = client(&fixture.socket);
    success(
        rpc.call(&request("enqueue", enqueue_request("job-1", "key-1")))
            .unwrap(),
    );
    success(rpc.call(&request("start", RpcMethod::Start)).unwrap());
    fixture.factory.runtime("job-1");
    fixture.server.shutdown();

    let restarted_store = Arc::new(Store::open(&fixture.database).unwrap());
    let restarted_factory = Arc::new(FakeFactory::default());
    let runtime_factory: Arc<dyn RuntimeFactory> = restarted_factory;
    let restarted_scheduler = Scheduler::new(
        "rpc-restarted",
        Arc::clone(&restarted_store),
        runtime_factory,
        SchedulerConfig::default(),
    )
    .unwrap();
    assert_eq!(
        restarted_scheduler.reconcile_startup().unwrap(),
        vec![("job-1".into(), JobState::FailedRuntimeLost)]
    );
    let restarted_service =
        Arc::new(RpcService::new(restarted_scheduler, Arc::clone(&restarted_store)).unwrap());
    let restarted =
        RpcServer::bind(&fixture.socket, restarted_service, ServerOptions::default()).unwrap();
    let rpc = client(&fixture.socket);
    assert!(matches!(
        success(
            rpc.call(&request(
                "status",
                RpcMethod::Status {
                    agent_id: "job-1".into(),
                },
            ))
            .unwrap()
        ),
        RpcSuccess::Status { ref job }
            if job.state == JobStateView::FailedRuntimeLost
                && job.failure_code.as_deref() == Some("DAEMON_RESTART_RUNTIME_LOST")
    ));
    assert!(matches!(
        success(
            rpc.call(&request(
                "events",
                RpcMethod::Events(EventQuery {
                    agent_id: "job-1".into(),
                    runtime_agent_id: None,
                    after: 0,
                    limit: 10,
                }),
            ))
            .unwrap()
        ),
        RpcSuccess::Events { ref page } if page.events.len() == 1
    ));
    restarted.shutdown();
}

#[test]
fn unix_socket_lifecycle_is_private_exact_and_reconnectable() {
    let fixture = fixture();
    let parent_mode = std::fs::metadata(fixture.socket.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    let socket_mode = std::fs::metadata(&fixture.socket)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(parent_mode, 0o700);
    assert_eq!(socket_mode, 0o600);

    let blocked = fixture.socket.parent().unwrap().join("not-a-socket");
    std::fs::write(&blocked, "preserve").unwrap();
    assert_eq!(
        RpcServer::bind(
            &blocked,
            Arc::clone(&fixture.service),
            ServerOptions::default()
        )
        .err()
        .unwrap()
        .kind(),
        io::ErrorKind::AlreadyExists
    );
    assert_eq!(std::fs::read_to_string(&blocked).unwrap(), "preserve");

    let public_parent = fixture._directory.path().join("public");
    std::fs::create_dir(&public_parent).unwrap();
    std::fs::set_permissions(&public_parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        RpcServer::bind(
            public_parent.join("review.sock"),
            Arc::clone(&fixture.service),
            ServerOptions::default(),
        )
        .err()
        .unwrap()
        .kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        std::fs::metadata(&public_parent)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );

    let stale = fixture.socket.parent().unwrap().join("stale.sock");
    let listener = UnixListener::bind(&stale).unwrap();
    drop(listener);
    let replacement = RpcServer::bind(
        &stale,
        Arc::clone(&fixture.service),
        ServerOptions::default(),
    )
    .unwrap();
    replacement.shutdown();
    assert!(!stale.exists());

    let idle = UnixStream::connect(&fixture.socket).unwrap();
    let started = Instant::now();
    fixture.server.shutdown();
    assert!(started.elapsed() < Duration::from_secs(2));
    drop(idle);
}

#[test]
fn concurrent_transport_stop_close_reap_kills_driver_owned_group() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
    let factory = Arc::new(CommandRuntimeFactory::new(|_job: &Job| {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "read one; printf '%s\\n' '{\"id\":1,\"result\":{}}'; read two; printf '%s\\n' '{\"id\":2,\"result\":{\"session\":{\"sessionId\":\"real-fake-session\"}}}'; read three; printf '%s\\n' '{\"id\":3,\"result\":{}}'; read four; printf '%s\\n' '{\"id\":4,\"result\":{\"accepted\":true}}' '{\"method\":\"session/event\",\"params\":{\"sessionId\":\"real-fake-session\",\"type\":\"turn.started\",\"turnId\":\"turn-1\"}}'; trap '' TERM; sleep 30 & descendant=$!; wait $descendant",
        ]);
        Ok(command)
    }));
    let runtime_factory: Arc<dyn RuntimeFactory> = factory;
    let scheduler = Scheduler::new(
        "rpc-driver",
        Arc::clone(&store),
        runtime_factory,
        SchedulerConfig {
            global_max_agents: 1,
            per_workspace_max_agents: 1,
            stop_grace: Duration::from_millis(100),
            command_timeout: Duration::from_secs(1),
        },
    )
    .unwrap();
    let service = Arc::new(RpcService::new(scheduler, Arc::clone(&store)).unwrap());
    let socket = directory.path().join("private").join("review.sock");
    let server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
    let rpc = client(&socket);
    success(
        rpc.call(&request("enqueue", enqueue_request("job-1", "key-1")))
            .unwrap(),
    );
    success(rpc.call(&request("start", RpcMethod::Start)).unwrap());
    let identity = store
        .get_job("job-1")
        .unwrap()
        .unwrap()
        .process_identity
        .unwrap();
    let group_deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if observe_process_group(identity.process_group_id)
            .unwrap()
            .len()
            >= 2
        {
            break;
        }
        assert!(
            Instant::now() < group_deadline,
            "descendant was not observed"
        );
        thread::sleep(Duration::from_millis(5));
    }

    let barrier = Arc::new(Barrier::new(4));
    let methods = [
        RpcMethod::Stop {
            agent_id: "job-1".into(),
        },
        RpcMethod::Close {
            agent_id: "job-1".into(),
        },
        RpcMethod::Reap {
            agent_id: "job-1".into(),
        },
    ];
    let callers = methods
        .into_iter()
        .enumerate()
        .map(|(index, method)| {
            let socket = socket.clone();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                client(&socket)
                    .call(&request(&format!("concurrent-{index}"), method))
                    .unwrap()
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    for caller in callers {
        assert!(matches!(
            caller.join().unwrap().outcome,
            RpcOutcome::Success { .. }
        ));
    }
    let job = store.get_job("job-1").unwrap().unwrap();
    assert_eq!(job.state, JobState::Cancelled);
    assert!(job.closed_at.is_some());
    assert!(job.reaped_at.is_some());
    assert!(observe_process_group(identity.process_group_id)
        .unwrap()
        .is_empty());
    let runtime_id = job.runtime_agent_id.unwrap();
    let events = store.events_after("job-1", &runtime_id, 0, 100).unwrap();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.event_type.starts_with("runtime."))
            .count(),
        1
    );
    server.shutdown();
}

fn workspace_fake_runtime() -> PathBuf {
    let executable = std::env::current_exe().unwrap();
    let debug = executable
        .parent()
        .and_then(Path::parent)
        .expect("test executable must be under target/debug/deps");
    let path = debug.join(format!(
        "zcode-fake-runtime{}",
        std::env::consts::EXE_SUFFIX
    ));
    assert!(
        path.is_file(),
        "build zcode-fake-runtime before running this targeted fixture"
    );
    path
}

#[derive(Default)]
struct NullSink;

impl LifecycleSink for NullSink {
    fn emit(&self, _record: LifecycleRecord) {}
}

#[test]
fn prompt_already_running_is_returned_as_a_remote_error() {
    let owner =
        RuntimeOwner::spawn(Command::new(workspace_fake_runtime()), Arc::new(NullSink)).unwrap();
    let session = owner
        .bootstrap_session("/workspace", "keep active", Duration::from_secs(2))
        .unwrap();
    let error = owner
        .send_turn(
            &session.session_id,
            "must not live steer",
            Duration::from_secs(2),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        RuntimeCommandError::Remote(ref value)
            if value.get("code").and_then(serde_json::Value::as_i64) == Some(-32010)
    ));
    owner.stop(Duration::from_millis(100));
}

#[test]
fn real_fake_session_delivers_responses_fifo_interrupt_and_distinct_close() {
    let directory = tempfile::tempdir().unwrap();
    let store = Arc::new(Store::open(directory.path().join("session.sqlite3")).unwrap());
    let runtime_path = workspace_fake_runtime();
    let factory = Arc::new(CommandRuntimeFactory::new(move |_job: &Job| {
        Ok(Command::new(&runtime_path))
    }));
    let scheduler = Scheduler::new(
        "fake-session-owner",
        Arc::clone(&store),
        factory,
        SchedulerConfig {
            global_max_agents: 1,
            per_workspace_max_agents: 1,
            stop_grace: Duration::from_millis(100),
            command_timeout: Duration::from_secs(2),
        },
    )
    .unwrap();
    let service = Arc::new(RpcService::new(scheduler.clone(), Arc::clone(&store)).unwrap());
    let socket = directory.path().join("rpc").join("review.sock");
    let server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
    let rpc = client(&socket);
    let mut enqueue = enqueue_request("session-job", "session-key");
    let RpcMethod::Enqueue { job } = &mut enqueue else {
        unreachable!()
    };
    job.initial_prompt = "permission input unknown_event".into();
    success(rpc.call(&request("enqueue", enqueue)).unwrap());
    assert!(matches!(
        success(rpc.call(&request("start", RpcMethod::Start)).unwrap()),
        RpcSuccess::Started { ref agent_ids } if agent_ids == &["session-job"]
    ));

    let deadline = Instant::now() + Duration::from_secs(3);
    let (identity, pending) = loop {
        let job = store.get_job("session-job").unwrap().unwrap();
        let pending = store.pending_requests("session-job").unwrap();
        if job.state == JobState::Running && pending.len() == 2 {
            assert_eq!(job.zcode_session_id.as_deref(), Some("fake-session-7f3a"));
            assert_eq!(job.turn_state, review_store::TurnState::Active);
            break (job.process_identity.unwrap(), pending);
        }
        assert!(
            Instant::now() < deadline,
            "session bootstrap did not settle"
        );
        thread::sleep(Duration::from_millis(5));
    };
    let permission = pending
        .iter()
        .find(|request| request.request_type == "permission")
        .unwrap();
    let input = pending
        .iter()
        .find(|request| request.request_type == "unsupported_input")
        .unwrap();
    assert!(matches!(
        success(
            rpc.call(&request(
                "permission",
                RpcMethod::Respond(RespondInput {
                    agent_id: "session-job".into(),
                    request_id: permission.request_id.clone(),
                    decision: ResponseDecision::Allow,
                    content: None,
                }),
            ))
            .unwrap()
        ),
        RpcSuccess::Respond {
            outcome: ResponseOutcomeView {
                disposition: ResponseDispositionView::Responded,
                ..
            }
        }
    ));
    let unsupported = rpc
        .call(&request(
            "input",
            RpcMethod::Respond(RespondInput {
                agent_id: "session-job".into(),
                request_id: input.request_id.clone(),
                decision: ResponseDecision::Answer,
                content: Some("fixture answer".into()),
            }),
        ))
        .unwrap();
    assert!(matches!(
        unsupported.outcome,
        RpcOutcome::Error {
            error: RpcError {
                code: RpcErrorCode::Validation,
                ..
            }
        }
    ));
    let pending = store.pending_requests("session-job").unwrap();
    assert_eq!(
        pending
            .iter()
            .find(|request| request.request_type == "permission")
            .unwrap()
            .state,
        PendingRequestState::Responded
    );
    assert_eq!(
        pending
            .iter()
            .find(|request| request.request_type == "unsupported_input")
            .unwrap()
            .state,
        PendingRequestState::Pending
    );

    assert!(matches!(
        success(
            rpc.call(&request(
                "queue",
                RpcMethod::Message(MessageInput {
                    agent_id: "session-job".into(),
                    message_id: "message-queue".into(),
                    mode: "queue".into(),
                    content: "auto_complete queued turn".into(),
                }),
            ))
            .unwrap()
        ),
        RpcSuccess::Message {
            disposition: MessageDispositionView::Queued
        }
    ));
    success(
        rpc.call(&request(
            "interrupt",
            RpcMethod::Message(MessageInput {
                agent_id: "session-job".into(),
                message_id: "message-interrupt".into(),
                mode: "interrupt_and_continue".into(),
                content: "auto_complete interrupt turn".into(),
            }),
        ))
        .unwrap(),
    );

    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let first = store.message("message-queue").unwrap().unwrap();
        let second = store.message("message-interrupt").unwrap().unwrap();
        let job = store.get_job("session-job").unwrap().unwrap();
        if first.state == MessageState::Delivered
            && second.state == MessageState::Delivered
            && job.state == JobState::Completed
        {
            break;
        }
        assert!(Instant::now() < deadline, "queued turns did not complete");
        thread::sleep(Duration::from_millis(5));
    }
    assert!(matches!(
        success(
            rpc.call(&request(
                "duplicate-message",
                RpcMethod::Message(MessageInput {
                    agent_id: "session-job".into(),
                    message_id: "message-interrupt".into(),
                    mode: "interrupt_and_continue".into(),
                    content: "auto_complete interrupt turn".into(),
                }),
            ))
            .unwrap()
        ),
        RpcSuccess::Message {
            disposition: MessageDispositionView::AlreadyDelivered
        }
    ));
    assert!(observe_process_group(identity.process_group_id)
        .unwrap()
        .is_empty());
    assert!(matches!(
        success(
            rpc.call(&request(
                "close",
                RpcMethod::Close {
                    agent_id: "session-job".into(),
                },
            ))
            .unwrap()
        ),
        RpcSuccess::Closed {
            state: JobStateView::Completed
        }
    ));
    success(
        rpc.call(&request(
            "reap",
            RpcMethod::Reap {
                agent_id: "session-job".into(),
            },
        ))
        .unwrap(),
    );
    let job = store.get_job("session-job").unwrap().unwrap();
    assert!(job.closed_at.is_some());
    assert!(job.reaped_at.is_some());
    let events = store
        .events_after(
            "session-job",
            job.runtime_agent_id.as_deref().unwrap(),
            0,
            100,
        )
        .unwrap();
    assert!(events.iter().any(|event| event.event_type == "raw.unknown"));
    assert!(events.iter().any(|event| {
        event.event_type == "driver.message" && event.payload_json.contains("permission.responded")
    }));
    server.shutdown();
}
