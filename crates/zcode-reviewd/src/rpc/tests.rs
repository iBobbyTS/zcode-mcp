use super::*;
use crate::{
    CommandRuntimeFactory, LifecycleRecord, LifecycleSink, ManagedRuntime, RuntimeEvent,
    RuntimeFactory, RuntimeTerminal, SchedulerConfig,
};
use review_store::{Job, LifecycleWrite, NewArtifact};
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
}

impl FakeRuntime {
    fn new(sink: Arc<dyn LifecycleSink>) -> Self {
        Self {
            sink,
            next_sequence: AtomicU64::new(1),
            terminal: Mutex::new(None),
            changed: Condvar::new(),
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
        }),
        RpcMethod::Stop {
            agent_id: "job-1".into(),
        },
        RpcMethod::Result(ResultQuery {
            agent_id: "job-1".into(),
            preview_bytes: 64,
        }),
        RpcMethod::List { limit: 10 },
        RpcMethod::Close {
            agent_id: "job-1".into(),
        },
        RpcMethod::Reap {
            agent_id: "job-1".into(),
        },
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
        b"{\"version\":2,\"request_id\":\"v\",\"method\":\"status\",\"params\":{\"agent_id\":\"job\"}}\n",
    );
    assert_eq!(unsupported.request_id.as_deref(), Some("v"));
    assert_eq!(error(unsupported).code, RpcErrorCode::UnsupportedVersion);
    assert_eq!(
        error(raw_call(
            &fixture.socket,
            b"{\"version\":1,\"request_id\":\"m\",\"method\":\"missing\"}\n"
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
                .call(&request("invalid", RpcMethod::List { limit: 0 }))
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
            accepted: true,
            created: true
        }
    ));
    assert!(matches!(
        success(rpc.call(&request("message-2", message)).unwrap()),
        RpcSuccess::Message {
            accepted: true,
            created: false
        }
    ));
    fixture
        .store
        .insert_pending_request("req-1", "job-1", "corr-1", "permission", "{}")
        .unwrap();
    let respond = RpcMethod::Respond(RespondInput {
        agent_id: "job-1".into(),
        request_id: "req-1".into(),
    });
    assert!(matches!(
        success(rpc.call(&request("respond-1", respond.clone())).unwrap()),
        RpcSuccess::Respond {
            accepted: true,
            changed: true
        }
    ));
    assert!(matches!(
        success(rpc.call(&request("respond-2", respond)).unwrap()),
        RpcSuccess::Respond {
            accepted: true,
            changed: false
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
            sha256: "abc123".into(),
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
    assert!(matches!(
        result,
        RpcSuccess::Result {
            artifact: Some(ArtifactView {
                preview_state: PreviewState::Available,
                preview: Some(ref preview),
                ..
            }),
            ..
        } if preview == "bounded"
    ));

    assert_eq!(
        error(
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
        )
        .code,
        RpcErrorCode::Timeout
    );
    let emit_runtime = Arc::clone(&runtime);
    let emit = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        emit_runtime.emit(RuntimeEvent::Driver(Inbound::OversizedLine { bytes: 4096 }));
    });
    assert!(matches!(
        success(
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
        success(rpc.call(&request("list", RpcMethod::List { limit: 10 })).unwrap()),
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
            "trap '' TERM; sleep 30 & descendant=$!; wait $descendant",
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
    assert_eq!(job.state, JobState::Closed);
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
