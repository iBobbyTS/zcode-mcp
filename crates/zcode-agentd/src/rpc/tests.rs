use super::*;
use crate::{
    GeneralCommandCatalog, LifecycleRecord, LifecycleSink, ManagedRuntime, RuntimeCommandError,
    RuntimeEvent, RuntimeFactory, RuntimeOwner, RuntimeTerminal, SchedulerConfig, SessionReady,
    TurnBoundary, TurnSnapshot, GENERAL_COMMAND_CATALOG_SCHEMA,
};
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
        Arc, Condvar, Mutex,
    },
};
use zcode_agent_store::{
    ArtifactKind, NewArtifact, PendingRequestState, ResultArtifact, TaskOutcome, TaskRecord,
    TaskResult,
};
use zcode_driver::{ChildExit, Inbound, ProcessIdentity, StopOutcome};
use zcode_protocol::{EventEnvelope, RequestEnvelope, WireMessage};

struct FakeRuntime {
    sink: Arc<dyn LifecycleSink>,
    next_sequence: AtomicU64,
    terminal: Mutex<Option<RuntimeTerminal>>,
    stop_terminal: Mutex<Option<RuntimeTerminal>>,
    changed: Condvar,
    turn: Mutex<TurnSnapshot>,
}

impl FakeRuntime {
    fn new(sink: Arc<dyn LifecycleSink>) -> Self {
        Self {
            sink,
            next_sequence: AtomicU64::new(1),
            terminal: Mutex::new(None),
            stop_terminal: Mutex::new(None),
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

    fn emit_text_delta(&self, event_id: &str, delta: &str) {
        self.emit(RuntimeEvent::Driver(Inbound::Message(WireMessage::Event(
            EventEnvelope {
                method: "session/event".into(),
                params: serde_json::json!({
                    "type": "model.streaming",
                    "eventId": event_id,
                    "payload": {
                        "kind": "text_delta",
                        "delta": delta,
                    },
                }),
            },
        ))));
    }

    fn publish_terminal(&self, outcome: RuntimeTerminal) -> RuntimeTerminal {
        let mut terminal = self.terminal.lock().unwrap();
        if let Some(terminal) = terminal.as_ref() {
            return terminal.clone();
        }
        self.emit(RuntimeEvent::Terminal(outcome.clone()));
        *terminal = Some(outcome.clone());
        self.changed.notify_all();
        outcome
    }

    fn finish(&self) -> RuntimeTerminal {
        self.publish_terminal(RuntimeTerminal::Stopped(StopOutcome::AlreadyExited(
            ChildExit::Exited(Some(0)),
        )))
    }

    fn complete(&self) -> RuntimeTerminal {
        self.publish_terminal(RuntimeTerminal::Completed(StopOutcome::AlreadyExited(
            ChildExit::Exited(Some(0)),
        )))
    }

    fn set_stop_terminal(&self, terminal: RuntimeTerminal) {
        *self.stop_terminal.lock().unwrap() = Some(terminal);
    }
}

impl ManagedRuntime for FakeRuntime {
    fn identity(&self) -> Option<ProcessIdentity> {
        None
    }

    fn stop(&self, _grace: Duration) -> RuntimeTerminal {
        self.stop_terminal
            .lock()
            .unwrap()
            .take()
            .map(|terminal| self.publish_terminal(terminal))
            .unwrap_or_else(|| self.finish())
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
        job: &TaskRecord,
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
        _validated_denial: Option<&zcode_agent_preparation::ValidatedPermissionDenial>,
        _deadline: std::time::Instant,
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
        job: &TaskRecord,
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
    scheduler: Scheduler,
    service: Arc<RpcService>,
    server: RpcServer,
}

fn fixture() -> Fixture {
    fixture_with_options(ServerOptions::default(), Duration::from_secs(1))
}

fn fixture_with_options(options: ServerOptions, control_timeout: Duration) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("zcode-agent.sqlite3");
    let socket = directory.path().join("rpc").join("zcode-agent.sock");
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
            bootstrap_timeout: Duration::from_secs(1),
            control_timeout,
            ..SchedulerConfig::default()
        },
    )
    .unwrap();
    let service = Arc::new(RpcService::new(scheduler.clone(), Arc::clone(&store)).unwrap());
    let server = RpcServer::bind(&socket, Arc::clone(&service), options).unwrap();
    Fixture {
        _directory: directory,
        database,
        socket,
        store,
        factory,
        scheduler,
        service,
        server,
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
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().into()
}

fn submit_general_fixture(fixture: &Fixture, name: &str, group_id: &str) -> (PathBuf, String) {
    submit_general_fixture_with_budget(fixture, name, group_id, None)
}

fn submit_general_fixture_with_budget(
    fixture: &Fixture,
    name: &str,
    group_id: &str,
    budget: Option<BudgetLimits>,
) -> (PathBuf, String) {
    let repository = fixture._directory.path().join(format!("repository-{name}"));
    std::fs::create_dir_all(repository.join("src")).unwrap();
    std::fs::write(repository.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    git(&repository, &["init"]);
    git(&repository, &["config", "user.name", "S05 Test"]);
    git(
        &repository,
        &["config", "user.email", "s05@example.invalid"],
    );
    git(&repository, &["add", "src/lib.rs"]);
    git(&repository, &["commit", "-m", "fixture"]);
    let base_ref = git(&repository, &["rev-parse", "HEAD"]);
    let repository = std::fs::canonicalize(repository).unwrap();
    let requested_agent_id = format!("s05-{name}");
    let result = fixture
        .service
        .dispatch(RpcMethod::SubmitGeneral {
            input: GeneralSubmitInput {
                manifest: GeneralTaskManifest {
                    schema: zcode_agent_preparation::GENERAL_TASK_SCHEMA.into(),
                    agent_id: requested_agent_id.clone(),
                    repository: repository.clone(),
                    base_ref,
                    access_mode: AccessMode::ReadOnly,
                    permission_mode: zcode_agent_preparation::PermissionMode::Plan,
                    prompt: "inspect the fixture".into(),
                    repo_context: vec!["src/lib.rs".into()],
                    attachments: Vec::new(),
                    write_manifest: Vec::new(),
                    scratch_root: ".agent-work/scratch/general".into(),
                    artifact_root: PathBuf::from(".agent-work/artifacts").join(&requested_agent_id),
                    budget,
                    validation_commands: Default::default(),
                    retain_partial: false,
                    idempotency_key: format!("s05-{name}-key"),
                },
                group_id: Some(group_id.into()),
                allowed_command_ids: Vec::new(),
                required_command_ids: Vec::new(),
            },
        })
        .unwrap();
    let agent_id = match result {
        RpcSuccess::GeneralSubmitted {
            task,
            disposition: SubmissionDispositionView::Created,
        } => task.agent_id,
        other => panic!("unexpected general submission: {other:?}"),
    };
    (repository, agent_id)
}

#[test]
fn task_poll_uses_revision_and_wakes_for_pending_and_terminal() {
    let fixture = fixture();
    let (_, agent_id) = submit_general_fixture(&fixture, "poll", "feature-poll");
    fixture.scheduler.start_ready().unwrap();
    let task = fixture.store.get_task(&agent_id).unwrap().unwrap();
    let runtime = fixture.factory.runtime(&task.agent_id);

    let initial = fixture
        .service
        .dispatch(RpcMethod::TaskPoll(TaskPollQuery {
            agent_id: agent_id.clone(),
            after_revision: 0,
            timeout_ms: 0,
        }))
        .unwrap();
    let revision = match initial {
        RpcSuccess::TaskPoll {
            revision,
            next_revision,
            timed_out,
            ..
        } => {
            assert_eq!(revision, next_revision);
            assert!(!timed_out);
            revision
        }
        other => panic!("unexpected poll result: {other:?}"),
    };

    let service = Arc::clone(&fixture.service);
    let waiting_agent = agent_id.clone();
    let waiter = thread::spawn(move || {
        service
            .dispatch(RpcMethod::TaskPoll(TaskPollQuery {
                agent_id: waiting_agent,
                after_revision: revision,
                timeout_ms: 1000,
            }))
            .unwrap()
    });
    thread::sleep(Duration::from_millis(20));
    runtime.emit(RuntimeEvent::Driver(Inbound::Message(WireMessage::Request(
        RequestEnvelope {
            id: zcode_protocol::WireId::String("permission-wire".into()),
            method: zcode_protocol::INTERACTION_REQUEST_PERMISSION.into(),
            params: serde_json::json!({
                "requestId":"permission-1",
                "toolCallId":"read-1",
                "toolName":"Read",
                "input":{"path":"src/lib.rs"},
                "options":[{"id":"deny","kind":"deny","label":"Deny","response":{"decision":"deny"}}]
            }),
        },
    ))));
    let (pending_revision, request_id) = match waiter.join().unwrap() {
        RpcSuccess::TaskPoll {
            revision,
            pending_requests,
            timed_out,
            ..
        } => {
            assert!(revision > 0);
            assert_eq!(pending_requests.len(), 1);
            assert!(!timed_out);
            (revision, pending_requests[0].request_id.clone())
        }
        other => panic!("unexpected pending poll result: {other:?}"),
    };

    fixture
        .service
        .dispatch(RpcMethod::TaskRespond(RespondInput {
            agent_id: agent_id.clone(),
            request_id,
            decision: ResponseDecision::Deny,
            content: None,
        }))
        .unwrap();
    runtime.finish();
    let deadline = Instant::now() + Duration::from_secs(1);
    while fixture.store.get_task(&agent_id).unwrap().unwrap().phase != TaskPhase::Terminal {
        assert!(Instant::now() < deadline, "task did not reach terminal");
        thread::sleep(Duration::from_millis(5));
    }
    let terminal = fixture
        .service
        .dispatch(RpcMethod::TaskPoll(TaskPollQuery {
            agent_id,
            after_revision: pending_revision,
            timeout_ms: 1000,
        }))
        .unwrap();
    assert!(matches!(
        terminal,
        RpcSuccess::TaskPoll {
            task: TaskView { phase, .. },
            timed_out: false,
            ..
        } if phase == "TERMINAL"
    ));
}

#[test]
fn terminal_poll_settles_pending_requests_after_cancel_and_input_timeout() {
    for timed_out in [false, true] {
        let fixture = fixture();
        let budget = timed_out.then(|| {
            let mut budget = AccessMode::ReadOnly.default_budget();
            budget.input_wait_timeout_ms = 40;
            budget.absolute_wall_time_ms = 5_000;
            budget
        });
        let (_, agent_id) = submit_general_fixture_with_budget(
            &fixture,
            if timed_out {
                "pending-timeout"
            } else {
                "pending-cancel"
            },
            "feature-pending-terminal",
            budget,
        );
        fixture.scheduler.start_ready().unwrap();
        let runtime = fixture.factory.runtime(&agent_id);
        runtime.emit(RuntimeEvent::Driver(Inbound::Message(WireMessage::Request(
            RequestEnvelope {
                id: zcode_protocol::WireId::String("terminal-pending-wire".into()),
                method: zcode_protocol::INTERACTION_REQUEST_PERMISSION.into(),
                params: serde_json::json!({
                    "requestId":"terminal-pending",
                    "toolCallId":"read-terminal",
                    "toolName":"Read",
                    "input":{"path":"src/lib.rs"},
                    "options":[{"id":"deny","kind":"deny","label":"Deny","response":{"decision":"deny"}}]
                }),
            },
        ))));
        let deadline = Instant::now() + Duration::from_secs(2);
        let request_id = loop {
            if let Some(request) = fixture
                .store
                .pending_requests(&agent_id)
                .unwrap()
                .into_iter()
                .next()
            {
                break request.request_id;
            }
            assert!(
                Instant::now() < deadline,
                "pending request was not published"
            );
            thread::sleep(Duration::from_millis(5));
        };
        if !timed_out {
            fixture
                .service
                .dispatch(RpcMethod::TaskCancel {
                    agent_id: agent_id.clone(),
                })
                .unwrap();
        }
        while fixture.store.task_result(&agent_id).unwrap().is_none() {
            assert!(
                Instant::now() < deadline,
                "terminal result was not persisted"
            );
            thread::sleep(Duration::from_millis(5));
        }

        match fixture
            .service
            .dispatch(RpcMethod::TaskPoll(TaskPollQuery {
                agent_id: agent_id.clone(),
                after_revision: 0,
                timeout_ms: 1000,
            }))
            .unwrap()
        {
            RpcSuccess::TaskPoll {
                task,
                pending_requests,
                result_available,
                timed_out: poll_timed_out,
                ..
            } => {
                assert_eq!(task.phase, "TERMINAL");
                assert_eq!(
                    task.outcome,
                    Some(if timed_out {
                        TaskOutcome::TimedOut
                    } else {
                        TaskOutcome::Cancelled
                    })
                );
                assert!(pending_requests.is_empty());
                assert!(result_available);
                assert!(!poll_timed_out);
            }
            other => panic!("unexpected terminal poll: {other:?}"),
        }
        assert!(fixture
            .service
            .dispatch(RpcMethod::TaskRespond(RespondInput {
                agent_id,
                request_id,
                decision: ResponseDecision::Deny,
                content: None,
            }))
            .is_err());
    }
}

#[test]
fn cancel_and_close_return_the_reaped_generic_task_without_followup_rpc() {
    let fixture = fixture();
    let (_, cancelled) = submit_general_fixture(&fixture, "cancel-rpc", "feature-control");
    let cancelled_task = match fixture
        .service
        .dispatch(RpcMethod::TaskCancel {
            agent_id: cancelled.clone(),
        })
        .unwrap()
    {
        RpcSuccess::Stopped { task } => task,
        other => panic!("unexpected cancel result: {other:?}"),
    };
    assert_eq!(cancelled_task.agent_id, cancelled);
    assert_eq!(cancelled_task.phase, "TERMINAL");
    assert!(cancelled_task.stop_requested);
    assert!(!cancelled_task.close_requested);
    assert!(!cancelled_task.closed);
    assert!(cancelled_task.reaped);
    let cancelled_execution_id = fixture
        .store
        .get_task(&cancelled)
        .unwrap()
        .unwrap()
        .agent_id;
    let cancelled_result = fixture
        .store
        .task_result(&cancelled_execution_id)
        .unwrap()
        .unwrap();
    let cancelled_artifacts = fixture
        .store
        .artifacts(&cancelled_execution_id, 16)
        .unwrap();

    for _ in 0..2 {
        let explicitly_closed = match fixture
            .service
            .dispatch(RpcMethod::TaskClose {
                agent_id: cancelled.clone(),
            })
            .unwrap()
        {
            RpcSuccess::Closed { task } => task,
            other => panic!("unexpected close-after-cancel result: {other:?}"),
        };
        assert!(explicitly_closed.stop_requested);
        assert!(explicitly_closed.close_requested);
        assert!(explicitly_closed.closed);
        assert!(explicitly_closed.reaped);
        assert_eq!(
            fixture
                .store
                .task_result(&cancelled_execution_id)
                .unwrap()
                .unwrap(),
            cancelled_result
        );
        assert_eq!(
            fixture
                .store
                .artifacts(&cancelled_execution_id, 16)
                .unwrap(),
            cancelled_artifacts
        );
    }

    let (_, closed) = submit_general_fixture(&fixture, "close-rpc", "feature-control");
    let closed_task = match fixture
        .service
        .dispatch(RpcMethod::TaskClose {
            agent_id: closed.clone(),
        })
        .unwrap()
    {
        RpcSuccess::Closed { task } => task,
        other => panic!("unexpected close result: {other:?}"),
    };
    assert_eq!(closed_task.agent_id, closed);
    assert_eq!(closed_task.phase, "TERMINAL");
    assert!(closed_task.close_requested);
    assert!(closed_task.closed);
    assert!(closed_task.reaped);
}

#[test]
fn public_stop_does_not_mark_runtime_loss_as_reaped_before_restart_recovery() {
    let cases = [
        (
            false,
            RuntimeTerminal::FailedRuntimeLost(crate::RuntimeLoss::StopFailed(
                "stop failed while the process group remained live".into(),
            )),
        ),
        (
            true,
            RuntimeTerminal::Orphaned(crate::RuntimeLoss::UnknownMembership),
        ),
    ];

    for (close, terminal) in cases {
        let fixture = fixture();
        let (_, agent_id) = submit_general_fixture(
            &fixture,
            if close {
                "public-close-orphan"
            } else {
                "public-cancel-stop-failed"
            },
            "feature-recovery-truth",
        );
        fixture.scheduler.start_ready().unwrap();
        let runtime = fixture.factory.runtime(&agent_id);
        runtime.set_stop_terminal(terminal);

        let task = if close {
            match fixture
                .service
                .dispatch(RpcMethod::TaskClose {
                    agent_id: agent_id.clone(),
                })
                .unwrap()
            {
                RpcSuccess::Closed { task } => task,
                other => panic!("unexpected close result: {other:?}"),
            }
        } else {
            match fixture
                .service
                .dispatch(RpcMethod::TaskCancel {
                    agent_id: agent_id.clone(),
                })
                .unwrap()
            {
                RpcSuccess::Stopped { task } => task,
                other => panic!("unexpected cancel result: {other:?}"),
            }
        };
        assert_eq!(task.phase, "TERMINAL");
        assert!(!task.reaped, "public stop must not perform mark-only reap");
        let stored_result = fixture.store.task_result(&agent_id).unwrap().unwrap();
        let stored_task = fixture.store.get_task(&agent_id).unwrap().unwrap();
        assert!(stored_task.reaped_at.is_none());
        assert_eq!(stored_result.result.outcome, TaskOutcome::Cancelled);

        assert!(fixture
            .store
            .startup_recovery_tasks()
            .unwrap()
            .iter()
            .any(|candidate| candidate.agent_id == agent_id));
        assert_eq!(
            fixture.store.task_result(&agent_id).unwrap().unwrap(),
            stored_result
        );
    }
}

#[test]
fn oversized_terminal_text_persists_a_readable_result_invalid_response() {
    let fixture = fixture();
    let (_, agent_id) =
        submit_general_fixture(&fixture, "result-frame-limit", "feature-result-frame");
    fixture.scheduler.start_ready().unwrap();
    let task = fixture.store.get_task(&agent_id).unwrap().unwrap();
    let runtime = fixture.factory.runtime(&task.agent_id);
    let visible_text = "x".repeat(140 * 1024);
    assert!(visible_text.len() < task.effective_budget.max_result_bytes as usize);
    runtime.emit_text_delta("result-frame-text", &visible_text);
    runtime.complete();

    let deadline = Instant::now() + Duration::from_secs(2);
    while fixture.store.get_task(&agent_id).unwrap().unwrap().phase != TaskPhase::Terminal {
        assert!(Instant::now() < deadline, "task did not reach terminal");
        thread::sleep(Duration::from_millis(5));
    }

    let response = client(&fixture.socket)
        .call(&request("large-result", RpcMethod::TaskResult { agent_id }))
        .unwrap();
    match response.outcome {
        RpcOutcome::Success { result } => match *result {
            RpcSuccess::TaskResult {
                result: Some(result),
                artifacts,
                ..
            } => {
                assert_eq!(result.outcome, TaskOutcome::ResultInvalid);
                assert_eq!(
                    result.final_text,
                    "terminal result exceeds private RPC response frame"
                );
                assert!(result
                    .residual_gaps
                    .contains(&"RESULT_RESPONSE_FRAME_EXCEEDED".into()));
                assert!(artifacts.is_empty());
            }
            other => panic!("unexpected task result response: {other:?}"),
        },
        RpcOutcome::Error { error } => panic!("large result was not readable: {error:?}"),
    }
}

#[test]
fn failed_required_check_text_is_guarded_by_the_real_rpc_frame() {
    let directory = tempfile::tempdir().unwrap();
    let repository = directory.path().join("required-check-frame-repository");
    std::fs::create_dir_all(repository.join("src")).unwrap();
    std::fs::write(repository.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    git(&repository, &["init"]);
    git(&repository, &["config", "user.name", "Result Frame Test"]);
    git(
        &repository,
        &["config", "user.email", "result-frame@example.invalid"],
    );
    git(&repository, &["add", "src/lib.rs"]);
    git(&repository, &["commit", "-m", "fixture"]);
    let base_ref = git(&repository, &["rev-parse", "HEAD"]);
    let repository = std::fs::canonicalize(repository).unwrap();
    let catalog_path = directory.path().join("general-commands.json");
    std::fs::write(
        &catalog_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema":GENERAL_COMMAND_CATALOG_SCHEMA,
            "commands":[{
                "repository":repository,
                "command_id":"required",
                "command":{
                    "program":"/bin/test",
                    "args":["-f","missing"],
                    "cwd":".",
                    "timeout_ms":1000,
                    "max_output_bytes":1024
                },
                "allowed_access_modes":["read_only"],
                "readonly_safe":true
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let store = Arc::new(Store::open(directory.path().join("zcode-agent.sqlite3")).unwrap());
    let factory = Arc::new(FakeFactory::default());
    let scheduler = Scheduler::new(
        "required-check-frame-owner",
        Arc::clone(&store),
        factory.clone(),
        SchedulerConfig::default(),
    )
    .unwrap()
    .with_general_command_catalog(GeneralCommandCatalog::load(&catalog_path).unwrap())
    .unwrap();
    let socket = directory.path().join("rpc").join("zcode-agent.sock");
    let service = Arc::new(RpcService::new(scheduler.clone(), Arc::clone(&store)).unwrap());
    let server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
    let submitted = scheduler
        .enqueue_general_with_commands(
            &GeneralTaskManifest {
                schema: zcode_agent_preparation::GENERAL_TASK_SCHEMA.into(),
                agent_id: "required-check-frame".into(),
                repository,
                base_ref,
                access_mode: AccessMode::ReadOnly,
                permission_mode: zcode_agent_preparation::PermissionMode::Plan,
                prompt: "inspect the fixture".into(),
                repo_context: vec!["src/lib.rs".into()],
                attachments: Vec::new(),
                write_manifest: Vec::new(),
                scratch_root: ".agent-work/scratch/required-check-frame".into(),
                artifact_root: ".agent-work/artifacts/required-check-frame".into(),
                budget: None,
                validation_commands: Default::default(),
                retain_partial: false,
                idempotency_key: "required-check-frame-key".into(),
            },
            Some("required-check-frame"),
            &[],
            &["required".into()],
        )
        .unwrap();
    let agent_id = submitted.task.agent_id;
    scheduler.start_ready().unwrap();
    let runtime = factory.runtime(&agent_id);
    runtime.emit_text_delta("required-check-frame-text", &"x".repeat(140 * 1024));
    runtime.complete();

    let deadline = Instant::now() + Duration::from_secs(2);
    while store.get_task(&agent_id).unwrap().unwrap().phase != TaskPhase::Terminal {
        assert!(Instant::now() < deadline, "task did not reach terminal");
        thread::sleep(Duration::from_millis(5));
    }
    let response = client(&socket)
        .call(&request(
            "failed-required-check-result",
            RpcMethod::TaskResult { agent_id },
        ))
        .unwrap();
    match response.outcome {
        RpcOutcome::Success { result } => match *result {
            RpcSuccess::TaskResult {
                result: Some(result),
                artifacts,
                ..
            } => {
                assert_eq!(result.outcome, TaskOutcome::ResultInvalid);
                assert_eq!(
                    result.final_text,
                    "terminal result exceeds private RPC response frame"
                );
                assert!(result
                    .residual_gaps
                    .contains(&"RESULT_RESPONSE_FRAME_EXCEEDED".into()));
                assert!(artifacts.is_empty());
            }
            other => panic!("unexpected task result response: {other:?}"),
        },
        RpcOutcome::Error { error } => panic!("failed result was not readable: {error:?}"),
    }
    server.shutdown();
}

#[test]
fn near_cap_terminal_result_is_safe_for_maximally_escaped_request_id() {
    let fixture = fixture();
    let (_, agent_id) =
        submit_general_fixture(&fixture, "escaped-result-frame", "feature-escaped-frame");
    fixture.scheduler.start_ready().unwrap();
    let task = fixture.store.get_task(&agent_id).unwrap().unwrap();
    let mut terminal_task = task.clone();
    terminal_task.phase = TaskPhase::Terminal;
    terminal_task.outcome = Some(TaskOutcome::Completed);
    let result = |summary: String| TaskResult {
        outcome: TaskOutcome::Completed,
        final_text: summary,
        partial: false,
        base_commit: None,
        head_commit: None,
        changed_files: Vec::new(),
        diff_stat: None,
        checks: Vec::new(),
        residual_gaps: Vec::new(),
        artifacts: Vec::new(),
    };
    let empty = result(String::new());
    let ascii_id = "r".repeat(MAX_REQUEST_ID_BYTES);
    let escaped_id = "\u{1}".repeat(MAX_REQUEST_ID_BYTES);
    assert!(valid_request_id(&escaped_id));
    let ascii_overhead =
        terminal_result_response_size(&terminal_task, &empty, &[], &ascii_id).unwrap();
    let escaped_overhead =
        terminal_result_response_size(&terminal_task, &empty, &[], &escaped_id).unwrap();
    assert_eq!(escaped_overhead - ascii_overhead, 5 * MAX_REQUEST_ID_BYTES);

    let ascii_only = result("x".repeat(MAX_FRAME_BYTES - ascii_overhead));
    assert_eq!(
        terminal_result_response_size(&terminal_task, &ascii_only, &[], &ascii_id),
        Some(MAX_FRAME_BYTES)
    );
    assert!(
        terminal_result_response_size(&terminal_task, &ascii_only, &[], &escaped_id).unwrap()
            > MAX_FRAME_BYTES
    );
    assert!(!terminal_result_response_fits(
        &terminal_task,
        &ascii_only,
        &[]
    ));

    let visible_text = "x".repeat(MAX_FRAME_BYTES - escaped_overhead);
    let safe = result(visible_text.clone());
    assert_eq!(
        terminal_result_response_size(&terminal_task, &safe, &[], &escaped_id),
        Some(MAX_FRAME_BYTES)
    );
    assert!(terminal_result_response_fits(&terminal_task, &safe, &[]));

    let runtime = fixture.factory.runtime(&task.agent_id);
    runtime.emit_text_delta("escaped-result-frame-text", &visible_text);
    runtime.complete();
    let deadline = Instant::now() + Duration::from_secs(2);
    while fixture.store.get_task(&agent_id).unwrap().unwrap().phase != TaskPhase::Terminal {
        assert!(Instant::now() < deadline, "task did not reach terminal");
        thread::sleep(Duration::from_millis(5));
    }

    let response = client(&fixture.socket)
        .call(&request(&escaped_id, RpcMethod::TaskResult { agent_id }))
        .unwrap();
    assert_eq!(response.request_id.as_deref(), Some(escaped_id.as_str()));
    let response_size = serde_json::to_vec(&response).unwrap().len();
    assert!(response_size <= MAX_FRAME_BYTES);
    assert!(
        response_size >= MAX_FRAME_BYTES - 4,
        "near-cap response was {response_size} bytes"
    );
    match response.outcome {
        RpcOutcome::Success { result } => match *result {
            RpcSuccess::TaskResult {
                result: Some(result),
                ..
            } => {
                assert_eq!(result.outcome, TaskOutcome::Completed);
                assert_eq!(result.final_text, visible_text);
            }
            other => panic!("unexpected task result response: {other:?}"),
        },
        RpcOutcome::Error { error } => panic!("near-cap result was not readable: {error:?}"),
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

fn error(response: RpcResponse) -> RpcError {
    match response.outcome {
        RpcOutcome::Error { error } => error,
        RpcOutcome::Success { result } => panic!("unexpected RPC success: {result:?}"),
    }
}

#[test]
fn system_status_is_bounded_layered_and_generation_is_restart_scoped() {
    let fixture = fixture();
    assert_eq!(RPC_VERSION, 12);
    let first = match fixture.service.dispatch(RpcMethod::SystemStatus).unwrap() {
        RpcSuccess::SystemStatus { status } => status,
        other => panic!("unexpected status result: {other:?}"),
    };
    let repeated = match fixture.service.dispatch(RpcMethod::SystemStatus).unwrap() {
        RpcSuccess::SystemStatus { status } => status,
        other => panic!("unexpected status result: {other:?}"),
    };
    assert_eq!(first.service_generation, repeated.service_generation);
    assert_eq!(first.service_generation.len(), 32);
    assert!(first
        .service_generation
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));
    assert_eq!(first.api_surface, "generic_agent");
    assert_eq!(first.protocol_version, RPC_VERSION);
    assert_eq!(
        first.components.keys().cloned().collect::<Vec<_>>(),
        vec![
            "daemon",
            "driver",
            "facade",
            "model_auth",
            "runtime",
            "scheduler",
            "store"
        ]
    );
    assert_eq!(first.capabilities.max_rpc_frame_bytes, MAX_FRAME_BYTES);
    assert_eq!(first.capabilities.max_wait_ms, MAX_WAIT.as_millis() as u64);
    assert!(!first.capabilities.named_checks);
    assert_eq!(
        first.capabilities.maturity,
        BTreeMap::from([
            (
                "workspace_write".into(),
                CapabilityMaturityView::ExperimentalUnverifiedRuntime
            ),
            (
                "read_only".into(),
                CapabilityMaturityView::ExperimentalUnverifiedRuntime
            ),
        ])
    );

    let replacement =
        RpcService::new(fixture.scheduler.clone(), Arc::clone(&fixture.store)).unwrap();
    let replacement = match replacement.dispatch(RpcMethod::SystemStatus).unwrap() {
        RpcSuccess::SystemStatus { status } => status,
        other => panic!("unexpected status result: {other:?}"),
    };
    assert_ne!(first.service_generation, replacement.service_generation);

    let oversized = fixture
        .service
        .handle_bytes(&vec![b' '; MAX_FRAME_BYTES + 1]);
    assert_eq!(error(oversized).code, RpcErrorCode::Oversized);
    let unknown_outer = fixture.service.handle_bytes(
        format!(
            "{{\"version\":{RPC_VERSION},\"request_id\":\"strict\",\"method\":\"system_status\",\"extra\":true}}"
        )
        .as_bytes(),
    );
    assert_eq!(error(unknown_outer).code, RpcErrorCode::Validation);
}

#[test]
fn v12_gate_rejects_v11_before_method_dispatch() {
    let fixture = fixture();
    let old_peer = fixture
        .service
        .handle_bytes(br#"{"version":11,"request_id":"v11-peer","method":"missing"}"#);
    assert_eq!(old_peer.version, RPC_VERSION);
    assert_eq!(old_peer.request_id.as_deref(), Some("v11-peer"));
    assert_eq!(error(old_peer).code, RpcErrorCode::UnsupportedVersion);

    let current_unknown = fixture
        .service
        .handle_bytes(br#"{"version":12,"request_id":"generic-peer","method":"missing"}"#);
    assert_eq!(error(current_unknown).code, RpcErrorCode::UnknownMethod);

    let status = fixture
        .service
        .handle_bytes(br#"{"version":12,"request_id":"generic-status","method":"system_status"}"#);
    match status.outcome {
        RpcOutcome::Success { result } => match *result {
            RpcSuccess::SystemStatus { status } => assert_eq!(status.protocol_version, 12),
            other => panic!("unexpected success: {other:?}"),
        },
        RpcOutcome::Error { error } => panic!("unexpected error: {error:?}"),
    }
}

#[test]
fn retired_private_rpc_methods_are_unknown() {
    let fixture = fixture();
    for method in [
        "system_ensure_ready",
        "task_status",
        "task_pending",
        "task_events",
        "task_wait",
        "task_reap",
        "enqueue",
        "start",
        "status",
        "pending",
        "events",
        "wait",
        "message",
        "respond",
        "stop",
        "result",
        "list",
        "close",
        "reap",
    ] {
        let response = fixture.service.handle_bytes(
            format!(
                "{{\"version\":{RPC_VERSION},\"request_id\":\"retired\",\"method\":\"{method}\"}}"
            )
            .as_bytes(),
        );
        assert_eq!(
            error(response).code,
            RpcErrorCode::UnknownMethod,
            "retired method {method} remained reachable"
        );
    }
}

#[test]
fn s05_scoped_task_list_and_typed_pending_are_daemon_authoritative() {
    let fixture = fixture();
    let (repository_a, agent_a) = submit_general_fixture(&fixture, "scope-a", "feature-a");
    let (_, agent_b) = submit_general_fixture(&fixture, "scope-b", "feature-b");
    let (_, agent_c) = submit_general_fixture(&fixture, "scope-c", "feature-a");
    let (_, agent_d) = submit_general_fixture(&fixture, "scope-d", "feature-a");

    match fixture
        .service
        .dispatch(RpcMethod::TaskList(TaskListQuery {
            repository: Some(repository_a.to_string_lossy().into_owned()),
            group_id: Some("feature-a".into()),
            phase: None,
            outcome: None,
            access_mode: None,
            cursor: None,
            limit: 10,
        }))
        .unwrap()
    {
        RpcSuccess::TaskListed { tasks, .. } => {
            assert_eq!(tasks.len(), 1);
            assert_eq!(tasks[0].agent_id, agent_a);
            assert_ne!(tasks[0].agent_id, agent_b);
        }
        other => panic!("unexpected list: {other:?}"),
    }
    let (first_page, cursor) = match fixture
        .service
        .dispatch(RpcMethod::TaskList(TaskListQuery {
            repository: None,
            group_id: Some("feature-a".into()),
            phase: Some(TaskPhaseFilter::Queued),
            outcome: None,
            access_mode: Some(AccessMode::ReadOnly),
            cursor: None,
            limit: 2,
        }))
        .unwrap()
    {
        RpcSuccess::TaskListed { tasks, next_cursor } => {
            (tasks, next_cursor.expect("first page must expose a cursor"))
        }
        other => panic!("unexpected first page: {other:?}"),
    };
    assert_eq!(first_page.len(), 2);
    let second_page = match fixture
        .service
        .dispatch(RpcMethod::TaskList(TaskListQuery {
            repository: None,
            group_id: Some("feature-a".into()),
            phase: Some(TaskPhaseFilter::Queued),
            outcome: None,
            access_mode: Some(AccessMode::ReadOnly),
            cursor: Some(cursor),
            limit: 2,
        }))
        .unwrap()
    {
        RpcSuccess::TaskListed { tasks, next_cursor } => {
            assert!(next_cursor.is_none());
            tasks
        }
        other => panic!("unexpected second page: {other:?}"),
    };
    assert_eq!(second_page.len(), 1);
    let listed_ids = first_page
        .into_iter()
        .chain(second_page)
        .map(|task| task.agent_id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        listed_ids,
        [agent_a.clone(), agent_c, agent_d].into_iter().collect()
    );
    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::TaskList(TaskListQuery {
                repository: None,
                group_id: Some("feature-a".into()),
                phase: None,
                outcome: None,
                access_mode: None,
                cursor: Some("not-a-cursor".into()),
                limit: 2,
            }))
            .unwrap_err()
            .code,
        RpcErrorCode::Validation
    );
    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::TaskList(TaskListQuery {
                repository: None,
                group_id: None,
                phase: None,
                outcome: None,
                access_mode: None,
                cursor: None,
                limit: 10,
            }))
            .unwrap_err()
            .code,
        RpcErrorCode::Validation
    );

    let started = fixture.scheduler.start_ready().unwrap();
    assert!(started.contains(&agent_a));
    let execution_id = fixture.store.get_task(&agent_a).unwrap().unwrap().agent_id;
    fixture
        .store
        .insert_pending_request(
            "s05-request",
            &execution_id,
            "private-correlation",
            "permission",
            r#"{"toolName":"read","input":{"path":"/private/repository/src/lib.rs"}}"#,
        )
        .unwrap();
    match fixture
        .service
        .dispatch(RpcMethod::TaskPoll(TaskPollQuery {
            agent_id: agent_a,
            after_revision: 0,
            timeout_ms: 0,
        }))
        .unwrap()
    {
        RpcSuccess::TaskPoll {
            pending_requests, ..
        } => {
            assert_eq!(pending_requests.len(), 1);
            assert_eq!(pending_requests[0].request_id, "s05-request");
            assert_eq!(pending_requests[0].operation, "read");
            assert!(!pending_requests[0].summary.contains("/private/repository"));
        }
        other => panic!("unexpected pending: {other:?}"),
    }
}

#[test]
fn artifact_chunks_are_verified_against_the_authoritative_result() {
    let fixture = fixture();
    let (repository, agent_id) = submit_general_fixture(&fixture, "artifact", "feature-artifact");
    let execution_id = fixture.store.get_task(&agent_id).unwrap().unwrap().agent_id;
    assert!(fixture
        .scheduler
        .start_ready()
        .unwrap()
        .contains(&execution_id));
    fixture.factory.runtime(&execution_id);
    let bytes = b"verified bounded artifact";
    let sha256 = format!("{:x}", Sha256::digest(bytes));
    let path = repository
        .join(".agent-work/artifacts")
        .join(&agent_id)
        .join("changes.patch");
    std::fs::write(&path, bytes).unwrap();
    let artifact = NewArtifact {
        artifact_id: "s05-artifact".into(),
        agent_id: execution_id.clone(),
        artifact_type: "changes_patch".into(),
        path: path.to_string_lossy().into_owned(),
        sha256: sha256.clone(),
        bytes: bytes.len() as u64,
    };
    fixture
        .store
        .store_task_result_with_patch(
            &execution_id,
            &TaskResult {
                outcome: TaskOutcome::Completed,
                final_text: "completed".into(),
                partial: false,
                base_commit: None,
                head_commit: None,
                changed_files: Vec::new(),
                diff_stat: None,
                checks: vec!["check".into()],
                residual_gaps: Vec::new(),
                artifacts: vec![ResultArtifact {
                    kind: ArtifactKind::ChangesPatch,
                    artifact_id: "s05-artifact".into(),
                    sha256: sha256.clone(),
                }],
            },
            Some(&artifact),
        )
        .unwrap();

    match fixture
        .service
        .dispatch(RpcMethod::TaskArtifact(TaskArtifactQuery {
            agent_id: agent_id.clone(),
            artifact_id: "s05-artifact".into(),
            offset_bytes: 9,
            limit_bytes: 7,
        }))
        .unwrap()
    {
        RpcSuccess::TaskArtifact { chunk } => {
            assert_eq!(chunk.bytes, &bytes[9..16]);
            assert_eq!(chunk.sha256, sha256);
            assert!(!chunk.eof);
        }
        other => panic!("unexpected artifact: {other:?}"),
    }

    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::TaskArtifact(TaskArtifactQuery {
                agent_id: agent_id.clone(),
                artifact_id: "s05-artifact".into(),
                offset_bytes: bytes.len() as u64,
                limit_bytes: 1,
            }))
            .unwrap_err()
            .code,
        RpcErrorCode::Validation
    );

    std::fs::write(&path, b"tampered").unwrap();
    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::TaskArtifact(TaskArtifactQuery {
                agent_id,
                artifact_id: "s05-artifact".into(),
                offset_bytes: 0,
                limit_bytes: MAX_ARTIFACT_CHUNK_BYTES,
            }))
            .unwrap_err()
            .code,
        RpcErrorCode::ResultInvalid
    );
}

#[test]
fn pending_permission_preview_uses_the_typed_active_policy() {
    let directory = tempfile::tempdir().unwrap();
    let worktree = directory.path().join("worktree");
    let scratch = directory.path().join("scratch");
    let artifact_root = directory.path().join("artifacts");
    std::fs::create_dir_all(worktree.join("src")).unwrap();
    std::fs::write(worktree.join("src/lib.rs"), "pub fn original() {}\n").unwrap();
    std::fs::create_dir_all(&scratch).unwrap();
    std::fs::create_dir_all(&artifact_root).unwrap();
    let policy = zcode_agent_preparation::PolicyLauncher::for_general(
        worktree,
        scratch,
        artifact_root.join("result.json"),
        Vec::new(),
        std::collections::BTreeMap::new(),
        zcode_agent_preparation::PolicyCapabilities::default(),
        AccessMode::WorkspaceWrite,
        vec![PathBuf::from("src")],
    )
    .unwrap();
    let request = |request_id: &str, payload_json: &str| StoredPendingRequest {
        request_id: request_id.into(),
        agent_id: "general-task".into(),
        correlation_id: format!("correlation-{request_id}"),
        request_type: "permission".into(),
        payload_json: payload_json.into(),
        state: PendingRequestState::Pending,
        response_decision: None,
        response_content: None,
        created_at: 0,
    };

    let editable = pending_request_view(
        Some(&policy),
        request(
            "edit",
            r#"{"toolName":"edit","input":{"path":"src/lib.rs"}}"#,
        ),
    );
    assert_eq!(editable.policy_preview, "externally_decidable");

    let network = pending_request_view(
        Some(&policy),
        request(
            "network",
            r#"{"toolName":"network","input":{"target":"example.com"}}"#,
        ),
    );
    assert_eq!(network.policy_preview, "hard_deny");
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
fn transport_reports_malformed_oversized_version_method_validation_and_not_found() {
    let fixture = fixture();
    assert_eq!(
        error(raw_call(&fixture.socket, b"{]\n")).code,
        RpcErrorCode::Malformed
    );
    let unsupported = raw_call(
        &fixture.socket,
        b"{\"version\":3,\"request_id\":\"v\",\"method\":\"system_status\"}\n",
    );
    assert_eq!(unsupported.request_id.as_deref(), Some("v"));
    assert_eq!(error(unsupported).code, RpcErrorCode::UnsupportedVersion);
    assert_eq!(
        error(raw_call(
            &fixture.socket,
            format!("{{\"version\":{RPC_VERSION},\"request_id\":\"m\",\"method\":\"missing\"}}\n")
                .as_bytes()
        ))
        .code,
        RpcErrorCode::UnknownMethod
    );
    assert_eq!(
        error(
            client(&fixture.socket)
                .call(&request(
                    "missing",
                    RpcMethod::TaskPoll(TaskPollQuery {
                        agent_id: "none".into(),
                        after_revision: 0,
                        timeout_ms: 0,
                    })
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
                    RpcMethod::TaskList(TaskListQuery {
                        repository: None,
                        group_id: Some("feature".into()),
                        phase: None,
                        outcome: None,
                        access_mode: None,
                        cursor: None,
                        limit: 0,
                    })
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
            method: RpcMethod::SystemStatus,
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
fn forced_persistence_failure_is_typed_without_server_disconnect() {
    let fixture = fixture();
    let connection = rusqlite::Connection::open(&fixture.database).unwrap();
    connection
        .execute_batch("PRAGMA foreign_keys = OFF; DROP TABLE tasks;")
        .unwrap();
    let rpc = client(&fixture.socket);
    assert_eq!(
        error(
            rpc.call(&request(
                "persist",
                RpcMethod::TaskList(TaskListQuery {
                    repository: None,
                    group_id: Some("feature".into()),
                    phase: None,
                    outcome: None,
                    access_mode: None,
                    cursor: None,
                    limit: 1,
                }),
            ))
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
            public_parent.join("zcode-agent.sock"),
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
