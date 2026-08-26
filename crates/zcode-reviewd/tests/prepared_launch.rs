use review_ledger::{LedgerManager, REVIEW_CHECKPOINT, REVIEW_FINALIZE};
use review_preparation::{
    NetworkPolicy, PreparedLaunchSpec, ReviewKind, ReviewManifest, ReviewPreparer, RoundKind,
    ScratchPolicy,
};
use review_store::{
    BudgetRequest, EffectiveBudget, NewJob, NewTask, Store, TaskKind, TaskOutcome, TaskPhase,
};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Barrier, Mutex,
    },
    thread,
    time::Duration,
};
use tempfile::TempDir;
use zcode_driver::Inbound;
use zcode_driver::{ChildExit, StopOutcome};
use zcode_protocol::{EventEnvelope, StdioMcpServer, WireMessage};
use zcode_reviewd::{
    CommandRuntimeFactory, InternalLedgerMcpConfig, LifecycleRecord, LifecycleSink, ManagedRuntime,
    RuntimeFactory, RuntimeTerminal, Scheduler, SchedulerConfig, SessionReady, TurnBoundary,
    TurnSnapshot,
};

struct UnusedFactory;

struct NullSink;

impl LifecycleSink for NullSink {
    fn emit(&self, _record: LifecycleRecord) {}
}

impl RuntimeFactory for UnusedFactory {
    fn spawn(
        &self,
        _job: &review_store::Job,
        _sink: Arc<dyn LifecycleSink>,
    ) -> io::Result<Arc<dyn ManagedRuntime>> {
        Err(io::Error::other(
            "runtime must not start during preparation",
        ))
    }
}

struct CountingFactory {
    calls: Arc<AtomicUsize>,
}

impl RuntimeFactory for CountingFactory {
    fn spawn(
        &self,
        _job: &review_store::Job,
        _sink: Arc<dyn LifecycleSink>,
    ) -> io::Result<Arc<dyn ManagedRuntime>> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Err(io::Error::other("spawn must remain unreachable"))
    }
}

#[test]
fn review_without_ledger_fails_closed_before_runtime_spawn() {
    let directory = tempfile::tempdir().unwrap();
    let repository = create_repository(&directory);
    let head = git(&repository, &["rev-parse", "HEAD"]);
    let prepared = ReviewPreparer
        .prepare(&ReviewManifest {
            schema: "sectioned-zcode-review/v1".into(),
            review_kind: ReviewKind::Code,
            feature_id: "feature".into(),
            section_id: "S03".into(),
            round_kind: RoundKind::InitialBounded,
            repository,
            base_ref: head.clone(),
            head_ref: head,
            plan_path: ".agent-work/PLAN.md".into(),
            context_paths: Vec::new(),
            scope_paths: vec!["src".into()],
            forbidden_input_globs: Vec::new(),
            validation_commands: Default::default(),
            report_target: ".agent-work/reviews/feature/S03/no-ledger.md".into(),
            scratch_root: ".agent-work/scratch/jobs".into(),
            model: None,
            fresh_session: true,
            network_policy: NetworkPolicy::Deny,
            scratch_policy: ScratchPolicy::Isolated,
            idempotency_key: "feature:S03:no-ledger".into(),
        })
        .unwrap();
    let store = Arc::new(Store::open(directory.path().join("no-ledger.sqlite3")).unwrap());
    let calls = Arc::new(AtomicUsize::new(0));
    let scheduler = Scheduler::new(
        "no-ledger",
        Arc::clone(&store),
        Arc::new(CountingFactory {
            calls: Arc::clone(&calls),
        }),
        SchedulerConfig::default(),
    )
    .unwrap();
    scheduler
        .enqueue_prepared("no-ledger-review", "review", &prepared)
        .unwrap();

    assert!(scheduler.start_ready().is_err());
    assert_eq!(calls.load(Ordering::Acquire), 0);
    let failed = store.get_job("no-ledger-review").unwrap().unwrap();
    assert!(failed.state.is_terminal());
    assert_eq!(
        failed.failure_code.as_deref(),
        Some("REPORT_INITIALIZATION_FAILED")
    );
    assert_eq!(store.active_count().unwrap(), 0);
}

struct BudgetRuntime {
    sink: Arc<dyn LifecycleSink>,
    sequence: AtomicU64,
    stop_calls: AtomicUsize,
}

impl BudgetRuntime {
    fn emit_turn(&self, turn_id: &str) {
        let sequence = self.sequence.fetch_add(1, Ordering::AcqRel);
        self.sink.emit(LifecycleRecord {
            sequence,
            event: zcode_reviewd::RuntimeEvent::Driver(Inbound::Message(WireMessage::Event(
                EventEnvelope {
                    method: "session/event".into(),
                    params: serde_json::json!({
                        "type":"turn.started",
                        "payload":{"turnId":turn_id}
                    }),
                },
            ))),
        });
    }
}

impl ManagedRuntime for BudgetRuntime {
    fn identity(&self) -> Option<zcode_driver::ProcessIdentity> {
        None
    }

    fn stop(&self, _grace: Duration) -> RuntimeTerminal {
        self.stop_calls.fetch_add(1, Ordering::AcqRel);
        RuntimeTerminal::Stopped(StopOutcome::AlreadyExited(ChildExit::Exited(Some(0))))
    }

    fn wait_terminal(&self, timeout: Duration) -> Option<RuntimeTerminal> {
        thread::sleep(timeout);
        None
    }

    fn bootstrap_session(
        &self,
        _job: &review_store::Job,
        _timeout: Duration,
    ) -> Result<SessionReady, zcode_reviewd::RuntimeCommandError> {
        Ok(SessionReady {
            session_id: "budget-review-session".into(),
            initial_turn_id: Some("initial-turn".into()),
            observed_model: None,
        })
    }

    fn turn_snapshot(&self) -> TurnSnapshot {
        TurnSnapshot {
            generation: 1,
            active: true,
            boundary: None,
        }
    }
}

struct BudgetFactory {
    runtime: Arc<Mutex<Option<Arc<BudgetRuntime>>>>,
}

fn prepare_review(directory: &TempDir, name: &str) -> PreparedLaunchSpec {
    let repository = create_repository(directory);
    let head = git(&repository, &["rev-parse", "HEAD"]);
    ReviewPreparer
        .prepare(&ReviewManifest {
            schema: "sectioned-zcode-review/v1".into(),
            review_kind: ReviewKind::Code,
            feature_id: "feature".into(),
            section_id: "S03".into(),
            round_kind: RoundKind::InitialBounded,
            repository,
            base_ref: head.clone(),
            head_ref: head,
            plan_path: ".agent-work/PLAN.md".into(),
            context_paths: Vec::new(),
            scope_paths: vec!["src".into()],
            forbidden_input_globs: Vec::new(),
            validation_commands: Default::default(),
            report_target: format!(".agent-work/reviews/feature/S03/{name}.md").into(),
            scratch_root: ".agent-work/scratch/jobs".into(),
            model: None,
            fresh_session: true,
            network_policy: NetworkPolicy::Deny,
            scratch_policy: ScratchPolicy::Isolated,
            idempotency_key: format!("feature:S03:{name}"),
        })
        .unwrap()
}

fn enqueue_v2_review(
    store: &Store,
    execution_id: &str,
    public_id: &str,
    prepared: &PreparedLaunchSpec,
    budget: BudgetRequest,
) {
    let mut job = NewJob::new(execution_id, prepared.worktree.path.to_string_lossy());
    job.idempotency_key = Some(prepared.idempotency_key.clone());
    job.review_kind = Some(prepared.review_kind.as_str().into());
    job.feature_id = Some(prepared.feature_id.clone());
    job.section_id = Some(prepared.section_id.clone());
    job.round_kind = Some(prepared.round_kind.as_str().into());
    job.report_path = Some(prepared.report_target.to_string_lossy().into_owned());
    job.initial_prompt = "review".into();
    job.prepared_launch_json = Some(prepared.canonical_json().unwrap());
    job.prepared_launch_sha256 = Some(prepared.prepared_sha256.clone());
    store
        .enqueue_task(&NewTask {
            job,
            public_agent_id: public_id.into(),
            task_kind: TaskKind::Review,
            review_id: Some(format!("{public_id}-id")),
            continuation_of: None,
            repository: prepared.repository.to_string_lossy().into_owned(),
            feature_id: prepared.feature_id.clone(),
            ownership_token: "owner".into(),
            budget,
            retain_partial: false,
        })
        .unwrap();
}

impl RuntimeFactory for BudgetFactory {
    fn spawn(
        &self,
        _job: &review_store::Job,
        sink: Arc<dyn LifecycleSink>,
    ) -> io::Result<Arc<dyn ManagedRuntime>> {
        let runtime = Arc::new(BudgetRuntime {
            sink,
            sequence: AtomicU64::new(1),
            stop_calls: AtomicUsize::new(0),
        });
        *self.runtime.lock().unwrap() = Some(Arc::clone(&runtime));
        Ok(runtime)
    }
}

#[test]
fn v2_review_attempt_enforces_effective_turn_budget_and_releases_slot() {
    let directory = tempfile::tempdir().unwrap();
    let prepared = prepare_review(&directory, "review-budget");
    let store = Arc::new(Store::open(directory.path().join("review-budget.sqlite3")).unwrap());
    enqueue_v2_review(
        &store,
        "review-budget-attempt",
        "review-budget",
        &prepared,
        BudgetRequest::Limits(EffectiveBudget {
            wall_time_ms: 10_000,
            max_turns: 1,
            max_tool_calls: 10,
            max_context_bytes: 1_048_576,
            max_result_bytes: 1_048_576,
            max_artifact_bytes: 16_777_216,
        }),
    );
    let runtime = Arc::new(Mutex::new(None));
    let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
    let scheduler = Scheduler::new(
        "review-budget-owner",
        Arc::clone(&store),
        Arc::new(BudgetFactory {
            runtime: Arc::clone(&runtime),
        }),
        SchedulerConfig::default(),
    )
    .unwrap()
    .with_ledger(
        ledger,
        InternalLedgerMcpConfig {
            command: PathBuf::from("/usr/bin/false"),
            socket: directory.path().join("review-budget.sock"),
            runtime_sha256: None,
        },
    )
    .unwrap();
    assert_eq!(
        scheduler.start_ready().unwrap(),
        vec!["review-budget-attempt"]
    );
    let runtime = runtime.lock().unwrap().clone().unwrap();
    runtime.emit_turn("turn-1");
    runtime.emit_turn("turn-1");
    thread::sleep(Duration::from_millis(80));
    assert!(store
        .task_result("review-budget-attempt")
        .unwrap()
        .is_none());
    runtime.emit_turn("turn-2");
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let result = loop {
        if let Some(result) = store.task_result("review-budget-attempt").unwrap() {
            break result;
        }
        assert!(std::time::Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(result.result.outcome, TaskOutcome::BudgetExhausted);
    assert!(result
        .result
        .residual_gaps
        .contains(&"TURN_BUDGET_EXHAUSTED".into()));
    assert_eq!(
        store
            .task_by_execution_agent_id("review-budget-attempt")
            .unwrap()
            .unwrap()
            .phase,
        TaskPhase::Terminal
    );
    assert!(runtime.stop_calls.load(Ordering::Acquire) >= 1);
    assert_eq!(scheduler.active_count(), 0);
}

struct RegisteredFailureRuntime {
    worktree: PathBuf,
    stop_calls: AtomicUsize,
    worktree_existed_at_stop: AtomicBool,
}

impl ManagedRuntime for RegisteredFailureRuntime {
    fn identity(&self) -> Option<zcode_driver::ProcessIdentity> {
        None
    }

    fn stop(&self, _grace: Duration) -> RuntimeTerminal {
        self.stop_calls.fetch_add(1, Ordering::AcqRel);
        self.worktree_existed_at_stop
            .store(self.worktree.exists(), Ordering::Release);
        RuntimeTerminal::Stopped(StopOutcome::AlreadyExited(ChildExit::Exited(Some(0))))
    }

    fn wait_terminal(&self, _timeout: Duration) -> Option<RuntimeTerminal> {
        None
    }

    fn bootstrap_session_with_mcp(
        &self,
        _job: &review_store::Job,
        _servers: &[StdioMcpServer],
        _timeout: Duration,
    ) -> Result<SessionReady, zcode_reviewd::RuntimeCommandError> {
        Ok(SessionReady {
            session_id: "registered-failure-session".into(),
            initial_turn_id: Some("turn-1".into()),
            observed_model: None,
        })
    }

    fn turn_snapshot(&self) -> TurnSnapshot {
        TurnSnapshot {
            generation: 1,
            active: true,
            boundary: None,
        }
    }
}

struct TriggeringReviewFactory {
    database: PathBuf,
    trigger_sql: String,
    runtime: Arc<Mutex<Option<Arc<RegisteredFailureRuntime>>>>,
}

impl RuntimeFactory for TriggeringReviewFactory {
    fn spawn(
        &self,
        job: &review_store::Job,
        _sink: Arc<dyn LifecycleSink>,
    ) -> io::Result<Arc<dyn ManagedRuntime>> {
        rusqlite::Connection::open(&self.database)
            .and_then(|connection| connection.execute_batch(&self.trigger_sql))
            .map_err(io::Error::other)?;
        let runtime = Arc::new(RegisteredFailureRuntime {
            worktree: PathBuf::from(&job.workspace_path),
            stop_calls: AtomicUsize::new(0),
            worktree_existed_at_stop: AtomicBool::new(false),
        });
        *self.runtime.lock().unwrap() = Some(Arc::clone(&runtime));
        Ok(runtime)
    }
}

fn assert_registered_review_failure_converges(
    attempt: &str,
    trigger_sql: String,
    expected_reason: &str,
) {
    let directory = tempfile::tempdir().unwrap();
    let prepared = prepare_review(&directory, attempt);
    let database = directory.path().join(format!("{attempt}.sqlite3"));
    let store = Arc::new(Store::open(&database).unwrap());
    enqueue_v2_review(
        &store,
        attempt,
        &format!("public-{attempt}"),
        &prepared,
        BudgetRequest::Omitted,
    );
    let runtime = Arc::new(Mutex::new(None));
    let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
    let scheduler = Scheduler::new(
        format!("owner-{attempt}"),
        Arc::clone(&store),
        Arc::new(TriggeringReviewFactory {
            database,
            trigger_sql,
            runtime: Arc::clone(&runtime),
        }),
        SchedulerConfig::default(),
    )
    .unwrap()
    .with_ledger(
        ledger,
        InternalLedgerMcpConfig {
            command: PathBuf::from("/usr/bin/false"),
            socket: directory.path().join(format!("{attempt}.sock")),
            runtime_sha256: None,
        },
    )
    .unwrap();

    assert!(scheduler.start_ready().is_err());
    let runtime = runtime.lock().unwrap().clone().unwrap();
    assert_eq!(runtime.stop_calls.load(Ordering::Acquire), 1);
    assert!(runtime.worktree_existed_at_stop.load(Ordering::Acquire));
    assert!(!prepared.worktree.path.exists());
    let listed = Command::new("git")
        .args(["worktree", "list", "--porcelain"])
        .current_dir(&prepared.repository)
        .output()
        .unwrap();
    assert!(listed.status.success());
    assert!(!String::from_utf8_lossy(&listed.stdout)
        .contains(prepared.worktree.path.to_string_lossy().as_ref()));

    let result = store.task_result(attempt).unwrap().unwrap();
    assert_eq!(result.result.outcome, TaskOutcome::Failed);
    assert!(result
        .result
        .residual_gaps
        .contains(&expected_reason.to_owned()));
    assert_eq!(
        store
            .task_by_execution_agent_id(attempt)
            .unwrap()
            .unwrap()
            .phase,
        TaskPhase::Terminal
    );
    assert!(store.get_job(attempt).unwrap().unwrap().state.is_terminal());
    assert_eq!(store.active_count().unwrap(), 0);
    assert_eq!(scheduler.active_count(), 0);

    scheduler.close_job(attempt).unwrap();
    scheduler.reap_job(attempt).unwrap();
    assert_eq!(store.task_result(attempt).unwrap().unwrap(), result);
}

#[test]
fn review_runtime_provenance_failure_stops_cleans_and_persists_one_result() {
    assert_registered_review_failure_converges(
        "review-provenance-failure",
        "CREATE TRIGGER fail_review_runtime BEFORE UPDATE OF zcode_session_id ON review_provenance
         WHEN NEW.agent_id='review-provenance-failure'
         BEGIN SELECT RAISE(FAIL, 'scripted provenance failure'); END;"
            .into(),
        "REPORT_PROVENANCE_FAILED",
    );
}

#[test]
fn review_mark_running_failure_stops_cleans_and_persists_one_result() {
    assert_registered_review_failure_converges(
        "review-mark-running-failure",
        "CREATE TRIGGER fail_review_mark_running BEFORE UPDATE OF state ON agents
         WHEN NEW.agent_id='review-mark-running-failure' AND NEW.state='RUNNING'
         BEGIN SELECT RAISE(FAIL, 'scripted mark running failure'); END;"
            .into(),
        "STORE_START_FAILED",
    );
}

#[test]
fn prepared_launch_is_the_only_workspace_consumed_by_scheduler_adapter() {
    let directory = tempfile::tempdir().unwrap();
    let repository = create_repository(&directory);
    let head = git(&repository, &["rev-parse", "HEAD"]);
    let manifest = ReviewManifest {
        schema: "sectioned-zcode-review/v1".into(),
        review_kind: ReviewKind::Code,
        feature_id: "feature".into(),
        section_id: "S04".into(),
        round_kind: RoundKind::InitialBounded,
        repository: repository.clone(),
        base_ref: head.clone(),
        head_ref: head,
        plan_path: ".agent-work/PLAN.md".into(),
        context_paths: Vec::new(),
        scope_paths: vec!["src".into()],
        forbidden_input_globs: Vec::new(),
        validation_commands: Default::default(),
        report_target: ".agent-work/reviews/feature/S04/report.md".into(),
        scratch_root: ".agent-work/scratch/jobs".into(),
        model: None,
        fresh_session: true,
        network_policy: NetworkPolicy::Deny,
        scratch_policy: ScratchPolicy::Isolated,
        idempotency_key: "feature:S04:initial".into(),
    };
    let prepared = ReviewPreparer.prepare(&manifest).unwrap();
    let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
    let scheduler = Scheduler::new(
        "prepared-test",
        Arc::clone(&store),
        Arc::new(UnusedFactory),
        SchedulerConfig::default(),
    )
    .unwrap();
    let job = scheduler
        .enqueue_prepared("prepared-job", "review the accepted section", &prepared)
        .unwrap();
    assert_eq!(job.workspace_path, prepared.worktree.path.to_string_lossy());
    assert_eq!(
        job.prepared_launch_sha256,
        Some(prepared.prepared_sha256.clone())
    );
    assert_eq!(
        job.prepared_launch_json.as_deref(),
        Some(prepared.canonical_json().unwrap().as_str())
    );
    assert_eq!(store.active_count().unwrap(), 0);

    let same = scheduler
        .enqueue_prepared("different-agent", "different ignored prompt", &prepared)
        .unwrap();
    assert_eq!(same.agent_id, "prepared-job");

    let mut changed = manifest;
    changed.scope_paths = vec!["src/lib.rs".into()];
    assert!(ReviewPreparer.prepare(&changed).is_err());

    fs::write(
        prepared.repository.join("src/lib.rs"),
        "pub fn unexpected_user_change() {}\n",
    )
    .unwrap();
    assert!(scheduler
        .enqueue_prepared("after-source-change", "review", &prepared)
        .is_err());
}

#[test]
fn production_factory_rejects_unprepared_job_before_command_construction() {
    let called = Arc::new(AtomicBool::new(false));
    let callback_called = Arc::clone(&called);
    let factory = CommandRuntimeFactory::new_prepared(
        move |_job: &review_store::Job| -> io::Result<Command> {
            callback_called.store(true, Ordering::Release);
            Ok(Command::new("/usr/bin/false"))
        },
    );
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path().join("raw.sqlite3")).unwrap();
    let raw = store
        .enqueue_job(&review_store::NewJob::new("raw", "/unprepared"))
        .unwrap();
    assert!(factory.spawn(&raw, Arc::new(NullSink)).is_err());
    assert!(!called.load(Ordering::Acquire));
}

struct CapturingRuntime {
    servers: Arc<Mutex<Vec<StdioMcpServer>>>,
}

impl ManagedRuntime for CapturingRuntime {
    fn identity(&self) -> Option<zcode_driver::ProcessIdentity> {
        None
    }

    fn stop(&self, _grace: Duration) -> RuntimeTerminal {
        RuntimeTerminal::Completed(StopOutcome::AlreadyExited(ChildExit::Exited(Some(0))))
    }

    fn wait_terminal(&self, _timeout: Duration) -> Option<RuntimeTerminal> {
        None
    }

    fn bootstrap_session_with_mcp(
        &self,
        _job: &review_store::Job,
        servers: &[StdioMcpServer],
        _timeout: Duration,
    ) -> Result<SessionReady, zcode_reviewd::RuntimeCommandError> {
        *self.servers.lock().unwrap() = servers.to_vec();
        Ok(SessionReady {
            session_id: "real-session-id".into(),
            initial_turn_id: Some("turn-1".into()),
            observed_model: Some("requested-model".into()),
        })
    }

    fn turn_snapshot(&self) -> TurnSnapshot {
        TurnSnapshot {
            generation: 1,
            active: false,
            boundary: Some(TurnBoundary::Completed),
        }
    }
}

struct CapturingFactory {
    servers: Arc<Mutex<Vec<StdioMcpServer>>>,
    spawn_gate: SpawnGate,
}

struct SpawnGate {
    ledger: Arc<LedgerManager>,
    agent_id: String,
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
    observed_valid: Arc<AtomicBool>,
}

impl RuntimeFactory for CapturingFactory {
    fn spawn(
        &self,
        _job: &review_store::Job,
        _sink: Arc<dyn LifecycleSink>,
    ) -> io::Result<Arc<dyn ManagedRuntime>> {
        let valid = self
            .spawn_gate
            .ledger
            .verify_artifact(&self.spawn_gate.agent_id, 0)
            .is_ok_and(|artifact| artifact.integrity == review_ledger::ArtifactIntegrity::Valid);
        self.spawn_gate
            .observed_valid
            .store(valid, Ordering::Release);
        self.spawn_gate.entered.wait();
        self.spawn_gate.release.wait();
        Ok(Arc::new(CapturingRuntime {
            servers: Arc::clone(&self.servers),
        }))
    }
}

#[test]
fn prepared_job_gets_one_job_scoped_internal_ledger_and_verified_report() {
    let directory = tempfile::tempdir().unwrap();
    let repository = create_repository(&directory);
    fs::create_dir_all(repository.join(".agent-work/reviews/feature/S05")).unwrap();
    fs::create_dir_all(repository.join(".agent-work/scratch/jobs")).unwrap();
    let head = git(&repository, &["rev-parse", "HEAD"]);
    let manifest = ReviewManifest {
        schema: "sectioned-zcode-review/v1".into(),
        review_kind: ReviewKind::Code,
        feature_id: "feature".into(),
        section_id: "S05".into(),
        round_kind: RoundKind::InitialBounded,
        repository: repository.clone(),
        base_ref: head.clone(),
        head_ref: head,
        plan_path: ".agent-work/PLAN.md".into(),
        context_paths: Vec::new(),
        scope_paths: vec!["src".into()],
        forbidden_input_globs: Vec::new(),
        validation_commands: Default::default(),
        report_target: ".agent-work/reviews/feature/S05/GLM-RAW.md".into(),
        scratch_root: ".agent-work/scratch/jobs".into(),
        model: Some("requested-model".into()),
        fresh_session: true,
        network_policy: NetworkPolicy::Deny,
        scratch_policy: ScratchPolicy::Isolated,
        idempotency_key: "feature:S05:initial".into(),
    };
    let prepared = ReviewPreparer.prepare(&manifest).unwrap();
    let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
    let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
    let captured = Arc::new(Mutex::new(Vec::new()));
    let spawn_entered = Arc::new(Barrier::new(2));
    let spawn_release = Arc::new(Barrier::new(2));
    let spawn_observed_valid = Arc::new(AtomicBool::new(false));
    let scheduler = Scheduler::new(
        "ledger-test",
        Arc::clone(&store),
        Arc::new(CapturingFactory {
            servers: Arc::clone(&captured),
            spawn_gate: SpawnGate {
                ledger: Arc::clone(&ledger),
                agent_id: "ledger-job".into(),
                entered: Arc::clone(&spawn_entered),
                release: Arc::clone(&spawn_release),
                observed_valid: Arc::clone(&spawn_observed_valid),
            },
        }),
        SchedulerConfig::default(),
    )
    .unwrap()
    .with_ledger(
        Arc::clone(&ledger),
        InternalLedgerMcpConfig {
            command: PathBuf::from("/usr/bin/false"),
            socket: directory.path().join("reviewd.sock"),
            runtime_sha256: Some("c".repeat(64)),
        },
    )
    .unwrap();
    scheduler
        .enqueue_prepared("ledger-job", "review", &prepared)
        .unwrap();
    let initial = fs::read_to_string(&prepared.report_target).unwrap();
    assert!(initial.contains("FINALIZED: false"));
    assert!(initial.contains("not\\_observed"));
    fs::write(&prepared.report_target, "substituted before claim").unwrap();
    let starter = {
        let scheduler = scheduler.clone();
        thread::spawn(move || scheduler.start_ready())
    };
    spawn_entered.wait();
    assert!(spawn_observed_valid.load(Ordering::Acquire));
    assert!(!fs::read_to_string(&prepared.report_target)
        .unwrap()
        .contains("substituted"));
    spawn_release.wait();
    assert_eq!(starter.join().unwrap().unwrap(), vec!["ledger-job"]);
    for _ in 0..100 {
        if store
            .get_job("ledger-job")
            .unwrap()
            .is_some_and(|job| job.state.is_terminal())
        {
            break;
        }
        thread::sleep(Duration::from_millis(2));
    }
    let servers = captured.lock().unwrap().clone();
    assert_eq!(servers.len(), 1);
    assert_eq!(servers[0].name, "review-ledger");
    assert_eq!(servers[0].command, "/usr/bin/false");
    assert_eq!(
        servers[0].args,
        vec![
            "--ledger-mcp",
            "--socket",
            directory.path().join("reviewd.sock").to_str().unwrap(),
            "--agent-id",
            "ledger-job"
        ]
    );
    scheduler
        .call_review_tool(
            "ledger-job",
            REVIEW_CHECKPOINT,
            serde_json::json!({
                "checkpoint_id":"cp-1","stage":"inspection","summary":"observed",
                "inspected":[],"commands":[],"open_questions":[],"remaining_scope":[]
            }),
        )
        .unwrap();
    scheduler
        .call_review_tool(
            "ledger-job",
            REVIEW_FINALIZE,
            serde_json::json!({
                "signal":"no_findings_observed","summary":"clean",
                "coverage":{"covered":["scope"],"not_covered":[]},
                "uncertainties":[],"recommended_next_actions":[]
            }),
        )
        .unwrap();
    let artifact = scheduler
        .verify_review_artifact("ledger-job", 256)
        .unwrap()
        .unwrap();
    assert_eq!(artifact.integrity, review_ledger::ArtifactIntegrity::Valid);
    let final_report = fs::read_to_string(&prepared.report_target).unwrap();
    assert!(final_report.contains("real\\-session\\-id"));
    assert!(final_report.contains("requested\\-model"));
    assert!(final_report.contains("FINALIZED: true"));
}

fn create_repository(directory: &TempDir) -> PathBuf {
    let repository = directory.path().join("repository");
    fs::create_dir_all(repository.join("src")).unwrap();
    fs::write(repository.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    git(&repository, &["init"]);
    git(&repository, &["config", "user.name", "S04 Test"]);
    git(
        &repository,
        &["config", "user.email", "s04@example.invalid"],
    );
    git(&repository, &["add", "src/lib.rs"]);
    git(&repository, &["commit", "-m", "fixture"]);
    fs::create_dir_all(repository.join(".agent-work")).unwrap();
    fs::write(repository.join(".agent-work/PLAN.md"), "# plan\n").unwrap();
    fs::canonicalize(repository).unwrap()
}

fn git(repository: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().into()
}
