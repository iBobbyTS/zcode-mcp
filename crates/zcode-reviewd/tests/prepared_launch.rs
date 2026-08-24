use review_ledger::{LedgerManager, REVIEW_CHECKPOINT, REVIEW_FINALIZE};
use review_preparation::{
    NetworkPolicy, ReviewKind, ReviewManifest, ReviewPreparer, RoundKind, ScratchPolicy,
};
use review_store::Store;
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use tempfile::TempDir;
use zcode_driver::{ChildExit, StopOutcome};
use zcode_protocol::StdioMcpServer;
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
            observed_model: Some("observed-model".into()),
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
}

impl RuntimeFactory for CapturingFactory {
    fn spawn(
        &self,
        _job: &review_store::Job,
        _sink: Arc<dyn LifecycleSink>,
    ) -> io::Result<Arc<dyn ManagedRuntime>> {
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
    let scheduler = Scheduler::new(
        "ledger-test",
        Arc::clone(&store),
        Arc::new(CapturingFactory {
            servers: Arc::clone(&captured),
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
    assert!(initial.contains("not_observed"));
    scheduler.start_ready().unwrap();
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
    assert!(final_report.contains("real-session-id"));
    assert!(final_report.contains("observed-model"));
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
