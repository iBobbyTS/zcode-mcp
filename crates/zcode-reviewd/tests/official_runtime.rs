use review_ledger::{ArtifactIntegrity, LedgerManager};
use review_preparation::{NetworkPolicy, ReviewKind, ReviewManifest, RoundKind, ScratchPolicy};
use review_store::{Job, JobState, MessageState, PendingRequestState, Store};
use std::{
    env, fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    time::Duration,
};
use zcode_driver::observe_process_group;
use zcode_driver::Inbound;
use zcode_protocol::{WireMessage, INTERACTION_REQUEST_PERMISSION, INTERACTION_REQUEST_USER_INPUT};
use zcode_reviewd::{
    rpc::{RpcServer, RpcService, ServerOptions},
    CommandRuntimeFactory, InternalLedgerMcpConfig, RuntimeFactory, Scheduler, SchedulerConfig,
};
use zcode_reviewd::{LifecycleRecord, LifecycleSink, RuntimeEvent, RuntimeOwner};

#[derive(Default)]
struct Records(Mutex<Vec<LifecycleRecord>>);

impl LifecycleSink for Records {
    fn emit(&self, record: LifecycleRecord) {
        self.0.lock().unwrap().push(record);
    }
}

impl Records {
    fn wait_request(&self, method: &str, timeout: Duration) -> Option<(String, serde_json::Value)> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(request) = self.0.lock().unwrap().iter().find_map(|record| {
                let RuntimeEvent::Driver(Inbound::Message(WireMessage::Request(request))) =
                    &record.event
                else {
                    return None;
                };
                (request.method == method).then(|| {
                    (
                        serde_json::to_string(&request.id).unwrap(),
                        request.params.clone(),
                    )
                })
            }) {
                return Some(request);
            }
            if std::time::Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn runtime_path() -> Option<PathBuf> {
    env::var_os("ZCODE_RUNTIME_PATH").map(PathBuf::from)
}

#[test]
fn official_runtime_permission_and_unsupported_input_are_bounded() {
    let Some(path) = runtime_path() else {
        eprintln!("skipped: ZCODE_RUNTIME_PATH is unset");
        return;
    };
    let workspace = tempfile::tempdir().unwrap();
    let denied_target = workspace.path().join("must-not-exist.txt");
    let records = Arc::new(Records::default());
    let owner = RuntimeOwner::spawn(runtime_command(&path).unwrap(), records.clone()).unwrap();
    let identity = owner.identity();
    let prompt = format!(
        "Use the Bash tool to create {} and wait for permission. Do not use any other tool.",
        denied_target.display()
    );
    let ready = owner
        .bootstrap_session(
            workspace.path().to_str().unwrap(),
            &prompt,
            Duration::from_secs(90),
        )
        .unwrap();
    let (correlation, params) = records
        .wait_request(INTERACTION_REQUEST_PERMISSION, Duration::from_secs(90))
        .expect("official runtime did not request permission");
    assert!(params
        .get("options")
        .is_some_and(serde_json::Value::is_array));
    let validated_denial = review_preparation::PolicyLauncher::external_zcode_denial(&params)
        .expect("daemon denial identity must be derived from the permission payload");
    assert!(validated_denial
        .feedback(false)
        .contains("code=external_policy_denied;"));
    assert!(validated_denial
        .fingerprint()
        .contains("family="));
    owner
        .respond_request(
            &correlation,
            "deny",
            None,
            Some(&validated_denial),
            std::time::Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
    owner
        .stop_turn(&ready.session_id, Duration::from_secs(30))
        .unwrap();
    assert!(!denied_target.exists());

    owner
        .send_turn(
            &ready.session_id,
            "Ask me a question with the user-input interaction tool, then wait.",
            Duration::from_secs(90),
        )
        .unwrap();
    let unsupported = records.wait_request(INTERACTION_REQUEST_USER_INPUT, Duration::from_secs(90));
    owner
        .stop_turn(&ready.session_id, Duration::from_secs(30))
        .unwrap();
    let terminal = owner.stop(Duration::from_secs(2));
    assert!(observe_process_group(identity.pgid).unwrap().is_empty());
    eprintln!(
        "official permission denied target_absent=true unsupported_input={} terminal={terminal:?}",
        unsupported.is_some()
    );
}

#[test]
fn official_runtime_full_review_uses_ledger_queue_interrupt_and_reaps() {
    let Some(path) = runtime_path() else {
        eprintln!("skipped: ZCODE_RUNTIME_PATH is unset");
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let repository = directory.path().join("repository");
    fs::create_dir_all(repository.join("src")).unwrap();
    fs::write(
        repository.join("src/lib.rs"),
        "pub fn reviewed() -> bool { true }\n",
    )
    .unwrap();
    git(&repository, &["init"]);
    git(&repository, &["config", "user.name", "S09 Runtime Test"]);
    git(
        &repository,
        &["config", "user.email", "s09-runtime@example.invalid"],
    );
    git(&repository, &["add", "src/lib.rs"]);
    git(&repository, &["commit", "-m", "fixture"]);
    fs::write(repository.join(".git/info/exclude"), ".agent-work/\n").unwrap();
    fs::create_dir_all(repository.join(".agent-work/reviews")).unwrap();
    fs::create_dir_all(repository.join(".agent-work/scratch/jobs")).unwrap();
    fs::write(
        repository.join(".agent-work/PLAN.md"),
        "# S09 bounded review\n",
    )
    .unwrap();
    let repository = fs::canonicalize(repository).unwrap();
    let head = git(&repository, &["rev-parse", "HEAD"]);
    let report = repository.join(".agent-work/reviews/official.md");
    let manifest = ReviewManifest {
        schema: "sectioned-zcode-review/v1".into(),
        review_kind: ReviewKind::Code,
        feature_id: "official-runtime".into(),
        section_id: "S09".into(),
        round_kind: RoundKind::InitialBounded,
        repository: repository.clone(),
        base_ref: head.clone(),
        head_ref: head,
        plan_path: ".agent-work/PLAN.md".into(),
        context_paths: vec![],
        scope_paths: vec!["src/lib.rs".into()],
        forbidden_input_globs: vec![".agent-work/reviews/*".into()],
        validation_commands: Default::default(),
        report_target: ".agent-work/reviews/official.md".into(),
        scratch_root: ".agent-work/scratch/jobs".into(),
        model: Some("zai/glm-5.3".into()),
        fresh_session: true,
        network_policy: NetworkPolicy::Deny,
        scratch_policy: ScratchPolicy::Isolated,
        idempotency_key: "official-runtime:S09:full".into(),
    };

    let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
    let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
    let factory = Arc::new(CommandRuntimeFactory::new_prepared(move |_job: &Job| {
        runtime_command(&path)
    }));
    let runtime_factory: Arc<dyn RuntimeFactory> = factory;
    let socket_root = directory.path().join("socket");
    fs::create_dir(&socket_root).unwrap();
    fs::set_permissions(&socket_root, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = socket_root.join("private.sock");
    let scheduler = Scheduler::new(
        "s09-official",
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
        ledger,
        InternalLedgerMcpConfig {
            command: fs::canonicalize(env!("CARGO_BIN_EXE_zcode-reviewd")).unwrap(),
            socket,
            runtime_sha256: Some(
                "9318f60fb8c2c3bc83ce62da10220ebcdc9a99786df0a9abb1a4435ba66e4274".into(),
            ),
        },
    )
    .unwrap();
    let service = Arc::new(RpcService::new(scheduler.clone(), Arc::clone(&store)).unwrap());
    let _server = RpcServer::bind(
        socket_root.join("private.sock"),
        service,
        ServerOptions::default(),
    )
    .unwrap();
    let spawned = zcode_reviewd::orchestration::ReviewJobOrchestrator::new(scheduler.clone())
        .unwrap()
        .spawn_review(&manifest)
        .unwrap();
    let agent_id = spawned.job.agent_id;
    let running = store.get_job(&agent_id).unwrap().unwrap();
    assert_eq!(running.state, JobState::Running);
    assert!(running
        .zcode_session_id
        .as_deref()
        .is_some_and(|id| id.starts_with("sess_")));
    let identity = running.process_identity.clone().unwrap();
    assert!(report.is_file());
    assert!(fs::read_to_string(&report)
        .unwrap()
        .contains("FINALIZED: false"));

    let (before_interrupt, stop_boundaries_before) = scheduler
        .active_turn_observation(&agent_id)
        .expect("official runtime must be active before interrupt");
    assert!(before_interrupt.active);

    let interrupted = scheduler
        .message_job(
            &agent_id,
            "official-interrupt",
            "interrupt_and_continue",
            "Continue the bounded review, call the required ledger tools exactly once, and finalize.",
        )
        .unwrap();
    assert_eq!(
        interrupted,
        zcode_reviewd::MessageDisposition::InterruptedThenDelivered
    );
    let (after_interrupt, stop_boundaries_after) = scheduler
        .active_turn_observation(&agent_id)
        .expect("official runtime must remain active for the delivered next turn");
    assert!(after_interrupt.active);
    assert_eq!(stop_boundaries_after, stop_boundaries_before + 1);

    let deadline = std::time::Instant::now() + Duration::from_secs(240);
    let mut responded = std::collections::HashSet::new();
    let terminal = loop {
        for request in store.pending_requests(&agent_id).unwrap() {
            if request.request_type == "permission"
                && request.state == PendingRequestState::Pending
                && responded.insert(request.request_id.clone())
            {
                let payload: serde_json::Value =
                    serde_json::from_str(&request.payload_json).unwrap();
                let prepared: review_preparation::PreparedLaunchSpec = serde_json::from_str(
                    store
                        .get_job(&agent_id)
                        .unwrap()
                        .unwrap()
                        .prepared_launch_json
                        .as_deref()
                        .unwrap(),
                )
                .unwrap();
                let policy = prepared
                    .launcher()
                    .unwrap()
                    .decide_zcode_permission(&payload, review_preparation::ExternalDecision::Allow);
                eprintln!(
                    "official permission tool={} local_allowed={} reason={}",
                    payload
                        .get("toolName")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("missing"),
                    policy.allowed,
                    policy.reason
                );
                let outcome = scheduler
                    .respond_job(&agent_id, &request.request_id, "allow", None)
                    .unwrap();
                eprintln!(
                    "official permission effective={} overrode={}",
                    outcome.effective_decision, outcome.policy_overrode
                );
            }
        }
        let job = store.get_job(&agent_id).unwrap().unwrap();
        if job.state.is_terminal() {
            break job;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "official review timed out: state={:?} failure_code={:?}",
            job.state,
            job.failure_code
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(
        terminal.state,
        JobState::Completed,
        "official review failed: code={:?} message={:?}",
        terminal.failure_code,
        terminal.failure_message
    );
    assert_eq!(
        store.message("official-interrupt").unwrap().unwrap().state,
        MessageState::Delivered
    );
    let snapshot = store.review_snapshot(&agent_id).unwrap().unwrap();
    assert!(snapshot.report.finalized);
    assert!(!snapshot.checkpoints.is_empty());
    assert!(!snapshot.validations.is_empty());
    assert!(snapshot.finalization.is_some());
    assert_eq!(
        snapshot.provenance.observed_model.as_deref(),
        Some("glm-5.3")
    );
    let artifact = scheduler
        .verify_review_artifact(&agent_id, 256)
        .unwrap()
        .unwrap();
    assert_eq!(artifact.integrity, ArtifactIntegrity::Valid);
    assert_eq!(artifact.expected_sha256, artifact.actual_sha256);
    assert_eq!(artifact.expected_bytes, artifact.actual_bytes);
    assert!(fs::read_to_string(&report)
        .unwrap()
        .contains("FINALIZED: true"));
    assert!(observe_process_group(identity.process_group_id)
        .unwrap()
        .is_empty());
    assert!(scheduler.reap_job(&agent_id).unwrap().is_terminal());
    assert!(store
        .get_job(&agent_id)
        .unwrap()
        .is_some_and(|job| job.reaped_at.is_some()));
    eprintln!(
        "official full review permissions={} checkpoints={} finalized=true reaped=true",
        responded.len(),
        snapshot.checkpoints.len()
    );
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

fn runtime_command(path: &Path) -> io::Result<Command> {
    if matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("js" | "cjs" | "mjs")
    ) {
        let mut command = Command::new("node");
        command.arg(path).arg("app-server");
        Ok(command)
    } else {
        Ok(Command::new(path))
    }
}

#[test]
fn official_runtime_current_driver_session_seam() {
    let Some(path) = runtime_path() else {
        eprintln!("skipped: ZCODE_RUNTIME_PATH is unset");
        return;
    };
    assert!(path.is_file(), "ZCODE_RUNTIME_PATH must be a regular file");
    let workspace = tempfile::tempdir().unwrap();
    let records = Arc::new(Records::default());
    let owner = RuntimeOwner::spawn(runtime_command(&path).unwrap(), records.clone()).unwrap();
    let identity = owner.identity();

    let ready = owner
        .bootstrap_session(
            workspace.path().to_str().unwrap(),
            "Reply with a short acknowledgement and do not use tools.",
            Duration::from_secs(90),
        )
        .unwrap();
    assert!(!ready.session_id.is_empty());

    let stopped = owner
        .stop_turn(&ready.session_id, Duration::from_secs(30))
        .unwrap();
    assert!(!stopped.active);

    let second_turn = owner
        .send_turn(
            &ready.session_id,
            "Reply with one word and do not use tools.",
            Duration::from_secs(90),
        )
        .unwrap();
    let _ = second_turn;
    let interrupted = owner
        .stop_turn(&ready.session_id, Duration::from_secs(30))
        .unwrap();
    assert!(!interrupted.active);

    let close_result = owner.close_session(&ready.session_id, Duration::from_secs(10));
    let terminal = owner.stop(Duration::from_secs(2));
    assert!(observe_process_group(identity.pgid).unwrap().is_empty());
    assert!(!records.0.lock().unwrap().is_empty());
    eprintln!(
        "official runtime session_present=true model={:?} records={} close={close_result:?} terminal={terminal:?}",
        ready.observed_model,
        records.0.lock().unwrap().len()
    );
}
