use review_ledger::{
    ArtifactIntegrity, LedgerManager, REVIEW_CHECKPOINT, REVIEW_FINALIZE, REVIEW_FINDING_UPSERT,
    REVIEW_VALIDATION_RECORD,
};
use review_preparation::{NetworkPolicy, ReviewKind, ReviewManifest, RoundKind, ScratchPolicy};
use review_store::{Job, JobState, MessageState, PendingRequestState, Store};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use zcode_driver::observe_process_group;
use zcode_reviewd::{
    rpc::{
        ArtifactIntegrityView, MessageInput, RespondInput, ResponseDecision, ResultQuery,
        ReviewToolInput, RpcMethod, RpcService, RpcSuccess,
    },
    CommandRuntimeFactory, InternalLedgerMcpConfig, RuntimeFactory, Scheduler, SchedulerConfig,
};

struct Fixture {
    _directory: tempfile::TempDir,
    repository: PathBuf,
    head: String,
    store: Arc<Store>,
    scheduler: Scheduler,
    service: RpcService,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let repository = directory.path().join("repository");
        fs::create_dir_all(repository.join("src")).unwrap();
        fs::write(repository.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        git(&repository, &["init"]);
        git(&repository, &["config", "user.name", "S06 Test"]);
        git(
            &repository,
            &["config", "user.email", "s06@example.invalid"],
        );
        git(&repository, &["add", "src/lib.rs"]);
        git(&repository, &["commit", "-m", "fixture"]);
        fs::write(repository.join(".git/info/exclude"), ".agent-work/\n").unwrap();
        fs::create_dir_all(repository.join(".agent-work/context")).unwrap();
        fs::create_dir_all(repository.join(".agent-work/reviews/feature/S06")).unwrap();
        fs::create_dir_all(repository.join(".agent-work/scratch/jobs")).unwrap();
        fs::write(
            repository.join(".agent-work/PLAN.md"),
            "# Current S06 plan\n",
        )
        .unwrap();
        fs::write(
            repository.join(".agent-work/context/S06.md"),
            "# Current bounded context\n",
        )
        .unwrap();
        let repository = fs::canonicalize(repository).unwrap();
        let head = git(&repository, &["rev-parse", "HEAD"]);
        let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
        let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
        let runtime = workspace_fake_runtime();
        let factory = Arc::new(CommandRuntimeFactory::new_prepared(move |job: &Job| {
            let prepared: review_preparation::PreparedLaunchSpec = serde_json::from_str(
                job.prepared_launch_json
                    .as_deref()
                    .ok_or_else(|| io::Error::other("prepared launch missing"))?,
            )
            .map_err(io::Error::other)?;
            let mode = if prepared.section_id == "CRASH" {
                "crash"
            } else {
                "review-flow"
            };
            let mut command = Command::new(&runtime);
            command
                .arg(mode)
                .env(
                    "ZCODE_FAKE_SESSION_ID",
                    format!("fake-session-{}", job.agent_id),
                )
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            Ok(command)
        }));
        let runtime_factory: Arc<dyn RuntimeFactory> = factory;
        let scheduler = Scheduler::new(
            "s06-fixture",
            Arc::clone(&store),
            runtime_factory,
            SchedulerConfig {
                global_max_agents: 2,
                per_workspace_max_agents: 2,
                stop_grace: Duration::from_millis(100),
                command_timeout: Duration::from_secs(2),
            },
        )
        .unwrap()
        .with_ledger(
            ledger,
            InternalLedgerMcpConfig {
                command: PathBuf::from("/usr/bin/false"),
                socket: directory.path().join("private.sock"),
                runtime_sha256: Some("f".repeat(64)),
            },
        )
        .unwrap();
        let service = RpcService::new(scheduler.clone(), Arc::clone(&store)).unwrap();
        Self {
            _directory: directory,
            repository,
            head,
            store,
            scheduler,
            service,
        }
    }

    fn manifest(&self, suffix: &str, section: &str) -> ReviewManifest {
        ReviewManifest {
            schema: "sectioned-zcode-review/v1".into(),
            review_kind: if suffix.contains("plan") {
                ReviewKind::Plan
            } else {
                ReviewKind::Code
            },
            feature_id: "feature".into(),
            section_id: section.into(),
            round_kind: RoundKind::InitialBounded,
            repository: self.repository.clone(),
            base_ref: self.head.clone(),
            head_ref: self.head.clone(),
            plan_path: ".agent-work/PLAN.md".into(),
            context_paths: vec![".agent-work/context/S06.md".into()],
            scope_paths: vec!["src".into()],
            forbidden_input_globs: vec![".agent-work/reviews/*".into()],
            validation_commands: Default::default(),
            report_target: format!(".agent-work/reviews/feature/S06/{suffix}.md").into(),
            scratch_root: ".agent-work/scratch/jobs".into(),
            model: Some("fixture-model".into()),
            fresh_session: true,
            network_policy: NetworkPolicy::Deny,
            scratch_policy: ScratchPolicy::Isolated,
            idempotency_key: format!("feature:S06:{suffix}"),
        }
    }

    fn spawn(&self, manifest: ReviewManifest) -> (String, bool, bool) {
        match self
            .service
            .dispatch(RpcMethod::SpawnReview { manifest })
            .unwrap()
        {
            RpcSuccess::ReviewSpawned {
                job,
                resumed_existing,
                counts_as_independent,
                capabilities,
                ..
            } => {
                assert!(!capabilities.public_mcp);
                assert!(!capabilities.live_steer);
                assert!(!capabilities.resume_counts_as_independent);
                assert!(capabilities.fresh_session);
                assert!(job.provenance.is_some());
                (job.agent_id, resumed_existing, counts_as_independent)
            }
            other => panic!("unexpected spawn response: {other:?}"),
        }
    }

    fn wait_pending(&self, agent_id: &str) -> Vec<review_store::StoredPendingRequest> {
        wait_until(|| {
            let pending = self.store.pending_requests(agent_id).unwrap();
            (pending.len() == 2).then_some(pending)
        })
    }

    fn checkpoint_and_finalize(&self, agent_id: &str) {
        self.tool(
            agent_id,
            REVIEW_CHECKPOINT,
            serde_json::json!({
                "checkpoint_id":"scope-1","stage":"inspection","summary":"bounded evidence observed",
                "inspected":[{"path":"src/lib.rs","line_ranges":["1"]}],
                "commands":[],"open_questions":[],"remaining_scope":[]
            }),
        )
        .unwrap();
        self.tool(
            agent_id,
            REVIEW_FINDING_UPSERT,
            serde_json::json!({
                "finding_id":"S06-F1","severity":"P2","confidence":"medium",
                "title":"candidate","locations":[{"path":"src/lib.rs","start_line":1,"end_line":1}],
                "evidence":["observable fixture"],"impact":"bounded","suggested_remediation":"none",
                "status":"open"
            }),
        )
        .unwrap();
        self.tool(
            agent_id,
            REVIEW_FINDING_UPSERT,
            serde_json::json!({
                "finding_id":"S06-F1","severity":"P2","confidence":"high",
                "title":"candidate disproved","locations":[{"path":"src/lib.rs","start_line":1,"end_line":1}],
                "evidence":["later observable fixture"],"impact":"none","suggested_remediation":"none",
                "status":"withdrawn"
            }),
        )
        .unwrap();
        self.tool(
            agent_id,
            REVIEW_VALIDATION_RECORD,
            serde_json::json!({
                "validation_id":"validation-1","command":"cargo test -p fixture","cwd":".",
                "exit_code":0,"duration_ms":1,"stdout_summary":"passed","stderr_summary":"",
                "related_findings":[]
            }),
        )
        .unwrap();
        self.tool(
            agent_id,
            REVIEW_FINALIZE,
            serde_json::json!({
                "signal":"no_findings_observed","summary":"bounded review complete",
                "coverage":{"covered":["src"],"not_covered":[]},
                "uncertainties":[],"recommended_next_actions":[]
            }),
        )
        .unwrap();
    }

    fn tool(
        &self,
        agent_id: &str,
        tool: &str,
        arguments: serde_json::Value,
    ) -> Result<RpcSuccess, zcode_reviewd::rpc::RpcError> {
        self.service
            .dispatch(RpcMethod::ReviewTool(ReviewToolInput {
                agent_id: agent_id.into(),
                tool: tool.into(),
                arguments,
            }))
    }

    fn respond_permission(&self, agent_id: &str) {
        let pending = self.wait_pending(agent_id);
        let permission = pending
            .iter()
            .find(|request| request.request_type == "permission")
            .unwrap();
        self.service
            .dispatch(RpcMethod::Respond(RespondInput {
                agent_id: agent_id.into(),
                request_id: permission.request_id.clone(),
                decision: ResponseDecision::Allow,
                content: None,
            }))
            .unwrap();
    }

    fn wait_terminal(&self, agent_id: &str) -> Job {
        wait_until(|| {
            self.store
                .get_job(agent_id)
                .unwrap()
                .filter(|job| job.state.is_terminal())
        })
    }
}

#[test]
fn full_internal_fake_review_composes_all_accepted_owners_and_two_fresh_sessions() {
    let fixture = Fixture::new();
    let source_before = git(&fixture.repository, &["status", "--porcelain=v1"]);
    let first_manifest = fixture.manifest("code-first", "S06");
    let first_report = fixture.repository.join(&first_manifest.report_target);
    let (first, resumed, independent) = fixture.spawn(first_manifest.clone());
    assert!(!resumed && independent);
    let first_running = fixture.store.get_job(&first).unwrap().unwrap();
    assert!(first_running.initial_prompt.contains("REVIEW_KIND: code"));
    assert!(first_running
        .initial_prompt
        .contains("LEGAL_FINAL_SIGNALS:"));
    let first_worktree = PathBuf::from(first_running.workspace_path.clone());
    let identity = first_running.process_identity.clone().unwrap();
    assert!(fs::read_to_string(&first_report)
        .unwrap()
        .contains("FINALIZED: false"));
    wait_until(|| {
        (observe_process_group(identity.process_group_id)
            .unwrap()
            .len()
            >= 2)
            .then_some(())
    });
    let pending = fixture.wait_pending(&first);
    assert!(pending
        .iter()
        .any(|request| request.request_type == "unsupported_input"));
    assert!(pending
        .iter()
        .any(|request| request.request_type == "permission"));
    assert!(matches!(
        fixture
            .service
            .dispatch(RpcMethod::Message(MessageInput {
                agent_id: first.clone(),
                message_id: "next-turn-1".into(),
                mode: "queue".into(),
                content: "auto_complete queued review turn".into(),
            }))
            .unwrap(),
        RpcSuccess::Message { .. }
    ));
    fixture.checkpoint_and_finalize(&first);

    let (same, resumed, independent) = fixture.spawn(first_manifest);
    assert_eq!(same, first);
    assert!(resumed);
    assert!(!independent);

    fixture.respond_permission(&first);
    let first_done = fixture.wait_terminal(&first);
    assert_eq!(first_done.state, JobState::Completed);
    assert_eq!(
        fixture.store.message("next-turn-1").unwrap().unwrap().state,
        MessageState::Delivered
    );
    assert!(!first_worktree.exists());
    assert!(observe_process_group(identity.process_group_id)
        .unwrap()
        .is_empty());
    let artifact = match fixture
        .service
        .dispatch(RpcMethod::Result(ResultQuery {
            agent_id: first.clone(),
            preview_bytes: 256,
        }))
        .unwrap()
    {
        RpcSuccess::Result {
            artifact: Some(artifact),
            ..
        } => artifact,
        other => panic!("unexpected result: {other:?}"),
    };
    assert_eq!(artifact.integrity, ArtifactIntegrityView::Valid);
    assert_eq!(artifact.expected_sha256, artifact.observed_sha256);
    assert_eq!(artifact.expected_bytes, artifact.observed_bytes);
    assert!(fs::read_to_string(&first_report)
        .unwrap()
        .contains("FINALIZED: true"));

    let second_manifest = fixture.manifest("plan-second", "S06");
    let (second, resumed, independent) = fixture.spawn(second_manifest);
    assert!(!resumed && independent);
    assert_ne!(first, second);
    let second_running = fixture.store.get_job(&second).unwrap().unwrap();
    assert!(second_running.initial_prompt.contains("REVIEW_KIND: plan"));
    assert_ne!(first_done.zcode_session_id, second_running.zcode_session_id);
    assert!(!second_running.initial_prompt.contains(&first));
    assert!(!second_running.initial_prompt.contains("RAW"));
    fixture.checkpoint_and_finalize(&second);
    fixture.respond_permission(&second);
    assert_eq!(fixture.wait_terminal(&second).state, JobState::Completed);
    assert_eq!(
        git(&fixture.repository, &["status", "--porcelain=v1"]),
        source_before
    );

    let first_events = fixture
        .store
        .events_after(
            &first,
            first_done.runtime_agent_id.as_deref().unwrap(),
            0,
            100,
        )
        .unwrap();
    assert!(first_events
        .iter()
        .any(|event| event.event_type == "runtime.completed"));
    assert!(first_events
        .iter()
        .any(|event| event.event_type == "raw.unknown"));
    let unsupported = fixture
        .store
        .pending_requests(&first)
        .unwrap()
        .into_iter()
        .find(|request| request.request_type == "unsupported_input")
        .unwrap();
    assert_eq!(unsupported.state, PendingRequestState::Pending);
    let permission = fixture
        .store
        .pending_requests(&first)
        .unwrap()
        .into_iter()
        .find(|request| request.request_type == "permission")
        .unwrap();
    assert_eq!(permission.state, PendingRequestState::Responded);
}

#[test]
fn interrupt_and_continue_is_an_observable_separate_next_turn_fixture() {
    let fixture = Fixture::new();
    let (agent_id, _, _) = fixture.spawn(fixture.manifest("interrupt", "S06"));
    fixture.wait_pending(&agent_id);
    fixture.checkpoint_and_finalize(&agent_id);
    let disposition = fixture
        .service
        .dispatch(RpcMethod::Message(MessageInput {
            agent_id: agent_id.clone(),
            message_id: "interrupt-next".into(),
            mode: "interrupt_and_continue".into(),
            content: "auto_complete interrupt review turn".into(),
        }))
        .unwrap();
    assert!(matches!(
        disposition,
        RpcSuccess::Message {
            disposition: zcode_reviewd::rpc::MessageDispositionView::InterruptedThenDelivered
        }
    ));
    let terminal = fixture.wait_terminal(&agent_id);
    assert_eq!(terminal.state, JobState::Completed);
    let message = fixture.store.message("interrupt-next").unwrap().unwrap();
    assert_eq!(message.state, MessageState::Delivered);
}

#[test]
fn completion_failure_matrix_is_typed_nonclean_and_reaps_runtime_groups() {
    for scenario in ["missing-final", "report-replaced", "source-mutated"] {
        let fixture = Fixture::new();
        let manifest = fixture.manifest(scenario, "S06");
        let report = fixture.repository.join(&manifest.report_target);
        let (agent_id, _, _) = fixture.spawn(manifest);
        let running = fixture.store.get_job(&agent_id).unwrap().unwrap();
        let identity = running.process_identity.clone().unwrap();
        if scenario != "missing-final" {
            fixture.checkpoint_and_finalize(&agent_id);
        }
        if scenario == "report-replaced" {
            fs::write(&report, "substituted final report").unwrap();
        }
        if scenario == "source-mutated" {
            fs::write(
                PathBuf::from(&running.workspace_path).join("src/lib.rs"),
                "pub fn mutated() {}\n",
            )
            .unwrap();
        }
        fixture.respond_permission(&agent_id);
        let failed = fixture.wait_terminal(&agent_id);
        assert_eq!(failed.state, JobState::Failed, "{scenario}");
        assert_eq!(
            failed.failure_code.as_deref(),
            Some(match scenario {
                "missing-final" => "REVIEW_NOT_FINALIZED",
                "report-replaced" => "REVIEW_REPORT_INVALID",
                "source-mutated" => "SOURCE_INTEGRITY_FAILED",
                _ => unreachable!(),
            })
        );
        assert!(observe_process_group(identity.process_group_id)
            .unwrap()
            .is_empty());
        assert!(report.exists());
    }

    for scenario in ["malformed-ledger", "duplicate-final", "cancel"] {
        let fixture = Fixture::new();
        let (agent_id, _, _) = fixture.spawn(fixture.manifest(scenario, "S06"));
        let identity = fixture
            .store
            .get_job(&agent_id)
            .unwrap()
            .unwrap()
            .process_identity
            .unwrap();
        match scenario {
            "malformed-ledger" => {
                assert!(fixture
                    .tool(
                        &agent_id,
                        REVIEW_CHECKPOINT,
                        serde_json::json!({"checkpoint_id":"bad","stage":"scope","summary":""}),
                    )
                    .is_err());
            }
            "duplicate-final" => {
                fixture.checkpoint_and_finalize(&agent_id);
                assert!(fixture
                    .tool(
                        &agent_id,
                        REVIEW_FINALIZE,
                        serde_json::json!({
                            "signal":"incomplete_evidence","summary":"conflicting second final",
                            "coverage":{"covered":[],"not_covered":["src"]},
                            "uncertainties":["conflict"],"recommended_next_actions":[]
                        }),
                    )
                    .is_err());
            }
            "cancel" => {
                assert_eq!(
                    fixture.scheduler.stop_job(&agent_id).unwrap(),
                    JobState::Cancelled
                );
            }
            _ => unreachable!(),
        }
        let terminal = fixture.wait_terminal(&agent_id);
        if scenario == "cancel" {
            assert_eq!(terminal.state, JobState::Cancelled);
        } else {
            assert_eq!(terminal.state, JobState::Failed);
            assert_eq!(
                terminal.failure_code.as_deref(),
                Some(if scenario == "malformed-ledger" {
                    "REVIEW_LEDGER_INVALID"
                } else {
                    "REVIEW_FINALIZE_CONFLICT"
                })
            );
        }
        assert!(observe_process_group(identity.process_group_id)
            .unwrap()
            .is_empty());
        assert!(fixture
            .scheduler
            .verify_review_artifact(&agent_id, 0)
            .unwrap()
            .is_some_and(|artifact| artifact.integrity == ArtifactIntegrity::Valid));
    }

    let fixture = Fixture::new();
    let (crashed, _, _) = fixture.spawn(fixture.manifest("runtime-crash", "CRASH"));
    let crash = fixture.wait_terminal(&crashed);
    assert_eq!(crash.state, JobState::FailedRuntimeLost);
    assert!(crash.failure_code.is_some());
    assert!(fixture
        .scheduler
        .verify_review_artifact(&crashed, 0)
        .unwrap()
        .is_some_and(|artifact| artifact.integrity == ArtifactIntegrity::Valid));

    drop(fixture.service);
    drop(fixture.scheduler);
    let reopened = Arc::new(Store::open(fixture.store.database_path()).unwrap());
    let ledger = Arc::new(LedgerManager::new(Arc::clone(&reopened)));
    let restart_factory = Arc::new(CommandRuntimeFactory::new_prepared(
        |_job: &Job| -> io::Result<Command> {
            Err(io::Error::other("restart must not spawn a runtime"))
        },
    ));
    let restarted = Scheduler::new(
        "s06-restart",
        Arc::clone(&reopened),
        restart_factory,
        SchedulerConfig::default(),
    )
    .unwrap()
    .with_ledger(
        ledger,
        InternalLedgerMcpConfig {
            command: PathBuf::from("/usr/bin/false"),
            socket: fixture._directory.path().join("restart-private.sock"),
            runtime_sha256: Some("f".repeat(64)),
        },
    )
    .unwrap();
    assert!(restarted.reconcile_startup().unwrap().is_empty());
    assert_eq!(
        reopened.get_job(&crashed).unwrap().unwrap().state,
        crash.state
    );
    assert!(reopened
        .review_snapshot(&crashed)
        .unwrap()
        .is_some_and(|snapshot| !snapshot.report.finalized));
}

fn wait_until<T>(mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(value) = probe() {
            return value;
        }
        assert!(Instant::now() < deadline, "fixture deadline elapsed");
        thread::sleep(Duration::from_millis(5));
    }
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
    assert!(path.is_file(), "zcode-fake-runtime binary is missing");
    path
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
