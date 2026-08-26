use review_ledger::{
    ArtifactIntegrity, LedgerManager, REVIEW_CHECKPOINT, REVIEW_FINALIZE, REVIEW_FINDING_UPSERT,
    REVIEW_VALIDATION_RECORD,
};
use review_preparation::{
    BudgetLimits, NetworkPolicy, ReviewKind, ReviewManifest, ReviewPreparer, RoundKind,
    ScratchPolicy,
};
use review_store::{
    BudgetRequest, Job, JobState, MessageState, NewJob, NewTask, PendingRequestState, Store,
    TaskKind, TaskOutcome, TaskPhase, TaskQueryScope,
};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};
use zcode_driver::observe_process_group;
use zcode_reviewd::{
    orchestration::{
        ReviewSubmissionDisposition, StructuredReviewContinuation, StructuredReviewKind,
        StructuredReviewProjection, StructuredReviewSubmission,
    },
    rpc::{
        ArtifactIntegrityView, MessageInput, RespondInput, ResponseDecision, ResultQuery,
        ReviewToolInput, RpcErrorCode, RpcMethod, RpcServer, RpcService, RpcSuccess, ServerOptions,
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
    _server: RpcServer,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let repository = directory.path().join("repository");
        fs::create_dir_all(repository.join("src")).unwrap();
        fs::write(repository.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        fs::write(
            repository.join("src/approval.rs"),
            "pub fn metadata_word_is_legal() {}\n",
        )
        .unwrap();
        git(&repository, &["init"]);
        git(&repository, &["config", "user.name", "S06 Test"]);
        git(
            &repository,
            &["config", "user.email", "s06@example.invalid"],
        );
        git(&repository, &["add", "src/lib.rs", "src/approval.rs"]);
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
            repository.join(".agent-work/context/admission.json"),
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
            let mode = match (
                prepared.section_id.as_str(),
                prepared.idempotency_key.as_str(),
            ) {
                ("CRASH", _) => "crash",
                ("SEND-FAIL", _) => "review-flow-send-failure",
                (_, key) if key.ends_with("missing-final") => "review-flow-no-finalize",
                (_, key)
                    if [
                        "report-replaced",
                        "source-mutated",
                        "malformed-ledger",
                        "duplicate-final",
                        "cancel",
                    ]
                    .iter()
                    .any(|suffix| key.ends_with(suffix)) =>
                {
                    "review-flow-no-ledger"
                }
                _ => "review-flow",
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
        let socket_root = directory.path().join("socket");
        fs::create_dir(&socket_root).unwrap();
        fs::set_permissions(&socket_root, fs::Permissions::from_mode(0o700)).unwrap();
        let socket = socket_root.join("private.sock");
        let scheduler = Scheduler::new(
            "s06-fixture",
            Arc::clone(&store),
            runtime_factory,
            SchedulerConfig {
                global_max_agents: 2,
                per_workspace_max_agents: 2,
                stop_grace: Duration::from_millis(100),
                bootstrap_timeout: Duration::from_secs(2),
                control_timeout: Duration::from_secs(2),
            },
        )
        .unwrap()
        .with_ledger(
            ledger,
            InternalLedgerMcpConfig {
                command: fs::canonicalize(env!("CARGO_BIN_EXE_zcode-reviewd")).unwrap(),
                socket: socket.clone(),
                runtime_sha256: Some("f".repeat(64)),
            },
        )
        .unwrap();
        let service = RpcService::new(scheduler.clone(), Arc::clone(&store)).unwrap();
        let server =
            RpcServer::bind(&socket, Arc::new(service.clone()), ServerOptions::default()).unwrap();
        Self {
            _directory: directory,
            repository,
            head,
            store,
            scheduler,
            service,
            _server: server,
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
            context_paths: vec![".agent-work/context/admission.json".into()],
            scope_paths: vec!["src/approval.rs".into()],
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

    fn structured_submission(&self, suffix: &str) -> StructuredReviewSubmission {
        StructuredReviewSubmission {
            review_kind: StructuredReviewKind::InitialBounded,
            manifest: self.manifest(suffix, "S04"),
            ownership_token: "s04-owner".into(),
            read_only: true,
            budget: Some(BudgetLimits {
                wall_time_ms: 5_000,
                max_turns: 8,
                max_tool_calls: 32,
                max_context_bytes: 1_048_576,
                max_result_bytes: 262_144,
                max_artifact_bytes: 2_097_152,
            }),
        }
    }

    fn structured_continuation(
        &self,
        agent_id: &str,
        review_id: &str,
        suffix: &str,
    ) -> StructuredReviewContinuation {
        let mut manifest = self.manifest(suffix, "S04");
        manifest.round_kind = RoundKind::RepairDelta;
        StructuredReviewContinuation {
            agent_id: agent_id.into(),
            review_id: review_id.into(),
            review_kind: StructuredReviewKind::RepairDelta,
            manifest,
            frozen_finding_ids: vec!["S06-F1".into()],
            read_only: true,
            budget: Some(BudgetLimits {
                wall_time_ms: 7_000,
                max_turns: 12,
                max_tool_calls: 48,
                max_context_bytes: 1_048_576,
                max_result_bytes: 262_144,
                max_artifact_bytes: 2_097_152,
            }),
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
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let pending = self.store.pending_requests(agent_id).unwrap();
            if pending.len() == 2 {
                return pending;
            }
            assert!(
                Instant::now() < deadline,
                "pending requests did not arrive: job={:?}, pending={pending:?}, scheduler={:?}",
                self.store.get_job(agent_id).unwrap(),
                self.scheduler.last_error(agent_id)
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    // Success-path E2E evidence must come from the fake session's ledger MCP child.
    fn direct_finalize_for_negative_control(&self, agent_id: &str) {
        self.direct_tool_for_negative_control(
            agent_id,
            REVIEW_CHECKPOINT,
            serde_json::json!({
                "checkpoint_id":"scope-1","stage":"inspection","summary":"bounded evidence observed",
                "inspected":[{"path":"src/approval.rs","line_ranges":["1"]}],
                "commands":[],"open_questions":[],"remaining_scope":[]
            }),
        )
        .unwrap();
        self.direct_tool_for_negative_control(
            agent_id,
            REVIEW_FINDING_UPSERT,
            serde_json::json!({
                "finding_id":"S06-F1","severity":"P2","confidence":"medium",
                "title":"candidate","locations":[{"path":"src/approval.rs","start_line":1,"end_line":1}],
                "evidence":["observable fixture"],"impact":"bounded","suggested_remediation":"none",
                "status":"open"
            }),
        )
        .unwrap();
        self.direct_tool_for_negative_control(
            agent_id,
            REVIEW_FINDING_UPSERT,
            serde_json::json!({
                "finding_id":"S06-F1","severity":"P2","confidence":"high",
                "title":"candidate disproved","locations":[{"path":"src/approval.rs","start_line":1,"end_line":1}],
                "evidence":["later observable fixture"],"impact":"none","suggested_remediation":"none",
                "status":"withdrawn"
            }),
        )
        .unwrap();
        self.direct_tool_for_negative_control(
            agent_id,
            REVIEW_VALIDATION_RECORD,
            serde_json::json!({
                "validation_id":"validation-1","command":"cargo test -p fixture","cwd":".",
                "exit_code":0,"duration_ms":1,"stdout_summary":"passed","stderr_summary":"",
                "related_findings":[]
            }),
        )
        .unwrap();
        self.direct_tool_for_negative_control(
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

    fn direct_tool_for_negative_control(
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

    fn respond_permission(&self, agent_id: &str) -> zcode_reviewd::rpc::ResponseOutcomeView {
        let pending = self.wait_pending(agent_id);
        let permission = pending
            .iter()
            .find(|request| request.request_type == "permission")
            .unwrap();
        match self
            .service
            .dispatch(RpcMethod::Respond(RespondInput {
                agent_id: agent_id.into(),
                request_id: permission.request_id.clone(),
                decision: ResponseDecision::Allow,
                content: None,
            }))
            .unwrap()
        {
            RpcSuccess::Respond { outcome } => outcome,
            other => panic!("unexpected permission response: {other:?}"),
        }
    }

    fn fail_terminal_event_writes(&self) {
        let connection = rusqlite::Connection::open(self.store.database_path()).unwrap();
        connection
            .execute_batch(
                "CREATE TRIGGER fail_terminal_event_write
                 BEFORE INSERT ON events
                 WHEN NEW.event_type LIKE 'runtime.%'
                 BEGIN
                   SELECT RAISE(FAIL, 'scripted terminal event failure');
                 END;",
            )
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

fn submit_and_complete_structured(
    fixture: &Fixture,
    input: &StructuredReviewSubmission,
) -> (StructuredReviewProjection, String) {
    let review = match fixture
        .service
        .dispatch(RpcMethod::SubmitStructuredReview {
            input: input.clone(),
        })
        .unwrap()
    {
        RpcSuccess::StructuredReviewSubmitted { review } => review,
        other => panic!("unexpected structured submission: {other:?}"),
    };
    let execution = fixture
        .store
        .get_task(&review.agent_id)
        .unwrap()
        .unwrap()
        .execution_agent_id;
    assert_eq!(
        fixture.scheduler.start_ready().unwrap(),
        vec![execution.clone()]
    );
    let permission = fixture
        .wait_pending(&execution)
        .into_iter()
        .find(|request| request.request_type == "permission")
        .unwrap();
    fixture
        .service
        .dispatch(RpcMethod::TaskRespond(RespondInput {
            agent_id: review.agent_id.clone(),
            request_id: permission.request_id,
            decision: ResponseDecision::Allow,
            content: None,
        }))
        .unwrap();
    assert_eq!(fixture.wait_terminal(&execution).state, JobState::Completed);
    (review, execution)
}

#[test]
fn injected_ledger_mcp_completes_v2_review_while_legacy_tool_stays_hidden() {
    let fixture = Fixture::new();
    let manifest = fixture.manifest("v2-injected-ledger", "S03");
    let prepared = ReviewPreparer.prepare(&manifest).unwrap();
    let execution_id = "v2-injected-ledger-attempt";
    let public_id = execution_id;
    let mut job = NewJob::new(execution_id, prepared.worktree.path.to_string_lossy());
    job.idempotency_key = Some(prepared.idempotency_key.clone());
    job.review_kind = Some(prepared.review_kind.as_str().into());
    job.feature_id = Some(prepared.feature_id.clone());
    job.section_id = Some(prepared.section_id.clone());
    job.round_kind = Some(prepared.round_kind.as_str().into());
    job.report_path = Some(prepared.report_target.to_string_lossy().into_owned());
    job.initial_prompt = "review through the injected ledger".into();
    job.prepared_launch_json = Some(prepared.canonical_json().unwrap());
    job.prepared_launch_sha256 = Some(prepared.prepared_sha256.clone());
    fixture
        .store
        .enqueue_task(&NewTask {
            job,
            public_agent_id: public_id.into(),
            task_kind: TaskKind::Review,
            review_id: Some("v2-injected-ledger-review".into()),
            continuation_of: None,
            repository: prepared.repository.to_string_lossy().into_owned(),
            feature_id: prepared.feature_id.clone(),
            ownership_token: "owner".into(),
            budget: BudgetRequest::Omitted,
            retain_partial: false,
        })
        .unwrap();

    assert_eq!(
        fixture.scheduler.start_ready().unwrap(),
        vec![execution_id.to_owned()]
    );
    let legacy_error = fixture
        .service
        .dispatch(RpcMethod::ReviewTool(ReviewToolInput {
            agent_id: execution_id.into(),
            tool: REVIEW_CHECKPOINT.into(),
            arguments: serde_json::json!({
                "checkpoint_id":"legacy-must-not-see-v2","stage":"inspection",
                "summary":"must remain hidden"
            }),
        }))
        .unwrap_err();
    assert_eq!(legacy_error.code, RpcErrorCode::NotFound);

    let pending = fixture.wait_pending(execution_id);
    let permission = pending
        .iter()
        .find(|request| request.request_type == "permission")
        .unwrap();
    assert!(matches!(
        fixture
            .service
            .dispatch(RpcMethod::TaskRespond(RespondInput {
                agent_id: public_id.into(),
                request_id: permission.request_id.clone(),
                decision: ResponseDecision::Allow,
                content: None,
            }))
            .unwrap(),
        RpcSuccess::Respond { .. }
    ));

    let terminal = fixture.wait_terminal(execution_id);
    assert_eq!(terminal.state, JobState::Completed);
    let task = fixture
        .store
        .task_by_execution_agent_id(execution_id)
        .unwrap()
        .unwrap();
    assert_eq!(task.phase, TaskPhase::Terminal);
    let result = fixture.store.task_result(execution_id).unwrap().unwrap();
    assert_eq!(result.result.outcome, TaskOutcome::Succeeded);
    let snapshot = fixture
        .store
        .review_snapshot(execution_id)
        .unwrap()
        .unwrap();
    assert!(snapshot.report.finalized);
    assert_eq!(snapshot.checkpoints.len(), 1);
    assert_eq!(snapshot.validations.len(), 1);
    assert!(snapshot.finalization.is_some());
    assert!(!prepared.worktree.path.exists());

    fixture.scheduler.close_job(execution_id).unwrap();
    fixture.scheduler.reap_job(execution_id).unwrap();
    assert_eq!(
        fixture.store.task_result(execution_id).unwrap().unwrap(),
        result
    );
}

#[test]
fn submit_only_returns_stable_job_before_runtime_bootstrap() {
    let fixture = Fixture::new();
    let manifest = fixture.manifest("submit-only", "S07");
    let first = fixture
        .service
        .dispatch(RpcMethod::SubmitReview {
            manifest: manifest.clone(),
        })
        .unwrap();
    let (agent_id, prompt_sha256) = match first {
        RpcSuccess::ReviewSubmitted {
            job,
            prompt_sha256,
            resumed_existing,
            ..
        } => {
            assert!(!resumed_existing);
            assert_eq!(job.state, zcode_reviewd::rpc::JobStateView::Queued);
            assert!(job.zcode_session_id.is_none());
            (job.agent_id, prompt_sha256)
        }
        other => panic!("unexpected submit response: {other:?}"),
    };
    assert_eq!(fixture.scheduler.active_count(), 0);
    assert!(fixture
        .store
        .get_job(&agent_id)
        .unwrap()
        .unwrap()
        .process_identity
        .is_none());
    match fixture
        .service
        .dispatch(RpcMethod::SubmitReview { manifest })
        .unwrap()
    {
        RpcSuccess::ReviewSubmitted {
            job,
            prompt_sha256: replay_sha256,
            resumed_existing,
            ..
        } => {
            assert!(resumed_existing);
            assert_eq!(job.agent_id, agent_id);
            assert_eq!(replay_sha256, prompt_sha256);
        }
        other => panic!("unexpected replay response: {other:?}"),
    }
    assert_eq!(fixture.scheduler.active_count(), 0);
    assert_eq!(
        fixture.scheduler.stop_job(&agent_id).unwrap(),
        JobState::Cancelled
    );
}

#[test]
fn structured_fresh_then_same_review_continuation_preserves_attempt_evidence() {
    let fixture = Fixture::new();
    let expected_runtime = "f".repeat(64);
    let first_input = fixture.structured_submission("structured-first");
    let first_report = fixture.repository.join(&first_input.manifest.report_target);
    let first = match fixture
        .service
        .dispatch(RpcMethod::SubmitStructuredReview {
            input: first_input.clone(),
        })
        .unwrap()
    {
        RpcSuccess::StructuredReviewSubmitted { review } => review,
        other => panic!("unexpected structured submission: {other:?}"),
    };
    assert_eq!(
        first.submission_disposition,
        ReviewSubmissionDisposition::Created
    );
    assert_eq!(first.phase, "QUEUED");
    assert_eq!(first.attempt_sequence, 1);
    assert!(!first.counts_as_independent);
    assert!(!first.provenance.fresh_session_observed);
    assert_eq!(
        first.provenance.review_kind,
        StructuredReviewKind::InitialBounded
    );
    assert_eq!(first.provenance.base_sha, fixture.head);
    assert_eq!(first.provenance.head_sha, fixture.head);
    assert_eq!(first.effective_budget.wall_time_ms, 5_000);
    let replayed_first = match fixture
        .service
        .dispatch(RpcMethod::SubmitStructuredReview {
            input: first_input.clone(),
        })
        .unwrap()
    {
        RpcSuccess::StructuredReviewSubmitted { review } => review,
        other => panic!("unexpected idempotent submission: {other:?}"),
    };
    assert_eq!(replayed_first.agent_id, first.agent_id);
    assert_eq!(replayed_first.review_id, first.review_id);
    assert_eq!(replayed_first.attempt_sequence, 1);
    assert_eq!(
        replayed_first.submission_disposition,
        ReviewSubmissionDisposition::Existing
    );
    let redacted = serde_json::to_string(&first).unwrap();
    for forbidden in [
        fixture.repository.to_string_lossy().as_ref(),
        "s04-owner",
        "initial_prompt",
        "workspace_path",
        "zcode_session_id",
        "runtime_agent_id",
        "correlation",
        "payload_json",
        "environment",
    ] {
        assert!(
            !redacted.contains(forbidden),
            "leaked {forbidden}: {redacted}"
        );
    }

    let first_task = fixture
        .store
        .get_task_scoped(
            &first.agent_id,
            TaskQueryScope {
                repository: None,
                feature_id: Some("feature"),
                ownership_token: None,
            },
        )
        .unwrap()
        .unwrap();
    let first_execution = first_task.execution_agent_id.clone();
    assert_eq!(first_task.task_kind, TaskKind::Review);
    assert!(first_task.independent_evidence);
    assert_eq!(
        fixture.scheduler.start_ready().unwrap(),
        vec![first_execution.clone()]
    );
    let first_running = fixture.store.get_job(&first_execution).unwrap().unwrap();
    let first_identity = first_running.process_identity.clone().unwrap();
    let first_session = first_running.zcode_session_id.clone().unwrap();
    assert!(!first_session.is_empty());
    assert!(first_running
        .initial_prompt
        .contains("ROUND_KIND: INITIAL_BOUNDED"));
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(first_running.initial_prompt.as_bytes())
        ),
        first.provenance.prompt_sha256
    );
    match fixture
        .service
        .dispatch(RpcMethod::TaskStatus {
            agent_id: first.agent_id.clone(),
        })
        .unwrap()
    {
        RpcSuccess::TaskStatus { task } => {
            assert_eq!(task.review_id.as_deref(), Some(first.review_id.as_str()));
            assert!(task.independent_evidence);
            assert!(task.fresh_session_observed);
        }
        other => panic!("unexpected structured task status: {other:?}"),
    }
    let first_worktree = PathBuf::from(first_running.workspace_path);
    let first_pending = fixture.wait_pending(&first_execution);
    let first_permission = first_pending
        .iter()
        .find(|request| request.request_type == "permission")
        .unwrap();
    let first_response = fixture
        .service
        .dispatch(RpcMethod::TaskRespond(RespondInput {
            agent_id: first.agent_id.clone(),
            request_id: first_permission.request_id.clone(),
            decision: ResponseDecision::Allow,
            content: None,
        }));
    assert!(
        matches!(first_response, Ok(RpcSuccess::Respond { .. })),
        "response={first_response:?} job={:?} task={:?} last_error={:?}",
        fixture.store.get_job(&first_execution).unwrap(),
        fixture
            .store
            .task_by_execution_agent_id(&first_execution)
            .unwrap(),
        fixture.scheduler.last_error(&first_execution)
    );
    assert_eq!(
        fixture.wait_terminal(&first_execution).state,
        JobState::Completed
    );
    assert!(!first_worktree.exists());
    assert!(observe_process_group(first_identity.process_group_id)
        .unwrap()
        .is_empty());
    let first_snapshot = fixture
        .store
        .review_snapshot(&first_execution)
        .unwrap()
        .unwrap();
    let first_result = fixture
        .store
        .task_result(&first_execution)
        .unwrap()
        .unwrap();
    let first_report_bytes = fs::read(&first_report).unwrap();
    assert!(first_snapshot.report.finalized);
    assert_eq!(
        first_snapshot.provenance.runtime_sha256.as_deref(),
        Some(expected_runtime.as_str())
    );
    assert_eq!(
        first_snapshot.provenance.manifest_sha256,
        first.provenance.manifest_sha256
    );
    assert_eq!(
        first_snapshot.provenance.prepared_sha256,
        first.provenance.prepared_sha256
    );
    assert_eq!(
        first_snapshot.provenance.base_sha,
        first.provenance.base_sha
    );
    assert_eq!(
        first_snapshot.provenance.head_sha,
        first.provenance.head_sha
    );
    assert_eq!(
        first_snapshot.provenance.requested_model.as_deref(),
        Some("fixture-model")
    );
    assert_eq!(first_result.result.outcome, TaskOutcome::Succeeded);

    let continuation_input = fixture.structured_continuation(
        &first.agent_id,
        &first.review_id,
        "structured-continuation",
    );
    let second_report = fixture
        .repository
        .join(&continuation_input.manifest.report_target);
    let second = match fixture
        .service
        .dispatch(RpcMethod::ContinueStructuredReview {
            input: continuation_input.clone(),
        })
        .unwrap()
    {
        RpcSuccess::StructuredReviewSubmitted { review } => review,
        other => panic!("unexpected continuation submission: {other:?}"),
    };
    assert_eq!(second.agent_id, first.agent_id);
    assert_eq!(second.review_id, first.review_id);
    assert_eq!(second.attempt_sequence, 2);
    assert_eq!(second.phase, "QUEUED");
    assert_eq!(second.effective_budget.wall_time_ms, 7_000);
    assert!(!second.counts_as_independent);
    assert_eq!(
        second.provenance.review_kind,
        StructuredReviewKind::RepairDelta
    );
    let replayed_second = match fixture
        .service
        .dispatch(RpcMethod::ContinueStructuredReview {
            input: continuation_input.clone(),
        })
        .unwrap()
    {
        RpcSuccess::StructuredReviewSubmitted { review } => review,
        other => panic!("unexpected idempotent continuation: {other:?}"),
    };
    assert_eq!(replayed_second.agent_id, first.agent_id);
    assert_eq!(replayed_second.review_id, first.review_id);
    assert_eq!(replayed_second.attempt_sequence, 2);
    assert_eq!(
        replayed_second.submission_disposition,
        ReviewSubmissionDisposition::Existing
    );

    let second_task = fixture
        .store
        .get_task_scoped(
            &first.agent_id,
            TaskQueryScope {
                repository: None,
                feature_id: Some("feature"),
                ownership_token: None,
            },
        )
        .unwrap()
        .unwrap();
    let second_execution = second_task.execution_agent_id.clone();
    assert_ne!(second_execution, first_execution);
    assert_eq!(second_task.task_kind, TaskKind::ReviewContinuation);
    assert_eq!(
        second_task.continuation_of.as_deref(),
        Some(first_execution.as_str())
    );
    assert!(!second_task.independent_evidence);
    assert_eq!(
        fixture.scheduler.start_ready().unwrap(),
        vec![second_execution.clone()]
    );
    let second_running = fixture.store.get_job(&second_execution).unwrap().unwrap();
    let second_identity = second_running.process_identity.clone().unwrap();
    let second_session = second_running.zcode_session_id.clone().unwrap();
    assert_ne!(second_session, first_session);
    assert_ne!(
        second_identity.process_group_id,
        first_identity.process_group_id
    );
    assert!(second_running
        .initial_prompt
        .contains("ROUND_KIND: REPAIR_DELTA"));
    assert_eq!(
        format!(
            "{:x}",
            Sha256::digest(second_running.initial_prompt.as_bytes())
        ),
        second.provenance.prompt_sha256
    );
    match fixture
        .service
        .dispatch(RpcMethod::TaskStatus {
            agent_id: first.agent_id.clone(),
        })
        .unwrap()
    {
        RpcSuccess::TaskStatus { task } => {
            assert_eq!(task.review_id.as_deref(), Some(first.review_id.as_str()));
            assert_eq!(task.attempt_sequence, 2);
            assert!(!task.independent_evidence);
            assert!(task.fresh_session_observed);
        }
        other => panic!("unexpected continuation task status: {other:?}"),
    }
    assert!(second_running
        .initial_prompt
        .contains("COUNTS_AS_INDEPENDENT: false"));
    assert!(second_running
        .initial_prompt
        .contains("FROZEN_FINDING_IDS: [\"S06-F1\"]"));
    assert!(!second_running
        .initial_prompt
        .contains("candidate disproved"));
    let second_worktree = PathBuf::from(second_running.workspace_path);
    let second_pending = fixture.wait_pending(&second_execution);
    let second_permission = second_pending
        .iter()
        .find(|request| request.request_type == "permission")
        .unwrap();
    assert_eq!(
        fixture
            .store
            .get_task(&first.agent_id)
            .unwrap()
            .unwrap()
            .execution_agent_id,
        second_execution
    );
    fixture
        .service
        .dispatch(RpcMethod::TaskRespond(RespondInput {
            agent_id: first.agent_id.clone(),
            request_id: second_permission.request_id.clone(),
            decision: ResponseDecision::Allow,
            content: None,
        }))
        .unwrap();
    assert_eq!(
        fixture.wait_terminal(&second_execution).state,
        JobState::Completed
    );
    assert!(!second_worktree.exists());
    assert!(observe_process_group(second_identity.process_group_id)
        .unwrap()
        .is_empty());
    let second_snapshot = fixture
        .store
        .review_snapshot(&second_execution)
        .unwrap()
        .unwrap();
    assert!(second_snapshot.report.finalized);
    assert_eq!(
        second_snapshot.provenance.runtime_sha256.as_deref(),
        Some(expected_runtime.as_str())
    );
    assert_eq!(
        second_snapshot.provenance.manifest_sha256,
        second.provenance.manifest_sha256
    );
    assert_eq!(
        second_snapshot.provenance.prepared_sha256,
        second.provenance.prepared_sha256
    );
    assert!(fs::read_to_string(&second_report)
        .unwrap()
        .contains("FINALIZED: true"));

    assert_eq!(
        fixture
            .store
            .review_snapshot(&first_execution)
            .unwrap()
            .unwrap(),
        first_snapshot
    );
    assert_eq!(
        fixture
            .store
            .task_result(&first_execution)
            .unwrap()
            .unwrap(),
        first_result
    );
    assert_eq!(fs::read(&first_report).unwrap(), first_report_bytes);
    fixture.scheduler.close_job(&second_execution).unwrap();
    fixture.scheduler.reap_job(&second_execution).unwrap();
    assert_eq!(
        fixture
            .store
            .review_snapshot(&first_execution)
            .unwrap()
            .unwrap(),
        first_snapshot
    );
    assert_eq!(fs::read(&first_report).unwrap(), first_report_bytes);
}

#[test]
fn report_target_conflicts_preserve_finalized_owner_across_reviews_and_lineages() {
    let fixture = Fixture::new();
    let first_input = fixture.structured_submission("global-report-owner");
    let first_report = fixture.repository.join(&first_input.manifest.report_target);
    let (_first, first_execution) = submit_and_complete_structured(&fixture, &first_input);
    let first_snapshot = fixture
        .store
        .review_snapshot(&first_execution)
        .unwrap()
        .unwrap();
    let first_report_bytes = fs::read(&first_report).unwrap();
    let first_artifact = fixture
        .scheduler
        .verify_review_artifact(&first_execution, 0)
        .unwrap()
        .unwrap();
    assert_eq!(first_artifact.integrity, ArtifactIntegrity::Valid);

    let roots_before_fresh = scratch_job_roots(&fixture.repository);
    let mut fresh_collision = fixture.structured_submission("global-report-collision");
    fresh_collision.manifest.report_target = first_input.manifest.report_target.clone();
    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::SubmitStructuredReview {
                input: fresh_collision,
            })
            .unwrap_err()
            .code,
        RpcErrorCode::Conflict
    );
    assert_eq!(scratch_job_roots(&fixture.repository), roots_before_fresh);

    let other_input = fixture.structured_submission("other-report-lineage");
    let (other, _other_execution) = submit_and_complete_structured(&fixture, &other_input);
    let mut continuation = fixture.structured_continuation(
        &other.agent_id,
        &other.review_id,
        "other-lineage-report-collision",
    );
    continuation.manifest.report_target = first_input.manifest.report_target.clone();
    let roots_before_continuation = scratch_job_roots(&fixture.repository);
    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::ContinueStructuredReview {
                input: continuation,
            })
            .unwrap_err()
            .code,
        RpcErrorCode::Conflict
    );
    assert_eq!(
        scratch_job_roots(&fixture.repository),
        roots_before_continuation
    );

    assert_eq!(
        fixture
            .store
            .review_snapshot(&first_execution)
            .unwrap()
            .unwrap(),
        first_snapshot
    );
    assert_eq!(fs::read(&first_report).unwrap(), first_report_bytes);
    let artifact_after = fixture
        .scheduler
        .verify_review_artifact(&first_execution, 0)
        .unwrap()
        .unwrap();
    assert_eq!(artifact_after.integrity, ArtifactIntegrity::Valid);
    assert_eq!(
        artifact_after.expected_sha256,
        first_artifact.expected_sha256
    );
    assert_eq!(artifact_after.actual_sha256, first_artifact.actual_sha256);
    assert_eq!(artifact_after.expected_bytes, first_artifact.expected_bytes);
    assert_eq!(artifact_after.actual_bytes, first_artifact.actual_bytes);
}

#[test]
fn legacy_active_idempotency_owner_survives_structured_collision() {
    let fixture = Fixture::new();
    let manifest = fixture.manifest("legacy-active-owner", "S04");
    let (legacy_agent, _, _) = fixture.spawn(manifest.clone());
    fixture.wait_pending(&legacy_agent);
    let legacy_before = fixture.store.get_job(&legacy_agent).unwrap().unwrap();
    let identity = legacy_before.process_identity.clone().unwrap();
    let workspace = PathBuf::from(&legacy_before.workspace_path);
    let marker = workspace.join("legacy-owner-marker.txt");
    fs::write(&marker, "legacy owner remains live\n").unwrap();
    let registrations_before = git(&fixture.repository, &["worktree", "list", "--porcelain"]);
    let report = fixture.repository.join(&manifest.report_target);
    let report_before = fs::read(&report).unwrap();
    let snapshot_before = fixture
        .store
        .review_snapshot(&legacy_agent)
        .unwrap()
        .unwrap();
    let input = StructuredReviewSubmission {
        review_kind: StructuredReviewKind::InitialBounded,
        manifest,
        ownership_token: "structured-collision-owner".into(),
        read_only: true,
        budget: None,
    };

    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::SubmitStructuredReview { input })
            .unwrap_err()
            .code,
        RpcErrorCode::Conflict
    );
    let legacy_after = fixture.store.get_job(&legacy_agent).unwrap().unwrap();
    assert_eq!(
        legacy_after.process_identity,
        legacy_before.process_identity
    );
    assert_eq!(legacy_after.state, legacy_before.state);
    assert!(workspace.is_dir());
    assert_eq!(
        fs::read_to_string(&marker).unwrap(),
        "legacy owner remains live\n"
    );
    assert_eq!(
        git(&fixture.repository, &["worktree", "list", "--porcelain"]),
        registrations_before
    );
    assert!(observe_process_group(identity.process_group_id)
        .unwrap()
        .iter()
        .any(|process| process.pid == identity.pid));
    assert_eq!(fs::read(&report).unwrap(), report_before);
    assert_eq!(
        fixture
            .store
            .review_snapshot(&legacy_agent)
            .unwrap()
            .unwrap(),
        snapshot_before
    );
    assert!(fixture
        .store
        .task_by_execution_agent_id(&legacy_agent)
        .unwrap()
        .is_none());

    assert!(matches!(
        fixture.scheduler.stop_job(&legacy_agent).unwrap(),
        JobState::Stopping | JobState::Cancelled
    ));
    assert_eq!(
        fixture.wait_terminal(&legacy_agent).state,
        JobState::Cancelled
    );
    assert!(observe_process_group(identity.process_group_id)
        .unwrap()
        .is_empty());
}

#[test]
fn structured_first_idempotency_owner_rejects_legacy_without_mutation() {
    let fixture = Fixture::new();
    let input = fixture.structured_submission("structured-first-owner");
    let report = fixture.repository.join(&input.manifest.report_target);
    let structured = match fixture
        .service
        .dispatch(RpcMethod::SubmitStructuredReview {
            input: input.clone(),
        })
        .unwrap()
    {
        RpcSuccess::StructuredReviewSubmitted { review } => review,
        other => panic!("unexpected structured submission: {other:?}"),
    };
    let task_before = fixture
        .store
        .get_task(&structured.agent_id)
        .unwrap()
        .unwrap();
    let snapshot_before = fixture
        .store
        .review_snapshot(&task_before.execution_agent_id)
        .unwrap()
        .unwrap();
    let artifacts_before = fixture
        .store
        .artifact_count(&task_before.execution_agent_id)
        .unwrap();
    let report_before = fs::read(&report).unwrap();
    let roots_before = scratch_job_roots(&fixture.repository);
    let tasks_before = fixture
        .store
        .list_tasks_scoped(
            TaskQueryScope {
                repository: None,
                feature_id: Some("feature"),
                ownership_token: None,
            },
            None,
            false,
            10,
        )
        .unwrap();

    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::SubmitReview {
                manifest: input.manifest,
            })
            .unwrap_err()
            .code,
        RpcErrorCode::Conflict
    );
    assert_eq!(
        fixture
            .store
            .get_task(&structured.agent_id)
            .unwrap()
            .unwrap(),
        task_before
    );
    assert_eq!(
        fixture
            .store
            .review_snapshot(&task_before.execution_agent_id)
            .unwrap()
            .unwrap(),
        snapshot_before
    );
    assert_eq!(fs::read(&report).unwrap(), report_before);
    assert_eq!(scratch_job_roots(&fixture.repository), roots_before);
    assert_eq!(
        fixture
            .store
            .list_tasks_scoped(
                TaskQueryScope {
                    repository: None,
                    feature_id: Some("feature"),
                    ownership_token: None,
                },
                None,
                false,
                10,
            )
            .unwrap(),
        tasks_before
    );
    assert_eq!(
        fixture
            .store
            .artifact_count(&task_before.execution_agent_id)
            .unwrap(),
        artifacts_before
    );
    fixture
        .scheduler
        .stop_job(&task_before.execution_agent_id)
        .unwrap();
}

#[test]
fn concurrent_legacy_and_structured_same_key_preserve_the_single_winner_root() {
    let fixture = Fixture::new();
    let manifest = fixture.manifest("cross-family-concurrent", "S04");
    let structured = StructuredReviewSubmission {
        review_kind: StructuredReviewKind::InitialBounded,
        manifest: manifest.clone(),
        ownership_token: "concurrent-owner".into(),
        read_only: true,
        budget: None,
    };
    let barrier = Arc::new(Barrier::new(3));
    let results = thread::scope(|scope| {
        let legacy_service = fixture.service.clone();
        let legacy_barrier = Arc::clone(&barrier);
        let legacy = scope.spawn(move || {
            legacy_barrier.wait();
            legacy_service.dispatch(RpcMethod::SubmitReview { manifest })
        });
        let structured_service = fixture.service.clone();
        let structured_barrier = Arc::clone(&barrier);
        let structured = scope.spawn(move || {
            structured_barrier.wait();
            structured_service.dispatch(RpcMethod::SubmitStructuredReview { input: structured })
        });
        barrier.wait();
        vec![legacy.join().unwrap(), structured.join().unwrap()]
    });
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| result
                .as_ref()
                .is_err_and(|error| error.code == RpcErrorCode::Conflict))
            .count(),
        1
    );
    let owner = fixture
        .store
        .submission_by_idempotency("feature:S06:cross-family-concurrent")
        .unwrap()
        .unwrap();
    let job = fixture
        .store
        .get_job(&owner.execution_agent_id)
        .unwrap()
        .unwrap();
    let workspace = PathBuf::from(&job.workspace_path);
    assert!(workspace.is_dir());
    assert!(
        git(&fixture.repository, &["worktree", "list", "--porcelain"])
            .contains(workspace.to_string_lossy().as_ref())
    );
    assert_eq!(scratch_job_roots(&fixture.repository).len(), 1);
    fixture
        .scheduler
        .stop_job(&owner.execution_agent_id)
        .unwrap();
}

#[test]
fn structured_continuation_rejects_active_closed_incompatible_and_conflicting_inputs() {
    let fixture = Fixture::new();
    let input = fixture.structured_submission("structured-rejections");
    let first = match fixture
        .service
        .dispatch(RpcMethod::SubmitStructuredReview {
            input: input.clone(),
        })
        .unwrap()
    {
        RpcSuccess::StructuredReviewSubmitted { review } => review,
        other => panic!("unexpected structured submission: {other:?}"),
    };
    let mut conflicting_replay = input.clone();
    conflicting_replay.manifest.model = Some("different-model".into());
    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::SubmitStructuredReview {
                input: conflicting_replay,
            })
            .unwrap_err()
            .code,
        RpcErrorCode::Conflict
    );
    assert_eq!(
        fixture
            .store
            .list_tasks_scoped(
                TaskQueryScope {
                    repository: None,
                    feature_id: Some("feature"),
                    ownership_token: None,
                },
                None,
                false,
                10,
            )
            .unwrap()
            .len(),
        1
    );

    let active_continuation =
        fixture.structured_continuation(&first.agent_id, &first.review_id, "active-continuation");
    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::ContinueStructuredReview {
                input: active_continuation,
            })
            .unwrap_err()
            .code,
        RpcErrorCode::Conflict
    );

    let first_task = fixture.store.get_task(&first.agent_id).unwrap().unwrap();
    let first_execution = first_task.execution_agent_id;
    fixture.scheduler.start_ready().unwrap();
    let pending = fixture.wait_pending(&first_execution);
    let permission = pending
        .iter()
        .find(|request| request.request_type == "permission")
        .unwrap();
    fixture
        .service
        .dispatch(RpcMethod::TaskRespond(RespondInput {
            agent_id: first.agent_id.clone(),
            request_id: permission.request_id.clone(),
            decision: ResponseDecision::Allow,
            content: None,
        }))
        .unwrap();
    assert_eq!(
        fixture.wait_terminal(&first_execution).state,
        JobState::Completed
    );

    let mut wrong_kind = fixture.structured_continuation(
        &first.agent_id,
        &first.review_id,
        "wrong-kind-continuation",
    );
    wrong_kind.review_kind = StructuredReviewKind::PlanReview;
    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::ContinueStructuredReview { input: wrong_kind })
            .unwrap_err()
            .code,
        RpcErrorCode::Validation
    );

    let mut wrong_scope = fixture.structured_continuation(
        &first.agent_id,
        &first.review_id,
        "wrong-scope-continuation",
    );
    wrong_scope.manifest.scope_paths = vec!["src".into()];
    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::ContinueStructuredReview { input: wrong_scope })
            .unwrap_err()
            .code,
        RpcErrorCode::Conflict
    );

    fs::write(fixture.repository.join("src/new.rs"), "pub fn newer() {}\n").unwrap();
    git(&fixture.repository, &["add", "src/new.rs"]);
    git(&fixture.repository, &["commit", "-m", "new lineage"]);
    let unrelated = git(&fixture.repository, &["rev-parse", "HEAD"]);
    let mut wrong_base = fixture.structured_continuation(
        &first.agent_id,
        &first.review_id,
        "wrong-base-continuation",
    );
    wrong_base.manifest.base_ref = unrelated.clone();
    wrong_base.manifest.head_ref = unrelated;
    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::ContinueStructuredReview { input: wrong_base })
            .unwrap_err()
            .code,
        RpcErrorCode::Conflict
    );

    let mut invalid_head = fixture.structured_continuation(
        &first.agent_id,
        &first.review_id,
        "invalid-head-continuation",
    );
    invalid_head.manifest.head_ref = "missing-review-head".into();
    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::ContinueStructuredReview {
                input: invalid_head,
            })
            .unwrap_err()
            .code,
        RpcErrorCode::Validation
    );

    fixture.scheduler.close_job(&first_execution).unwrap();
    let closed =
        fixture.structured_continuation(&first.agent_id, &first.review_id, "closed-continuation");
    assert_eq!(
        fixture
            .service
            .dispatch(RpcMethod::ContinueStructuredReview { input: closed })
            .unwrap_err()
            .code,
        RpcErrorCode::Conflict
    );
    assert_eq!(
        fixture
            .store
            .get_task(&first.agent_id)
            .unwrap()
            .unwrap()
            .attempt_sequence,
        1
    );

    let independent = match fixture
        .service
        .dispatch(RpcMethod::SubmitStructuredReview {
            input: fixture.structured_submission("new-independent-review"),
        })
        .unwrap()
    {
        RpcSuccess::StructuredReviewSubmitted { review } => review,
        other => panic!("unexpected independent review: {other:?}"),
    };
    assert_ne!(independent.agent_id, first.agent_id);
    assert_ne!(independent.review_id, first.review_id);
    assert_eq!(independent.attempt_sequence, 1);
    let independent_task = fixture
        .store
        .get_task(&independent.agent_id)
        .unwrap()
        .unwrap();
    let independent_job = fixture
        .store
        .get_job(&independent_task.execution_agent_id)
        .unwrap()
        .unwrap();
    let independent_worktree = PathBuf::from(independent_job.workspace_path);
    fixture
        .scheduler
        .stop_job(&independent_task.execution_agent_id)
        .unwrap();
    assert!(!independent_worktree.exists());
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
    assert!(first_running.initial_prompt.contains("src/approval.rs"));
    assert!(first_running.initial_prompt.contains("admission.json"));
    let first_worktree = PathBuf::from(first_running.workspace_path.clone());
    let identity = first_running.process_identity.clone().unwrap();
    assert!(fs::read_to_string(&first_report)
        .unwrap()
        .contains("FINALIZED: false"));
    let in_progress = fixture.store.review_snapshot(&first).unwrap().unwrap();
    assert!(!in_progress.report.finalized);
    assert!(in_progress.checkpoints.is_empty());
    assert!(in_progress.findings.is_empty());
    assert!(in_progress.validations.is_empty());
    assert!(in_progress.finalization.is_none());
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
    let projected_pending = match fixture
        .service
        .dispatch(RpcMethod::Pending {
            agent_id: first.clone(),
        })
        .unwrap()
    {
        RpcSuccess::Pending { requests } => requests,
        other => panic!("unexpected pending response: {other:?}"),
    };
    assert!(projected_pending
        .iter()
        .any(|request| { request.kind == "unsupported_input" && !request.respondable }));
    assert!(projected_pending.iter().any(|request| {
        request.kind == "permission"
            && request.respondable
            && request.policy_preview == "hard_deny"
            && !request
                .summary
                .contains(fixture.repository.to_string_lossy().as_ref())
    }));
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
    let (same, resumed, independent) = fixture.spawn(first_manifest.clone());
    assert_eq!(same, first);
    assert!(resumed);
    assert!(!independent);

    let permission_outcome = fixture.respond_permission(&first);
    assert_eq!(
        permission_outcome.disposition,
        zcode_reviewd::rpc::ResponseDispositionView::Responded
    );
    assert_eq!(permission_outcome.requested_decision, "allow");
    assert_eq!(permission_outcome.effective_decision, "deny");
    assert!(permission_outcome.policy_overrode);
    assert!(permission_outcome.policy_reason_code.is_some());
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
    let completed_snapshot = fixture.store.review_snapshot(&first).unwrap().unwrap();
    assert!(completed_snapshot.report.finalized);
    assert_eq!(completed_snapshot.checkpoints.len(), 1);
    assert_eq!(completed_snapshot.findings.len(), 1);
    assert_eq!(
        completed_snapshot.findings[0].status.as_deref(),
        Some("withdrawn")
    );
    assert_eq!(completed_snapshot.validations.len(), 1);
    assert!(completed_snapshot.finalization.is_some());
    let report_events = fixture.store.review_report_events(&first).unwrap();
    assert!(report_events.len() >= 5);
    assert!(report_events
        .windows(2)
        .all(|pair| pair[0].revision < pair[1].revision));
    let (completed_replay, resumed, independent) = fixture.spawn(first_manifest);
    assert_eq!(completed_replay, first);
    assert!(resumed);
    assert!(!independent);
    assert_eq!(
        fixture
            .store
            .get_job(&completed_replay)
            .unwrap()
            .unwrap()
            .zcode_session_id,
        first_done.zcode_session_id
    );

    let mut second_manifest = fixture.manifest("plan-second", "S06");
    second_manifest.round_kind = RoundKind::PlanReview;
    let (second, resumed, independent) = fixture.spawn(second_manifest);
    assert!(!resumed && independent);
    assert_ne!(first, second);
    let second_running = fixture.store.get_job(&second).unwrap().unwrap();
    assert!(second_running.initial_prompt.contains("REVIEW_KIND: plan"));
    assert_ne!(first_done.zcode_session_id, second_running.zcode_session_id);
    assert!(!second_running.initial_prompt.contains(&first));
    assert!(!second_running.initial_prompt.contains("RAW"));
    fixture.respond_permission(&second);
    assert_eq!(fixture.wait_terminal(&second).state, JobState::Completed);
    let second_snapshot = fixture.store.review_snapshot(&second).unwrap().unwrap();
    assert_eq!(second_snapshot.checkpoints.len(), 1);
    assert_eq!(second_snapshot.validations.len(), 1);
    assert!(second_snapshot.finalization.is_some());
    assert_eq!(
        fixture
            .store
            .review_snapshot(&first)
            .unwrap()
            .unwrap()
            .report
            .current_revision,
        completed_snapshot.report.current_revision
    );
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
    let unknown = first_events
        .iter()
        .find(|event| event.event_type == "raw.unknown")
        .expect("unknown non-critical notification must remain visible");
    assert_eq!(unknown.redaction_level, "redacted");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&unknown.payload_json).unwrap(),
        serde_json::json!({"kind":"unknown_event","raw":"[REDACTED]"})
    );
    assert!(!unknown.payload_json.contains("secret"));
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
    assert_eq!(permission.response_decision.as_deref(), Some("deny"));
    assert!(matches!(
        fixture
            .service
            .dispatch(RpcMethod::Respond(RespondInput {
                agent_id: first.clone(),
                request_id: permission.request_id.clone(),
                decision: ResponseDecision::Allow,
                content: None,
            }))
            .unwrap(),
        RpcSuccess::Respond {
            outcome: zcode_reviewd::rpc::ResponseOutcomeView {
                disposition: zcode_reviewd::rpc::ResponseDispositionView::AlreadyResponded,
                requested_decision,
                effective_decision,
                policy_overrode: true,
                policy_reason_code: Some(_),
            }
        } if requested_decision == "allow" && effective_decision == "deny"
    ));
    assert_eq!(
        fixture
            .store
            .pending_requests(&first)
            .unwrap()
            .into_iter()
            .filter(|request| request.request_type == "permission")
            .count(),
        1
    );
}

#[test]
fn concurrent_first_spawn_is_one_independent_job_and_conflicts_stay_rejected() {
    let fixture = Fixture::new();
    let manifest = fixture.manifest("concurrent-spawn", "S06");
    let barrier = Arc::new(Barrier::new(3));
    let responses = thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 0..2 {
            let service = fixture.service.clone();
            let manifest = manifest.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(scope.spawn(move || {
                barrier.wait();
                match service
                    .dispatch(RpcMethod::SpawnReview { manifest })
                    .unwrap()
                {
                    RpcSuccess::ReviewSpawned {
                        job,
                        resumed_existing,
                        counts_as_independent,
                        ..
                    } => (
                        job.agent_id,
                        job.zcode_session_id,
                        resumed_existing,
                        counts_as_independent,
                    ),
                    other => panic!("unexpected spawn response: {other:?}"),
                }
            }));
        }
        barrier.wait();
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(responses[0].0, responses[1].0);
    assert_eq!(responses[0].1, responses[1].1);
    assert!(responses[0].1.is_some());
    assert_eq!(
        responses
            .iter()
            .filter(|(_, _, _, independent)| *independent)
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|(_, _, resumed, _)| *resumed)
            .count(),
        1
    );

    let mut conflicting = manifest;
    conflicting.model = Some("conflicting-model".into());
    let conflict = fixture
        .service
        .dispatch(RpcMethod::SpawnReview {
            manifest: conflicting,
        })
        .unwrap_err();
    assert_eq!(conflict.code, RpcErrorCode::Conflict);
    assert!(!conflict.message.contains("conflicting-model"));
    assert_eq!(
        fixture.scheduler.stop_job(&responses[0].0).unwrap(),
        JobState::Cancelled
    );
}

#[test]
fn terminal_event_write_faults_classify_nonclean_before_releasing_slots() {
    let fixture = Fixture::new();
    let (natural, _, _) = fixture.spawn(fixture.manifest("terminal-fault", "S06"));
    fixture.wait_pending(&natural);
    fixture.fail_terminal_event_writes();
    fixture.respond_permission(&natural);
    let natural_terminal = fixture.wait_terminal(&natural);
    assert_eq!(natural_terminal.state, JobState::FailedRuntimeLost);
    assert_eq!(
        natural_terminal.failure_code.as_deref(),
        Some("LIFECYCLE_SINK_FAILED")
    );
    wait_until(|| (fixture.scheduler.active_count() == 0).then_some(()));

    let fixture = Fixture::new();
    let (delivery, _, _) = fixture.spawn(fixture.manifest("delivery-fault", "SEND-FAIL"));
    fixture.wait_pending(&delivery);
    fixture
        .service
        .dispatch(RpcMethod::Message(MessageInput {
            agent_id: delivery.clone(),
            message_id: "scripted-send-failure".into(),
            mode: "queue".into(),
            content: "this queued delivery must fail".into(),
        }))
        .unwrap();
    fixture.fail_terminal_event_writes();
    fixture.respond_permission(&delivery);
    let delivery_terminal = fixture.wait_terminal(&delivery);
    assert_eq!(delivery_terminal.state, JobState::FailedRuntimeLost);
    assert_eq!(
        delivery_terminal.failure_code.as_deref(),
        Some("LIFECYCLE_SINK_FAILED")
    );
    assert_eq!(
        fixture
            .store
            .message("scripted-send-failure")
            .unwrap()
            .unwrap()
            .state,
        MessageState::Failed
    );
    wait_until(|| (fixture.scheduler.active_count() == 0).then_some(()));
}

#[test]
fn interrupt_and_continue_is_an_observable_separate_next_turn_fixture() {
    let fixture = Fixture::new();
    let (agent_id, _, _) = fixture.spawn(fixture.manifest("interrupt", "S06"));
    fixture.wait_pending(&agent_id);
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
            fixture.direct_finalize_for_negative_control(&agent_id);
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
                    .direct_tool_for_negative_control(
                        &agent_id,
                        REVIEW_CHECKPOINT,
                        serde_json::json!({"checkpoint_id":"bad","stage":"scope","summary":""}),
                    )
                    .is_err());
            }
            "duplicate-final" => {
                fixture.direct_finalize_for_negative_control(&agent_id);
                assert!(fixture
                    .direct_tool_for_negative_control(
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
            command: fs::canonicalize(env!("CARGO_BIN_EXE_zcode-reviewd")).unwrap(),
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

fn scratch_job_roots(repository: &Path) -> Vec<String> {
    let mut roots = fs::read_dir(repository.join(".agent-work/scratch/jobs"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    roots.sort();
    roots
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
