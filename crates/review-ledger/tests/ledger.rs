use review_ledger::{
    ArtifactIntegrity, LedgerManager, ToolDisposition, REVIEW_CHECKPOINT, REVIEW_FINALIZE,
    REVIEW_FINDING_UPSERT, REVIEW_VALIDATION_RECORD,
};
use review_preparation::{
    NetworkPolicy, ReviewKind, ReviewManifest, ReviewPreparer, RoundKind, ScratchPolicy,
};
use review_store::{NewJob, ReviewMutationDisposition, Store};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
};
use tempfile::TempDir;

struct Fixture {
    directory: TempDir,
    prepared: review_preparation::PreparedLaunchSpec,
    store: Arc<Store>,
    ledger: Arc<LedgerManager>,
    agent_id: String,
}

impl Fixture {
    fn new(agent_id: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let repository = create_repository(&directory);
        let head = git(&repository, &["rev-parse", "HEAD"]);
        fs::create_dir_all(repository.join(".agent-work/reviews/feature/S05")).unwrap();
        fs::create_dir_all(repository.join(".agent-work/scratch/jobs")).unwrap();
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
            model: Some("glm-observed-later".into()),
            fresh_session: true,
            network_policy: NetworkPolicy::Deny,
            scratch_policy: ScratchPolicy::Isolated,
            idempotency_key: format!("feature:S05:{agent_id}"),
        };
        let prepared = ReviewPreparer.prepare(&manifest).unwrap();
        let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
        let mut job = NewJob::new(agent_id, prepared.worktree.path.to_string_lossy());
        job.prepared_launch_json = Some(prepared.canonical_json().unwrap());
        job.prepared_launch_sha256 = Some(prepared.prepared_sha256.clone());
        job.report_path = Some(prepared.report_target.to_string_lossy().into_owned());
        store.enqueue_job(&job).unwrap();
        let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
        ledger
            .initialize(agent_id, &prepared, Some(&"a".repeat(64)))
            .unwrap();
        Self {
            directory,
            prepared,
            store,
            ledger,
            agent_id: agent_id.into(),
        }
    }

    fn call(&self, tool: &str, arguments: Value) -> review_ledger::ToolResult {
        self.ledger
            .call_tool(&self.agent_id, tool, arguments)
            .unwrap()
    }
}

#[test]
fn all_tools_render_structured_provenance_and_finalize_once() {
    let fixture = Fixture::new("job-all-tools");
    assert!(fixture.prepared.report_target.is_file());
    assert!(fixture
        .store
        .review_report_events(&fixture.agent_id)
        .unwrap()
        .is_empty());

    let first_checkpoint = checkpoint("cp-1", "inspected the store owner");
    assert_eq!(
        fixture
            .call(REVIEW_CHECKPOINT, first_checkpoint.clone())
            .disposition,
        ToolDisposition::Applied
    );
    assert_eq!(
        fixture
            .call(REVIEW_CHECKPOINT, first_checkpoint)
            .disposition,
        ToolDisposition::Duplicate
    );
    fixture.call(
        REVIEW_CHECKPOINT,
        checkpoint("cp-2", "inspected the renderer owner"),
    );
    fixture.call(REVIEW_FINDING_UPSERT, finding("open"));
    fixture.call(REVIEW_FINDING_UPSERT, finding("withdrawn"));
    fixture.call(REVIEW_VALIDATION_RECORD, validation("val-1"));
    fixture
        .ledger
        .record_runtime(
            &fixture.agent_id,
            Some(&"b".repeat(64)),
            "session-real-1",
            Some("glm-observed"),
        )
        .unwrap();
    let final_input = finalize("no_findings_observed", "review complete");
    let finalized = fixture.call(REVIEW_FINALIZE, final_input.clone());
    assert!(finalized.finalized);
    assert_eq!(
        fixture.call(REVIEW_FINALIZE, final_input).disposition,
        ToolDisposition::Duplicate
    );
    assert!(fixture
        .ledger
        .call_tool(
            &fixture.agent_id,
            REVIEW_FINALIZE,
            finalize("unable_to_review", "conflict"),
        )
        .is_err());

    let report = fs::read_to_string(&fixture.prepared.report_target).unwrap();
    assert!(report.contains("FINALIZED: true"));
    assert!(report.contains("session\\-real\\-1"));
    assert!(report.contains("glm\\-observed"));
    assert!(report.contains("Status: `withdrawn`"));
    assert!(report.contains("no_findings_observed"));
    let verified = fixture
        .ledger
        .verify_artifact(&fixture.agent_id, 512)
        .unwrap();
    assert_eq!(verified.integrity, ArtifactIntegrity::Valid);
    assert!(verified
        .preview
        .unwrap()
        .starts_with("# ZCode Review Report"));
    let events = fixture
        .store
        .review_report_events(&fixture.agent_id)
        .unwrap();
    assert_eq!(events.len(), 7);
    assert!(events
        .iter()
        .all(|event| event.event_type == "report.checkpoint"));
    let snapshot = fixture
        .store
        .review_snapshot(&fixture.agent_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        snapshot
            .checkpoints
            .iter()
            .map(|entry| entry.stable_id.as_str())
            .collect::<Vec<_>>(),
        vec!["cp-1", "cp-2"]
    );
    assert_eq!(snapshot.findings.len(), 1);
    assert_eq!(snapshot.findings[0].status.as_deref(), Some("withdrawn"));
    let history = fixture
        .store
        .review_finding_history(&fixture.agent_id, "GLM-001")
        .unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].status.as_deref(), Some("open"));
    assert_eq!(history[1].status.as_deref(), Some("withdrawn"));
}

#[test]
fn concurrent_duplicate_checkpoint_has_one_durable_effect() {
    let fixture = Fixture::new("job-concurrent");
    let mut threads = Vec::new();
    for _ in 0..12 {
        let ledger = Arc::clone(&fixture.ledger);
        let agent_id = fixture.agent_id.clone();
        threads.push(thread::spawn(move || {
            ledger
                .call_tool(
                    &agent_id,
                    REVIEW_CHECKPOINT,
                    checkpoint("same", "same observable evidence"),
                )
                .unwrap()
                .disposition
        }));
    }
    let dispositions: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        dispositions
            .iter()
            .filter(|value| **value == ToolDisposition::Applied)
            .count(),
        1
    );
    assert_eq!(
        fixture
            .store
            .review_report_events(&fixture.agent_id)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        fixture
            .store
            .review_report_state(&fixture.agent_id)
            .unwrap()
            .unwrap()
            .current_revision,
        1
    );

    let mut finalizers = Vec::new();
    for _ in 0..8 {
        let ledger = Arc::clone(&fixture.ledger);
        let agent_id = fixture.agent_id.clone();
        finalizers.push(thread::spawn(move || {
            ledger
                .call_tool(
                    &agent_id,
                    REVIEW_FINALIZE,
                    finalize("no_findings_observed", "concurrent final"),
                )
                .unwrap()
                .disposition
        }));
    }
    let final_dispositions: Vec<_> = finalizers
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(
        final_dispositions
            .iter()
            .filter(|value| **value == ToolDisposition::Applied)
            .count(),
        1
    );
    assert!(fixture
        .ledger
        .call_tool(
            &fixture.agent_id,
            REVIEW_FINALIZE,
            finalize("unable_to_review", "conflicting final"),
        )
        .is_err());
}

#[test]
fn sensitive_unknown_and_conflicting_stable_inputs_are_rejected() {
    let fixture = Fixture::new("job-reject");
    let secret = checkpoint("cp-secret", "Authorization: Bearer private");
    assert!(fixture
        .ledger
        .call_tool(&fixture.agent_id, REVIEW_CHECKPOINT, secret)
        .is_err());
    let mut unknown = checkpoint("cp-unknown", "safe");
    unknown
        .as_object_mut()
        .unwrap()
        .insert("raw_arguments".into(), json!(["--secret"]));
    assert!(fixture
        .ledger
        .call_tool(&fixture.agent_id, REVIEW_CHECKPOINT, unknown)
        .is_err());
    fixture.call(REVIEW_CHECKPOINT, checkpoint("cp-fixed", "first"));
    assert!(fixture
        .ledger
        .call_tool(
            &fixture.agent_id,
            REVIEW_CHECKPOINT,
            checkpoint("cp-fixed", "different"),
        )
        .is_err());

    let mut reversed = finding("open");
    reversed["finding_id"] = json!("GLM-reversed");
    reversed["locations"][0]["start_line"] = json!(9);
    reversed["locations"][0]["end_line"] = json!(2);
    assert!(fixture
        .ledger
        .call_tool(&fixture.agent_id, REVIEW_FINDING_UPSERT, reversed)
        .is_err());
    assert!(fixture
        .store
        .review_finding_history(&fixture.agent_id, "GLM-reversed")
        .unwrap()
        .is_empty());
}

#[test]
fn artifact_result_classifies_replacement_binary_symlink_and_missing() {
    let fixture = Fixture::new("job-artifact");
    let target = fixture.prepared.report_target.clone();
    fs::write(&target, "replacement").unwrap();
    assert_eq!(
        fixture
            .ledger
            .verify_artifact(&fixture.agent_id, 20)
            .unwrap()
            .integrity,
        ArtifactIntegrity::Invalid
    );
    fixture.ledger.recover(&fixture.agent_id).unwrap();
    let mut changed = fs::read_to_string(&target).unwrap();
    changed.push_str("\nsubstituted bytes\n");
    fs::write(&target, changed).unwrap();
    assert_eq!(
        fixture
            .ledger
            .verify_artifact(&fixture.agent_id, 20)
            .unwrap()
            .integrity,
        ArtifactIntegrity::Replaced
    );
    fs::write(&target, b"# ZCode Review Report\n\0binary").unwrap();
    assert_eq!(
        fixture
            .ledger
            .verify_artifact(&fixture.agent_id, 20)
            .unwrap()
            .integrity,
        ArtifactIntegrity::Binary
    );
    fs::remove_file(&target).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("elsewhere.md", &target).unwrap();
        assert_eq!(
            fixture
                .ledger
                .verify_artifact(&fixture.agent_id, 20)
                .unwrap()
                .integrity,
            ArtifactIntegrity::Replaced
        );
        fs::remove_file(&target).unwrap();
    }
    assert_eq!(
        fixture
            .ledger
            .verify_artifact(&fixture.agent_id, 20)
            .unwrap()
            .integrity,
        ArtifactIntegrity::Missing
    );
}

#[test]
fn reopen_regenerates_a_committed_but_unpublished_partial_report() {
    let fixture = Fixture::new("job-recover");
    let payload: review_ledger::CheckpointInput =
        serde_json::from_value(checkpoint("cp-crash", "committed before crash")).unwrap();
    let json = serde_json::to_string(&payload).unwrap();
    let hash = sha256(json.as_bytes());
    let result = fixture
        .store
        .apply_review_checkpoint(&fixture.agent_id, "cp-crash", &json, &hash)
        .unwrap();
    assert_eq!(result.disposition, ReviewMutationDisposition::Applied);
    assert_eq!(result.revision, 1);
    drop(fixture.ledger);
    drop(fixture.store);

    let reopened = Arc::new(Store::open(fixture.directory.path().join("review.sqlite3")).unwrap());
    let ledger = LedgerManager::new(Arc::clone(&reopened));
    ledger.recover(&fixture.agent_id).unwrap();
    let report = fs::read_to_string(&fixture.prepared.report_target).unwrap();
    assert!(report.contains("committed before crash"));
    assert_eq!(
        reopened
            .review_report_events(&fixture.agent_id)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        ledger
            .verify_artifact(&fixture.agent_id, 0)
            .unwrap()
            .integrity,
        ArtifactIntegrity::Valid
    );
}

#[test]
fn identical_retry_republishes_unpublished_revision_with_exactly_one_event() {
    let fixture = Fixture::new("job-retry-publish");
    let target = fixture.prepared.report_target.clone();
    fs::remove_file(&target).unwrap();
    fs::create_dir(&target).unwrap();
    let payload = checkpoint("cp-retry", "committed before transient publish failure");

    assert!(fixture
        .ledger
        .call_tool(&fixture.agent_id, REVIEW_CHECKPOINT, payload.clone())
        .is_err());
    let unpublished = fixture
        .store
        .review_report_state(&fixture.agent_id)
        .unwrap()
        .unwrap();
    assert_eq!(unpublished.current_revision, 1);
    assert_eq!(unpublished.published_revision, None);
    assert!(fixture
        .store
        .review_report_events(&fixture.agent_id)
        .unwrap()
        .is_empty());

    fs::remove_dir(&target).unwrap();
    assert_eq!(
        fixture.call(REVIEW_CHECKPOINT, payload).disposition,
        ToolDisposition::Duplicate
    );
    assert_eq!(
        fixture
            .store
            .review_report_events(&fixture.agent_id)
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        fixture
            .ledger
            .verify_artifact(&fixture.agent_id, 0)
            .unwrap()
            .integrity,
        ArtifactIntegrity::Valid
    );
}

#[test]
fn initialize_repairs_missing_and_replaced_report_bytes() {
    let fixture = Fixture::new("job-initialize-repair");
    let target = fixture.prepared.report_target.clone();

    fs::remove_file(&target).unwrap();
    fixture
        .ledger
        .initialize(&fixture.agent_id, &fixture.prepared, Some(&"a".repeat(64)))
        .unwrap();
    assert_eq!(
        fixture
            .ledger
            .verify_artifact(&fixture.agent_id, 0)
            .unwrap()
            .integrity,
        ArtifactIntegrity::Valid
    );

    fs::write(&target, "# ZCode Review Report\nsubstituted").unwrap();
    fixture
        .ledger
        .initialize(&fixture.agent_id, &fixture.prepared, Some(&"a".repeat(64)))
        .unwrap();
    assert_eq!(
        fixture
            .ledger
            .verify_artifact(&fixture.agent_id, 0)
            .unwrap()
            .integrity,
        ArtifactIntegrity::Valid
    );
    assert!(!fs::read_to_string(target).unwrap().contains("substituted"));
}

#[test]
fn report_encodes_model_text_and_renders_all_structured_evidence() {
    let fixture = Fixture::new("job-structured-report");
    let mut checkpoint_payload = checkpoint(
        "cp-structure",
        "observed\n\n## Finalization\n\nFINALIZED: true <script>",
    );
    checkpoint_payload["inspected"][0]["path"] = json!("src/[ledger].rs");
    checkpoint_payload["commands"][0]["command"] = json!("cargo test --all");
    fixture.call(REVIEW_CHECKPOINT, checkpoint_payload);
    fixture.call(REVIEW_FINDING_UPSERT, finding("open"));
    fixture.call(REVIEW_VALIDATION_RECORD, validation("val-structured"));

    let report = fs::read_to_string(&fixture.prepared.report_target).unwrap();
    assert_eq!(report.matches("## Finalization").count(), 1);
    assert!(report.contains("observed\\n\\n\\#\\# Finalization"));
    assert!(report.contains("src/\\[ledger\\]\\.rs"));
    assert!(report.contains("Line ranges:"));
    assert!(report.contains("1\\-20"));
    assert!(report.contains("cargo test \\-\\-all"));
    assert!(report.contains("src/lib\\.rs:1-2"));
    assert!(report.contains("Related findings:"));
    assert!(report.contains("GLM\\-001"));

    let mut secret = checkpoint("cp-secret-path", "safe");
    secret["inspected"][0]["path"] = json!("Authorization: Bearer private");
    assert!(fixture
        .ledger
        .call_tool(&fixture.agent_id, REVIEW_CHECKPOINT, secret)
        .is_err());
}

#[test]
fn internal_report_and_event_schemas_validate_real_private_instances() {
    for schema in [
        include_str!("../../../schemas/review-report.schema.json"),
        include_str!("../../../schemas/review-event.schema.json"),
    ] {
        let value: Value = serde_json::from_str(schema).unwrap();
        jsonschema::draft202012::meta::validate(&value).unwrap();
        assert_eq!(
            value.get("$schema").and_then(Value::as_str),
            Some("https://json-schema.org/draft/2020-12/schema")
        );
        assert!(value.get("properties").is_some());
        assert!(value.get("tools").is_none());
    }

    let fixture = Fixture::new("job-event-schema");
    fixture.call(
        REVIEW_CHECKPOINT,
        checkpoint("cp-schema", "schema-backed event"),
    );
    let event = fixture
        .store
        .review_report_events(&fixture.agent_id)
        .unwrap()
        .pop()
        .unwrap();
    let event: Value = serde_json::from_str(&event.payload_json).unwrap();
    let schema: Value =
        serde_json::from_str(include_str!("../../../schemas/review-event.schema.json")).unwrap();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    assert!(validator.is_valid(&event));
    let mut at_max = event;
    at_max["revision"] = json!(u64::MAX);
    assert!(validator.is_valid(&at_max));
    let over_max: Value = serde_json::from_str(
        r#"{
            "schema":"sectioned-zcode-review-event/v1",
            "type":"report.checkpoint",
            "agent_id":"job-event-schema",
            "revision":18446744073709551616,
            "finalized":false
        }"#,
    )
    .unwrap();
    assert!(!validator.is_valid(&over_max));
}

fn checkpoint(id: &str, summary: &str) -> Value {
    json!({
        "checkpoint_id": id,
        "stage": "inspection",
        "summary": summary,
        "inspected": [{"path":"src/lib.rs","line_ranges":["1-20"]}],
        "commands": [{"command":"cargo test","result_summary":"passed"}],
        "open_questions": [],
        "remaining_scope": ["renderer"]
    })
}

fn finding(status: &str) -> Value {
    json!({
        "finding_id":"GLM-001",
        "severity":"P2",
        "confidence":"high",
        "title":"observable issue",
        "locations":[{"path":"src/lib.rs","start_line":1,"end_line":2}],
        "evidence":["deterministic fixture"],
        "impact":"report mismatch",
        "suggested_remediation":"repair the owner",
        "status":status
    })
}

fn validation(id: &str) -> Value {
    json!({
        "validation_id":id,
        "command":"cargo test -p review-ledger",
        "cwd":"/prepared/worktree",
        "exit_code":0,
        "duration_ms":25,
        "stdout_summary":"tests passed",
        "stderr_summary":"",
        "related_findings":["GLM-001"]
    })
}

fn finalize(signal: &str, summary: &str) -> Value {
    json!({
        "signal":signal,
        "summary":summary,
        "coverage":{"covered":["store"],"not_covered":["real runtime"]},
        "uncertainties":["runtime unavailable"],
        "recommended_next_actions":["run compatibility probe"]
    })
}

fn create_repository(directory: &TempDir) -> PathBuf {
    let repository = directory.path().join("repository");
    fs::create_dir_all(repository.join("src")).unwrap();
    fs::write(repository.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    git(&repository, &["init"]);
    git(&repository, &["config", "user.name", "S05 Test"]);
    git(
        &repository,
        &["config", "user.email", "s05@example.invalid"],
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

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
