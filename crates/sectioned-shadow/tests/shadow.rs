use review_preparation::{NetworkPolicy, ReviewKind, ReviewManifest, RoundKind, ScratchPolicy};
use sectioned_shadow::{
    calibration, render_admission, run_shadow, write_admission, AdmissionDecision,
    AdmissionDisposition, CalibrationRecord, EvidenceClassification, PublicMcpClient, ShadowConfig,
    ShadowError, ShadowMode, ShadowProvenance, REQUIRED_ARTIFACT_SUFFIXES, SHADOW_SCHEMA,
};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, VecDeque},
    future::{self, Future},
    path::{Path, PathBuf},
    sync::Mutex,
};

struct FakeClient {
    calls: Mutex<Vec<String>>,
    responses: Mutex<VecDeque<(&'static str, Value)>>,
}

impl FakeClient {
    fn new(responses: Vec<(&'static str, Value)>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responses: Mutex::new(responses.into()),
        }
    }
}

impl PublicMcpClient for FakeClient {
    fn call(
        &self,
        tool: &'static str,
        _arguments: Value,
    ) -> impl Future<Output = Result<Value, ShadowError>> + Send {
        self.calls.lock().unwrap().push(tool.into());
        let response = self.responses.lock().unwrap().pop_front();
        future::ready(match response {
            Some((expected, value)) if expected == tool => Ok(value),
            Some((expected, _)) => Err(ShadowError::Protocol(format!(
                "expected {expected}, got {tool}"
            ))),
            None => Err(ShadowError::Protocol("unexpected call".into())),
        })
    }
}

fn manifest(root: &Path, kind: ReviewKind, round: RoundKind, id: &str) -> PathBuf {
    let plan = root.join("PLAN.md");
    std::fs::write(&plan, "# bounded plan\n").unwrap();
    let manifest = ReviewManifest {
        schema: "sectioned-zcode-review/v1".into(),
        review_kind: kind,
        feature_id: "shadow-feature".into(),
        section_id: "S08".into(),
        round_kind: round,
        repository: root.to_path_buf(),
        base_ref: "1111111111111111111111111111111111111111".into(),
        head_ref: "2222222222222222222222222222222222222222".into(),
        plan_path: plan,
        context_paths: vec![],
        scope_paths: vec![root.join("src")],
        forbidden_input_globs: vec![],
        validation_commands: BTreeMap::new(),
        report_target: root.join(".agent-work/reviews/report.md"),
        scratch_root: root.join("scratch"),
        model: Some("glm-shadow".into()),
        fresh_session: true,
        network_policy: NetworkPolicy::Deny,
        scratch_policy: ScratchPolicy::Isolated,
        idempotency_key: id.into(),
    };
    std::fs::create_dir_all(root.join(".agent-work/reviews")).unwrap();
    std::fs::write(
        root.join(".agent-work/reviews/report.md"),
        "# ZCode Review Report\n\nFixture evidence.\n",
    )
    .unwrap();
    let path = root.join(format!("{id}.json"));
    std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    path
}

fn config(root: &Path, manifest_path: PathBuf, stem: &str, mode: ShadowMode) -> ShadowConfig {
    ShadowConfig {
        schema: SHADOW_SCHEMA.into(),
        manifest_path,
        artifact_directory: root.join("artifacts"),
        artifact_stem: stem.into(),
        mode,
        wait_timeout_ms: 10,
        max_waits: 3,
    }
}

fn spawn(agent_id: &str, disposition: &str) -> Value {
    json!({
        "agent_id":agent_id,
        "submission_disposition":disposition,
        "state":"QUEUED",
        "last_event_sequence":0,
        "prompt_sha256":"prompt-hash",
        "capabilities":{}
    })
}

fn job(agent_id: &str, state: &str, fresh: bool) -> Value {
    json!({
        "agent_id":agent_id,
        "state":state,
        "turn_state":"IDLE",
        "last_event_sequence":2,
        "zcode_session_id": if fresh { Value::String(format!("session-{agent_id}")) } else { Value::Null },
        "fresh_session_observed":fresh,
        "manifest_sha256":"manifest-hash",
        "prepared_sha256":"prepared-hash",
        "prompt_sha256":"prompt-hash",
        "base_sha":"1111111111111111111111111111111111111111",
        "head_sha":"2222222222222222222222222222222222222222"
    })
}

fn report(agent_id: &str, valid: bool) -> Value {
    use sha2::Digest;
    let raw = b"# ZCode Review Report\n\nFixture evidence.\n";
    let hash = format!("{:x}", sha2::Sha256::digest(raw));
    json!({
        "job":job(agent_id, "COMPLETED", true),
        "report":{
            "finalized":true,
            "integrity":if valid { "valid" } else { "invalid" },
            "expected_sha256":hash,
            "observed_sha256":hash,
            "expected_bytes":raw.len(),
            "observed_bytes":raw.len(),
            "checkpoint_number":1,
            "preview":"# ZCode Review Report\n\nFixture evidence.\n"
        }
    })
}

fn successful_responses(agent_id: &'static str) -> Vec<(&'static str, Value)> {
    vec![
        ("zcode_review_spawn", spawn(agent_id, "created")),
        (
            "zcode_review_status",
            json!({"job":job(agent_id,"RUNNING",true),"pending_requests":[]}),
        ),
        (
            "zcode_review_wait",
            json!({
                "job":job(agent_id,"RUNNING",true),
                "events":[{"sequence":1,"event_type":"report.checkpoint","redaction_level":"allowlisted"}],
                "timed_out":false
            }),
        ),
        (
            "zcode_review_status",
            json!({"job":job(agent_id,"COMPLETED",true),"pending_requests":[]}),
        ),
        ("zcode_review_result", report(agent_id, true)),
        (
            "zcode_review_close",
            json!({"agent_id":agent_id,"state":"COMPLETED","resources_reaped":true}),
        ),
    ]
}

#[tokio::test]
async fn full_plan_and_code_runs_produce_independent_separate_artifacts() {
    for (kind, round, stem) in [
        (ReviewKind::Plan, RoundKind::PlanReview, "S08-plan"),
        (ReviewKind::Code, RoundKind::FinalBounded, "S08-code"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let manifest_path = manifest(directory.path(), kind, round, stem);
        let config = config(directory.path(), manifest_path, stem, ShadowMode::Full);
        let paths = config.artifact_paths();
        std::fs::create_dir_all(paths.gpt_raw.parent().unwrap()).unwrap();
        std::fs::write(&paths.gpt_raw, "# independent GPT raw\n").unwrap();
        std::fs::write(&paths.gpt_admission, "# GPT admission\n").unwrap();
        let client = FakeClient::new(successful_responses(stem));
        let run = run_shadow(&client, &config).await.unwrap();
        assert_eq!(
            run.provenance.classification,
            EvidenceClassification::IndependentEvidence
        );
        assert_eq!(run.provenance.review_kind, kind.as_str());
        assert_eq!(run.provenance.checkpoint_count, 1);
        assert!(paths.glm_raw.is_file());
        assert!(paths.glm_provenance.is_file());
        assert_eq!(
            std::fs::read_to_string(&paths.gpt_raw).unwrap(),
            "# independent GPT raw\n"
        );
        assert!(!paths.glm_admission.exists());
        assert_eq!(
            client.calls.into_inner().unwrap(),
            [
                "zcode_review_spawn",
                "zcode_review_status",
                "zcode_review_wait",
                "zcode_review_status",
                "zcode_review_result",
                "zcode_review_close"
            ]
        );
    }
}

#[tokio::test]
async fn duplicate_spawn_and_missing_fresh_session_never_count() {
    let directory = tempfile::tempdir().unwrap();
    let manifest_path = manifest(
        directory.path(),
        ReviewKind::Code,
        RoundKind::InitialBounded,
        "duplicate",
    );
    let transport_config = config(
        directory.path(),
        manifest_path,
        "duplicate",
        ShadowMode::Full,
    );
    let client = FakeClient::new(vec![
        (
            "zcode_review_spawn",
            spawn("same-agent", "existing_compatible"),
        ),
        (
            "zcode_review_status",
            json!({"job":job("same-agent","COMPLETED",false),"pending_requests":[]}),
        ),
        ("zcode_review_result", report("same-agent", true)),
        (
            "zcode_review_close",
            json!({"agent_id":"same-agent","state":"COMPLETED","resources_reaped":true}),
        ),
    ]);
    let run = run_shadow(&client, &transport_config).await.unwrap();
    assert_eq!(
        run.provenance.classification,
        EvidenceClassification::EvidenceIncomplete
    );
    assert_eq!(run.provenance.submission_disposition, "existing_compatible");
    assert!(!run.provenance.fresh_session_observed);
}

#[tokio::test]
async fn delta_and_resume_are_consultation_only() {
    for (round, mode, stem) in [
        (
            RoundKind::RepairDelta,
            ShadowMode::DeltaConsultation,
            "delta",
        ),
        (
            RoundKind::FinalBounded,
            ShadowMode::ResumeConsultation,
            "resume",
        ),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let manifest_path = manifest(directory.path(), ReviewKind::Code, round, stem);
        let config = config(directory.path(), manifest_path, stem, mode);
        let client = FakeClient::new(vec![
            ("zcode_review_spawn", spawn(stem, "created")),
            (
                "zcode_review_status",
                json!({"job":job(stem,"COMPLETED",true),"pending_requests":[]}),
            ),
            ("zcode_review_result", report(stem, true)),
            (
                "zcode_review_close",
                json!({"agent_id":stem,"state":"COMPLETED","resources_reaped":true}),
            ),
        ]);
        let run = run_shadow(&client, &config).await.unwrap();
        assert_eq!(
            run.provenance.classification,
            EvidenceClassification::Consultation
        );
    }
}

#[tokio::test]
async fn unsupported_input_and_runtime_failure_are_evidence_incomplete() {
    for (state, pending, stem) in [
        (
            "COMPLETED",
            json!([{"kind":"unsupported_input","respondable":false}]),
            "unsupported",
        ),
        ("FAILED_RUNTIME_LOST", json!([]), "runtime-lost"),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let manifest_path = manifest(
            directory.path(),
            ReviewKind::Code,
            RoundKind::InitialBounded,
            stem,
        );
        let config = config(directory.path(), manifest_path, stem, ShadowMode::Full);
        let client = FakeClient::new(vec![
            ("zcode_review_spawn", spawn(stem, "created")),
            (
                "zcode_review_status",
                json!({"job":job(stem,state,true),"pending_requests":pending}),
            ),
            ("zcode_review_result", report(stem, true)),
            (
                "zcode_review_close",
                json!({"agent_id":stem,"state":state,"resources_reaped":true}),
            ),
        ]);
        let run = run_shadow(&client, &config).await.unwrap();
        assert_eq!(
            run.provenance.classification,
            EvidenceClassification::EvidenceIncomplete
        );
    }
}

#[tokio::test]
async fn transport_failure_and_report_replacement_are_evidence_incomplete() {
    let directory = tempfile::tempdir().unwrap();
    let manifest_path = manifest(
        directory.path(),
        ReviewKind::Code,
        RoundKind::InitialBounded,
        "transport",
    );
    let transport_config = config(
        directory.path(),
        manifest_path,
        "transport",
        ShadowMode::Full,
    );
    let client = FakeClient::new(vec![
        ("zcode_review_spawn", spawn("transport", "created")),
        ("wrong_tool", json!({})),
    ]);
    let run = run_shadow(&client, &transport_config).await.unwrap();
    assert_eq!(
        run.provenance.classification,
        EvidenceClassification::EvidenceIncomplete
    );
    assert!(run.provenance.runtime_failure_observed);
    assert!(run.artifacts.glm_provenance.is_file());

    let replaced = tempfile::tempdir().unwrap();
    let manifest_path = manifest(
        replaced.path(),
        ReviewKind::Code,
        RoundKind::InitialBounded,
        "replaced",
    );
    std::fs::write(
        replaced.path().join(".agent-work/reviews/report.md"),
        "# replaced after daemon projection\n",
    )
    .unwrap();
    let config = config(replaced.path(), manifest_path, "replaced", ShadowMode::Full);
    let client = FakeClient::new(vec![
        ("zcode_review_spawn", spawn("replaced", "created")),
        (
            "zcode_review_status",
            json!({"job":job("replaced","COMPLETED",true),"pending_requests":[]}),
        ),
        ("zcode_review_result", report("replaced", true)),
        (
            "zcode_review_close",
            json!({"agent_id":"replaced","state":"COMPLETED","resources_reaped":true}),
        ),
    ]);
    let run = run_shadow(&client, &config).await.unwrap();
    assert_eq!(
        run.provenance.classification,
        EvidenceClassification::EvidenceIncomplete
    );
    assert!(!run.provenance.report_schema_compliant);
}

#[test]
fn prior_review_artifacts_and_full_delta_configuration_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let manifest_path = manifest(
        directory.path(),
        ReviewKind::Code,
        RoundKind::FinalBounded,
        "context",
    );
    let mut value: Value = serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    value["context_paths"] = json!([directory.path().join("S07-GLM-RAW.md")]);
    std::fs::write(&manifest_path, serde_json::to_vec(&value).unwrap()).unwrap();
    let context_config = config(directory.path(), manifest_path, "context", ShadowMode::Full);
    assert!(context_config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("prior review evidence"));

    let delta = manifest(
        directory.path(),
        ReviewKind::Code,
        RoundKind::RepairDelta,
        "full-delta",
    );
    let config = config(directory.path(), delta, "full-delta", ShadowMode::Full);
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("consultation"));
}

#[test]
fn admission_and_calibration_are_explicit_deterministic_projections() {
    let admissions = vec![
        AdmissionDecision {
            finding_id: "GLM-001".into(),
            disposition: AdmissionDisposition::Admitted,
            rationale: "reachable".into(),
        },
        AdmissionDecision {
            finding_id: "GLM-002".into(),
            disposition: AdmissionDisposition::Rejected,
            rationale: "outside boundary".into(),
        },
        AdmissionDecision {
            finding_id: "GLM-001".into(),
            disposition: AdmissionDisposition::Duplicate,
            rationale: "same root cause".into(),
        },
        AdmissionDecision {
            finding_id: "GLM-003".into(),
            disposition: AdmissionDisposition::Deferred,
            rationale: "separate feature".into(),
        },
    ];
    let provenance = vec![provenance(false, false), provenance(true, true)];
    let record = calibration(&provenance, &admissions);
    assert_eq!(record.unique_findings, 3);
    assert_eq!(record.duplicate_findings, 1);
    assert_eq!(record.admitted_findings, 1);
    assert_eq!(record.rejected_findings, 1);
    assert_eq!(record.deferred_findings, 1);
    assert_eq!(record.unsupported_evidence_rate, 0.5);
    assert_eq!(record.runtime_failure_rate, 0.5);
    assert!(record.report_schema_compliance);
    assert_eq!(record.wall_time_ms, 20);
    assert_eq!(record.checkpoint_count, 4);
    let rendered = render_admission(&admissions);
    assert!(rendered.contains("sole admission authority"));
    assert!(!rendered.contains("Clean A"));
    let directory = tempfile::tempdir().unwrap();
    let admission_path = directory.path().join("S08-GLM-ADMISSION.md");
    write_admission(&admission_path, &admissions).unwrap();
    assert_eq!(std::fs::read_to_string(admission_path).unwrap(), rendered);
    assert_eq!(REQUIRED_ARTIFACT_SUFFIXES.len(), 5);
}

#[test]
fn checked_in_schemas_accept_typed_examples_and_require_all_calibration_fields() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let compile = |name: &str| {
        let schema: Value =
            serde_json::from_slice(&std::fs::read(root.join("schemas").join(name)).unwrap())
                .unwrap();
        jsonschema::validator_for(&schema).unwrap()
    };
    let directory = tempfile::tempdir().unwrap();
    let config = config(
        directory.path(),
        manifest(
            directory.path(),
            ReviewKind::Plan,
            RoundKind::PlanReview,
            "schema",
        ),
        "schema",
        ShadowMode::Full,
    );
    assert!(compile("shadow-config.schema.json").is_valid(&serde_json::to_value(config).unwrap()));
    assert!(compile("shadow-provenance.schema.json")
        .is_valid(&serde_json::to_value(provenance(false, false)).unwrap()));
    let record = CalibrationRecord {
        schema: SHADOW_SCHEMA.into(),
        unique_findings: 1,
        duplicate_findings: 0,
        admitted_findings: 1,
        rejected_findings: 0,
        deferred_findings: 0,
        unsupported_evidence_rate: 0.0,
        runtime_failure_rate: 0.0,
        report_schema_compliance: true,
        wall_time_ms: 1,
        checkpoint_count: 1,
    };
    let calibration = serde_json::to_value(record).unwrap();
    let validator = compile("shadow-calibration.schema.json");
    assert!(validator.is_valid(&calibration));
    let mut missing = calibration;
    missing.as_object_mut().unwrap().remove("checkpoint_count");
    assert!(!validator.is_valid(&missing));
}

fn provenance(unsupported: bool, failed: bool) -> ShadowProvenance {
    ShadowProvenance {
        schema: SHADOW_SCHEMA.into(),
        agent_id: "agent".into(),
        submission_disposition: "created".into(),
        zcode_session_id: Some("session".into()),
        fresh_session_observed: true,
        classification: EvidenceClassification::IndependentEvidence,
        review_kind: "code".into(),
        round_kind: "INITIAL_BOUNDED".into(),
        manifest_sha256: Some("manifest".into()),
        prepared_sha256: Some("prepared".into()),
        prompt_sha256: "prompt".into(),
        base_sha: Some("base".into()),
        head_sha: Some("head".into()),
        report_sha256: Some("report".into()),
        report_bytes: Some(42),
        report_schema_compliant: true,
        checkpoint_count: 2,
        unsupported_input_observed: unsupported,
        runtime_failure_observed: failed,
        wall_time_ms: 10,
    }
}
