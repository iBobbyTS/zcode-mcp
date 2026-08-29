use review_preparation::{ReviewKind, ReviewManifest, RoundKind};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt, fs,
    future::Future,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const SHADOW_SCHEMA: &str = "sectioned-zcode-shadow/v1";
pub const REQUIRED_ARTIFACT_SUFFIXES: [&str; 5] = [
    "-GPT-RAW.md",
    "-GPT-ADMISSION.md",
    "-GLM-RAW.md",
    "-GLM-PROVENANCE.json",
    "-GLM-ADMISSION.md",
];

#[derive(Debug)]
pub enum ShadowError {
    Configuration(String),
    Transport(String),
    Protocol(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for ShadowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => write!(f, "shadow configuration invalid: {message}"),
            Self::Transport(message) => write!(f, "shadow MCP transport failed: {message}"),
            Self::Protocol(message) => write!(f, "shadow MCP response invalid: {message}"),
            Self::Io(error) => write!(f, "shadow artifact IO failed: {error}"),
            Self::Json(error) => write!(f, "shadow JSON failed: {error}"),
        }
    }
}

impl std::error::Error for ShadowError {}
impl From<std::io::Error> for ShadowError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for ShadowError {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShadowMode {
    Full,
    DeltaConsultation,
    ResumeConsultation,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ShadowConfig {
    pub schema: String,
    pub manifest_path: PathBuf,
    pub artifact_directory: PathBuf,
    pub artifact_stem: String,
    pub mode: ShadowMode,
    #[schemars(range(min = 1, max = 5000))]
    pub wait_timeout_ms: u64,
    #[schemars(range(min = 1, max = 1000))]
    pub max_waits: u16,
}

impl ShadowConfig {
    pub fn validate(&self) -> Result<ReviewManifest, ShadowError> {
        if self.schema != SHADOW_SCHEMA {
            return Err(ShadowError::Configuration("unsupported schema".into()));
        }
        if !self.manifest_path.is_absolute() || !self.artifact_directory.is_absolute() {
            return Err(ShadowError::Configuration(
                "manifest_path and artifact_directory must be absolute".into(),
            ));
        }
        if self.artifact_stem.is_empty()
            || self.artifact_stem.len() > 160
            || !self
                .artifact_stem
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(ShadowError::Configuration(
                "artifact_stem must be a bounded portable identifier".into(),
            ));
        }
        if !(1..=5000).contains(&self.wait_timeout_ms) || !(1..=1000).contains(&self.max_waits) {
            return Err(ShadowError::Configuration("wait bounds are invalid".into()));
        }
        let bytes = fs::read(&self.manifest_path)?;
        let manifest = ReviewManifest::from_json(&bytes)
            .map_err(|error| ShadowError::Configuration(error.to_string()))?;
        validate_independent_context(&manifest)?;
        if self.mode == ShadowMode::Full && manifest.round_kind == RoundKind::RepairDelta {
            return Err(ShadowError::Configuration(
                "REPAIR_DELTA is consultation and cannot be configured as full evidence".into(),
            ));
        }
        Ok(manifest)
    }

    pub fn artifact_paths(&self) -> ArtifactPaths {
        ArtifactPaths {
            gpt_raw: self
                .artifact_directory
                .join(format!("{}-GPT-RAW.md", self.artifact_stem)),
            gpt_admission: self
                .artifact_directory
                .join(format!("{}-GPT-ADMISSION.md", self.artifact_stem)),
            glm_raw: self
                .artifact_directory
                .join(format!("{}-GLM-RAW.md", self.artifact_stem)),
            glm_provenance: self
                .artifact_directory
                .join(format!("{}-GLM-PROVENANCE.json", self.artifact_stem)),
            glm_admission: self
                .artifact_directory
                .join(format!("{}-GLM-ADMISSION.md", self.artifact_stem)),
        }
    }
}

fn validate_independent_context(manifest: &ReviewManifest) -> Result<(), ShadowError> {
    let paths = std::iter::once(&manifest.plan_path).chain(manifest.context_paths.iter());
    for path in paths {
        let text = path.to_string_lossy();
        if REQUIRED_ARTIFACT_SUFFIXES
            .iter()
            .any(|suffix| text.ends_with(suffix))
            || text.to_ascii_lowercase().contains("session-transcript")
            || text.to_ascii_lowercase().contains("review-conclusion")
        {
            return Err(ShadowError::Configuration(format!(
                "counted context contains prior review evidence: {text}"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactPaths {
    pub gpt_raw: PathBuf,
    pub gpt_admission: PathBuf,
    pub glm_raw: PathBuf,
    pub glm_provenance: PathBuf,
    pub glm_admission: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClassification {
    IndependentEvidence,
    Consultation,
    EvidenceIncomplete,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ShadowProvenance {
    pub schema: String,
    pub agent_id: String,
    pub submission_disposition: String,
    pub zcode_session_id: Option<String>,
    pub fresh_session_observed: bool,
    pub classification: EvidenceClassification,
    pub review_kind: String,
    pub round_kind: String,
    pub manifest_sha256: Option<String>,
    pub prepared_sha256: Option<String>,
    pub prompt_sha256: String,
    pub base_sha: Option<String>,
    pub head_sha: Option<String>,
    pub report_sha256: Option<String>,
    pub report_bytes: Option<u64>,
    pub report_schema_compliant: bool,
    pub checkpoint_count: u64,
    pub unsupported_input_observed: bool,
    pub runtime_failure_observed: bool,
    pub wall_time_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionDisposition {
    Admitted,
    Rejected,
    Deferred,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct AdmissionDecision {
    pub finding_id: String,
    pub disposition: AdmissionDisposition,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct CalibrationRecord {
    pub schema: String,
    pub unique_findings: u64,
    pub duplicate_findings: u64,
    pub admitted_findings: u64,
    pub rejected_findings: u64,
    pub deferred_findings: u64,
    pub unsupported_evidence_rate: f64,
    pub runtime_failure_rate: f64,
    pub report_schema_compliance: bool,
    pub wall_time_ms: u64,
    pub checkpoint_count: u64,
}

pub fn calibration(
    provenance: &[ShadowProvenance],
    admissions: &[AdmissionDecision],
) -> CalibrationRecord {
    let total = provenance.len() as f64;
    let rate = |count: usize| {
        if total == 0.0 {
            0.0
        } else {
            count as f64 / total
        }
    };
    CalibrationRecord {
        schema: SHADOW_SCHEMA.into(),
        unique_findings: admissions
            .iter()
            .filter(|item| item.disposition != AdmissionDisposition::Duplicate)
            .map(|item| item.finding_id.as_str())
            .collect::<BTreeSet<_>>()
            .len() as u64,
        duplicate_findings: admissions
            .iter()
            .filter(|item| item.disposition == AdmissionDisposition::Duplicate)
            .count() as u64,
        admitted_findings: count_admissions(admissions, AdmissionDisposition::Admitted),
        rejected_findings: count_admissions(admissions, AdmissionDisposition::Rejected),
        deferred_findings: count_admissions(admissions, AdmissionDisposition::Deferred),
        unsupported_evidence_rate: rate(
            provenance
                .iter()
                .filter(|item| item.unsupported_input_observed)
                .count(),
        ),
        runtime_failure_rate: rate(
            provenance
                .iter()
                .filter(|item| item.runtime_failure_observed)
                .count(),
        ),
        report_schema_compliance: !provenance.is_empty()
            && provenance.iter().all(|item| item.report_schema_compliant),
        wall_time_ms: provenance.iter().map(|item| item.wall_time_ms).sum(),
        checkpoint_count: provenance.iter().map(|item| item.checkpoint_count).sum(),
    }
}

fn count_admissions(items: &[AdmissionDecision], wanted: AdmissionDisposition) -> u64 {
    items
        .iter()
        .filter(|item| item.disposition == wanted)
        .count() as u64
}

pub fn render_admission(decisions: &[AdmissionDecision]) -> String {
    let mut output = String::from(
        "# GLM Shadow Admission\n\nMain Codex is the sole admission authority. This artifact does not approve or accept a section.\n\n",
    );
    for decision in decisions {
        output.push_str(&format!(
            "- `{}`: `{}` - {}\n",
            decision.finding_id,
            admission_name(decision.disposition),
            decision.rationale.replace('\n', " ")
        ));
    }
    output
}

fn admission_name(disposition: AdmissionDisposition) -> &'static str {
    match disposition {
        AdmissionDisposition::Admitted => "admitted",
        AdmissionDisposition::Rejected => "rejected",
        AdmissionDisposition::Deferred => "deferred",
        AdmissionDisposition::Duplicate => "duplicate",
    }
}

pub fn write_admission(path: &Path, decisions: &[AdmissionDecision]) -> Result<(), ShadowError> {
    atomic_write(path, render_admission(decisions).as_bytes())
}

pub fn normalized_manifest_sha256(manifest: &ReviewManifest) -> Result<String, ShadowError> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec_pretty(manifest)?)
    ))
}

pub trait PublicMcpClient {
    fn call(
        &self,
        tool: &'static str,
        arguments: Value,
    ) -> impl Future<Output = Result<Value, ShadowError>> + Send;
}

pub struct RmcpFacadeClient {
    service: rmcp::service::RunningService<rmcp::RoleClient, ()>,
}

impl RmcpFacadeClient {
    pub async fn spawn(facade_program: &Path, daemon_socket: &Path) -> Result<Self, ShadowError> {
        let mut command = tokio::process::Command::new(facade_program);
        command
            .env("ZCODE_REVIEWD_SOCKET", daemon_socket)
            .env("ZCODE_PUBLIC_API_MODE", "subagent_v2");
        let transport = rmcp::transport::TokioChildProcess::new(command)
            .map_err(|error| ShadowError::Transport(error.to_string()))?;
        let service = rmcp::ServiceExt::serve((), transport)
            .await
            .map_err(|error| ShadowError::Transport(error.to_string()))?;
        Ok(Self { service })
    }

    pub async fn shutdown(self) -> Result<(), ShadowError> {
        self.service
            .cancel()
            .await
            .map(|_| ())
            .map_err(|error| ShadowError::Transport(error.to_string()))
    }
}

impl PublicMcpClient for RmcpFacadeClient {
    async fn call(&self, tool: &'static str, arguments: Value) -> Result<Value, ShadowError> {
        let arguments = arguments
            .as_object()
            .cloned()
            .ok_or_else(|| ShadowError::Protocol("tool arguments must be an object".into()))?;
        let result = self
            .service
            .peer()
            .call_tool(rmcp::model::CallToolRequestParams::new(tool).with_arguments(arguments))
            .await
            .map_err(|error| ShadowError::Transport(error.to_string()))?;
        if result.is_error == Some(true) {
            return Err(ShadowError::Protocol(format!("{tool} returned an error")));
        }
        result
            .structured_content
            .ok_or_else(|| ShadowError::Protocol(format!("{tool} omitted structuredContent")))
    }
}

#[derive(Debug, Clone)]
pub struct ShadowRun {
    pub provenance: ShadowProvenance,
    pub artifacts: ArtifactPaths,
}

const SHADOW_REPORT_CAP_BYTES: u64 = 16 * 1024 * 1024;
const SHADOW_ARTIFACT_CHUNK_BYTES: u64 = 8 * 1024;

pub async fn run_shadow_v2<C: PublicMcpClient>(
    client: &C,
    config: &ShadowConfig,
) -> Result<ShadowRun, ShadowError> {
    let manifest = config.validate()?;
    let started = Instant::now();
    let spawn = client
        .call("zcode_review_spawn", v2_spawn_arguments(&manifest))
        .await?;
    let agent_id = string_field(&spawn, "agent_id")?.to_owned();
    let submission = string_field(&spawn, "submission_disposition")?.to_owned();
    let spawn_provenance = spawn
        .get("provenance")
        .ok_or_else(|| ShadowError::Protocol("review spawn omitted provenance".into()))?;
    let prompt_sha256 = string_field(spawn_provenance, "prompt_sha256")?.to_owned();
    let mut last_sequence = 0_u64;
    let mut unsupported = false;
    let mut terminal = None;
    for _ in 0..config.max_waits {
        let status = match client
            .call("zcode_agent_get", json!({"agent_id": agent_id}))
            .await
        {
            Ok(status) => status,
            Err(_) => {
                let _ = client
                    .call("zcode_agent_close", json!({"agent_id": agent_id}))
                    .await;
                return persist_incomplete(
                    config,
                    &manifest,
                    agent_id,
                    submission,
                    prompt_sha256,
                    started,
                );
            }
        };
        unsupported |= status
            .get("pending_requests")
            .and_then(Value::as_array)
            .is_some_and(|requests| {
                requests
                    .iter()
                    .any(|request| request["kind"] == "unsupported_input")
            });
        let task = status
            .get("task")
            .ok_or_else(|| ShadowError::Protocol("agent get omitted task".into()))?;
        if string_field(task, "phase")? == "TERMINAL" {
            terminal = Some(status);
            break;
        }
        let waited = match client
            .call(
                "zcode_agent_wait",
                json!({
                    "agent_id": agent_id,
                    "after_sequence": last_sequence,
                    "timeout_ms": config.wait_timeout_ms
                }),
            )
            .await
        {
            Ok(waited) => waited,
            Err(_) => {
                let _ = client
                    .call("zcode_agent_close", json!({"agent_id": agent_id}))
                    .await;
                return persist_incomplete(
                    config,
                    &manifest,
                    agent_id,
                    submission,
                    prompt_sha256,
                    started,
                );
            }
        };
        last_sequence = waited
            .get("next_sequence")
            .and_then(Value::as_u64)
            .unwrap_or(last_sequence);
        if waited
            .get("task")
            .and_then(|task| task.get("phase"))
            .and_then(Value::as_str)
            == Some("TERMINAL")
        {
            terminal = Some(json!({
                "task": waited["task"].clone(),
                "pending_requests": []
            }));
            break;
        }
    }
    let Some(status) = terminal else {
        let _ = client
            .call("zcode_agent_close", json!({"agent_id": agent_id}))
            .await;
        return persist_incomplete(
            config,
            &manifest,
            agent_id,
            submission,
            prompt_sha256,
            started,
        );
    };
    let task = status
        .get("task")
        .ok_or_else(|| ShadowError::Protocol("terminal agent get omitted task".into()))?;
    let fresh_session = task
        .get("fresh_session_observed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let counts_as_independent = task
        .get("counts_as_independent")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let result = match client
        .call("zcode_agent_result", json!({"agent_id": agent_id}))
        .await
    {
        Ok(result) => result,
        Err(_) => {
            let _ = client
                .call("zcode_agent_close", json!({"agent_id": agent_id}))
                .await;
            return persist_incomplete(
                config,
                &manifest,
                agent_id,
                submission,
                prompt_sha256,
                started,
            );
        }
    };
    let terminal_success = result
        .get("result")
        .and_then(|value| value.get("outcome"))
        .and_then(Value::as_str)
        == Some("SUCCEEDED");
    let report = read_v2_verified_report(client, &agent_id, &result)
        .await
        .ok();
    let checkpoint_count = report
        .as_ref()
        .and_then(|(_, _, bytes)| finalized_checkpoint_count(bytes));
    let review_evidence_valid = result
        .get("result")
        .and_then(|value| value.get("review_evidence"))
        .zip(report.as_ref())
        .zip(checkpoint_count)
        .is_some_and(|((evidence, (sha256, size_bytes, _)), checkpoint_count)| {
            let counts = &evidence["counts"];
            let validation_count = counts["validations"].as_u64();
            let daemon = &evidence["validation_provenance"]["daemon_verification"];
            let model = &evidence["validation_provenance"]["model_attestation"];
            evidence["finalized"] == true
                && matches!(
                    evidence["final_signal"].as_str(),
                    Some(
                        "findings_present"
                            | "no_findings_observed"
                            | "incomplete_evidence"
                            | "unable_to_review"
                    )
                )
                && evidence["report_revision"]
                    .as_u64()
                    .is_some_and(|revision| {
                        revision > 0
                            && evidence["finalization_revision"].as_u64().is_some_and(
                                |finalization| finalization > 0 && finalization <= revision,
                            )
                    })
                && evidence["artifact"]["sha256"].as_str() == Some(sha256.as_str())
                && evidence["artifact"]["size_bytes"].as_u64() == Some(*size_bytes)
                && counts["checkpoints"].as_u64() == Some(checkpoint_count)
                && validation_count.is_some_and(|count| count > 0)
                && evidence["independence"]["fresh_session_observed"].as_bool()
                    == Some(fresh_session)
                && evidence["independence"]["counts_as_independent"].as_bool()
                    == Some(counts_as_independent)
                && daemon["source_integrity_verified"] == true
                && daemon["finalized_report_verified"] == true
                && daemon["artifact_digest_verified"] == true
                && daemon["validation_records_structurally_verified"] == true
                && model["present"] == true
                && model["validation_record_count"].as_u64() == validation_count
        });
    let report_valid = checkpoint_count.is_some() && review_evidence_valid;
    let close_reaped = client
        .call("zcode_agent_close", json!({"agent_id": agent_id}))
        .await
        .ok()
        .and_then(|value| value.get("task").cloned())
        .and_then(|task| task.get("resources_reaped").and_then(Value::as_bool))
        .unwrap_or(false);
    let provenance_valid = spawn_provenance
        .get("base_sha")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
        && spawn_provenance
            .get("head_sha")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
        && spawn_provenance
            .get("manifest_sha256")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty())
        && spawn_provenance
            .get("prepared_sha256")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty());
    let complete_evidence =
        provenance_valid && report_valid && terminal_success && close_reaped && !unsupported;
    let classification = match config.mode {
        ShadowMode::Full
            if complete_evidence
                && submission == "created"
                && fresh_session
                && counts_as_independent =>
        {
            EvidenceClassification::IndependentEvidence
        }
        ShadowMode::DeltaConsultation | ShadowMode::ResumeConsultation if complete_evidence => {
            EvidenceClassification::Consultation
        }
        _ => EvidenceClassification::EvidenceIncomplete,
    };
    let report_sha256 = report.as_ref().map(|(sha256, _, _)| sha256.clone());
    let report_bytes = report.as_ref().map(|(_, size, _)| *size);
    let provenance = ShadowProvenance {
        schema: SHADOW_SCHEMA.into(),
        agent_id: agent_id.clone(),
        submission_disposition: submission,
        zcode_session_id: None,
        fresh_session_observed: fresh_session,
        classification,
        review_kind: manifest.review_kind.as_str().into(),
        round_kind: manifest.round_kind.as_str().into(),
        manifest_sha256: optional_string(spawn_provenance, "manifest_sha256"),
        prepared_sha256: optional_string(spawn_provenance, "prepared_sha256"),
        prompt_sha256,
        base_sha: optional_string(spawn_provenance, "base_sha"),
        head_sha: optional_string(spawn_provenance, "head_sha"),
        report_sha256,
        report_bytes,
        report_schema_compliant: report_valid,
        checkpoint_count: checkpoint_count.unwrap_or(0),
        unsupported_input_observed: unsupported,
        runtime_failure_observed: !terminal_success || !close_reaped,
        wall_time_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    };
    let artifacts = config.artifact_paths();
    fs::create_dir_all(&config.artifact_directory)?;
    let raw = report.map(|(_, _, bytes)| bytes).unwrap_or_else(|| {
        b"# ZCode Shadow Review\n\nEvidence incomplete: the verified public artifact was unavailable.\n".to_vec()
    });
    atomic_write(&artifacts.glm_raw, &raw)?;
    atomic_write(
        &artifacts.glm_provenance,
        &serde_json::to_vec_pretty(&provenance)?,
    )?;
    Ok(ShadowRun {
        provenance,
        artifacts,
    })
}

fn finalized_checkpoint_count(bytes: &[u8]) -> Option<u64> {
    let report = std::str::from_utf8(bytes).ok()?;
    if !report.contains("FINALIZED: true") {
        return None;
    }
    let checkpoints = report
        .split_once("\n## Checkpoints\n\n")?
        .1
        .split_once("\n## Findings\n\n")?
        .0;
    Some(
        checkpoints
            .lines()
            .filter(|line| line.starts_with("### "))
            .count()
            .try_into()
            .unwrap_or(u64::MAX),
    )
}

fn public_path(repository: &Path, path: &Path) -> String {
    path.strip_prefix(repository)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn v2_spawn_arguments(manifest: &ReviewManifest) -> Value {
    let review_kind = match manifest.round_kind {
        RoundKind::PlanReview => "plan_review",
        RoundKind::InitialBounded => "initial_bounded",
        RoundKind::RepairDelta => "repair_delta",
        RoundKind::FinalBounded => "final_bounded",
    };
    let mut arguments = json!({
        "review_kind": review_kind,
        "repository": manifest.repository,
        "base_ref": manifest.base_ref,
        "head_ref": manifest.head_ref,
        "scope_manifest": manifest.scope_paths.iter().map(|path| public_path(&manifest.repository, path)).collect::<Vec<_>>(),
        "requirements_path": public_path(&manifest.repository, &manifest.plan_path),
        "report_path": public_path(&manifest.repository, &manifest.report_target),
        "feature_id": manifest.feature_id,
        "section_id": manifest.section_id,
        "ownership_token": format!("sectioned-shadow:{}:{}", manifest.feature_id, manifest.section_id),
        "idempotency_key": manifest.idempotency_key,
        "read_only": true,
        "attachments": manifest.context_paths.iter().map(|path| public_path(&manifest.repository, path)).collect::<Vec<_>>()
    });
    if let Some(model) = &manifest.model {
        arguments["model"] = Value::String(model.clone());
    }
    arguments
}

async fn read_v2_verified_report<C: PublicMcpClient>(
    client: &C,
    agent_id: &str,
    result: &Value,
) -> Result<(String, u64, Vec<u8>), ShadowError> {
    let artifact = result
        .get("artifacts")
        .and_then(Value::as_array)
        .and_then(|artifacts| {
            artifacts
                .iter()
                .find(|artifact| artifact["kind"] == "report_markdown")
        })
        .ok_or_else(|| ShadowError::Protocol("result omitted report artifact".into()))?;
    let artifact_id = string_field(artifact, "artifact_id")?.to_owned();
    let sha256 = string_field(artifact, "sha256")?.to_owned();
    let size_bytes = artifact
        .get("size_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| ShadowError::Protocol("report artifact omitted size".into()))?;
    if size_bytes == 0 || size_bytes > SHADOW_REPORT_CAP_BYTES {
        return Err(ShadowError::Protocol(
            "report artifact size is outside the shadow bounds".into(),
        ));
    }
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ShadowError::Protocol(
            "report artifact digest is invalid".into(),
        ));
    }
    let attempt_sequence = result
        .get("task")
        .and_then(|task| task.get("attempt_sequence"))
        .and_then(Value::as_u64)
        .ok_or_else(|| ShadowError::Protocol("result omitted attempt sequence".into()))?;
    let mut bytes = Vec::with_capacity(size_bytes as usize);
    let max_chunks = size_bytes.div_ceil(SHADOW_ARTIFACT_CHUNK_BYTES);
    for _ in 0..max_chunks {
        if bytes.len() as u64 == size_bytes {
            break;
        }
        let offset = bytes.len() as u64;
        let requested = (size_bytes - offset).min(SHADOW_ARTIFACT_CHUNK_BYTES);
        let response = client
            .call(
                "zcode_agent_result",
                json!({
                    "agent_id": agent_id,
                    "attempt_sequence": attempt_sequence,
                    "artifact_id": artifact_id,
                    "offset_bytes": offset,
                    "limit_bytes": requested
                }),
            )
            .await?;
        let chunk = response
            .get("artifact_chunk")
            .ok_or_else(|| ShadowError::Protocol("artifact response omitted chunk".into()))?;
        let decoded = validate_v2_artifact_chunk(
            chunk,
            &artifact_id,
            &sha256,
            size_bytes,
            offset,
            requested,
        )?;
        bytes.extend_from_slice(&decoded);
    }
    if bytes.len() as u64 != size_bytes || format!("{:x}", Sha256::digest(&bytes)) != sha256 {
        return Err(ShadowError::Protocol(
            "artifact bytes failed final verification".into(),
        ));
    }
    Ok((sha256, size_bytes, bytes))
}

fn validate_v2_artifact_chunk(
    chunk: &Value,
    artifact_id: &str,
    sha256: &str,
    size_bytes: u64,
    offset: u64,
    requested: u64,
) -> Result<Vec<u8>, ShadowError> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    if string_field(chunk, "artifact_id")? != artifact_id
        || string_field(chunk, "sha256")? != sha256
        || chunk.get("size_bytes").and_then(Value::as_u64) != Some(size_bytes)
        || chunk.get("offset_bytes").and_then(Value::as_u64) != Some(offset)
    {
        return Err(ShadowError::Protocol(
            "artifact chunk metadata changed during retrieval".into(),
        ));
    }
    let decoded = BASE64
        .decode(string_field(chunk, "bytes_base64")?)
        .map_err(|_| ShadowError::Protocol("artifact chunk base64 is invalid".into()))?;
    let returned = chunk
        .get("returned_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| ShadowError::Protocol("artifact chunk omitted returned size".into()))?;
    let next_offset = offset
        .checked_add(
            u64::try_from(decoded.len())
                .map_err(|_| ShadowError::Protocol("artifact chunk length overflowed".into()))?,
        )
        .ok_or_else(|| ShadowError::Protocol("artifact chunk offset overflowed".into()))?;
    if decoded.is_empty()
        || returned != decoded.len() as u64
        || decoded.len() as u64 != requested
        || next_offset > size_bytes
        || chunk.get("eof").and_then(Value::as_bool) != Some(next_offset == size_bytes)
    {
        return Err(ShadowError::Protocol(
            "artifact chunk progress is invalid".into(),
        ));
    }
    Ok(decoded)
}

pub async fn run_shadow<C: PublicMcpClient>(
    client: &C,
    config: &ShadowConfig,
) -> Result<ShadowRun, ShadowError> {
    let manifest = config.validate()?;
    let started = Instant::now();
    let spawn = client
        .call(
            "zcode_review_spawn",
            json!({"manifest_path": config.manifest_path}),
        )
        .await?;
    let agent_id = string_field(&spawn, "agent_id")?.to_owned();
    let submission = string_field(&spawn, "submission_disposition")?.to_owned();
    let prompt_sha256 = string_field(&spawn, "prompt_sha256")?.to_owned();
    let mut last_sequence = spawn
        .get("last_event_sequence")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let mut checkpoint_count = 0_u64;
    let mut unsupported = false;
    let mut terminal_status = None;
    for _ in 0..config.max_waits {
        let status = match client
            .call("zcode_review_status", json!({"agent_id": agent_id}))
            .await
        {
            Ok(status) => status,
            Err(_) => {
                let _ = client
                    .call("zcode_review_close", json!({"agent_id": agent_id}))
                    .await;
                return persist_incomplete(
                    config,
                    &manifest,
                    agent_id,
                    submission,
                    prompt_sha256,
                    started,
                );
            }
        };
        unsupported |= status
            .get("pending_requests")
            .and_then(Value::as_array)
            .is_some_and(|requests| {
                requests
                    .iter()
                    .any(|request| request["kind"] == "unsupported_input")
            });
        let job = status
            .get("job")
            .ok_or_else(|| ShadowError::Protocol("status omitted job".into()))?;
        if is_terminal(string_field(job, "state")?) {
            terminal_status = Some(status);
            break;
        }
        let waited = match client
            .call(
                "zcode_review_wait",
                json!({
                    "agent_id": agent_id,
                    "after_sequence": last_sequence,
                    "timeout_ms": config.wait_timeout_ms
                }),
            )
            .await
        {
            Ok(waited) => waited,
            Err(_) => {
                let _ = client
                    .call("zcode_review_close", json!({"agent_id": agent_id}))
                    .await;
                return persist_incomplete(
                    config,
                    &manifest,
                    agent_id,
                    submission,
                    prompt_sha256,
                    started,
                );
            }
        };
        if let Some(events) = waited.get("events").and_then(Value::as_array) {
            checkpoint_count += events
                .iter()
                .filter(|event| event["event_type"] == "report.checkpoint")
                .count() as u64;
            last_sequence = events
                .iter()
                .filter_map(|event| event["sequence"].as_u64())
                .max()
                .unwrap_or(last_sequence);
        }
        if waited
            .get("job")
            .and_then(|job| job.get("state"))
            .and_then(Value::as_str)
            .is_some_and(is_terminal)
        {
            terminal_status = Some(json!({"job": waited["job"].clone(), "pending_requests": []}));
            break;
        }
    }
    let Some(status) = terminal_status else {
        let _ = client
            .call("zcode_review_close", json!({"agent_id": agent_id}))
            .await;
        return persist_incomplete(
            config,
            &manifest,
            agent_id,
            submission,
            prompt_sha256,
            started,
        );
    };
    let job = status
        .get("job")
        .ok_or_else(|| ShadowError::Protocol("terminal status omitted job".into()))?;
    let result = match client
        .call(
            "zcode_review_result",
            json!({"agent_id": agent_id, "preview_bytes": 8192}),
        )
        .await
    {
        Ok(result) => result,
        Err(_) => {
            let _ = client
                .call("zcode_review_close", json!({"agent_id": agent_id}))
                .await;
            return persist_incomplete(
                config,
                &manifest,
                agent_id,
                submission,
                prompt_sha256,
                started,
            );
        }
    };
    let report = result.get("report").filter(|value| !value.is_null());
    let public_report_valid = report.is_some_and(|report| {
        report["finalized"] == true
            && report["integrity"] == "valid"
            && report["expected_sha256"] == report["observed_sha256"]
            && report["expected_bytes"] == report["observed_bytes"]
    });
    let report_bytes = report.and_then(|summary| read_verified_report(&manifest, summary).ok());
    let report_valid = public_report_valid && report_bytes.is_some();
    let mut runtime_failure = string_field(job, "state")? != "COMPLETED";
    let session_id = job
        .get("zcode_session_id")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let fresh_session = job
        .get("fresh_session_observed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let close_reaped = client
        .call("zcode_review_close", json!({"agent_id": agent_id}))
        .await
        .ok()
        .and_then(|value| value["resources_reaped"].as_bool())
        .unwrap_or(false);
    runtime_failure |= !close_reaped;
    let expected_manifest_sha256 = normalized_manifest_sha256(&manifest)?;
    let provenance_valid = job["base_sha"].as_str() == Some(manifest.base_ref.as_str())
        && job["head_sha"].as_str() == Some(manifest.head_ref.as_str())
        && job["manifest_sha256"].as_str() == Some(expected_manifest_sha256.as_str())
        && job["prepared_sha256"]
            .as_str()
            .is_some_and(|value| !value.is_empty())
        && job["prompt_sha256"].as_str() == Some(prompt_sha256.as_str());
    let complete_evidence = provenance_valid && report_valid && !unsupported && !runtime_failure;
    let classification = match config.mode {
        ShadowMode::Full
            if complete_evidence
                && submission == "created"
                && fresh_session
                && session_id.as_deref().is_some_and(|value| !value.is_empty()) =>
        {
            EvidenceClassification::IndependentEvidence
        }
        ShadowMode::DeltaConsultation | ShadowMode::ResumeConsultation if complete_evidence => {
            EvidenceClassification::Consultation
        }
        _ => EvidenceClassification::EvidenceIncomplete,
    };
    let provenance = ShadowProvenance {
        schema: SHADOW_SCHEMA.into(),
        agent_id: agent_id.clone(),
        submission_disposition: submission,
        zcode_session_id: session_id,
        fresh_session_observed: fresh_session,
        classification,
        review_kind: manifest.review_kind.as_str().into(),
        round_kind: manifest.round_kind.as_str().into(),
        manifest_sha256: optional_string(job, "manifest_sha256"),
        prepared_sha256: optional_string(job, "prepared_sha256"),
        prompt_sha256,
        base_sha: optional_string(job, "base_sha"),
        head_sha: optional_string(job, "head_sha"),
        report_sha256: report.and_then(|value| optional_string(value, "observed_sha256")),
        report_bytes: report.and_then(|value| value["observed_bytes"].as_u64()),
        report_schema_compliant: report_valid,
        checkpoint_count: checkpoint_count.max(
            report
                .and_then(|value| value["checkpoint_number"].as_u64())
                .unwrap_or(0),
        ),
        unsupported_input_observed: unsupported,
        runtime_failure_observed: runtime_failure,
        wall_time_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    };
    let artifacts = config.artifact_paths();
    fs::create_dir_all(&config.artifact_directory)?;
    let raw = report_bytes.unwrap_or_else(|| {
        b"# ZCode Shadow Review\n\nEvidence incomplete: the full report did not match its public integrity projection.\n".to_vec()
    });
    atomic_write(&artifacts.glm_raw, &raw)?;
    atomic_write(
        &artifacts.glm_provenance,
        &serde_json::to_vec_pretty(&provenance)?,
    )?;
    Ok(ShadowRun {
        provenance,
        artifacts,
    })
}

fn persist_incomplete(
    config: &ShadowConfig,
    manifest: &ReviewManifest,
    agent_id: String,
    submission_disposition: String,
    prompt_sha256: String,
    started: Instant,
) -> Result<ShadowRun, ShadowError> {
    let provenance = ShadowProvenance {
        schema: SHADOW_SCHEMA.into(),
        agent_id,
        submission_disposition,
        zcode_session_id: None,
        fresh_session_observed: false,
        classification: EvidenceClassification::EvidenceIncomplete,
        review_kind: manifest.review_kind.as_str().into(),
        round_kind: manifest.round_kind.as_str().into(),
        manifest_sha256: None,
        prepared_sha256: None,
        prompt_sha256,
        base_sha: Some(manifest.base_ref.clone()),
        head_sha: Some(manifest.head_ref.clone()),
        report_sha256: None,
        report_bytes: None,
        report_schema_compliant: false,
        checkpoint_count: 0,
        unsupported_input_observed: false,
        runtime_failure_observed: true,
        wall_time_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
    };
    let artifacts = config.artifact_paths();
    atomic_write(
        &artifacts.glm_raw,
        b"# ZCode Shadow Review\n\nEvidence incomplete: the public MCP lifecycle did not produce complete review evidence.\n",
    )?;
    atomic_write(
        &artifacts.glm_provenance,
        &serde_json::to_vec_pretty(&provenance)?,
    )?;
    Ok(ShadowRun {
        provenance,
        artifacts,
    })
}

fn read_verified_report(
    manifest: &ReviewManifest,
    summary: &Value,
) -> Result<Vec<u8>, ShadowError> {
    let path = if manifest.report_target.is_absolute() {
        manifest.report_target.clone()
    } else {
        manifest.repository.join(&manifest.report_target)
    };
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ShadowError::Protocol(
            "report target is not a regular non-symlink file".into(),
        ));
    }
    let bytes = fs::read(path)?;
    let observed_sha256 = format!("{:x}", Sha256::digest(&bytes));
    if summary["observed_sha256"].as_str() != Some(observed_sha256.as_str())
        || summary["observed_bytes"].as_u64() != Some(bytes.len() as u64)
    {
        return Err(ShadowError::Protocol(
            "report bytes do not match public integrity projection".into(),
        ));
    }
    Ok(bytes)
}

fn is_terminal(state: &str) -> bool {
    matches!(
        state,
        "COMPLETED" | "CANCELLED" | "FAILED" | "FAILED_RUNTIME_LOST" | "ORPHANED" | "CLOSED"
    )
}

fn string_field<'a>(value: &'a Value, field: &str) -> Result<&'a str, ShadowError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| ShadowError::Protocol(format!("missing string field {field}")))
}

fn optional_string(value: &Value, field: &str) -> Option<String> {
    value.get(field).and_then(Value::as_str).map(str::to_owned)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), ShadowError> {
    let parent = path
        .parent()
        .ok_or_else(|| ShadowError::Configuration("artifact path has no parent".into()))?;
    fs::create_dir_all(parent)?;
    let mut digest = Sha256::new();
    digest.update(path.as_os_str().as_encoded_bytes());
    let temporary = parent.join(format!(".shadow-{:x}.tmp", digest.finalize()));
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, path)?;
    Ok(())
}

pub fn schema_documents() -> (Value, Value) {
    (
        serde_json::to_value(schemars::schema_for!(ShadowProvenance)).expect("schema serializes"),
        serde_json::to_value(schemars::schema_for!(CalibrationRecord)).expect("schema serializes"),
    )
}

pub fn review_kind(config: &ShadowConfig) -> Result<ReviewKind, ShadowError> {
    Ok(config.validate()?.review_kind)
}

pub fn object(value: Value) -> Result<Map<String, Value>, ShadowError> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| ShadowError::Protocol("expected JSON object".into()))
}

pub fn bounded_pause(timeout_ms: u64) -> Duration {
    Duration::from_millis(timeout_ms.clamp(1, 5000))
}

#[cfg(test)]
mod artifact_chunk_tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    fn chunk(bytes: &[u8], offset: u64, size: u64, eof: bool) -> Value {
        serde_json::json!({
            "artifact_id":"report",
            "sha256":"a".repeat(64),
            "size_bytes":size,
            "offset_bytes":offset,
            "returned_bytes":bytes.len(),
            "eof":eof,
            "bytes_base64":BASE64.encode(bytes),
        })
    }

    #[test]
    fn collector_rejects_zero_nonmonotonic_oversized_and_incorrect_eof_chunks() {
        let digest = "a".repeat(64);
        assert_eq!(
            validate_v2_artifact_chunk(&chunk(b"data", 0, 4, true), "report", &digest, 4, 0, 4)
                .unwrap(),
            b"data"
        );
        for invalid in [
            chunk(b"", 0, 4, false),
            chunk(b"data", 1, 4, true),
            chunk(b"extra", 0, 4, true),
            chunk(b"data", 0, 4, false),
        ] {
            assert!(
                validate_v2_artifact_chunk(&invalid, "report", &digest, 4, 0, 4).is_err(),
                "collector accepted invalid chunk {invalid}"
            );
        }
    }
}
