use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, Json, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReviewSpawnInput {
    review_kind: String,
    repository: String,
    base_ref: String,
    head_ref: String,
    scope_manifest: Vec<String>,
    requirements_path: String,
    report_path: String,
    feature_id: String,
    section_id: String,
    ownership_token: String,
    idempotency_key: String,
    read_only: bool,
    #[serde(default)]
    attachments: Vec<String>,
    #[serde(default)]
    model: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct AgentInput {
    agent_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct WaitInput {
    agent_id: String,
    after_sequence: u64,
    timeout_ms: u64,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ResultInput {
    agent_id: String,
    #[serde(default)]
    attempt_sequence: Option<u64>,
    #[serde(default)]
    artifact_id: Option<String>,
    #[serde(default)]
    offset_bytes: Option<u64>,
    #[serde(default)]
    limit_bytes: Option<usize>,
}

#[derive(Clone)]
struct FixtureState {
    agent_id: String,
    review_kind: String,
    base_ref: String,
    head_ref: String,
    report: Arc<Vec<u8>>,
}

#[derive(Clone)]
struct FixtureMcp {
    state: Arc<std::sync::Mutex<Option<FixtureState>>>,
    status_calls: Arc<std::sync::atomic::AtomicUsize>,
    tool_router: ToolRouter<Self>,
}

impl FixtureMcp {
    fn new() -> Self {
        Self {
            state: Arc::new(std::sync::Mutex::new(None)),
            status_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            tool_router: Self::tool_router(),
        }
    }

    fn state(&self, agent_id: &str) -> Result<FixtureState, String> {
        let state = self
            .state
            .lock()
            .map_err(|_| "fixture state unavailable".to_owned())?
            .clone()
            .ok_or_else(|| "fixture has no submitted task".to_owned())?;
        if state.agent_id != agent_id {
            return Err("fixture task not found".into());
        }
        Ok(state)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for FixtureMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
    }
}

#[tool_router(router = tool_router)]
impl FixtureMcp {
    #[tool(name = "zcode_review_spawn", description = "fixture submit")]
    async fn spawn_tool(
        &self,
        Parameters(input): Parameters<ReviewSpawnInput>,
    ) -> Result<Json<Value>, String> {
        if !input.read_only || input.scope_manifest.is_empty() {
            return Err("fixture requires bounded read-only scope".into());
        }
        let manifest_sha256 = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&json!({
                    "repository":input.repository,
                    "requirements_path":input.requirements_path,
                    "report_path":input.report_path,
                    "feature_id":input.feature_id,
                    "section_id":input.section_id,
                    "ownership_token":input.ownership_token,
                    "idempotency_key":input.idempotency_key,
                    "attachments":input.attachments,
                    "model":input.model
                }))
                .map_err(|error| error.to_string())?,
            )
        );
        let agent_id = format!("fixture-{}", input.review_kind);
        let report = Arc::new(
            format!(
                "# ZCode Review Report\n\nREVIEW_KIND: {}\nFINALIZED: true\nREPORT_REVISION: 2\n\n## Provenance\n\nFixture shadow evidence.\n\n## Checkpoints\n\n### fixture-checkpoint (revision 1)\n\n- Stage: `Inspection`\n\n## Findings\n\nNo findings recorded.\n\n## Finalization\n\n- Signal: `no_findings_observed`\n",
                input.review_kind
            )
            .into_bytes(),
        );
        let state = FixtureState {
            agent_id: agent_id.clone(),
            review_kind: input.review_kind,
            base_ref: input.base_ref,
            head_ref: input.head_ref,
            report,
        };
        *self
            .state
            .lock()
            .map_err(|_| "fixture state unavailable".to_owned())? = Some(state.clone());
        self.status_calls
            .store(0, std::sync::atomic::Ordering::Release);
        Ok(Json(json!({
            "agent_id":agent_id,
            "review_id":"fixture-review",
            "submission_disposition":"created",
            "phase":"QUEUED",
            "attempt_sequence":1,
            "effective_budget":budget(),
            "counts_as_independent":false,
            "provenance":{
                "review_kind":state.review_kind,
                "manifest_sha256":manifest_sha256,
                "prepared_sha256":"fixture-prepared",
                "prompt_sha256":"fixture-prompt",
                "base_sha":state.base_ref,
                "head_sha":state.head_ref,
                "requested_model":Value::Null,
                "fresh_session_observed":false
            }
        })))
    }

    #[tool(name = "zcode_agent_get", description = "fixture get")]
    async fn get_tool(
        &self,
        Parameters(input): Parameters<AgentInput>,
    ) -> Result<Json<Value>, String> {
        let state = self.state(&input.agent_id)?;
        let calls = self
            .status_calls
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        let terminal = calls > 0;
        Ok(Json(json!({
            "task":task(&state, if terminal { "TERMINAL" } else { "ACTIVE" }, false),
            "result":if terminal { result(&state) } else { Value::Null },
            "artifacts":if terminal { artifacts(&state) } else { Vec::<Value>::new() },
            "pending_requests":[]
        })))
    }

    #[tool(name = "zcode_agent_wait", description = "fixture wait")]
    async fn wait_tool(
        &self,
        Parameters(input): Parameters<WaitInput>,
    ) -> Result<Json<Value>, String> {
        let state = self.state(&input.agent_id)?;
        if input.timeout_ms == 0 {
            return Err("timeout must be bounded".into());
        }
        Ok(Json(json!({
            "task":task(&state,"ACTIVE",false),
            "events":[{"sequence":input.after_sequence + 1,"attempt_sequence":1,"event_type":"attempt_started","redaction_level":"allowlisted","pending_request_id":Value::Null}],
            "next_sequence":input.after_sequence + 1,
            "has_more":false,
            "timed_out":false
        })))
    }

    #[tool(name = "zcode_agent_result", description = "fixture result")]
    async fn result_tool(
        &self,
        Parameters(input): Parameters<ResultInput>,
    ) -> Result<Json<Value>, String> {
        let state = self.state(&input.agent_id)?;
        let chunk = match (input.artifact_id, input.offset_bytes, input.limit_bytes) {
            (None, None, None) => Value::Null,
            (Some(artifact_id), Some(offset), Some(limit)) => {
                if input.attempt_sequence != Some(1)
                    || artifact_id != "fixture-report"
                    || limit == 0
                {
                    return Err("fixture artifact selector is invalid".into());
                }
                let start = usize::try_from(offset).map_err(|_| "offset overflow")?;
                let end = start.saturating_add(limit).min(state.report.len());
                let bytes = state.report.get(start..end).ok_or("offset out of range")?;
                json!({
                    "artifact_id":"fixture-report",
                    "offset_bytes":offset,
                    "returned_bytes":bytes.len(),
                    "eof":end == state.report.len(),
                    "sha256":format!("{:x}",Sha256::digest(state.report.as_slice())),
                    "size_bytes":state.report.len(),
                    "bytes_base64":BASE64.encode(bytes)
                })
            }
            _ => return Err("fixture artifact selector is incomplete".into()),
        };
        Ok(Json(json!({
            "task":task(&state,"TERMINAL",false),
            "result":result(&state),
            "artifacts":artifacts(&state),
            "artifact_chunk":chunk
        })))
    }

    #[tool(name = "zcode_agent_close", description = "fixture close")]
    async fn close_tool(
        &self,
        Parameters(input): Parameters<AgentInput>,
    ) -> Result<Json<Value>, String> {
        let state = self.state(&input.agent_id)?;
        Ok(Json(json!({"task":task(&state,"TERMINAL",true)})))
    }
}

fn budget() -> Value {
    json!({"wall_time_ms":5000,"max_turns":8,"max_tool_calls":32,"max_context_bytes":1048576,"max_result_bytes":262144,"max_artifact_bytes":2097152})
}

fn task(state: &FixtureState, phase: &str, reaped: bool) -> Value {
    json!({
        "agent_id":state.agent_id,
        "review_id":"fixture-review",
        "task_kind":"review",
        "phase":phase,
        "attempt_sequence":1,
        "effective_budget":budget(),
        "counts_as_independent":phase == "TERMINAL",
        "fresh_session_observed":true,
        "cancel_requested":false,
        "close_requested":reaped,
        "closed":reaped,
        "resources_reaped":reaped
    })
}

fn result(state: &FixtureState) -> Value {
    let artifact = json!({
        "artifact_id":"fixture-report",
        "kind":"report_markdown",
        "sha256":format!("{:x}",Sha256::digest(state.report.as_slice())),
        "size_bytes":state.report.len()
    });
    json!({
        "outcome":"SUCCEEDED",
        "summary":"fixture completed",
        "partial":false,
        "retained":false,
        "base_commit":Value::Null,
        "head_commit":Value::Null,
        "changed_files":[],
        "diff_stat":Value::Null,
        "checks":[],
        "residual_gaps":[],
        "result_sha256":"fixture-result",
        "review_evidence":{
            "final_signal":"no_findings_observed",
            "finalized":true,
            "report_revision":3,
            "finalization_revision":3,
            "artifact":artifact,
            "counts":{"checkpoints":1,"findings":0,"open_findings":0,"validations":1},
            "independence":{"independent_evidence":true,"fresh_session_observed":true,"counts_as_independent":true},
            "validation_provenance":{
                "daemon_verification":{
                    "source_integrity_verified":true,
                    "finalized_report_verified":true,
                    "artifact_digest_verified":true,
                    "validation_records_structurally_verified":true
                },
                "model_attestation":{"present":true,"validation_record_count":1}
            }
        }
    })
}

fn artifacts(state: &FixtureState) -> Vec<Value> {
    vec![json!({
        "artifact_id":"fixture-report",
        "kind":"report_markdown",
        "sha256":format!("{:x}",Sha256::digest(state.report.as_slice())),
        "size_bytes":state.report.len()
    })]
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = FixtureMcp::new()
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;
    service.waiting().await?;
    Ok(())
}
