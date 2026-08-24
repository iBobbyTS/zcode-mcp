use review_preparation::ReviewManifest;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, Json, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, sync::Arc};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct ManifestInput {
    manifest_path: String,
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
    preview_bytes: usize,
}

#[derive(Clone)]
struct FixtureState {
    agent_id: String,
    manifest: ReviewManifest,
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
            .ok_or_else(|| "fixture has no submitted job".to_owned())?;
        if state.agent_id != agent_id {
            return Err("fixture job not found".into());
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
        Parameters(input): Parameters<ManifestInput>,
    ) -> Result<Json<Value>, String> {
        let bytes = fs::read(&input.manifest_path).map_err(|error| error.to_string())?;
        let manifest = ReviewManifest::from_json(&bytes).map_err(|error| error.to_string())?;
        let agent_id = format!(
            "fixture-{}-{}",
            manifest.review_kind.as_str(),
            manifest.section_id
        );
        let report = Arc::new(
            format!(
                "# ZCode Review Report\n\nFixture {} shadow evidence.\n",
                manifest.review_kind.as_str()
            )
            .into_bytes(),
        );
        let report_path = if manifest.report_target.is_absolute() {
            manifest.report_target.clone()
        } else {
            manifest.repository.join(&manifest.report_target)
        };
        fs::create_dir_all(
            report_path
                .parent()
                .ok_or_else(|| "fixture report has no parent".to_owned())?,
        )
        .map_err(|error| error.to_string())?;
        fs::write(&report_path, report.as_slice()).map_err(|error| error.to_string())?;
        *self
            .state
            .lock()
            .map_err(|_| "fixture state unavailable".to_owned())? = Some(FixtureState {
            agent_id: agent_id.clone(),
            manifest,
            report,
        });
        self.status_calls
            .store(0, std::sync::atomic::Ordering::Release);
        Ok(Json(json!({
            "agent_id":agent_id,
            "submission_disposition":"created",
            "state":"QUEUED",
            "last_event_sequence":0,
            "prompt_sha256":"fixture-prompt",
            "capabilities":{}
        })))
    }

    #[tool(name = "zcode_review_status", description = "fixture status")]
    async fn status_tool(
        &self,
        Parameters(input): Parameters<AgentInput>,
    ) -> Result<Json<Value>, String> {
        let state = self.state(&input.agent_id)?;
        let calls = self
            .status_calls
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Ok(Json(json!({
            "job":job(&state, if calls == 0 { "RUNNING" } else { "COMPLETED" }),
            "pending_requests":[]
        })))
    }

    #[tool(name = "zcode_review_wait", description = "fixture wait")]
    async fn wait_tool(
        &self,
        Parameters(input): Parameters<WaitInput>,
    ) -> Result<Json<Value>, String> {
        let state = self.state(&input.agent_id)?;
        if input.timeout_ms == 0 {
            return Err("timeout must be bounded".into());
        }
        Ok(Json(json!({
            "job":job(&state,"RUNNING"),
            "events":[{
                "sequence":input.after_sequence + 1,
                "event_type":"report.checkpoint",
                "redaction_level":"allowlisted"
            }],
            "timed_out":false
        })))
    }

    #[tool(name = "zcode_review_result", description = "fixture result")]
    async fn result_tool(
        &self,
        Parameters(input): Parameters<ResultInput>,
    ) -> Result<Json<Value>, String> {
        let state = self.state(&input.agent_id)?;
        let hash = format!("{:x}", Sha256::digest(state.report.as_slice()));
        let preview =
            String::from_utf8_lossy(&state.report[..state.report.len().min(input.preview_bytes)]);
        Ok(Json(json!({
            "job":job(&state,"COMPLETED"),
            "report":{
                "finalized":true,
                "integrity":"valid",
                "expected_sha256":hash,
                "observed_sha256":hash,
                "expected_bytes":state.report.len(),
                "observed_bytes":state.report.len(),
                "checkpoint_number":1,
                "preview":preview
            }
        })))
    }

    #[tool(name = "zcode_review_close", description = "fixture close")]
    async fn close_tool(
        &self,
        Parameters(input): Parameters<AgentInput>,
    ) -> Result<Json<Value>, String> {
        self.state(&input.agent_id)?;
        Ok(Json(json!({
            "agent_id":input.agent_id,
            "state":"COMPLETED",
            "resources_reaped":true
        })))
    }
}

fn job(state: &FixtureState, job_state: &str) -> Value {
    json!({
        "agent_id":state.agent_id,
        "state":job_state,
        "turn_state":"IDLE",
        "review_kind":state.manifest.review_kind.as_str(),
        "feature_id":state.manifest.feature_id,
        "section_id":state.manifest.section_id,
        "round_kind":state.manifest.round_kind.as_str(),
        "created_at_ms":1,
        "last_event_sequence":1,
        "zcode_session_id":format!("fixture-session-{}",state.agent_id),
        "fresh_session_observed":true,
        "failure_code":Value::Null,
        "manifest_sha256":"fixture-manifest",
        "prepared_sha256":"fixture-prepared",
        "prompt_sha256":"fixture-prompt",
        "base_sha":state.manifest.base_ref,
        "head_sha":state.manifest.head_ref,
        "requested_model":state.manifest.model,
        "resources_reaped":false,
        "capabilities":{}
    })
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = FixtureMcp::new()
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?;
    service.waiting().await?;
    Ok(())
}
