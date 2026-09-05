use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, Json, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use zcode_agent_preparation::{
    AttachmentInput, BudgetLimits, GeneralTaskManifest, PermissionMode, GENERAL_TASK_SCHEMA,
};
use zcode_agent_store::{EffectiveBudget, TaskOutcome};
use zcode_agentd::rpc::{
    AgentCapabilitiesView, CapabilityMaturityView, ComponentStateView, GeneralSubmitInput,
    MessageInput, RespondInput, ResponseDecision, ResponseOutcomeView, RpcClient, RpcMethod,
    RpcOutcome, RpcRequest, RpcSuccess, SubmissionDispositionView, SystemStatusView,
    TaskActivityStateView, TaskActivityView, TaskArtifactMetadataView, TaskArtifactQuery,
    TaskListQuery, TaskPhaseFilter, TaskPollQuery, TaskResultView, TaskView, TelemetryStatusView,
    MAX_ARTIFACT_CHUNK_BYTES, RPC_VERSION,
};

use crate::{
    protocol_error, public_error, public_transport_error, PublicDecision, PublicPendingRequest,
    PublicResponseDisposition,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicPermissionMode {
    Build,
    Edit,
    Plan,
    Yolo,
}

impl From<PublicPermissionMode> for PermissionMode {
    fn from(value: PublicPermissionMode) -> Self {
        match value {
            PublicPermissionMode::Build => Self::Build,
            PublicPermissionMode::Edit => Self::Edit,
            PublicPermissionMode::Plan => Self::Plan,
            PublicPermissionMode::Yolo => Self::Yolo,
        }
    }
}

pub const PUBLIC_TOOLS: [&str; 9] = [
    "zcode_subagent_cancel",
    "zcode_subagent_close",
    "zcode_subagent_list",
    "zcode_subagent_poll",
    "zcode_subagent_respond",
    "zcode_subagent_result",
    "zcode_subagent_send",
    "zcode_subagent_spawn",
    "zcode_subagent_status",
];

const MAX_ID_BYTES: usize = 512;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PROMPT_BYTES: usize = 256 * 1024;
const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_REASON_BYTES: usize = 2048;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmptyInput {}

fn optional_non_null<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
}
fn validate_text(value: &str, field: &str, max: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > max || value.contains('\0') {
        Err(format!("validation: {field} is invalid"))
    } else {
        Ok(())
    }
}

fn validate_path(value: &str, field: &str) -> Result<(), String> {
    validate_text(value, field, MAX_PATH_BYTES)
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PublicBudget {
    pub absolute_wall_time_ms: u64,
    pub runtime_activity_idle_timeout_ms: u64,
    pub model_stream_idle_timeout_ms: u64,
    pub tool_call_timeout_ms: u64,
    pub input_wait_timeout_ms: u64,
    pub max_turns: u64,
    pub max_tool_calls: u64,
    pub max_context_bytes: u64,
    pub max_result_bytes: u64,
    pub max_artifact_bytes: u64,
}

impl From<PublicBudget> for BudgetLimits {
    fn from(value: PublicBudget) -> Self {
        Self {
            absolute_wall_time_ms: value.absolute_wall_time_ms,
            runtime_activity_idle_timeout_ms: value.runtime_activity_idle_timeout_ms,
            model_stream_idle_timeout_ms: value.model_stream_idle_timeout_ms,
            tool_call_timeout_ms: value.tool_call_timeout_ms,
            input_wait_timeout_ms: value.input_wait_timeout_ms,
            max_turns: value.max_turns,
            max_tool_calls: value.max_tool_calls,
            max_context_bytes: value.max_context_bytes,
            max_result_bytes: value.max_result_bytes,
            max_artifact_bytes: value.max_artifact_bytes,
        }
    }
}

impl From<BudgetLimits> for PublicBudget {
    fn from(value: BudgetLimits) -> Self {
        Self {
            absolute_wall_time_ms: value.absolute_wall_time_ms,
            runtime_activity_idle_timeout_ms: value.runtime_activity_idle_timeout_ms,
            model_stream_idle_timeout_ms: value.model_stream_idle_timeout_ms,
            tool_call_timeout_ms: value.tool_call_timeout_ms,
            input_wait_timeout_ms: value.input_wait_timeout_ms,
            max_turns: value.max_turns,
            max_tool_calls: value.max_tool_calls,
            max_context_bytes: value.max_context_bytes,
            max_result_bytes: value.max_result_bytes,
            max_artifact_bytes: value.max_artifact_bytes,
        }
    }
}

impl From<EffectiveBudget> for PublicBudget {
    fn from(value: EffectiveBudget) -> Self {
        Self {
            absolute_wall_time_ms: value.absolute_wall_time_ms,
            runtime_activity_idle_timeout_ms: value.runtime_activity_idle_timeout_ms,
            model_stream_idle_timeout_ms: value.model_stream_idle_timeout_ms,
            tool_call_timeout_ms: value.tool_call_timeout_ms,
            input_wait_timeout_ms: value.input_wait_timeout_ms,
            max_turns: value.max_turns,
            max_tool_calls: value.max_tool_calls,
            max_context_bytes: value.max_context_bytes,
            max_result_bytes: value.max_result_bytes,
            max_artifact_bytes: value.max_artifact_bytes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicComponentState {
    Ready,
    Degraded,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicCapabilityMaturity {
    BetaReady,
    ExperimentalUnverifiedRuntime,
}

impl From<CapabilityMaturityView> for PublicCapabilityMaturity {
    fn from(value: CapabilityMaturityView) -> Self {
        match value {
            CapabilityMaturityView::BetaReady => Self::BetaReady,
            CapabilityMaturityView::ExperimentalUnverifiedRuntime => {
                Self::ExperimentalUnverifiedRuntime
            }
        }
    }
}

impl From<ComponentStateView> for PublicComponentState {
    fn from(value: ComponentStateView) -> Self {
        match value {
            ComponentStateView::Ready => Self::Ready,
            ComponentStateView::Degraded => Self::Degraded,
            ComponentStateView::Unavailable => Self::Unavailable,
            ComponentStateView::Unknown => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicAgentCapabilities {
    pub hard_budget_caps: PublicBudget,
    pub max_rpc_frame_bytes: usize,
    pub max_wait_ms: u64,
    pub max_artifact_chunk_bytes: usize,
    pub named_checks: bool,
    pub maturity: BTreeMap<String, PublicCapabilityMaturity>,
}

impl From<AgentCapabilitiesView> for PublicAgentCapabilities {
    fn from(value: AgentCapabilitiesView) -> Self {
        let maturity = value
            .maturity
            .into_iter()
            .map(|(name, maturity)| (name, maturity.into()))
            .collect();
        Self {
            hard_budget_caps: value.hard_budget_caps.into(),
            max_rpc_frame_bytes: value.max_rpc_frame_bytes,
            max_wait_ms: value.max_wait_ms,
            max_artifact_chunk_bytes: MAX_ARTIFACT_CHUNK_BYTES,
            named_checks: value.named_checks,
            maturity,
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct SystemStatusOutput {
    pub api_surface: String,
    pub protocol_version: u16,
    pub service_generation: String,
    pub components: BTreeMap<String, PublicComponentState>,
    pub capabilities: PublicAgentCapabilities,
}

impl From<SystemStatusView> for SystemStatusOutput {
    fn from(value: SystemStatusView) -> Self {
        Self {
            api_surface: value.api_surface,
            protocol_version: value.protocol_version,
            service_generation: value.service_generation,
            components: value
                .components
                .into_iter()
                .map(|(name, state)| (name, state.into()))
                .collect(),
            capabilities: value.capabilities.into(),
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PublicAttachmentInput {
    pub logical_name: String,
    pub source_path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct AgentSpawnInput {
    pub repository: String,
    pub permission_mode: PublicPermissionMode,
    pub prompt: String,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub group_id: Option<String>,
    pub idempotency_key: String,
    #[serde(default)]
    pub repo_context: Vec<String>,
    #[serde(default)]
    pub attachments: Vec<PublicAttachmentInput>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub budget: Option<PublicBudget>,
    #[serde(default)]
    pub retain_partial: bool,
    #[serde(default)]
    pub allowed_command_ids: Vec<String>,
    #[serde(default)]
    pub required_command_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionDisposition {
    Created,
    Existing,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct AgentSpawnOutput {
    pub agent_id: String,
    pub submission_disposition: SubmissionDisposition,
    pub phase: String,
    pub effective_budget: PublicBudget,
    pub capabilities: PublicAgentCapabilities,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentInput {
    pub agent_id: String,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicTask {
    pub agent_id: String,
    pub phase: String,
    pub outcome: Option<PublicOutcome>,
    pub effective_budget: PublicBudget,
    pub cancel_requested: bool,
    pub close_requested: bool,
    pub closed: bool,
    pub resources_reaped: bool,
}

impl From<TaskView> for PublicTask {
    fn from(value: TaskView) -> Self {
        Self {
            agent_id: value.agent_id,
            phase: value.phase,
            outcome: value.outcome.map(Into::into),
            effective_budget: value.effective_budget.into(),
            cancel_requested: value.stop_requested,
            close_requested: value.close_requested,
            closed: value.closed,
            resources_reaped: value.reaped,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicOutcome {
    Completed,
    Failed,
    Cancelled,
    TimedOut,
    BudgetExhausted,
    RuntimeLost,
    ResultInvalid,
}

impl From<TaskOutcome> for PublicOutcome {
    fn from(value: TaskOutcome) -> Self {
        match value {
            TaskOutcome::Completed => Self::Completed,
            TaskOutcome::Failed => Self::Failed,
            TaskOutcome::Cancelled => Self::Cancelled,
            TaskOutcome::TimedOut => Self::TimedOut,
            TaskOutcome::BudgetExhausted => Self::BudgetExhausted,
            TaskOutcome::RuntimeLost => Self::RuntimeLost,
            TaskOutcome::ResultInvalid => Self::ResultInvalid,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicArtifactKind {
    ChangesPatch,
}

fn artifact_kind(value: &str) -> Result<PublicArtifactKind, String> {
    match value {
        "changes_patch" => Ok(PublicArtifactKind::ChangesPatch),
        _ => Err(protocol_error()),
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicArtifact {
    pub artifact_id: String,
    pub kind: PublicArtifactKind,
    pub sha256: String,
    pub size_bytes: u64,
}

impl TryFrom<TaskArtifactMetadataView> for PublicArtifact {
    type Error = String;

    fn try_from(value: TaskArtifactMetadataView) -> Result<Self, Self::Error> {
        Ok(Self {
            artifact_id: value.artifact_id,
            kind: artifact_kind(&value.kind)?,
            sha256: value.sha256,
            size_bytes: value.size_bytes,
        })
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicResult {
    pub outcome: PublicOutcome,
    pub final_text: String,
    pub partial: bool,
    pub retained: bool,
    pub base_commit: Option<String>,
    pub head_commit: Option<String>,
    pub changed_files: Vec<String>,
    pub diff_stat: Option<String>,
    pub checks: Vec<String>,
    pub residual_gaps: Vec<String>,
    pub result_sha256: String,
}

impl TryFrom<TaskResultView> for PublicResult {
    type Error = String;

    fn try_from(value: TaskResultView) -> Result<Self, Self::Error> {
        Ok(Self {
            outcome: value.outcome.into(),
            final_text: value.final_text,
            partial: value.partial,
            retained: value.retained,
            base_commit: value.base_commit,
            head_commit: value.head_commit,
            changed_files: value.changed_files,
            diff_stat: value.diff_stat,
            checks: value.checks,
            residual_gaps: value.residual_gaps,
            result_sha256: value.result_sha256,
        })
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentListInput {
    #[serde(default, deserialize_with = "optional_non_null")]
    pub repository: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub group_id: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub phase: Option<PublicTaskPhase>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub outcome: Option<PublicOutcomeFilter>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub cursor: Option<String>,
    #[schemars(range(min = 1, max = 100))]
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicTaskPhase {
    Queued,
    Preparing,
    Running,
    WaitingInput,
    Cancelling,
    Terminal,
}

impl From<PublicTaskPhase> for TaskPhaseFilter {
    fn from(value: PublicTaskPhase) -> Self {
        match value {
            PublicTaskPhase::Queued => Self::Queued,
            PublicTaskPhase::Preparing => Self::Preparing,
            PublicTaskPhase::Running => Self::Running,
            PublicTaskPhase::WaitingInput => Self::WaitingInput,
            PublicTaskPhase::Cancelling => Self::Cancelling,
            PublicTaskPhase::Terminal => Self::Terminal,
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicOutcomeFilter {
    Completed,
    Failed,
    Cancelled,
    TimedOut,
    BudgetExhausted,
    RuntimeLost,
    ResultInvalid,
}

impl From<PublicOutcomeFilter> for TaskOutcome {
    fn from(value: PublicOutcomeFilter) -> Self {
        match value {
            PublicOutcomeFilter::Completed => Self::Completed,
            PublicOutcomeFilter::Failed => Self::Failed,
            PublicOutcomeFilter::Cancelled => Self::Cancelled,
            PublicOutcomeFilter::TimedOut => Self::TimedOut,
            PublicOutcomeFilter::BudgetExhausted => Self::BudgetExhausted,
            PublicOutcomeFilter::RuntimeLost => Self::RuntimeLost,
            PublicOutcomeFilter::ResultInvalid => Self::ResultInvalid,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct AgentListOutput {
    pub tasks: Vec<PublicTask>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPollInput {
    pub agent_id: String,
    pub after_revision: u64,
    #[schemars(range(min = 0, max = 5000))]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicActivityState {
    Queued,
    Preparing,
    Active,
    WaitingInput,
    Cancelling,
    Idle,
    Terminal,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicTelemetryStatus {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicActivityToolKind {
    Read,
    Bash,
    Other,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicActiveTool {
    pub tool_call_id: String,
    pub kind: PublicActivityToolKind,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicActivityWindow {
    pub reasoning_delta_events: u64,
    pub reasoning_delta_bytes: u64,
    pub text_delta_events: u64,
    pub text_delta_bytes: u64,
    pub tool_calls_started: u64,
    pub tool_calls_completed: u64,
    pub tool_calls_failed: u64,
    pub read_calls: u64,
    pub bash_calls: u64,
    pub other_tool_calls: u64,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicActivity {
    pub state: PublicActivityState,
    pub last_runtime_event_at: Option<u64>,
    pub last_activity_age_ms: Option<u64>,
    pub model_request_active: bool,
    pub model_request_age_ms: Option<u64>,
    pub model_last_delta_age_ms: Option<u64>,
    pub latest_text_tail: String,
    pub latest_text_updated_at: Option<u64>,
    pub latest_text_truncated: bool,
    pub active_tools: Vec<PublicActiveTool>,
    pub window_60s: PublicActivityWindow,
    pub telemetry_status: PublicTelemetryStatus,
}

impl From<TaskActivityView> for PublicActivity {
    fn from(value: TaskActivityView) -> Self {
        Self {
            state: match value.state {
                TaskActivityStateView::Queued => PublicActivityState::Queued,
                TaskActivityStateView::Preparing => PublicActivityState::Preparing,
                TaskActivityStateView::Active => PublicActivityState::Active,
                TaskActivityStateView::WaitingInput => PublicActivityState::WaitingInput,
                TaskActivityStateView::Cancelling => PublicActivityState::Cancelling,
                TaskActivityStateView::Idle => PublicActivityState::Idle,
                TaskActivityStateView::Terminal => PublicActivityState::Terminal,
            },
            last_runtime_event_at: value.last_runtime_event_at,
            last_activity_age_ms: value.last_activity_age_ms,
            model_request_active: value.model_request_active,
            model_request_age_ms: value.model_request_age_ms,
            model_last_delta_age_ms: value.model_last_delta_age_ms,
            latest_text_tail: value.latest_text_tail,
            latest_text_updated_at: value.latest_text_updated_at,
            latest_text_truncated: value.latest_text_truncated,
            active_tools: value
                .active_tools
                .into_iter()
                .map(|tool| PublicActiveTool {
                    tool_call_id: tool.tool_call_id,
                    kind: match tool.kind {
                        zcode_agentd::rpc::ActivityToolKindView::Read => {
                            PublicActivityToolKind::Read
                        }
                        zcode_agentd::rpc::ActivityToolKindView::Bash => {
                            PublicActivityToolKind::Bash
                        }
                        zcode_agentd::rpc::ActivityToolKindView::Other => {
                            PublicActivityToolKind::Other
                        }
                    },
                })
                .collect(),
            window_60s: PublicActivityWindow {
                reasoning_delta_events: value.window_60s.reasoning_delta_events,
                reasoning_delta_bytes: value.window_60s.reasoning_delta_bytes,
                text_delta_events: value.window_60s.text_delta_events,
                text_delta_bytes: value.window_60s.text_delta_bytes,
                tool_calls_started: value.window_60s.tool_calls_started,
                tool_calls_completed: value.window_60s.tool_calls_completed,
                tool_calls_failed: value.window_60s.tool_calls_failed,
                read_calls: value.window_60s.read_calls,
                bash_calls: value.window_60s.bash_calls,
                other_tool_calls: value.window_60s.other_tool_calls,
            },
            telemetry_status: match value.telemetry_status {
                TelemetryStatusView::Healthy => PublicTelemetryStatus::Healthy,
                TelemetryStatusView::Degraded => PublicTelemetryStatus::Degraded,
                TelemetryStatusView::Unavailable => PublicTelemetryStatus::Unavailable,
            },
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct AgentPollOutput {
    pub task: PublicTask,
    pub revision: u64,
    pub next_revision: u64,
    pub pending_requests: Vec<PublicPendingRequest>,
    pub result_available: bool,
    pub activity: PublicActivity,
    pub timed_out: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentSendInput {
    pub agent_id: String,
    pub message_id: String,
    pub content: String,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicMessageDisposition {
    Queued,
    Delivered,
    AlreadyDelivered,
    Failed,
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct AgentSendOutput {
    pub disposition: PublicMessageDisposition,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentRespondInput {
    pub agent_id: String,
    pub request_id: String,
    pub decision: PublicDecision,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct AgentRespondOutput {
    pub disposition: PublicResponseDisposition,
    pub requested_decision: PublicDecision,
    pub effective_decision: PublicDecision,
    pub policy_overrode: bool,
    pub policy_reason_code: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct AgentStateOutput {
    pub task: PublicTask,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentResultInput {
    pub agent_id: String,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub artifact_id: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub offset_bytes: Option<u64>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub limit_bytes: Option<usize>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicArtifactChunk {
    pub artifact_id: String,
    pub offset_bytes: u64,
    pub returned_bytes: usize,
    pub eof: bool,
    pub sha256: String,
    pub size_bytes: u64,
    pub bytes_base64: String,
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct AgentResultOutput {
    pub task: PublicTask,
    pub result: Option<PublicResult>,
    pub artifacts: Vec<PublicArtifact>,
    pub artifact_chunk: Option<PublicArtifactChunk>,
}

#[derive(Debug, Clone)]
pub struct SubagentMcp {
    socket: PathBuf,
    timeout: Duration,
    next_request: Arc<AtomicU64>,
    tool_router: ToolRouter<Self>,
}

impl SubagentMcp {
    pub fn new(socket: PathBuf, timeout: Duration) -> Self {
        Self {
            socket,
            timeout,
            next_request: Arc::new(AtomicU64::new(1)),
            tool_router: Self::tool_router(),
        }
    }

    fn rpc(&self, method: RpcMethod) -> Result<RpcSuccess, String> {
        let request = RpcRequest {
            version: RPC_VERSION,
            request_id: format!(
                "subagent-mcp-{}",
                self.next_request.fetch_add(1, Ordering::Relaxed)
            ),
            method,
        };
        let response = RpcClient::new(&self.socket, self.timeout)
            .call(&request)
            .map_err(public_transport_error)?;
        if response.version != RPC_VERSION {
            return Err("protocol_version_mismatch: incompatible agent daemon".into());
        }
        match response.outcome {
            RpcOutcome::Success { result } => Ok(*result),
            RpcOutcome::Error { error } => Err(public_error(error)),
        }
    }

    fn result(
        &self,
        agent_id: String,
    ) -> Result<(PublicTask, Option<PublicResult>, Vec<PublicArtifact>), String> {
        match self.rpc(RpcMethod::TaskResult { agent_id })? {
            RpcSuccess::TaskResult {
                task,
                result,
                artifacts,
            } => Ok((
                task.into(),
                result.map(TryInto::try_into).transpose()?,
                artifacts
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            _ => Err(protocol_error()),
        }
    }
}

fn attachment(value: &PublicAttachmentInput) -> Result<AttachmentInput, String> {
    validate_text(&value.logical_name, "attachment.logical_name", 256)?;
    validate_path(&value.source_path, "attachment.source_path")?;
    let source_path = PathBuf::from(&value.source_path);
    if !source_path.is_absolute() {
        return Err("validation: attachment.source_path must be absolute".into());
    }
    let allowed_root = source_path
        .parent()
        .ok_or_else(|| "validation: attachment.source_path has no parent".to_owned())?
        .to_path_buf();
    Ok(AttachmentInput {
        logical_name: value.logical_name.clone(),
        source_path,
        allowed_root,
    })
}

fn general_manifest(input: &AgentSpawnInput) -> Result<GeneralTaskManifest, String> {
    for (field, value, max) in [
        ("repository", input.repository.as_str(), MAX_PATH_BYTES),
        ("prompt", input.prompt.as_str(), MAX_PROMPT_BYTES),
        (
            "idempotency_key",
            input.idempotency_key.as_str(),
            MAX_ID_BYTES,
        ),
    ] {
        validate_text(value, field, max)?;
    }
    if let Some(group_id) = input.group_id.as_deref() {
        validate_text(group_id, "group_id", 256)?;
    }
    let repository = PathBuf::from(&input.repository);
    if !repository.is_absolute() {
        return Err("validation: repository must be absolute".into());
    }
    validate_public_command_ids(&input.allowed_command_ids, "allowed_command_ids")?;
    validate_public_command_ids(&input.required_command_ids, "required_command_ids")?;
    let agent_id = "daemon-prepared".to_owned();
    let write_manifest = match input.permission_mode {
        PublicPermissionMode::Build | PublicPermissionMode::Edit | PublicPermissionMode::Yolo => {
            vec![PathBuf::from(".")]
        }
        PublicPermissionMode::Plan => Vec::new(),
    };
    Ok(GeneralTaskManifest {
        schema: GENERAL_TASK_SCHEMA.into(),
        agent_id: agent_id.clone(),
        repository,
        base_ref: String::new(),
        access_mode: PermissionMode::from(input.permission_mode).access_mode(),
        permission_mode: input.permission_mode.into(),
        prompt: input.prompt.clone(),
        repo_context: input.repo_context.iter().map(PathBuf::from).collect(),
        attachments: input
            .attachments
            .iter()
            .map(attachment)
            .collect::<Result<Vec<_>, _>>()?,
        // Write manifests are daemon-owned policy, never caller-controlled.
        write_manifest,
        scratch_root: PathBuf::from(".agent-work/scratch/general"),
        artifact_root: PathBuf::from(".agent-work/artifacts").join(agent_id),
        budget: Some(input.budget.clone().map(Into::into).unwrap_or_else(|| {
            PermissionMode::from(input.permission_mode)
                .access_mode()
                .default_budget()
        })),
        validation_commands: BTreeMap::new(),
        retain_partial: input.retain_partial,
        idempotency_key: input.idempotency_key.clone(),
    })
}

fn validate_public_command_ids(command_ids: &[String], field: &str) -> Result<(), String> {
    if command_ids.len() > 128 {
        return Err(format!("validation: {field} exceeds the selection cap"));
    }
    let mut seen_commands = std::collections::HashSet::new();
    for command_id in command_ids {
        validate_text(command_id, "command_id", 256)?;
        if !command_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
            || !seen_commands.insert(command_id)
        {
            return Err(format!(
                "validation: {field} must contain exact unique command ids"
            ));
        }
    }
    Ok(())
}

fn project_response(value: ResponseOutcomeView) -> AgentRespondOutput {
    let requested_decision = if value.requested_decision == "allow" {
        PublicDecision::Allow
    } else {
        PublicDecision::Deny
    };
    let effective_decision = if value.effective_decision == "allow" {
        PublicDecision::Allow
    } else {
        PublicDecision::Deny
    };
    let disposition = match value.disposition {
        zcode_agentd::rpc::ResponseDispositionView::Responded => {
            PublicResponseDisposition::Responded
        }
        zcode_agentd::rpc::ResponseDispositionView::AlreadyResponded => {
            PublicResponseDisposition::AlreadyResponded
        }
        zcode_agentd::rpc::ResponseDispositionView::InFlight => PublicResponseDisposition::InFlight,
    };
    AgentRespondOutput {
        disposition,
        requested_decision,
        effective_decision,
        policy_overrode: value.policy_overrode,
        policy_reason_code: value.policy_reason_code,
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for SubagentMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions("Stateless public facade for durable local ZCode subagent tasks")
    }
}

#[tool_router(router = tool_router)]
impl SubagentMcp {
    #[tool(
        name = "zcode_subagent_status",
        description = "Read bounded daemon and runtime readiness status",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn system_status(
        &self,
        Parameters(_): Parameters<EmptyInput>,
    ) -> Result<Json<SystemStatusOutput>, String> {
        match self.rpc(RpcMethod::SystemStatus)? {
            RpcSuccess::SystemStatus { status } => Ok(Json(status.into())),
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_subagent_spawn",
        description = "Submit a durable bounded general subagent task",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn agent_spawn(
        &self,
        Parameters(input): Parameters<AgentSpawnInput>,
    ) -> Result<Json<AgentSpawnOutput>, String> {
        let manifest = general_manifest(&input)?;
        let (task, disposition) = match self.rpc(RpcMethod::SubmitGeneral {
            input: GeneralSubmitInput {
                manifest,
                group_id: input.group_id,
                allowed_command_ids: input.allowed_command_ids,
                required_command_ids: input.required_command_ids,
            },
        })? {
            RpcSuccess::GeneralSubmitted { task, disposition } => (task, disposition),
            _ => return Err(protocol_error()),
        };
        let capabilities = match self.rpc(RpcMethod::SystemStatus)? {
            RpcSuccess::SystemStatus { status } => status.capabilities.into(),
            _ => return Err(protocol_error()),
        };
        Ok(Json(AgentSpawnOutput {
            agent_id: task.agent_id,
            submission_disposition: match disposition {
                SubmissionDispositionView::Created => SubmissionDisposition::Created,
                SubmissionDispositionView::Existing => SubmissionDisposition::Existing,
            },
            phase: task.phase,
            effective_budget: task.effective_budget.into(),
            capabilities,
        }))
    }

    #[tool(
        name = "zcode_subagent_poll",
        description = "Long-poll a task revision with typed pending requests and passive runtime activity",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn agent_poll(
        &self,
        Parameters(input): Parameters<AgentPollInput>,
    ) -> Result<Json<AgentPollOutput>, String> {
        validate_text(&input.agent_id, "agent_id", MAX_ID_BYTES)?;
        if input.timeout_ms > 5000 {
            return Err("validation: timeout_ms must be between 0 and 5000".into());
        }
        match self.rpc(RpcMethod::TaskPoll(TaskPollQuery {
            agent_id: input.agent_id,
            after_revision: input.after_revision,
            timeout_ms: input.timeout_ms,
        }))? {
            RpcSuccess::TaskPoll {
                task,
                revision,
                next_revision,
                pending_requests,
                result_available,
                activity,
                timed_out,
            } => Ok(Json(AgentPollOutput {
                task: task.into(),
                revision,
                next_revision,
                pending_requests: pending_requests.into_iter().map(Into::into).collect(),
                result_available,
                activity: activity.into(),
                timed_out,
            })),
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_subagent_list",
        description = "List tasks within an explicit daemon-enforced scope",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn agent_list(
        &self,
        Parameters(input): Parameters<AgentListInput>,
    ) -> Result<Json<AgentListOutput>, String> {
        if !(1..=100).contains(&input.limit) {
            return Err("validation: limit must be between 1 and 100".into());
        }
        if input.repository.is_none() && input.group_id.is_none() {
            return Err("validation: at least one list scope is required".into());
        }
        match self.rpc(RpcMethod::TaskList(TaskListQuery {
            repository: input.repository,
            group_id: input.group_id,
            phase: input.phase.map(Into::into),
            outcome: input.outcome.map(Into::into),
            cursor: input.cursor,
            limit: input.limit,
        }))? {
            RpcSuccess::TaskListed { tasks, next_cursor } => Ok(Json(AgentListOutput {
                tasks: tasks.into_iter().map(Into::into).collect(),
                next_cursor,
            })),
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_subagent_send",
        description = "Queue an idempotent bounded message for a running task",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn agent_send(
        &self,
        Parameters(input): Parameters<AgentSendInput>,
    ) -> Result<Json<AgentSendOutput>, String> {
        validate_text(&input.content, "content", MAX_MESSAGE_BYTES)?;
        match self.rpc(RpcMethod::TaskMessage(MessageInput {
            agent_id: input.agent_id.clone(),
            message_id: input.message_id,
            mode: "queue".into(),
            content: input.content,
        }))? {
            RpcSuccess::Message { disposition, .. } => Ok(Json(AgentSendOutput {
                disposition: match disposition {
                    zcode_agentd::rpc::MessageDispositionView::Queued => {
                        PublicMessageDisposition::Queued
                    }
                    zcode_agentd::rpc::MessageDispositionView::Delivered => {
                        PublicMessageDisposition::Delivered
                    }
                    zcode_agentd::rpc::MessageDispositionView::AlreadyDelivered => {
                        PublicMessageDisposition::AlreadyDelivered
                    }
                    zcode_agentd::rpc::MessageDispositionView::Failed => {
                        PublicMessageDisposition::Failed
                    }
                },
            })),
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_subagent_respond",
        description = "Respond idempotently to a typed pending permission request",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn agent_respond(
        &self,
        Parameters(input): Parameters<AgentRespondInput>,
    ) -> Result<Json<AgentRespondOutput>, String> {
        if input.reason.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > MAX_REASON_BYTES || value.contains('\0')
        }) {
            return Err("validation: reason is invalid".into());
        }
        let decision = match input.decision {
            PublicDecision::Allow => ResponseDecision::Allow,
            PublicDecision::Deny => ResponseDecision::Deny,
        };
        match self.rpc(RpcMethod::TaskRespond(RespondInput {
            agent_id: input.agent_id.clone(),
            request_id: input.request_id,
            decision,
            content: input.reason,
        }))? {
            RpcSuccess::Respond { outcome, .. } => Ok(Json(project_response(outcome))),
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_subagent_cancel",
        description = "Cancel a task without removing durable history",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn agent_cancel(
        &self,
        Parameters(input): Parameters<AgentInput>,
    ) -> Result<Json<AgentStateOutput>, String> {
        match self.rpc(RpcMethod::TaskCancel {
            agent_id: input.agent_id.clone(),
        })? {
            RpcSuccess::Stopped { task } => Ok(Json(AgentStateOutput { task: task.into() })),
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_subagent_result",
        description = "Read verified task results and an optional bounded artifact chunk",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn agent_result(
        &self,
        Parameters(input): Parameters<AgentResultInput>,
    ) -> Result<Json<AgentResultOutput>, String> {
        let selector_count = [
            input.artifact_id.is_some(),
            input.offset_bytes.is_some(),
            input.limit_bytes.is_some(),
        ]
        .into_iter()
        .filter(|value| *value)
        .count();
        if selector_count != 0 && selector_count != 3 {
            return Err(
                "validation: artifact_id, offset_bytes, and limit_bytes must be supplied together"
                    .into(),
            );
        }
        let (task, result, artifacts) = self.result(input.agent_id.clone())?;
        let artifact_chunk = if let (Some(artifact_id), Some(offset_bytes), Some(limit_bytes)) =
            (input.artifact_id, input.offset_bytes, input.limit_bytes)
        {
            if limit_bytes == 0 || limit_bytes > MAX_ARTIFACT_CHUNK_BYTES {
                return Err("validation: limit_bytes is outside the allowed range".into());
            }
            let expected = artifacts
                .iter()
                .find(|artifact| artifact.artifact_id == artifact_id)
                .ok_or_else(|| {
                    "validation: artifact_id is not in the authoritative result".to_owned()
                })?;
            if offset_bytes >= expected.size_bytes {
                return Err("validation: offset_bytes does not permit non-empty progress".into());
            }
            match self.rpc(RpcMethod::TaskArtifact(TaskArtifactQuery {
                agent_id: input.agent_id,
                artifact_id: artifact_id.clone(),
                offset_bytes,
                limit_bytes,
            }))? {
                RpcSuccess::TaskArtifact { chunk } => {
                    let returned_bytes = chunk.bytes.len();
                    let next_offset = offset_bytes
                        .checked_add(u64::try_from(returned_bytes).map_err(|_| protocol_error())?)
                        .ok_or_else(protocol_error)?;
                    if chunk.artifact_id != artifact_id
                        || chunk.sha256 != expected.sha256
                        || chunk.size_bytes != expected.size_bytes
                        || chunk.offset_bytes != offset_bytes
                        || returned_bytes == 0
                        || returned_bytes > limit_bytes
                        || next_offset > expected.size_bytes
                        || chunk.eof != (next_offset == expected.size_bytes)
                    {
                        return Err(
                            "protocol_error: artifact chunk violated authoritative metadata".into(),
                        );
                    }
                    Some(PublicArtifactChunk {
                        artifact_id: chunk.artifact_id,
                        offset_bytes: chunk.offset_bytes,
                        returned_bytes,
                        eof: chunk.eof,
                        sha256: chunk.sha256,
                        size_bytes: chunk.size_bytes,
                        bytes_base64: BASE64.encode(chunk.bytes),
                    })
                }
                _ => return Err(protocol_error()),
            }
        } else {
            None
        };
        Ok(Json(AgentResultOutput {
            task,
            result,
            artifacts,
            artifact_chunk,
        }))
    }

    #[tool(
        name = "zcode_subagent_close",
        description = "Close a task and reap runtime resources while preserving durable history",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn agent_close(
        &self,
        Parameters(input): Parameters<AgentInput>,
    ) -> Result<Json<AgentStateOutput>, String> {
        match self.rpc(RpcMethod::TaskClose {
            agent_id: input.agent_id.clone(),
        })? {
            RpcSuccess::Closed { task } => Ok(Json(AgentStateOutput { task: task.into() })),
            _ => Err(protocol_error()),
        }
    }
}

pub async fn serve_stdio(
    socket: PathBuf,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    SubagentMcp::new(socket, timeout)
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?
        .waiting()
        .await?;
    Ok(())
}

#[cfg(test)]
mod generic_tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{io, process::Command};
    use zcode_agent_store::{
        ArtifactKind, NewArtifact, ResultArtifact, Store, TaskRecord, TaskResult, TurnState,
    };
    use zcode_agentd::{
        rpc::{RpcServer, RpcService, ServerOptions},
        LifecycleSink, ManagedRuntime, RuntimeFactory, Scheduler, SchedulerConfig,
    };

    struct NeverRuntimeFactory;

    impl RuntimeFactory for NeverRuntimeFactory {
        fn spawn(
            &self,
            _task: &TaskRecord,
            _sink: Arc<dyn LifecycleSink>,
        ) -> io::Result<Arc<dyn ManagedRuntime>> {
            Err(io::Error::other(
                "runtime is not used by facade persistence test",
            ))
        }
    }

    fn git(repository: &std::path::Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repository)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success(), "git failed: {:?}", output.stderr);
        String::from_utf8(output.stdout).unwrap().trim().into()
    }

    #[test]
    fn exact_generic_catalog_and_no_legacy_symbols() {
        let facade = SubagentMcp::new(PathBuf::from("/tmp/unused"), Duration::from_secs(1));
        let tools = facade.tool_router.list_all();
        let names = tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(names, PUBLIC_TOOLS);
        let encoded = serde_json::to_string(&tools).unwrap();
        assert!(!encoded.contains("write_manifest"));
        for forbidden in [
            concat!("zcode_", "review_spawn"),
            concat!("zcode_", "review_continue"),
            concat!("zcode_", "system_ensure_ready"),
            concat!("zcode_", "agent_get"),
            concat!("zcode_", "agent_events"),
            concat!("zcode_", "agent_wait"),
            concat!("review", "_id"),
            concat!("review", "_evidence"),
            concat!("report_", "markdown"),
            concat!("check_", "report"),
            concat!("artifact", "_intents"),
            "semantic_soft_timeout_ms",
            "semantic_hard_timeout_ms",
            "interrupt_and_continue",
            concat!("attempt_", "sequence"),
            concat!("public_", "agent_id"),
            concat!("execution_", "agent_id"),
            concat!("feature_", "id"),
            concat!("ownership_", "token"),
            concat!("task_", "kind"),
            concat!("analysis_", "readonly"),
            concat!("implementation_", "worktree"),
            concat!("test_", "runner"),
        ] {
            assert!(
                !encoded.contains(forbidden),
                "public schema leaked {forbidden}"
            );
        }
    }

    #[test]
    fn public_spawn_rejects_caller_write_manifest() {
        let result = serde_json::from_value::<AgentSpawnInput>(serde_json::json!({
            "repository": "/tmp/repository",
            "permission_mode": "build",
            "prompt": "run checks",
            "idempotency_key": "key",
            "write_manifest": ["src"]
        }));
        assert!(result.is_err(), "write_manifest must not be a public input");
    }

    #[test]
    fn public_budget_contains_only_runtime_and_absolute_limits() {
        let budget = PublicBudget {
            absolute_wall_time_ms: 1,
            runtime_activity_idle_timeout_ms: 2,
            model_stream_idle_timeout_ms: 3,
            tool_call_timeout_ms: 4,
            input_wait_timeout_ms: 5,
            max_turns: 6,
            max_tool_calls: 7,
            max_context_bytes: 8,
            max_result_bytes: 9,
            max_artifact_bytes: 10,
        };
        let value = serde_json::to_value(budget).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 10);
        assert!(!value.to_string().contains("semantic"));
    }

    #[test]
    fn generic_spawn_rejects_duplicate_command_ids() {
        let mut input = serde_json::from_value::<AgentSpawnInput>(serde_json::json!({
            "repository": "/tmp/repository",
            "permission_mode": "build",
            "prompt": "run checks",
            "group_id": "feature",
            "idempotency_key": "key",
            "allowed_command_ids": ["unit"],
            "required_command_ids": ["lint"]
        }))
        .unwrap();
        input.allowed_command_ids.push("unit".into());
        assert!(general_manifest(&input).is_err());
    }

    #[test]
    fn public_write_modes_bind_the_canonical_workspace_write_scope() {
        for mode in ["build", "edit", "yolo"] {
            let input = serde_json::from_value::<AgentSpawnInput>(serde_json::json!({
                "repository": "/tmp/repository",
                "permission_mode": mode,
                "prompt": "write a file",
                "idempotency_key": mode
            }))
            .unwrap();
            assert_eq!(
                general_manifest(&input).unwrap().write_manifest,
                [PathBuf::from(".")]
            );
        }
        let input = serde_json::from_value::<AgentSpawnInput>(serde_json::json!({
            "repository": "/tmp/repository",
            "permission_mode": "plan",
            "prompt": "inspect files",
            "idempotency_key": "plan"
        }))
        .unwrap();
        assert!(general_manifest(&input).unwrap().write_manifest.is_empty());
    }

    #[tokio::test]
    async fn immutable_result_and_patch_survive_real_facade_reconstruction() {
        let directory = tempfile::tempdir().unwrap();
        let repository = directory.path().join("repository");
        std::fs::create_dir_all(repository.join("src")).unwrap();
        std::fs::write(
            repository.join("src/lib.rs"),
            "pub fn value() -> u8 { 1 }\n",
        )
        .unwrap();
        git(&repository, &["init"]);
        git(&repository, &["config", "user.name", "Facade Test"]);
        git(
            &repository,
            &["config", "user.email", "facade@example.invalid"],
        );
        git(&repository, &["add", "src/lib.rs"]);
        git(&repository, &["commit", "-m", "fixture"]);
        let base_ref = git(&repository, &["rev-parse", "HEAD"]);
        let repository = std::fs::canonicalize(repository).unwrap();
        let store = Arc::new(Store::open(directory.path().join("store.sqlite3")).unwrap());
        let scheduler = Scheduler::new(
            "facade-test",
            Arc::clone(&store),
            Arc::new(NeverRuntimeFactory),
            SchedulerConfig::default(),
        )
        .unwrap();
        let submitted = scheduler
            .enqueue_general(
                &GeneralTaskManifest {
                    schema: GENERAL_TASK_SCHEMA.into(),
                    agent_id: "facade-result".into(),
                    repository: repository.clone(),
                    base_ref,
                    access_mode: PermissionMode::Build.access_mode(),
                    permission_mode: PermissionMode::Build,
                    prompt: "produce a patch".into(),
                    repo_context: vec!["src/lib.rs".into()],
                    attachments: Vec::new(),
                    write_manifest: vec!["src".into()],
                    scratch_root: ".agent-work/scratch/facade-result".into(),
                    artifact_root: ".agent-work/artifacts/facade-result".into(),
                    budget: None,
                    validation_commands: BTreeMap::new(),
                    retain_partial: false,
                    idempotency_key: "facade-result-key".into(),
                },
                Some("facade-group"),
            )
            .unwrap();
        let agent_id = submitted.task.agent_id.clone();
        let prepared: zcode_agent_preparation::PreparedGeneralTask =
            serde_json::from_str(&submitted.task.prepared_launch_json).unwrap();
        let claim = store.claim_next("facade-owner", 1, 1).unwrap().unwrap();
        assert!(store
            .mark_session_running(
                &agent_id,
                claim.owner_epoch,
                "facade-runtime",
                None,
                None,
                Some(TurnState::Idle),
            )
            .unwrap());

        let patch_bytes = b"diff --git a/src/lib.rs b/src/lib.rs\n+facade reconstruction\n";
        let patch_path = prepared.artifact_root.join("changes.patch");
        std::fs::write(&patch_path, patch_bytes).unwrap();
        let patch_sha256 = format!("{:x}", Sha256::digest(patch_bytes));
        let artifact = NewArtifact {
            artifact_id: "changes-patch".into(),
            agent_id: agent_id.clone(),
            artifact_type: "changes_patch".into(),
            path: patch_path.to_string_lossy().into_owned(),
            sha256: patch_sha256.clone(),
            bytes: patch_bytes.len() as u64,
        };
        let result = TaskResult {
            outcome: TaskOutcome::Completed,
            final_text: "persisted terminal text".into(),
            partial: false,
            base_commit: Some(prepared.base_sha.clone()),
            head_commit: Some("detached-head".into()),
            changed_files: vec!["src/lib.rs".into()],
            diff_stat: Some("src/lib.rs | 1 +".into()),
            checks: vec!["required".into()],
            residual_gaps: Vec::new(),
            artifacts: vec![ResultArtifact {
                kind: ArtifactKind::ChangesPatch,
                artifact_id: artifact.artifact_id.clone(),
                sha256: patch_sha256.clone(),
            }],
        };
        store
            .store_task_result_with_patch(&agent_id, &result, Some(&artifact))
            .unwrap();

        let socket = directory.path().join("rpc/facade.sock");
        let service = Arc::new(RpcService::new(scheduler, Arc::clone(&store)).unwrap());
        let server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
        let first = SubagentMcp::new(socket.clone(), Duration::from_secs(1));
        let (_, first_result, first_artifacts) = first.result(agent_id.clone()).unwrap();
        assert_eq!(first_result.unwrap().final_text, "persisted terminal text");
        assert_eq!(first_artifacts.len(), 1);
        drop(first);

        let reconstructed = SubagentMcp::new(socket, Duration::from_secs(1));
        let Json(output) = reconstructed
            .agent_result(Parameters(AgentResultInput {
                agent_id,
                artifact_id: Some("changes-patch".into()),
                offset_bytes: Some(0),
                limit_bytes: Some(patch_bytes.len()),
            }))
            .await
            .unwrap();
        assert_eq!(output.task.phase, "TERMINAL");
        let persisted = output.result.unwrap();
        assert!(matches!(persisted.outcome, PublicOutcome::Completed));
        assert_eq!(persisted.final_text, "persisted terminal text");
        assert_eq!(persisted.changed_files, ["src/lib.rs"]);
        assert_eq!(output.artifacts.len(), 1);
        assert!(matches!(
            output.artifacts[0].kind,
            PublicArtifactKind::ChangesPatch
        ));
        let chunk = output.artifact_chunk.unwrap();
        assert!(chunk.eof);
        assert_eq!(chunk.sha256, patch_sha256);
        assert_eq!(BASE64.decode(chunk.bytes_base64).unwrap(), patch_bytes);
        server.shutdown();
    }
}
