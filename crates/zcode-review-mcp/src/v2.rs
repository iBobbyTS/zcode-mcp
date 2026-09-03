use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use review_preparation::{
    AttachmentInput, BudgetLimits, GeneralProfile, GeneralTaskManifest, GENERAL_TASK_SCHEMA,
};
use review_store::{EffectiveBudget, TaskOutcome};
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
use zcode_reviewd::rpc::{
    AgentCapabilitiesView, CapabilityMaturityView, ComponentStateView, GeneralSubmitInput,
    MessageInput, ReadinessResultView, RespondInput, ResponseDecision, ResponseOutcomeView,
    RpcClient, RpcMethod, RpcOutcome, RpcRequest, RpcSuccess, SubmissionDispositionView,
    SystemStatusView, TaskActivityStateView, TaskActivityView, TaskArtifactMetadataView,
    TaskArtifactQuery, TaskListQuery, TaskPhaseFilter, TaskPollQuery, TaskResultView, TaskView,
    TelemetryStatusView, MAX_ARTIFACT_CHUNK_BYTES, RPC_VERSION,
};

use crate::{
    protocol_error, public_error, public_transport_error, PublicDecision, PublicPendingRequest,
    PublicResponseDisposition,
};

pub const V2_PUBLIC_TOOLS: [&str; 9] = [
    "zcode_agent_cancel",
    "zcode_agent_close",
    "zcode_agent_list",
    "zcode_agent_poll",
    "zcode_agent_respond",
    "zcode_agent_result",
    "zcode_agent_send",
    "zcode_agent_spawn",
    "zcode_system_status",
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicAccessMode {
    ReadOnly,
    WorkspaceWrite,
}

impl From<PublicAccessMode> for GeneralProfile {
    fn from(value: PublicAccessMode) -> Self {
        match value {
            PublicAccessMode::ReadOnly => Self::AnalysisReadonly,
            PublicAccessMode::WorkspaceWrite => Self::ImplementationWorktree,
        }
    }
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
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicReadinessResult {
    Ready,
    ConfigInvalid,
    ZcodeStartFailed,
    RuntimeProtocolFailed,
    ModelAuthFailed,
    RuntimeFailed,
    NotObservedWithinTimeout,
    CleanupFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicReadinessReason {
    ConfigInvalid,
    ZcodeStartFailed,
    RuntimeProtocolFailed,
    ModelAuthFailed,
    RuntimeFailed,
    NotObservedWithinTimeout,
    CleanupFailed,
}

impl PublicReadinessReason {
    fn from_result(value: ReadinessResultView) -> Option<Self> {
        match value {
            ReadinessResultView::Ready => None,
            ReadinessResultView::ConfigInvalid => Some(Self::ConfigInvalid),
            ReadinessResultView::ZcodeStartFailed => Some(Self::ZcodeStartFailed),
            ReadinessResultView::RuntimeProtocolFailed => Some(Self::RuntimeProtocolFailed),
            ReadinessResultView::ModelAuthFailed => Some(Self::ModelAuthFailed),
            ReadinessResultView::RuntimeFailed => Some(Self::RuntimeFailed),
            ReadinessResultView::NotObservedWithinTimeout => Some(Self::NotObservedWithinTimeout),
            ReadinessResultView::CleanupFailed => Some(Self::CleanupFailed),
        }
    }

    fn as_wire_code(self) -> &'static str {
        match self {
            Self::ConfigInvalid => "CONFIG_INVALID",
            Self::ZcodeStartFailed => "ZCODE_START_FAILED",
            Self::RuntimeProtocolFailed => "RUNTIME_PROTOCOL_FAILED",
            Self::ModelAuthFailed => "MODEL_AUTH_FAILED",
            Self::RuntimeFailed => "RUNTIME_FAILED",
            Self::NotObservedWithinTimeout => "NOT_OBSERVED_WITHIN_TIMEOUT",
            Self::CleanupFailed => "CLEANUP_FAILED",
        }
    }
}

impl From<ReadinessResultView> for PublicReadinessResult {
    fn from(value: ReadinessResultView) -> Self {
        match value {
            ReadinessResultView::Ready => Self::Ready,
            ReadinessResultView::ConfigInvalid => Self::ConfigInvalid,
            ReadinessResultView::ZcodeStartFailed => Self::ZcodeStartFailed,
            ReadinessResultView::RuntimeProtocolFailed => Self::RuntimeProtocolFailed,
            ReadinessResultView::ModelAuthFailed => Self::ModelAuthFailed,
            ReadinessResultView::RuntimeFailed => Self::RuntimeFailed,
            ReadinessResultView::NotObservedWithinTimeout => Self::NotObservedWithinTimeout,
            ReadinessResultView::CleanupFailed => Self::CleanupFailed,
        }
    }
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
    pub access_modes: Vec<String>,
    pub access_mode_defaults: BTreeMap<String, PublicBudget>,
    pub hard_budget_caps: PublicBudget,
    pub max_rpc_frame_bytes: usize,
    pub max_events: usize,
    pub max_wait_ms: u64,
    pub max_artifact_chunk_bytes: usize,
    pub named_checks: bool,
    pub maturity: BTreeMap<String, PublicCapabilityMaturity>,
}

impl From<AgentCapabilitiesView> for PublicAgentCapabilities {
    fn from(mut value: AgentCapabilitiesView) -> Self {
        let access_mode_defaults = [
            ("read_only", "analysis_readonly"),
            ("workspace_write", "implementation_worktree"),
        ]
        .into_iter()
        .filter_map(|(access_mode, profile)| {
            value
                .profile_defaults
                .remove(profile)
                .map(|budget| (access_mode.into(), budget.into()))
        })
        .collect();
        let maturity = [
            ("read_only", "analysis_readonly"),
            ("workspace_write", "implementation_worktree"),
        ]
        .into_iter()
        .filter_map(|(access_mode, profile)| {
            value
                .maturity
                .remove(profile)
                .map(|maturity| (access_mode.into(), maturity.into()))
        })
        .collect();
        Self {
            access_modes: vec!["read_only".into(), "workspace_write".into()],
            access_mode_defaults,
            hard_budget_caps: value.hard_budget_caps.into(),
            max_rpc_frame_bytes: value.max_rpc_frame_bytes,
            max_events: value.max_events,
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
    pub base_ref: String,
    pub access_mode: PublicAccessMode,
    pub prompt: String,
    pub feature_id: String,
    pub ownership_token: String,
    pub idempotency_key: String,
    #[serde(default)]
    pub write_manifest: Vec<String>,
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
    pub attempt_sequence: u64,
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
    pub access_mode: String,
    pub phase: String,
    pub attempt_sequence: u64,
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
            access_mode: value.access_mode,
            phase: value.phase,
            attempt_sequence: value.attempt_sequence,
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
    Succeeded,
    Blocked,
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
            TaskOutcome::Succeeded => Self::Succeeded,
            TaskOutcome::Blocked => Self::Blocked,
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
    ReportMarkdown,
    ChangesPatch,
    CheckReport,
}

fn artifact_kind(value: &str) -> Result<PublicArtifactKind, String> {
    match value {
        "report_markdown" => Ok(PublicArtifactKind::ReportMarkdown),
        "changes_patch" => Ok(PublicArtifactKind::ChangesPatch),
        "check_report" => Ok(PublicArtifactKind::CheckReport),
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
            final_text: value.summary,
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
    pub feature_id: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub ownership_token: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub phase: Option<PublicTaskPhase>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub outcome: Option<PublicOutcomeFilter>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub access_mode: Option<PublicAccessMode>,
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
    Succeeded,
    Blocked,
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
            PublicOutcomeFilter::Succeeded => Self::Succeeded,
            PublicOutcomeFilter::Blocked => Self::Blocked,
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
                        zcode_reviewd::rpc::ActivityToolKindView::Read => {
                            PublicActivityToolKind::Read
                        }
                        zcode_reviewd::rpc::ActivityToolKindView::Bash => {
                            PublicActivityToolKind::Bash
                        }
                        zcode_reviewd::rpc::ActivityToolKindView::Other => {
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
    pub attempt_sequence: u64,
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
    pub attempt_sequence: u64,
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
    pub attempt_sequence: Option<u64>,
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
            return Err("protocol_version_mismatch: incompatible review daemon".into());
        }
        match response.outcome {
            RpcOutcome::Success { result } => Ok(*result),
            RpcOutcome::Error { error } => Err(public_error(error)),
        }
    }

    fn status(&self, agent_id: &str) -> Result<PublicTask, String> {
        validate_text(agent_id, "agent_id", MAX_ID_BYTES)?;
        match self.rpc(RpcMethod::TaskStatus {
            agent_id: agent_id.into(),
        })? {
            RpcSuccess::TaskStatus { task } => Ok(task.into()),
            _ => Err(protocol_error()),
        }
    }

    fn pending(&self, agent_id: &str) -> Result<Vec<PublicPendingRequest>, String> {
        match self.rpc(RpcMethod::TaskPending {
            agent_id: agent_id.into(),
        })? {
            RpcSuccess::Pending { requests } => Ok(requests.into_iter().map(Into::into).collect()),
            _ => Err(protocol_error()),
        }
    }

    fn result(
        &self,
        agent_id: String,
        attempt_sequence: Option<u64>,
    ) -> Result<(PublicTask, Option<PublicResult>, Vec<PublicArtifact>), String> {
        match self.rpc(RpcMethod::TaskResult {
            agent_id,
            attempt_sequence,
        })? {
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
        ("base_ref", input.base_ref.as_str(), MAX_ID_BYTES),
        ("prompt", input.prompt.as_str(), MAX_PROMPT_BYTES),
        ("feature_id", input.feature_id.as_str(), 256),
        (
            "ownership_token",
            input.ownership_token.as_str(),
            MAX_ID_BYTES,
        ),
        (
            "idempotency_key",
            input.idempotency_key.as_str(),
            MAX_ID_BYTES,
        ),
    ] {
        validate_text(value, field, max)?;
    }
    let repository = PathBuf::from(&input.repository);
    if !repository.is_absolute() {
        return Err("validation: repository must be absolute".into());
    }
    validate_public_command_ids(&input.allowed_command_ids, "allowed_command_ids")?;
    validate_public_command_ids(&input.required_command_ids, "required_command_ids")?;
    let task_id = "daemon-prepared".to_owned();
    Ok(GeneralTaskManifest {
        schema: GENERAL_TASK_SCHEMA.into(),
        task_id: task_id.clone(),
        repository,
        base_ref: input.base_ref.clone(),
        profile: input.access_mode.into(),
        prompt: input.prompt.clone(),
        repo_context: input.repo_context.iter().map(PathBuf::from).collect(),
        attachments: input
            .attachments
            .iter()
            .map(attachment)
            .collect::<Result<Vec<_>, _>>()?,
        write_manifest: input.write_manifest.iter().map(PathBuf::from).collect(),
        scratch_root: PathBuf::from(".agent-work/scratch/general"),
        artifact_root: PathBuf::from(".agent-work/artifacts").join(task_id),
        budget: Some(
            input
                .budget
                .clone()
                .map(Into::into)
                .unwrap_or_else(|| GeneralProfile::from(input.access_mode).default_budget()),
        ),
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

fn project_response(value: ResponseOutcomeView, attempt_sequence: u64) -> AgentRespondOutput {
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
        zcode_reviewd::rpc::ResponseDispositionView::Responded => {
            PublicResponseDisposition::Responded
        }
        zcode_reviewd::rpc::ResponseDispositionView::AlreadyResponded => {
            PublicResponseDisposition::AlreadyResponded
        }
        zcode_reviewd::rpc::ResponseDispositionView::InFlight => {
            PublicResponseDisposition::InFlight
        }
    };
    AgentRespondOutput {
        disposition,
        requested_decision,
        effective_decision,
        policy_overrode: value.policy_overrode,
        policy_reason_code: value.policy_reason_code,
        attempt_sequence,
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
        name = "zcode_system_status",
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
        name = "zcode_agent_spawn",
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
                feature_id: input.feature_id,
                ownership_token: input.ownership_token,
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
            attempt_sequence: task.attempt_sequence,
            effective_budget: task.effective_budget.into(),
            capabilities,
        }))
    }

    #[tool(
        name = "zcode_agent_poll",
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
        name = "zcode_agent_list",
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
        if input.repository.is_none()
            && input.feature_id.is_none()
            && input.ownership_token.is_none()
        {
            return Err("validation: at least one list scope is required".into());
        }
        match self.rpc(RpcMethod::TaskList(TaskListQuery {
            repository: input.repository,
            feature_id: input.feature_id,
            ownership_token: input.ownership_token,
            phase: input.phase.map(Into::into),
            outcome: input.outcome.map(Into::into),
            profile: input.access_mode.map(Into::into),
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
        name = "zcode_agent_send",
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
            RpcSuccess::Message { disposition } => Ok(Json(AgentSendOutput {
                disposition: match disposition {
                    zcode_reviewd::rpc::MessageDispositionView::Queued => {
                        PublicMessageDisposition::Queued
                    }
                    zcode_reviewd::rpc::MessageDispositionView::Delivered => {
                        PublicMessageDisposition::Delivered
                    }
                    zcode_reviewd::rpc::MessageDispositionView::AlreadyDelivered => {
                        PublicMessageDisposition::AlreadyDelivered
                    }
                    zcode_reviewd::rpc::MessageDispositionView::Failed => {
                        PublicMessageDisposition::Failed
                    }
                },
                attempt_sequence: self.status(&input.agent_id)?.attempt_sequence,
            })),
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_agent_respond",
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
            RpcSuccess::Respond { outcome } => Ok(Json(project_response(
                outcome,
                self.status(&input.agent_id)?.attempt_sequence,
            ))),
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_agent_cancel",
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
            RpcSuccess::Stopped { .. } => Ok(Json(AgentStateOutput {
                task: self.status(&input.agent_id)?,
            })),
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_agent_result",
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
        let (task, result, artifacts) =
            self.result(input.agent_id.clone(), input.attempt_sequence)?;
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
                attempt_sequence: input.attempt_sequence,
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
        name = "zcode_agent_close",
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
            RpcSuccess::Closed { .. } => {}
            _ => return Err(protocol_error()),
        }
        match self.rpc(RpcMethod::TaskReap {
            agent_id: input.agent_id.clone(),
        })? {
            RpcSuccess::Reaped { .. } => Ok(Json(AgentStateOutput {
                task: self.status(&input.agent_id)?,
            })),
            _ => Err(protocol_error()),
        }
    }
}

pub async fn serve_stdio_v2(
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

    #[test]
    fn exact_generic_catalog_and_no_legacy_symbols() {
        let facade = SubagentMcp::new(PathBuf::from("/tmp/unused"), Duration::from_secs(1));
        let tools = facade.tool_router.list_all();
        let names = tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(names, V2_PUBLIC_TOOLS);
        let encoded = serde_json::to_string(&tools).unwrap();
        for forbidden in [
            "zcode_review_spawn",
            "zcode_review_continue",
            "zcode_system_ensure_ready",
            "zcode_agent_get",
            "zcode_agent_events",
            "zcode_agent_wait",
            "review_id",
            "review_evidence",
            "semantic_soft_timeout_ms",
            "semantic_hard_timeout_ms",
            "interrupt_and_continue",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "public schema leaked {forbidden}"
            );
        }
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
            "base_ref": "a".repeat(40),
            "access_mode": "workspace_write",
            "prompt": "run checks",
            "feature_id": "feature",
            "ownership_token": "owner",
            "idempotency_key": "key",
            "write_manifest": ["src/lib.rs"],
            "allowed_command_ids": ["unit"],
            "required_command_ids": ["lint"]
        }))
        .unwrap();
        input.allowed_command_ids.push("unit".into());
        assert!(general_manifest(&input).is_err());
    }
}
