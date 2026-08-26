use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use review_preparation::{
    AttachmentInput, BudgetLimits, GeneralProfile, GeneralTaskManifest, NetworkPolicy, ReviewKind,
    ReviewManifest, RoundKind, ScratchPolicy, GENERAL_TASK_SCHEMA,
};
use review_store::{EffectiveBudget, TaskOutcome};
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, Json, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use zcode_reviewd::{
    orchestration::{
        MinimalStructuredReviewContinuation, ReviewSubmissionDisposition, StructuredReviewKind,
        StructuredReviewProjection, StructuredReviewSubmission,
    },
    rpc::{
        AgentCapabilitiesView, ComponentStateView, GeneralSubmitInput, MessageDispositionView,
        MessageInput, RespondInput, ResponseDecision, ResponseOutcomeView, RpcClient, RpcMethod,
        RpcOutcome, RpcRequest, RpcSuccess, SystemStatusView, TaskArtifactMetadataView,
        TaskArtifactQuery, TaskEventPage, TaskEventQuery, TaskListQuery, TaskResultView, TaskView,
        TaskWaitQuery, MAX_ARTIFACT_CHUNK_BYTES, RPC_VERSION,
    },
};

use crate::{
    protocol_error, public_error, public_transport_error, PublicDecision, PublicPendingRequest,
    PublicResponseDisposition,
};

pub const V2_PUBLIC_TOOLS: [&str; 14] = [
    "zcode_agent_cancel",
    "zcode_agent_close",
    "zcode_agent_events",
    "zcode_agent_get",
    "zcode_agent_list",
    "zcode_agent_message",
    "zcode_agent_respond",
    "zcode_agent_result",
    "zcode_agent_spawn",
    "zcode_agent_wait",
    "zcode_review_continue",
    "zcode_review_spawn",
    "zcode_system_ensure_ready",
    "zcode_system_status",
];

const MAX_ID_BYTES: usize = 512;
const MAX_PATH_BYTES: usize = 4096;
const MAX_PROMPT_BYTES: usize = 256 * 1024;
const MAX_MESSAGE_BYTES: usize = 16 * 1024;
const MAX_REASON_BYTES: usize = 2048;

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
pub enum PublicProfile {
    AnalysisReadonly,
    ImplementationWorktree,
    TestRunner,
}

impl From<PublicProfile> for GeneralProfile {
    fn from(value: PublicProfile) -> Self {
        match value {
            PublicProfile::AnalysisReadonly => Self::AnalysisReadonly,
            PublicProfile::ImplementationWorktree => Self::ImplementationWorktree,
            PublicProfile::TestRunner => Self::TestRunner,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct PublicBudget {
    pub wall_time_ms: u64,
    pub max_turns: u64,
    pub max_tool_calls: u64,
    pub max_context_bytes: u64,
    pub max_result_bytes: u64,
    pub max_artifact_bytes: u64,
}

impl From<PublicBudget> for BudgetLimits {
    fn from(value: PublicBudget) -> Self {
        Self {
            wall_time_ms: value.wall_time_ms,
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
            wall_time_ms: value.wall_time_ms,
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
            wall_time_ms: value.wall_time_ms,
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
    pub task_kinds: Vec<String>,
    pub profiles: Vec<String>,
    pub profile_defaults: BTreeMap<String, PublicBudget>,
    pub hard_budget_caps: PublicBudget,
    pub max_rpc_frame_bytes: usize,
    pub max_events: usize,
    pub max_wait_ms: u64,
    pub max_artifact_chunk_bytes: usize,
}

impl From<AgentCapabilitiesView> for PublicAgentCapabilities {
    fn from(value: AgentCapabilitiesView) -> Self {
        Self {
            task_kinds: value.task_kinds,
            profiles: value.profiles,
            profile_defaults: value
                .profile_defaults
                .into_iter()
                .map(|(name, budget)| (name, budget.into()))
                .collect(),
            hard_budget_caps: value.hard_budget_caps.into(),
            max_rpc_frame_bytes: value.max_rpc_frame_bytes,
            max_events: value.max_events,
            max_wait_ms: value.max_wait_ms,
            max_artifact_chunk_bytes: MAX_ARTIFACT_CHUNK_BYTES,
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
pub struct EmptyInput {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnsureReadyInput {
    #[serde(default = "default_ready_timeout")]
    #[schemars(range(min = 1, max = 5000))]
    pub timeout_ms: u64,
}

fn default_ready_timeout() -> u64 {
    1000
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct EnsureReadyOutput {
    pub ready: bool,
    pub status: SystemStatusOutput,
    pub reason_code: Option<String>,
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
    pub profile: PublicProfile,
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
    pub review_id: Option<String>,
    pub task_kind: String,
    pub phase: String,
    pub attempt_sequence: u64,
    pub effective_budget: PublicBudget,
    pub counts_as_independent: bool,
    pub fresh_session_observed: bool,
    pub cancel_requested: bool,
    pub close_requested: bool,
    pub closed: bool,
    pub resources_reaped: bool,
}

impl From<TaskView> for PublicTask {
    fn from(value: TaskView) -> Self {
        Self {
            agent_id: value.agent_id,
            review_id: value.review_id,
            task_kind: value.task_kind,
            phase: value.phase,
            attempt_sequence: value.attempt_sequence,
            effective_budget: value.effective_budget.into(),
            counts_as_independent: value.independent_evidence && value.fresh_session_observed,
            fresh_session_observed: value.fresh_session_observed,
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
    pub summary: String,
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

impl From<TaskResultView> for PublicResult {
    fn from(value: TaskResultView) -> Self {
        Self {
            outcome: value.outcome.into(),
            summary: value.summary,
            partial: value.partial,
            retained: value.retained,
            base_commit: value.base_commit,
            head_commit: value.head_commit,
            changed_files: value.changed_files,
            diff_stat: value.diff_stat,
            checks: value.checks,
            residual_gaps: value.residual_gaps,
            result_sha256: value.result_sha256,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct AgentGetOutput {
    pub task: PublicTask,
    pub result: Option<PublicResult>,
    pub artifacts: Vec<PublicArtifact>,
    pub pending_requests: Vec<PublicPendingRequest>,
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
    #[schemars(range(min = 1, max = 100))]
    pub limit: usize,
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct AgentListOutput {
    pub tasks: Vec<PublicTask>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentEventsInput {
    pub agent_id: String,
    pub after_sequence: u64,
    #[schemars(range(min = 1, max = 100))]
    pub limit: usize,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicTaskEvent {
    pub sequence: u64,
    pub attempt_sequence: u64,
    pub event_type: String,
    pub redaction_level: String,
    pub pending_request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct AgentEventsOutput {
    pub events: Vec<PublicTaskEvent>,
    pub next_sequence: u64,
    pub has_more: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentWaitInput {
    pub agent_id: String,
    pub after_sequence: u64,
    #[schemars(range(min = 1, max = 5000))]
    pub timeout_ms: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct AgentWaitOutput {
    pub task: PublicTask,
    pub events: Vec<PublicTaskEvent>,
    pub next_sequence: u64,
    pub has_more: bool,
    pub timed_out: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicMessageMode {
    Queue,
    InterruptAndContinue,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentMessageInput {
    pub agent_id: String,
    pub message_id: String,
    pub mode: PublicMessageMode,
    pub content: String,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicMessageDisposition {
    Queued,
    Delivered,
    InterruptedThenDelivered,
    AlreadyDelivered,
    Failed,
}

impl From<MessageDispositionView> for PublicMessageDisposition {
    fn from(value: MessageDispositionView) -> Self {
        match value {
            MessageDispositionView::Queued => Self::Queued,
            MessageDispositionView::Delivered => Self::Delivered,
            MessageDispositionView::InterruptedThenDelivered => Self::InterruptedThenDelivered,
            MessageDispositionView::AlreadyDelivered => Self::AlreadyDelivered,
            MessageDispositionView::Failed => Self::Failed,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct AgentMessageOutput {
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

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicReviewKind {
    PlanReview,
    InitialBounded,
    RepairDelta,
    FinalBounded,
}

impl From<PublicReviewKind> for StructuredReviewKind {
    fn from(value: PublicReviewKind) -> Self {
        match value {
            PublicReviewKind::PlanReview => Self::PlanReview,
            PublicReviewKind::InitialBounded => Self::InitialBounded,
            PublicReviewKind::RepairDelta => Self::RepairDelta,
            PublicReviewKind::FinalBounded => Self::FinalBounded,
        }
    }
}

fn review_contract(value: PublicReviewKind) -> (ReviewKind, RoundKind) {
    match value {
        PublicReviewKind::PlanReview => (ReviewKind::Plan, RoundKind::PlanReview),
        PublicReviewKind::InitialBounded => (ReviewKind::Code, RoundKind::InitialBounded),
        PublicReviewKind::RepairDelta => (ReviewKind::Code, RoundKind::RepairDelta),
        PublicReviewKind::FinalBounded => (ReviewKind::Code, RoundKind::FinalBounded),
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ReviewSpawnInput {
    pub review_kind: PublicReviewKind,
    pub repository: String,
    pub base_ref: String,
    pub head_ref: String,
    pub scope_manifest: Vec<String>,
    pub requirements_path: String,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub plan_path: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub finding_ledger_path: Option<String>,
    pub report_path: String,
    pub feature_id: String,
    pub section_id: String,
    pub ownership_token: String,
    pub idempotency_key: String,
    pub read_only: bool,
    #[serde(default)]
    pub attachments: Vec<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub model: Option<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub budget: Option<PublicBudget>,
}

#[derive(Debug, Clone, Copy, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDisposition {
    Created,
    Existing,
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicReviewProvenance {
    pub review_kind: PublicReviewKind,
    pub manifest_sha256: String,
    pub prepared_sha256: String,
    pub prompt_sha256: String,
    pub base_sha: String,
    pub head_sha: String,
    pub requested_model: Option<String>,
    pub fresh_session_observed: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct ReviewSubmissionOutput {
    pub agent_id: String,
    pub review_id: String,
    pub submission_disposition: ReviewDisposition,
    pub phase: String,
    pub attempt_sequence: u64,
    pub effective_budget: PublicBudget,
    pub counts_as_independent: bool,
    pub provenance: PublicReviewProvenance,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(deny_unknown_fields)]
pub struct ReviewContinueInput {
    pub agent_id: String,
    pub review_id: String,
    pub base_ref: String,
    pub head_ref: String,
    pub frozen_finding_ids: Vec<String>,
    pub idempotency_key: String,
    #[serde(default)]
    pub attachments: Vec<String>,
    #[serde(default, deserialize_with = "optional_non_null")]
    pub budget: Option<PublicBudget>,
}

fn public_review_kind(value: StructuredReviewKind) -> PublicReviewKind {
    match value {
        StructuredReviewKind::PlanReview => PublicReviewKind::PlanReview,
        StructuredReviewKind::InitialBounded => PublicReviewKind::InitialBounded,
        StructuredReviewKind::RepairDelta => PublicReviewKind::RepairDelta,
        StructuredReviewKind::FinalBounded => PublicReviewKind::FinalBounded,
    }
}

fn project_review(value: StructuredReviewProjection) -> ReviewSubmissionOutput {
    ReviewSubmissionOutput {
        agent_id: value.agent_id,
        review_id: value.review_id,
        submission_disposition: match value.submission_disposition {
            ReviewSubmissionDisposition::Created => ReviewDisposition::Created,
            ReviewSubmissionDisposition::Existing => ReviewDisposition::Existing,
        },
        phase: value.phase,
        attempt_sequence: value.attempt_sequence,
        effective_budget: value.effective_budget.into(),
        counts_as_independent: value.counts_as_independent,
        provenance: PublicReviewProvenance {
            review_kind: public_review_kind(value.provenance.review_kind),
            manifest_sha256: value.provenance.manifest_sha256,
            prepared_sha256: value.provenance.prepared_sha256,
            prompt_sha256: value.provenance.prompt_sha256,
            base_sha: value.provenance.base_sha,
            head_sha: value.provenance.head_sha,
            requested_model: value.provenance.requested_model,
            fresh_session_observed: value.provenance.fresh_session_observed,
        },
    }
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
                result.map(Into::into),
                artifacts
                    .into_iter()
                    .map(TryInto::try_into)
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            _ => Err(protocol_error()),
        }
    }
}

fn derived_task_id(repository: &str, idempotency_key: &str) -> String {
    let digest = Sha256::digest(format!("{repository}:{idempotency_key}").as_bytes());
    format!("ztask-{digest:x}")
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
    let task_id = derived_task_id(&input.repository, &input.idempotency_key);
    Ok(GeneralTaskManifest {
        schema: GENERAL_TASK_SCHEMA.into(),
        task_id: task_id.clone(),
        repository,
        base_ref: input.base_ref.clone(),
        profile: input.profile.into(),
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
                .unwrap_or_else(|| GeneralProfile::from(input.profile).default_budget()),
        ),
        validation_commands: BTreeMap::new(),
        retain_partial: input.retain_partial,
        idempotency_key: input.idempotency_key.clone(),
    })
}

fn review_manifest(input: &ReviewSpawnInput) -> Result<ReviewManifest, String> {
    if !input.read_only {
        return Err("validation: structured reviews require read_only=true".into());
    }
    for (field, value, max) in [
        ("repository", input.repository.as_str(), MAX_PATH_BYTES),
        ("base_ref", input.base_ref.as_str(), MAX_ID_BYTES),
        ("head_ref", input.head_ref.as_str(), MAX_ID_BYTES),
        (
            "requirements_path",
            input.requirements_path.as_str(),
            MAX_PATH_BYTES,
        ),
        ("report_path", input.report_path.as_str(), MAX_PATH_BYTES),
        ("feature_id", input.feature_id.as_str(), 256),
        ("section_id", input.section_id.as_str(), 256),
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
    if input.scope_manifest.is_empty() {
        return Err("validation: scope_manifest cannot be empty".into());
    }
    let repository = PathBuf::from(&input.repository);
    if !repository.is_absolute() {
        return Err("validation: repository must be absolute".into());
    }
    let (review_kind, round_kind) = review_contract(input.review_kind);
    let plan_path = input
        .plan_path
        .as_deref()
        .unwrap_or(&input.requirements_path)
        .into();
    let mut context_paths = vec![PathBuf::from(&input.requirements_path)];
    if let Some(path) = input.plan_path.as_ref() {
        context_paths.push(PathBuf::from(path));
    }
    if let Some(path) = input.finding_ledger_path.as_ref() {
        context_paths.push(PathBuf::from(path));
    }
    context_paths.extend(input.attachments.iter().map(PathBuf::from));
    context_paths.sort();
    context_paths.dedup();
    Ok(ReviewManifest {
        schema: "sectioned-zcode-review/v1".into(),
        review_kind,
        feature_id: input.feature_id.clone(),
        section_id: input.section_id.clone(),
        round_kind,
        repository: repository.clone(),
        base_ref: input.base_ref.clone(),
        head_ref: input.head_ref.clone(),
        plan_path,
        context_paths,
        scope_paths: input.scope_manifest.iter().map(PathBuf::from).collect(),
        forbidden_input_globs: Vec::new(),
        validation_commands: BTreeMap::new(),
        report_target: PathBuf::from(&input.report_path),
        scratch_root: repository
            .join(".agent-work")
            .join("scratch")
            .join("reviews"),
        model: input.model.clone(),
        fresh_session: true,
        network_policy: NetworkPolicy::Deny,
        scratch_policy: ScratchPolicy::Isolated,
        idempotency_key: input.idempotency_key.clone(),
    })
}

fn project_event_page(page: TaskEventPage) -> AgentEventsOutput {
    AgentEventsOutput {
        events: page
            .events
            .into_iter()
            .map(|event| {
                let pending_request_id =
                    serde_json::from_str::<serde_json::Value>(&event.payload_json)
                        .ok()
                        .and_then(|value| {
                            value
                                .get("request_id")
                                .and_then(|id| id.as_str())
                                .map(str::to_owned)
                        });
                let event_type = if pending_request_id.is_some() {
                    "pending_request"
                } else if event.event_type.contains("result") {
                    "result"
                } else if event.event_type.contains("attempt") {
                    "attempt"
                } else {
                    "lifecycle"
                };
                PublicTaskEvent {
                    sequence: event.sequence,
                    attempt_sequence: event.attempt_sequence,
                    event_type: event_type.into(),
                    redaction_level: event.redaction_level,
                    pending_request_id,
                }
            })
            .collect(),
        next_sequence: page.next_sequence,
        has_more: page.has_more,
    }
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
        name = "zcode_system_ensure_ready",
        description = "Wait boundedly for configured runtime readiness",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn system_ensure_ready(
        &self,
        Parameters(input): Parameters<EnsureReadyInput>,
    ) -> Result<Json<EnsureReadyOutput>, String> {
        if !(1..=5000).contains(&input.timeout_ms) {
            return Err("validation: timeout_ms must be between 1 and 5000".into());
        }
        match self.rpc(RpcMethod::SystemEnsureReady {
            timeout_ms: input.timeout_ms,
        })? {
            RpcSuccess::SystemReadiness {
                ready,
                status,
                reason_code,
            } => Ok(Json(EnsureReadyOutput {
                ready,
                status: status.into(),
                reason_code,
            })),
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
        let expected_id = derived_task_id(&input.repository, &input.idempotency_key);
        let existed = self.status(&expected_id).is_ok();
        let manifest = general_manifest(&input)?;
        let task = match self.rpc(RpcMethod::SubmitGeneral {
            input: GeneralSubmitInput {
                manifest,
                feature_id: input.feature_id,
                ownership_token: input.ownership_token,
            },
        })? {
            RpcSuccess::GeneralSubmitted { task } => task,
            _ => return Err(protocol_error()),
        };
        let capabilities = match self.rpc(RpcMethod::SystemStatus)? {
            RpcSuccess::SystemStatus { status } => status.capabilities.into(),
            _ => return Err(protocol_error()),
        };
        Ok(Json(AgentSpawnOutput {
            agent_id: task.agent_id,
            submission_disposition: if existed {
                SubmissionDisposition::Existing
            } else {
                SubmissionDisposition::Created
            },
            phase: task.phase,
            attempt_sequence: task.attempt_sequence,
            effective_budget: task.effective_budget.into(),
            capabilities,
        }))
    }

    #[tool(
        name = "zcode_agent_get",
        description = "Read a task, verified result metadata, and typed pending requests",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn agent_get(
        &self,
        Parameters(input): Parameters<AgentInput>,
    ) -> Result<Json<AgentGetOutput>, String> {
        let (task, result, artifacts) = self.result(input.agent_id.clone(), None)?;
        let pending_requests = self.pending(&input.agent_id)?;
        Ok(Json(AgentGetOutput {
            task,
            result,
            artifacts,
            pending_requests,
        }))
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
            limit: input.limit,
        }))? {
            RpcSuccess::TaskListed { tasks } => Ok(Json(AgentListOutput {
                tasks: tasks.into_iter().map(Into::into).collect(),
                next_cursor: None,
            })),
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_agent_events",
        description = "Read a redacted monotonic task event page",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn agent_events(
        &self,
        Parameters(input): Parameters<AgentEventsInput>,
    ) -> Result<Json<AgentEventsOutput>, String> {
        if !(1..=100).contains(&input.limit) {
            return Err("validation: limit must be between 1 and 100".into());
        }
        match self.rpc(RpcMethod::TaskEvents(TaskEventQuery {
            agent_id: input.agent_id,
            after: input.after_sequence,
            limit: input.limit,
        }))? {
            RpcSuccess::TaskEvents { page } => Ok(Json(project_event_page(page))),
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_agent_wait",
        description = "Wait boundedly for a redacted task event or terminal state",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn agent_wait(
        &self,
        Parameters(input): Parameters<AgentWaitInput>,
    ) -> Result<Json<AgentWaitOutput>, String> {
        if !(1..=5000).contains(&input.timeout_ms) {
            return Err("validation: timeout_ms must be between 1 and 5000".into());
        }
        match self.rpc(RpcMethod::TaskWait(TaskWaitQuery {
            agent_id: input.agent_id,
            after: input.after_sequence,
            timeout_ms: input.timeout_ms,
        }))? {
            RpcSuccess::TaskWait {
                task,
                page,
                timed_out,
            } => {
                let projected = project_event_page(page);
                Ok(Json(AgentWaitOutput {
                    task: task.into(),
                    events: projected.events,
                    next_sequence: projected.next_sequence,
                    has_more: projected.has_more,
                    timed_out,
                }))
            }
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_agent_message",
        description = "Queue an idempotent bounded message for a running task",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn agent_message(
        &self,
        Parameters(input): Parameters<AgentMessageInput>,
    ) -> Result<Json<AgentMessageOutput>, String> {
        validate_text(&input.content, "content", MAX_MESSAGE_BYTES)?;
        let mode = match input.mode {
            PublicMessageMode::Queue => "queue",
            PublicMessageMode::InterruptAndContinue => "interrupt_and_continue",
        };
        match self.rpc(RpcMethod::TaskMessage(MessageInput {
            agent_id: input.agent_id.clone(),
            message_id: input.message_id,
            mode: mode.into(),
            content: input.content,
        }))? {
            RpcSuccess::Message { disposition } => Ok(Json(AgentMessageOutput {
                disposition: disposition.into(),
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
            match self.rpc(RpcMethod::TaskArtifact(TaskArtifactQuery {
                agent_id: input.agent_id,
                attempt_sequence: input.attempt_sequence,
                artifact_id,
                offset_bytes,
                limit_bytes,
            }))? {
                RpcSuccess::TaskArtifact { chunk } => Some(PublicArtifactChunk {
                    artifact_id: chunk.artifact_id,
                    offset_bytes: chunk.offset_bytes,
                    returned_bytes: chunk.bytes.len(),
                    eof: chunk.eof,
                    sha256: chunk.sha256,
                    size_bytes: chunk.size_bytes,
                    bytes_base64: BASE64.encode(chunk.bytes),
                }),
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

    #[tool(
        name = "zcode_review_spawn",
        description = "Submit a strict bounded structured review",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn review_spawn(
        &self,
        Parameters(input): Parameters<ReviewSpawnInput>,
    ) -> Result<Json<ReviewSubmissionOutput>, String> {
        let manifest = review_manifest(&input)?;
        match self.rpc(RpcMethod::SubmitStructuredReview {
            input: StructuredReviewSubmission {
                review_kind: input.review_kind.into(),
                manifest,
                ownership_token: input.ownership_token,
                read_only: input.read_only,
                budget: input.budget.map(Into::into),
            },
        })? {
            RpcSuccess::StructuredReviewSubmitted { review } => Ok(Json(project_review(review))),
            _ => Err(protocol_error()),
        }
    }

    #[tool(
        name = "zcode_review_continue",
        description = "Continue an accepted structured review using daemon-owned immutable context",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn review_continue(
        &self,
        Parameters(input): Parameters<ReviewContinueInput>,
    ) -> Result<Json<ReviewSubmissionOutput>, String> {
        for (field, value, max) in [
            ("agent_id", input.agent_id.as_str(), MAX_ID_BYTES),
            ("review_id", input.review_id.as_str(), MAX_ID_BYTES),
            ("base_ref", input.base_ref.as_str(), MAX_ID_BYTES),
            ("head_ref", input.head_ref.as_str(), MAX_ID_BYTES),
            (
                "idempotency_key",
                input.idempotency_key.as_str(),
                MAX_ID_BYTES,
            ),
        ] {
            validate_text(value, field, max)?;
        }
        match self.rpc(RpcMethod::ContinueStructuredReviewMinimal {
            input: MinimalStructuredReviewContinuation {
                agent_id: input.agent_id,
                review_id: input.review_id,
                base_ref: input.base_ref,
                head_ref: input.head_ref,
                frozen_finding_ids: input.frozen_finding_ids,
                idempotency_key: input.idempotency_key,
                attachments: input.attachments.into_iter().map(PathBuf::from).collect(),
                budget: input.budget.map(Into::into),
            },
        })? {
            RpcSuccess::StructuredReviewSubmitted { review } => Ok(Json(project_review(review))),
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
mod tests {
    use super::*;

    #[test]
    fn v2_inventory_schemas_and_annotations_are_exact() {
        let facade = SubagentMcp::new(PathBuf::from("/tmp/unused"), Duration::from_secs(1));
        let tools = facade.tool_router.list_all();
        let names = tools
            .iter()
            .map(|tool| tool.name.as_ref())
            .collect::<Vec<_>>();
        assert_eq!(names, V2_PUBLIC_TOOLS);
        assert!(tools.iter().all(|tool| {
            tool.output_schema.is_some()
                && tool.annotations.as_ref().and_then(|a| a.open_world_hint) == Some(false)
                && tool.annotations.as_ref().and_then(|a| a.idempotent_hint) == Some(true)
        }));
        for name in [
            "zcode_system_status",
            "zcode_system_ensure_ready",
            "zcode_agent_get",
            "zcode_agent_list",
            "zcode_agent_events",
            "zcode_agent_wait",
            "zcode_agent_result",
        ] {
            let annotations = tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap()
                .annotations
                .as_ref()
                .unwrap();
            assert_eq!(annotations.read_only_hint, Some(true), "{name}");
            assert_eq!(annotations.destructive_hint, Some(false), "{name}");
        }
        for name in ["zcode_agent_cancel", "zcode_agent_close"] {
            assert_eq!(
                tools
                    .iter()
                    .find(|tool| tool.name == name)
                    .unwrap()
                    .annotations
                    .as_ref()
                    .and_then(|a| a.destructive_hint),
                Some(true),
                "{name}"
            );
        }
        let schemas = serde_json::to_string(&tools).unwrap();
        for forbidden in [
            "workspace_path",
            "runtime_agent_id",
            "owner_epoch",
            "correlation_id",
            "initial_prompt",
            "prompt_path",
            "prepared_path",
            "process_group_id",
            "environment",
            "credentials",
            "reasoning",
        ] {
            assert!(
                !schemas.contains(forbidden),
                "public schema leaked {forbidden}"
            );
        }
    }

    #[test]
    fn strict_optional_fields_reject_explicit_null() {
        let error = serde_json::from_value::<AgentResultInput>(serde_json::json!({
            "agent_id": "a",
            "attempt_sequence": null
        }))
        .unwrap_err();
        assert!(error.to_string().contains("invalid type"));
    }

    #[test]
    fn event_projection_redacts_private_payload() {
        let output = project_event_page(TaskEventPage {
            events: vec![zcode_reviewd::rpc::TaskEventView {
                sequence: 3,
                source_sequence: 99,
                attempt_sequence: 2,
                event_type: "runtime_request".into(),
                payload_json: serde_json::json!({
                    "request_id": "request-public",
                    "runtime_agent_id": "private-runtime",
                    "path": "/secret/path",
                    "prompt": "secret"
                })
                .to_string(),
                redaction_level: "bounded".into(),
            }],
            next_sequence: 3,
            has_more: false,
        });
        assert_eq!(output.events[0].event_type, "pending_request");
        assert_eq!(
            output.events[0].pending_request_id.as_deref(),
            Some("request-public")
        );
        let public = serde_json::to_string(&output).unwrap();
        assert!(!public.contains("private-runtime"));
        assert!(!public.contains("/secret/path"));
        assert!(!public.contains("secret"));
    }

    #[test]
    fn public_general_input_builds_a_preparable_manifest() {
        use review_preparation::GeneralTaskPreparer;
        use std::process::Command;

        let directory = tempfile::tempdir().unwrap();
        let repository = directory.path().join("repository");
        std::fs::create_dir_all(repository.join("src")).unwrap();
        std::fs::write(repository.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
        for arguments in [
            vec!["init"],
            vec!["config", "user.name", "S05 Test"],
            vec!["config", "user.email", "s05@example.invalid"],
            vec!["add", "src/lib.rs"],
            vec!["commit", "-m", "fixture"],
        ] {
            assert!(Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(arguments)
                .status()
                .unwrap()
                .success());
        }
        let head = String::from_utf8(
            Command::new("git")
                .arg("-C")
                .arg(&repository)
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        let repository = std::fs::canonicalize(repository).unwrap();
        let input = AgentSpawnInput {
            repository: repository.to_string_lossy().into_owned(),
            base_ref: head.trim().into(),
            profile: PublicProfile::AnalysisReadonly,
            prompt: "inspect".into(),
            feature_id: "feature".into(),
            ownership_token: "owner".into(),
            idempotency_key: "s05-v2-general-process".into(),
            write_manifest: Vec::new(),
            repo_context: vec!["src/lib.rs".into()],
            attachments: Vec::new(),
            budget: None,
            retain_partial: false,
        };
        let manifest = general_manifest(&input).unwrap();
        let prepared = GeneralTaskPreparer::new(Vec::new())
            .unwrap()
            .prepare(&manifest)
            .unwrap();
        assert_eq!(
            prepared.task_id,
            derived_task_id(&input.repository, &input.idempotency_key)
        );
    }
}
