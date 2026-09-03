use crate::{
    orchestration::{
        MinimalStructuredReviewContinuation, OrchestrationError, ReviewJobOrchestrator,
        StructuredReviewContinuation, StructuredReviewProjection, StructuredReviewSubmission,
    },
    GeneralCheckResult, MessageDisposition, PassiveActivitySnapshot, PassiveActivityWindow,
    PassiveToolKind, ResponseDisposition, RuntimePreflightResult, Scheduler, SchedulerError,
};
use review_ledger::{
    ArtifactIntegrity, ToolResult, VerifiedArtifact, MAX_TOOL_ID_BYTES, MAX_TOOL_TEXT_CHARS,
};
use review_preparation::{canonical_general_repository, ReviewManifest};
use review_preparation::{
    BudgetLimits, GeneralCompletionSubmission, GeneralProfile, GeneralTaskManifest,
    PreparedGeneralTask, PreparedLaunchSpec,
};
use review_store::{
    DeadlineRead, EffectiveBudget, Job, JobListScope, JobState, NewJob, PendingRequestState,
    ReviewProgressState, Store, StoreError, StoredArtifact, StoredEvent, StoredPendingRequest,
    StoredTaskResult, TaskKind, TaskOutcome, TaskPageFilter, TaskPhase, TaskQueryScope, TaskRecord,
    TaskSubmissionDisposition, TurnState, WaitSnapshot,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::Arc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const RPC_VERSION: u16 = 10;
pub const MAX_FRAME_BYTES: usize = 128 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
pub const MAX_PAGE_EVENTS: usize = 100;
pub const MAX_LIST_JOBS: usize = 100;
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 16 * 1024;
pub const MAX_PAGE_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_PREVIEW_BYTES: usize = 8 * 1024;
pub const MAX_PENDING_REQUESTS: usize = 100;
pub const MAX_ARTIFACT_CHUNK_BYTES: usize = 8 * 1024;
const MAX_PRIVATE_EVENTS_FOR_PUBLIC_PROJECTION: usize = 64 * 1024;
pub const MAX_WAIT: Duration = Duration::from_secs(5);
pub const RPC_TRANSPORT_SUPPORTED: bool = cfg!(unix);

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{RpcClient, RpcServer, ServerOptions};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcRequest {
    pub version: u16,
    pub request_id: String,
    #[serde(flatten)]
    pub method: RpcMethod,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RpcMethod {
    SystemStatus,
    SystemEnsureReady {
        timeout_ms: u64,
    },
    SubmitGeneral {
        input: GeneralSubmitInput,
    },
    GeneralComplete(GeneralCompleteInput),
    GeneralRunCheck(GeneralRunCheckInput),
    TaskStatus {
        agent_id: String,
    },
    TaskList(TaskListQuery),
    TaskPending {
        agent_id: String,
    },
    TaskEvents(TaskEventQuery),
    TaskWait(TaskWaitQuery),
    TaskPoll(TaskPollQuery),
    TaskMessage(MessageInput),
    TaskRespond(RespondInput),
    TaskCancel {
        agent_id: String,
    },
    TaskResult {
        agent_id: String,
        #[serde(default)]
        attempt_sequence: Option<u64>,
    },
    TaskArtifact(TaskArtifactQuery),
    TaskClose {
        agent_id: String,
    },
    TaskReap {
        agent_id: String,
    },
    SpawnReview {
        manifest: ReviewManifest,
    },
    SubmitReview {
        manifest: ReviewManifest,
    },
    SubmitStructuredReview {
        input: StructuredReviewSubmission,
    },
    ContinueStructuredReview {
        input: StructuredReviewContinuation,
    },
    ContinueStructuredReviewMinimal {
        input: MinimalStructuredReviewContinuation,
    },
    Enqueue {
        job: NewJobInput,
    },
    Start,
    Status {
        agent_id: String,
    },
    Pending {
        agent_id: String,
    },
    Events(EventQuery),
    Wait(WaitQuery),
    Message(MessageInput),
    Respond(RespondInput),
    Stop {
        agent_id: String,
    },
    Result(ResultQuery),
    List {
        scope: JobListScopeView,
        limit: usize,
    },
    Close {
        agent_id: String,
    },
    Reap {
        agent_id: String,
    },
    TaskReviewTool(ReviewToolInput),
    ReviewTool(ReviewToolInput),
}

impl RpcMethod {
    fn is_known(name: &str) -> bool {
        matches!(
            name,
            "system_status"
                | "system_ensure_ready"
                | "submit_general"
                | "general_complete"
                | "general_run_check"
                | "task_status"
                | "task_list"
                | "task_pending"
                | "task_events"
                | "task_wait"
                | "task_poll"
                | "task_message"
                | "task_respond"
                | "task_cancel"
                | "task_result"
                | "task_artifact"
                | "task_close"
                | "task_reap"
                | "spawn_review"
                | "submit_review"
                | "submit_structured_review"
                | "continue_structured_review"
                | "continue_structured_review_minimal"
                | "enqueue"
                | "start"
                | "status"
                | "pending"
                | "events"
                | "wait"
                | "message"
                | "respond"
                | "stop"
                | "result"
                | "list"
                | "close"
                | "reap"
                | "task_review_tool"
                | "review_tool"
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskListQuery {
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub feature_id: Option<String>,
    #[serde(default)]
    pub ownership_token: Option<String>,
    #[serde(default)]
    pub phase: Option<TaskPhaseFilter>,
    #[serde(default)]
    pub outcome: Option<TaskOutcome>,
    #[serde(default)]
    pub profile: Option<GeneralProfile>,
    #[serde(default)]
    pub cursor: Option<String>,
    pub limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskPhaseFilter {
    Queued,
    Preparing,
    Running,
    WaitingInput,
    Cancelling,
    Terminal,
}

impl From<TaskPhaseFilter> for TaskPhase {
    fn from(value: TaskPhaseFilter) -> Self {
        match value {
            TaskPhaseFilter::Queued => Self::Queued,
            TaskPhaseFilter::Preparing => Self::Preparing,
            TaskPhaseFilter::Running => Self::Running,
            TaskPhaseFilter::WaitingInput => Self::WaitingInput,
            TaskPhaseFilter::Cancelling => Self::Cancelling,
            TaskPhaseFilter::Terminal => Self::Terminal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskArtifactQuery {
    pub agent_id: String,
    #[serde(default)]
    pub attempt_sequence: Option<u64>,
    pub artifact_id: String,
    pub offset_bytes: u64,
    pub limit_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralSubmitInput {
    pub manifest: GeneralTaskManifest,
    pub feature_id: String,
    pub ownership_token: String,
    #[serde(default)]
    pub allowed_command_ids: Vec<String>,
    #[serde(default)]
    pub required_command_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralCompleteInput {
    pub agent_id: String,
    pub submission: GeneralCompletionSubmission,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralRunCheckInput {
    pub agent_id: String,
    pub command_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskEventQuery {
    pub agent_id: String,
    #[serde(default)]
    pub after: u64,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskWaitQuery {
    pub agent_id: String,
    #[serde(default)]
    pub after: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskPollQuery {
    pub agent_id: String,
    #[serde(default)]
    pub after_revision: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewJobInput {
    pub agent_id: String,
    pub workspace_path: String,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub parent_agent_id: Option<String>,
    #[serde(default)]
    pub review_kind: Option<String>,
    #[serde(default)]
    pub feature_id: Option<String>,
    #[serde(default)]
    pub section_id: Option<String>,
    #[serde(default)]
    pub round_kind: Option<String>,
    #[serde(default)]
    pub report_path: Option<String>,
    #[serde(default)]
    pub runtime_hash: Option<String>,
    #[serde(default = "default_initial_prompt")]
    pub initial_prompt: String,
}

fn default_initial_prompt() -> String {
    "Begin review.".into()
}

impl From<NewJobInput> for NewJob {
    fn from(value: NewJobInput) -> Self {
        Self {
            agent_id: value.agent_id,
            idempotency_key: value.idempotency_key,
            parent_agent_id: value.parent_agent_id,
            review_kind: value.review_kind,
            feature_id: value.feature_id,
            section_id: value.section_id,
            round_kind: value.round_kind,
            workspace_path: value.workspace_path,
            report_path: value.report_path,
            runtime_hash: value.runtime_hash,
            prepared_launch_json: None,
            prepared_launch_sha256: None,
            initial_prompt: value.initial_prompt,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventQuery {
    pub agent_id: String,
    #[serde(default)]
    pub runtime_agent_id: Option<String>,
    #[serde(default)]
    pub after: u64,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WaitQuery {
    pub agent_id: String,
    #[serde(default)]
    pub runtime_agent_id: Option<String>,
    #[serde(default)]
    pub after: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageInput {
    pub agent_id: String,
    pub message_id: String,
    pub mode: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RespondInput {
    pub agent_id: String,
    pub request_id: String,
    pub decision: ResponseDecision,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobListScopeView {
    Active,
    Recent,
    All,
}

impl From<JobListScopeView> for JobListScope {
    fn from(value: JobListScopeView) -> Self {
        match value {
            JobListScopeView::Active => Self::Active,
            JobListScopeView::Recent => Self::Recent,
            JobListScopeView::All => Self::All,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDecision {
    Allow,
    Deny,
    Answer,
}

impl ResponseDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Answer => "answer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResultQuery {
    pub agent_id: String,
    #[serde(default)]
    pub preview_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewToolInput {
    pub agent_id: String,
    pub tool: String,
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcResponse {
    pub version: u16,
    pub request_id: Option<String>,
    #[serde(flatten)]
    pub outcome: RpcOutcome,
}

impl RpcResponse {
    pub fn success(request_id: String, result: RpcSuccess) -> Self {
        Self {
            version: RPC_VERSION,
            request_id: Some(request_id),
            outcome: RpcOutcome::Success {
                result: Box::new(result),
            },
        }
    }

    pub fn error(request_id: Option<String>, error: RpcError) -> Self {
        Self {
            version: RPC_VERSION,
            request_id,
            outcome: RpcOutcome::Error { error },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum RpcOutcome {
    Success { result: Box<RpcSuccess> },
    Error { error: RpcError },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RpcSuccess {
    SystemStatus {
        status: SystemStatusView,
    },
    SystemReadiness {
        ready: bool,
        status: SystemStatusView,
        probe_result: ReadinessResultView,
        reason_code: Option<String>,
    },
    GeneralSubmitted {
        task: TaskView,
        disposition: SubmissionDispositionView,
    },
    GeneralCompletionAccepted {
        accepted: bool,
    },
    GeneralCheckCompleted {
        result: GeneralCheckResultView,
    },
    TaskStatus {
        task: TaskView,
    },
    TaskListed {
        tasks: Vec<TaskView>,
        next_cursor: Option<String>,
    },
    TaskEvents {
        page: TaskEventPage,
    },
    TaskWait {
        task: TaskView,
        page: TaskEventPage,
        timed_out: bool,
    },
    TaskPoll {
        task: TaskView,
        revision: u64,
        next_revision: u64,
        pending_requests: Vec<PendingRequestView>,
        result_available: bool,
        activity: TaskActivityView,
        timed_out: bool,
    },
    TaskResult {
        task: TaskView,
        result: Option<TaskResultView>,
        artifacts: Vec<TaskArtifactMetadataView>,
    },
    TaskArtifact {
        chunk: TaskArtifactChunkView,
    },
    ReviewSpawned {
        job: JobView,
        prompt_sha256: String,
        resumed_existing: bool,
        counts_as_independent: bool,
        capabilities: ReviewCapabilitiesView,
    },
    ReviewSubmitted {
        job: JobView,
        prompt_sha256: String,
        resumed_existing: bool,
        capabilities: ReviewCapabilitiesView,
    },
    StructuredReviewSubmitted {
        review: StructuredReviewProjection,
    },
    Enqueued {
        job: JobView,
    },
    Started {
        agent_ids: Vec<String>,
    },
    Status {
        job: JobView,
    },
    Pending {
        requests: Vec<PendingRequestView>,
    },
    Events {
        page: EventPage,
    },
    Wait {
        job: JobView,
        page: EventPage,
        timed_out: bool,
    },
    Message {
        disposition: MessageDispositionView,
    },
    Respond {
        outcome: ResponseOutcomeView,
    },
    Stopped {
        state: JobStateView,
    },
    Result {
        job: JobView,
        artifact: Option<ArtifactView>,
    },
    Listed {
        jobs: Vec<JobView>,
    },
    Closed {
        state: JobStateView,
    },
    Reaped {
        state: JobStateView,
        resources_reaped: bool,
    },
    ReviewTool {
        result: ToolResult,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ComponentStateView {
    Ready,
    Degraded,
    Unavailable,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReadinessResultView {
    Ready,
    ConfigInvalid,
    ZcodeStartFailed,
    RuntimeProtocolFailed,
    ModelAuthFailed,
    RuntimeFailed,
    NotObservedWithinTimeout,
    CleanupFailed,
}

impl ReadinessResultView {
    fn reason_code(self) -> Option<String> {
        (!matches!(self, Self::Ready)).then(|| {
            match self {
                Self::Ready => unreachable!(),
                Self::ConfigInvalid => "CONFIG_INVALID",
                Self::ZcodeStartFailed => "ZCODE_START_FAILED",
                Self::RuntimeProtocolFailed => "RUNTIME_PROTOCOL_FAILED",
                Self::ModelAuthFailed => "MODEL_AUTH_FAILED",
                Self::RuntimeFailed => "RUNTIME_FAILED",
                Self::NotObservedWithinTimeout => "NOT_OBSERVED_WITHIN_TIMEOUT",
                Self::CleanupFailed => "CLEANUP_FAILED",
            }
            .into()
        })
    }
}

impl From<RuntimePreflightResult> for ReadinessResultView {
    fn from(value: RuntimePreflightResult) -> Self {
        match value {
            RuntimePreflightResult::Ready => Self::Ready,
            RuntimePreflightResult::ConfigInvalid => Self::ConfigInvalid,
            RuntimePreflightResult::ZcodeStartFailed => Self::ZcodeStartFailed,
            RuntimePreflightResult::RuntimeProtocolFailed => Self::RuntimeProtocolFailed,
            RuntimePreflightResult::ModelAuthFailed => Self::ModelAuthFailed,
            RuntimePreflightResult::RuntimeFailed => Self::RuntimeFailed,
            RuntimePreflightResult::NotObservedWithinTimeout => Self::NotObservedWithinTimeout,
            RuntimePreflightResult::CleanupFailed => Self::CleanupFailed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityMaturityView {
    BetaReady,
    ExperimentalUnverifiedRuntime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionDispositionView {
    Created,
    Existing,
}

impl From<TaskSubmissionDisposition> for SubmissionDispositionView {
    fn from(value: TaskSubmissionDisposition) -> Self {
        match value {
            TaskSubmissionDisposition::Created => Self::Created,
            TaskSubmissionDisposition::Existing => Self::Existing,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemStatusView {
    pub api_surface: String,
    pub protocol_version: u16,
    pub service_generation: String,
    pub components: BTreeMap<String, ComponentStateView>,
    pub capabilities: AgentCapabilitiesView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentCapabilitiesView {
    pub task_kinds: Vec<String>,
    pub profiles: Vec<String>,
    pub profile_defaults: BTreeMap<String, BudgetLimits>,
    pub hard_budget_caps: BudgetLimits,
    pub max_rpc_frame_bytes: usize,
    pub max_events: usize,
    pub max_wait_ms: u64,
    pub named_checks: bool,
    pub maturity: BTreeMap<String, CapabilityMaturityView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneralCheckResultView {
    pub command_id: String,
    pub succeeded: bool,
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
}

impl From<GeneralCheckResult> for GeneralCheckResultView {
    fn from(value: GeneralCheckResult) -> Self {
        Self {
            command_id: value.command_id,
            succeeded: value.succeeded,
            status_code: value.output.status_code,
            stdout: value.output.stdout,
            stderr: value.output.stderr,
            stdout_truncated: value.output.stdout_truncated,
            stderr_truncated: value.output.stderr_truncated,
            timed_out: value.output.timed_out,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskView {
    pub agent_id: String,
    pub review_id: Option<String>,
    pub task_kind: String,
    pub access_mode: String,
    pub phase: String,
    pub attempt_sequence: u64,
    pub effective_budget: EffectiveBudget,
    pub independent_evidence: bool,
    pub fresh_session_observed: bool,
    pub stop_requested: bool,
    pub close_requested: bool,
    pub closed: bool,
    pub reaped: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskActivityStateView {
    Queued,
    Preparing,
    Active,
    WaitingInput,
    Cancelling,
    Idle,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryStatusView {
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivityToolKindView {
    Read,
    Bash,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveToolView {
    pub tool_call_id: String,
    pub kind: ActivityToolKindView,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityWindowView {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskActivityView {
    pub state: TaskActivityStateView,
    pub last_runtime_event_at: Option<u64>,
    pub last_activity_age_ms: Option<u64>,
    pub model_request_active: bool,
    pub model_request_age_ms: Option<u64>,
    pub model_last_delta_age_ms: Option<u64>,
    pub latest_text_tail: String,
    pub latest_text_updated_at: Option<u64>,
    pub latest_text_truncated: bool,
    pub active_tools: Vec<ActiveToolView>,
    pub window_60s: ActivityWindowView,
    pub telemetry_status: TelemetryStatusView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskResultView {
    pub outcome: TaskOutcome,
    pub summary: String,
    pub partial: bool,
    pub retained: bool,
    pub base_commit: Option<String>,
    pub head_commit: Option<String>,
    pub changed_files: Vec<String>,
    pub diff_stat: Option<String>,
    pub checks: Vec<String>,
    pub residual_gaps: Vec<String>,
    pub artifacts: Vec<review_store::ResultArtifact>,
    pub result_sha256: String,
    pub review_evidence: Option<TaskReviewEvidenceView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskReviewEvidenceView {
    pub final_signal: String,
    pub finalized: bool,
    pub report_revision: u64,
    pub finalization_revision: u64,
    pub artifact: TaskArtifactMetadataView,
    pub counts: TaskReviewEvidenceCountsView,
    pub independence: TaskReviewIndependenceView,
    pub validation_provenance: TaskValidationProvenanceView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskReviewEvidenceCountsView {
    pub checkpoints: u64,
    pub findings: u64,
    pub open_findings: u64,
    pub validations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskReviewIndependenceView {
    pub independent_evidence: bool,
    pub fresh_session_observed: bool,
    pub counts_as_independent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskValidationProvenanceView {
    pub daemon_verification: TaskDaemonVerificationView,
    pub model_attestation: TaskModelAttestationView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDaemonVerificationView {
    pub source_integrity_verified: bool,
    pub finalized_report_verified: bool,
    pub artifact_digest_verified: bool,
    pub validation_records_structurally_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskModelAttestationView {
    pub present: bool,
    pub validation_record_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskArtifactMetadataView {
    pub artifact_id: String,
    pub kind: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskArtifactChunkView {
    pub artifact_id: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub offset_bytes: u64,
    pub bytes: Vec<u8>,
    pub eof: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskEventView {
    pub sequence: u64,
    pub source_sequence: u64,
    pub attempt_sequence: u64,
    pub event_type: String,
    pub payload_json: String,
    pub redaction_level: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<TaskReviewProgressStage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<BTreeMap<String, u64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_progress_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_idle_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nudge_sent: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskReviewProgressStage {
    Scope,
    Inspection,
    Validation,
    Synthesis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskEventPage {
    pub events: Vec<TaskEventView>,
    pub next_sequence: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RpcErrorCode {
    Malformed,
    Oversized,
    UnsupportedVersion,
    UnknownMethod,
    Validation,
    NotFound,
    Conflict,
    Persistence,
    Timeout,
    RuntimeLost,
    ResultInvalid,
    Unavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: RpcErrorCode,
    pub message: String,
}

impl RpcError {
    pub fn new(code: RpcErrorCode, message: impl Into<String>) -> Self {
        let mut message = message.into();
        message.truncate(512);
        Self { code, message }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobStateView {
    Queued,
    Starting,
    Running,
    Stopping,
    Completed,
    Cancelled,
    Failed,
    FailedRuntimeLost,
    Orphaned,
    Closed,
}

impl From<JobState> for JobStateView {
    fn from(value: JobState) -> Self {
        match value {
            JobState::Queued => Self::Queued,
            JobState::Starting => Self::Starting,
            JobState::Running => Self::Running,
            JobState::Stopping => Self::Stopping,
            JobState::Completed => Self::Completed,
            JobState::Cancelled => Self::Cancelled,
            JobState::Failed => Self::Failed,
            JobState::FailedRuntimeLost => Self::FailedRuntimeLost,
            JobState::Orphaned => Self::Orphaned,
            JobState::Closed => Self::Closed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDispositionView {
    Queued,
    Delivered,
    InterruptedThenDelivered,
    AlreadyDelivered,
    Failed,
}

impl From<MessageDisposition> for MessageDispositionView {
    fn from(value: MessageDisposition) -> Self {
        match value {
            MessageDisposition::Queued => Self::Queued,
            MessageDisposition::Delivered => Self::Delivered,
            MessageDisposition::InterruptedThenDelivered => Self::InterruptedThenDelivered,
            MessageDisposition::AlreadyDelivered => Self::AlreadyDelivered,
            MessageDisposition::Failed => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseDispositionView {
    Responded,
    AlreadyResponded,
    InFlight,
}

impl From<ResponseDisposition> for ResponseDispositionView {
    fn from(value: ResponseDisposition) -> Self {
        match value {
            ResponseDisposition::Responded => Self::Responded,
            ResponseDisposition::AlreadyResponded => Self::AlreadyResponded,
            ResponseDisposition::InFlight => Self::InFlight,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResponseOutcomeView {
    pub disposition: ResponseDispositionView,
    pub requested_decision: String,
    pub effective_decision: String,
    pub policy_overrode: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_reason_code: Option<String>,
}

impl From<crate::ResponseOutcome> for ResponseOutcomeView {
    fn from(value: crate::ResponseOutcome) -> Self {
        Self {
            disposition: value.disposition.into(),
            requested_decision: value.requested_decision,
            effective_decision: value.effective_decision,
            policy_overrode: value.policy_overrode,
            policy_reason_code: value.policy_reason_code,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingRequestStateView {
    Pending,
    Sending,
    Responded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingRequestView {
    pub request_id: String,
    pub kind: String,
    pub state: PendingRequestStateView,
    pub respondable: bool,
    pub tool_name: Option<String>,
    pub operation: String,
    pub summary: String,
    pub policy_preview: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TurnStateView {
    Idle,
    Active,
    Failed,
}

impl From<TurnState> for TurnStateView {
    fn from(value: TurnState) -> Self {
        match value {
            TurnState::Idle => Self::Idle,
            TurnState::Active => Self::Active,
            TurnState::Failed => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobView {
    pub agent_id: String,
    pub idempotency_key: Option<String>,
    pub state: JobStateView,
    pub workspace_path: String,
    pub owner_epoch: u64,
    pub close_requested: bool,
    pub stop_requested: bool,
    pub last_event_seq: u64,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
    pub runtime_agent_id: Option<String>,
    pub zcode_session_id: Option<String>,
    pub turn_state: TurnStateView,
    pub closed: bool,
    pub reaped: bool,
    pub live_steer: bool,
    pub review_kind: Option<String>,
    pub feature_id: Option<String>,
    pub section_id: Option<String>,
    pub round_kind: Option<String>,
    pub prompt_sha256: String,
    pub provenance: Option<ReviewProvenanceView>,
    pub capabilities: ReviewCapabilitiesView,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewCapabilitiesView {
    pub private_review_orchestration: bool,
    pub public_mcp: bool,
    pub fresh_session: bool,
    pub independent_session_observed: bool,
    pub resume_counts_as_independent: bool,
    pub live_steer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewProvenanceView {
    pub manifest_sha256: String,
    pub prepared_sha256: String,
    pub base_sha: String,
    pub head_sha: String,
    pub requested_model: Option<String>,
    pub policy_version: String,
    pub policy_sha256: String,
    pub hook_provenance: review_preparation::ReviewHookProvenance,
}

impl From<Job> for JobView {
    fn from(value: Job) -> Self {
        let prepared = value.prepared_launch_json.as_deref().and_then(|json| {
            serde_json::from_str::<review_preparation::PreparedLaunchSpec>(json).ok()
        });
        let fresh_session = prepared
            .as_ref()
            .is_some_and(|prepared| prepared.fresh_session);
        let review_kind = prepared
            .as_ref()
            .map(|prepared| prepared.review_kind.as_str().to_owned());
        let feature_id = prepared
            .as_ref()
            .map(|prepared| prepared.feature_id.clone());
        let section_id = prepared
            .as_ref()
            .map(|prepared| prepared.section_id.clone());
        let round_kind = prepared
            .as_ref()
            .map(|prepared| prepared.round_kind.as_str().to_owned());
        let provenance = prepared.as_ref().map(|prepared| {
            let hook_provenance = review_preparation::review_bash_hook_provenance();
            ReviewProvenanceView {
                manifest_sha256: prepared.manifest_sha256.clone(),
                prepared_sha256: prepared.prepared_sha256.clone(),
                base_sha: prepared.base_sha.clone(),
                head_sha: prepared.head_sha.clone(),
                requested_model: prepared.model.clone(),
                policy_version: review_preparation::REVIEW_BASH_POLICY_VERSION.into(),
                policy_sha256: hook_provenance
                    .effective_hook_sha256
                    .clone()
                    .unwrap_or_default(),
                hook_provenance,
            }
        });
        let prompt_sha256 = format!("{:x}", Sha256::digest(value.initial_prompt.as_bytes()));
        let capabilities = ReviewCapabilitiesView {
            private_review_orchestration: fresh_session,
            public_mcp: false,
            fresh_session,
            independent_session_observed: fresh_session && value.zcode_session_id.is_some(),
            resume_counts_as_independent: false,
            live_steer: false,
        };
        Self {
            agent_id: value.agent_id,
            idempotency_key: value.idempotency_key,
            state: value.state.into(),
            workspace_path: value.workspace_path,
            owner_epoch: value.owner_epoch,
            close_requested: value.close_requested,
            stop_requested: value.stop_requested,
            last_event_seq: value.last_event_seq,
            failure_code: value.failure_code,
            failure_message: value.failure_message.map(|_| "[REDACTED]".into()),
            runtime_agent_id: value.runtime_agent_id,
            zcode_session_id: value.zcode_session_id,
            turn_state: value.turn_state.into(),
            closed: value.closed_at.is_some(),
            reaped: value.reaped_at.is_some(),
            live_steer: false,
            review_kind,
            feature_id,
            section_id,
            round_kind,
            prompt_sha256,
            provenance,
            capabilities,
            created_at: value.created_at,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventView {
    pub runtime_agent_id: String,
    pub sequence: u64,
    pub source_sequence: u64,
    pub event_type: String,
    pub payload_json: String,
    pub redaction_level: String,
}

impl From<StoredEvent> for EventView {
    fn from(value: StoredEvent) -> Self {
        Self {
            runtime_agent_id: value.runtime_agent_id,
            sequence: value.sequence,
            source_sequence: value.source_sequence,
            event_type: value.event_type,
            payload_json: value.payload_json,
            redaction_level: value.redaction_level,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPage {
    pub runtime_agent_id: Option<String>,
    pub events: Vec<EventView>,
    pub next_sequence: u64,
    pub has_more: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreviewState {
    Available,
    NotRequested,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactIntegrityView {
    Valid,
    Missing,
    Replaced,
    Binary,
    Invalid,
    LegacyUnverified,
}

impl From<ArtifactIntegrity> for ArtifactIntegrityView {
    fn from(value: ArtifactIntegrity) -> Self {
        match value {
            ArtifactIntegrity::Valid => Self::Valid,
            ArtifactIntegrity::Missing => Self::Missing,
            ArtifactIntegrity::Replaced => Self::Replaced,
            ArtifactIntegrity::Binary => Self::Binary,
            ArtifactIntegrity::Invalid => Self::Invalid,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactView {
    pub artifact_id: String,
    pub artifact_type: String,
    pub locator: String,
    pub expected_sha256: Option<String>,
    pub expected_bytes: Option<u64>,
    pub observed_sha256: Option<String>,
    pub observed_bytes: Option<u64>,
    pub checkpoint_number: Option<u64>,
    pub finalized: bool,
    pub integrity: ArtifactIntegrityView,
    pub preview_state: PreviewState,
    pub preview: Option<String>,
}

#[derive(Clone)]
pub struct RpcService {
    scheduler: Scheduler,
    store: Arc<Store>,
    orchestrator: Option<ReviewJobOrchestrator>,
    service_generation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcServiceConfigError {
    MismatchedStore,
    GenerationUnavailable,
}

impl RpcService {
    pub fn new(scheduler: Scheduler, store: Arc<Store>) -> Result<Self, RpcServiceConfigError> {
        if !Arc::ptr_eq(&scheduler.store(), &store) {
            return Err(RpcServiceConfigError::MismatchedStore);
        }
        // This identity is scoped to the daemon process lifetime.  Hook
        // installation/preflight has its own activation_generation and must
        // never control the public restart-scoped service generation.
        let service_generation = opaque_generation()?;
        let orchestrator = ReviewJobOrchestrator::new_with_service_generation(
            scheduler.clone(),
            service_generation.clone(),
        )
        .ok();
        Ok(Self {
            scheduler,
            store,
            orchestrator,
            service_generation,
        })
    }

    pub fn handle_bytes(&self, frame: &[u8]) -> RpcResponse {
        if frame.len() > MAX_FRAME_BYTES {
            return RpcResponse::error(
                None,
                RpcError::new(RpcErrorCode::Oversized, "request frame exceeds the RPC cap"),
            );
        }
        let value = match serde_json::from_slice::<Value>(frame) {
            Ok(value) => value,
            Err(_) => {
                return RpcResponse::error(
                    None,
                    RpcError::new(RpcErrorCode::Malformed, "request is not valid JSON"),
                )
            }
        };
        let request_id = value
            .get("request_id")
            .and_then(Value::as_str)
            .filter(|request_id| valid_request_id(request_id))
            .map(str::to_owned);
        let version = value.get("version").and_then(Value::as_u64);
        if version != Some(u64::from(RPC_VERSION)) {
            return RpcResponse::error(
                request_id,
                RpcError::new(
                    RpcErrorCode::UnsupportedVersion,
                    "unsupported RPC protocol version",
                ),
            );
        }
        if value.as_object().is_none_or(|object| {
            object
                .keys()
                .any(|key| !matches!(key.as_str(), "version" | "request_id" | "method" | "params"))
        }) {
            return RpcResponse::error(
                request_id,
                RpcError::new(RpcErrorCode::Validation, "request fields are invalid"),
            );
        }
        let method = value.get("method").and_then(Value::as_str);
        if let Some(method) = method {
            if !RpcMethod::is_known(method) {
                return RpcResponse::error(
                    request_id,
                    RpcError::new(RpcErrorCode::UnknownMethod, "unknown RPC method"),
                );
            }
        }
        let request = match serde_json::from_value::<RpcRequest>(value) {
            Ok(request) => request,
            Err(_) => {
                return RpcResponse::error(
                    request_id,
                    RpcError::new(RpcErrorCode::Validation, "request fields are invalid"),
                )
            }
        };
        if !valid_request_id(&request.request_id) {
            return RpcResponse::error(
                None,
                RpcError::new(RpcErrorCode::Validation, "request_id is invalid"),
            );
        }
        let request_id = request.request_id;
        match self.dispatch(request.method) {
            Ok(result) => RpcResponse::success(request_id, result),
            Err(error) => RpcResponse::error(Some(request_id), error),
        }
    }

    pub fn dispatch(&self, method: RpcMethod) -> Result<RpcSuccess, RpcError> {
        match method {
            RpcMethod::SystemStatus => Ok(RpcSuccess::SystemStatus {
                status: self.system_status(),
            }),
            RpcMethod::SystemEnsureReady { timeout_ms } => {
                if timeout_ms == 0 || timeout_ms > MAX_WAIT.as_millis() as u64 {
                    return Err(RpcError::new(
                        RpcErrorCode::Validation,
                        "readiness timeout is outside the allowed range",
                    ));
                }
                let preflight = self
                    .scheduler
                    .preflight_runtime(Duration::from_millis(timeout_ms));
                let probe_result = ReadinessResultView::from(preflight.result);
                let mut status = self.system_status();
                let (driver, runtime, model_auth) = readiness_components(probe_result);
                status.components.insert("driver".into(), driver);
                status.components.insert("runtime".into(), runtime);
                status.components.insert("model_auth".into(), model_auth);
                let ready = matches!(probe_result, ReadinessResultView::Ready)
                    && readiness_from_status(&status);
                Ok(RpcSuccess::SystemReadiness {
                    ready,
                    status,
                    probe_result,
                    reason_code: probe_result.reason_code(),
                })
            }
            RpcMethod::SubmitGeneral { input } => {
                validate_text(&input.feature_id, "feature_id", 256)?;
                validate_text(&input.ownership_token, "ownership_token", 512)?;
                validate_command_ids(&input.allowed_command_ids, "allowed_command_ids")?;
                validate_command_ids(&input.required_command_ids, "required_command_ids")?;
                let submitted = self
                    .scheduler
                    .enqueue_general_with_commands(
                        &input.manifest,
                        &input.feature_id,
                        &input.ownership_token,
                        &input.allowed_command_ids,
                        &input.required_command_ids,
                    )
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::GeneralSubmitted {
                    task: task_view(submitted.job, submitted.task),
                    disposition: submitted.disposition.into(),
                })
            }
            RpcMethod::GeneralComplete(input) => {
                validate_id(&input.agent_id, "agent_id")?;
                let accepted = self
                    .scheduler
                    .submit_general_completion(&input.agent_id, input.submission)
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::GeneralCompletionAccepted { accepted })
            }
            RpcMethod::GeneralRunCheck(input) => {
                validate_id(&input.agent_id, "agent_id")?;
                validate_text(&input.command_id, "command_id", 256)?;
                let result = self
                    .scheduler
                    .run_general_check(&input.agent_id, &input.command_id)
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::GeneralCheckCompleted {
                    result: result.into(),
                })
            }
            RpcMethod::TaskStatus { agent_id } => {
                let (job, task) = self.require_task(&agent_id)?;
                Ok(RpcSuccess::TaskStatus {
                    task: task_view(job, task),
                })
            }
            RpcMethod::TaskList(query) => {
                if query.limit == 0 || query.limit > MAX_LIST_JOBS {
                    return Err(RpcError::new(
                        RpcErrorCode::Validation,
                        "task list limit is outside the allowed range",
                    ));
                }
                for (field, value, cap) in [
                    ("repository", query.repository.as_deref(), 4096usize),
                    ("feature_id", query.feature_id.as_deref(), 256usize),
                    (
                        "ownership_token",
                        query.ownership_token.as_deref(),
                        512usize,
                    ),
                ] {
                    if let Some(value) = value {
                        validate_text(value, field, cap)?;
                    }
                }
                if let Some(cursor) = query.cursor.as_deref() {
                    validate_text(cursor, "cursor", 64)?;
                }
                if query.repository.is_none()
                    && query.feature_id.is_none()
                    && query.ownership_token.is_none()
                {
                    return Err(RpcError::new(
                        RpcErrorCode::Validation,
                        "at least one task list scope is required",
                    ));
                }
                let canonical_repository = query
                    .repository
                    .as_deref()
                    .map(|repository| canonical_general_repository(Path::new(repository)))
                    .transpose()
                    .map_err(|_| {
                        RpcError::new(RpcErrorCode::Validation, "repository scope is invalid")
                    })?
                    .map(|repository| repository.to_string_lossy().into_owned());
                let profile = query.profile.map(general_profile_name);
                let page = self
                    .store
                    .list_task_page(
                        TaskQueryScope {
                            repository: canonical_repository.as_deref(),
                            feature_id: query.feature_id.as_deref(),
                            ownership_token: query.ownership_token.as_deref(),
                        },
                        Some(TaskKind::General),
                        TaskPageFilter {
                            phase: query.phase.map(Into::into),
                            outcome: query.outcome,
                            profile,
                        },
                        query.cursor.as_deref().map(parse_task_cursor).transpose()?,
                        query.limit,
                    )
                    .map_err(map_store)?;
                let mut views = Vec::with_capacity(page.tasks.len());
                for task in page.tasks {
                    let job = self
                        .store
                        .get_job(&task.execution_agent_id)
                        .map_err(map_store)?
                        .ok_or_else(|| {
                            RpcError::new(RpcErrorCode::Internal, "task job disappeared")
                        })?;
                    views.push(task_view(job, task));
                }
                Ok(RpcSuccess::TaskListed {
                    tasks: views,
                    next_cursor: page.next_cursor.map(format_task_cursor),
                })
            }
            RpcMethod::TaskPending { agent_id } => {
                let (_, task) = self.require_task(&agent_id)?;
                let policy = self.scheduler.active_policy(&task.execution_agent_id);
                let requests = self
                    .store
                    .pending_requests_bounded(&task.execution_agent_id, MAX_PENDING_REQUESTS)
                    .map_err(map_store)?
                    .into_iter()
                    .map(|request| pending_request_view(policy.as_deref(), request))
                    .collect();
                Ok(RpcSuccess::Pending { requests })
            }
            RpcMethod::TaskEvents(query) => Ok(RpcSuccess::TaskEvents {
                page: self.task_event_page(query)?,
            }),
            RpcMethod::TaskWait(query) => self.task_wait(query),
            RpcMethod::TaskPoll(query) => self.task_poll(query),
            RpcMethod::TaskMessage(input) => {
                let (_, task) = self.require_task(&input.agent_id)?;
                validate_id(&input.message_id, "message_id")?;
                if !matches!(input.mode.as_str(), "queue" | "interrupt_and_continue") {
                    return Err(RpcError::new(
                        RpcErrorCode::Validation,
                        "message mode is invalid",
                    ));
                }
                validate_text(&input.content, "content", 16 * 1024)?;
                let disposition = self
                    .scheduler
                    .message_job(
                        &task.execution_agent_id,
                        &input.message_id,
                        &input.mode,
                        &input.content,
                    )
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::Message {
                    disposition: disposition.into(),
                })
            }
            RpcMethod::TaskRespond(input) => {
                let (_, task) = self.require_task(&input.agent_id)?;
                validate_id(&input.request_id, "request_id")?;
                if let Some(content) = input.content.as_deref() {
                    validate_text(content, "response content", 16 * 1024)?;
                }
                let outcome = self
                    .scheduler
                    .respond_job(
                        &task.execution_agent_id,
                        &input.request_id,
                        input.decision.as_str(),
                        input.content.as_deref(),
                    )
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::Respond {
                    outcome: outcome.into(),
                })
            }
            RpcMethod::TaskCancel { agent_id } => {
                let (_, task) = self.require_task(&agent_id)?;
                let state = self
                    .scheduler
                    .stop_job(&task.execution_agent_id)
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::Stopped {
                    state: state.into(),
                })
            }
            RpcMethod::TaskResult {
                agent_id,
                attempt_sequence,
            } => {
                let (job, task) = self.require_task_attempt(&agent_id, attempt_sequence)?;
                let artifacts = self.task_artifact_metadata(&task)?;
                let result = self
                    .store
                    .task_result(&task.execution_agent_id)
                    .map_err(map_store)?
                    .map(|stored| self.task_result_view(&job, &task, stored, &artifacts))
                    .transpose()?;
                Ok(RpcSuccess::TaskResult {
                    task: task_view(job, task),
                    result,
                    artifacts,
                })
            }
            RpcMethod::TaskArtifact(query) => {
                let (_, task) =
                    self.require_task_attempt(&query.agent_id, query.attempt_sequence)?;
                Ok(RpcSuccess::TaskArtifact {
                    chunk: self.task_artifact_chunk(&task, &query)?,
                })
            }
            RpcMethod::TaskClose { agent_id } => {
                let (_, task) = self.require_task(&agent_id)?;
                let state = self
                    .scheduler
                    .close_job(&task.execution_agent_id)
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::Closed {
                    state: state.into(),
                })
            }
            RpcMethod::TaskReap { agent_id } => {
                let (_, task) = self.require_task(&agent_id)?;
                let state = self
                    .scheduler
                    .reap_job(&task.execution_agent_id)
                    .map_err(map_scheduler)?;
                let resources_reaped = self.require_task(&agent_id)?.0.reaped_at.is_some();
                Ok(RpcSuccess::Reaped {
                    state: state.into(),
                    resources_reaped,
                })
            }
            RpcMethod::SpawnReview { manifest } => {
                let orchestrator = self.orchestrator.as_ref().ok_or_else(|| {
                    RpcError::new(
                        RpcErrorCode::Unavailable,
                        "private review orchestration is unavailable",
                    )
                })?;
                let spawned = orchestrator
                    .spawn_review(&manifest)
                    .map_err(map_orchestration)?;
                let capabilities = JobView::from(spawned.job.clone()).capabilities;
                let counts_as_independent =
                    !spawned.resumed_existing && spawned.job.zcode_session_id.is_some();
                Ok(RpcSuccess::ReviewSpawned {
                    job: spawned.job.into(),
                    prompt_sha256: spawned.prompt_sha256,
                    resumed_existing: spawned.resumed_existing,
                    counts_as_independent,
                    capabilities,
                })
            }
            RpcMethod::SubmitReview { manifest } => {
                let orchestrator = self.orchestrator.as_ref().ok_or_else(|| {
                    RpcError::new(
                        RpcErrorCode::Unavailable,
                        "private review orchestration is unavailable",
                    )
                })?;
                let submitted = orchestrator
                    .submit_review(&manifest)
                    .map_err(map_orchestration)?;
                let capabilities = JobView::from(submitted.job.clone()).capabilities;
                Ok(RpcSuccess::ReviewSubmitted {
                    job: submitted.job.into(),
                    prompt_sha256: submitted.prompt_sha256,
                    resumed_existing: submitted.resumed_existing,
                    capabilities,
                })
            }
            RpcMethod::SubmitStructuredReview { input } => {
                let orchestrator = self.orchestrator.as_ref().ok_or_else(|| {
                    RpcError::new(
                        RpcErrorCode::Unavailable,
                        "private review orchestration is unavailable",
                    )
                })?;
                let review = orchestrator
                    .submit_structured_review(&input)
                    .map_err(map_orchestration)?;
                Ok(RpcSuccess::StructuredReviewSubmitted { review })
            }
            RpcMethod::ContinueStructuredReview { input } => {
                let orchestrator = self.orchestrator.as_ref().ok_or_else(|| {
                    RpcError::new(
                        RpcErrorCode::Unavailable,
                        "private review orchestration is unavailable",
                    )
                })?;
                let review = orchestrator
                    .submit_structured_continuation(&input)
                    .map_err(map_orchestration)?;
                Ok(RpcSuccess::StructuredReviewSubmitted { review })
            }
            RpcMethod::ContinueStructuredReviewMinimal { input } => {
                let orchestrator = self.orchestrator.as_ref().ok_or_else(|| {
                    RpcError::new(
                        RpcErrorCode::Unavailable,
                        "private review orchestration is unavailable",
                    )
                })?;
                let review = orchestrator
                    .submit_minimal_structured_continuation(&input)
                    .map_err(map_orchestration)?;
                Ok(RpcSuccess::StructuredReviewSubmitted { review })
            }
            RpcMethod::Enqueue { job } => {
                validate_id(&job.agent_id, "agent_id")?;
                validate_text(&job.workspace_path, "workspace_path", 4096)?;
                validate_text(&job.initial_prompt, "initial_prompt", 64 * 1024)?;
                if let Some(key) = &job.idempotency_key {
                    validate_text(key, "idempotency_key", 512)?;
                }
                let job = self.scheduler.enqueue(&job.into()).map_err(map_scheduler)?;
                Ok(RpcSuccess::Enqueued { job: job.into() })
            }
            RpcMethod::Start => Ok(RpcSuccess::Started {
                agent_ids: self.scheduler.start_ready().map_err(map_scheduler)?,
            }),
            RpcMethod::Status { agent_id } => Ok(RpcSuccess::Status {
                job: self.require_legacy_job(&agent_id)?.into(),
            }),
            RpcMethod::Pending { agent_id } => {
                self.require_legacy_job(&agent_id)?;
                let policy = self.scheduler.active_policy(&agent_id);
                let requests = self
                    .store
                    .pending_requests_bounded(&agent_id, MAX_PENDING_REQUESTS)
                    .map_err(map_store)?
                    .into_iter()
                    .map(|request| pending_request_view(policy.as_deref(), request))
                    .collect();
                Ok(RpcSuccess::Pending { requests })
            }
            RpcMethod::Events(query) => Ok(RpcSuccess::Events {
                page: self.event_page(query)?,
            }),
            RpcMethod::Wait(query) => self.wait(query),
            RpcMethod::Message(input) => {
                self.require_legacy_job(&input.agent_id)?;
                validate_id(&input.message_id, "message_id")?;
                if !matches!(input.mode.as_str(), "queue" | "interrupt_and_continue") {
                    return Err(RpcError::new(
                        RpcErrorCode::Validation,
                        "message mode is invalid",
                    ));
                }
                validate_text(&input.content, "content", 16 * 1024)?;
                let disposition = self
                    .scheduler
                    .message_job(
                        &input.agent_id,
                        &input.message_id,
                        &input.mode,
                        &input.content,
                    )
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::Message {
                    disposition: disposition.into(),
                })
            }
            RpcMethod::Respond(input) => {
                self.require_legacy_job(&input.agent_id)?;
                validate_id(&input.request_id, "request_id")?;
                if let Some(content) = input.content.as_deref() {
                    validate_text(content, "response content", 16 * 1024)?;
                }
                let outcome = self
                    .scheduler
                    .respond_job(
                        &input.agent_id,
                        &input.request_id,
                        input.decision.as_str(),
                        input.content.as_deref(),
                    )
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::Respond {
                    outcome: outcome.into(),
                })
            }
            RpcMethod::Stop { agent_id } => {
                self.require_legacy_job(&agent_id)?;
                let state = self.scheduler.stop_job(&agent_id).map_err(map_scheduler)?;
                Ok(RpcSuccess::Stopped {
                    state: state.into(),
                })
            }
            RpcMethod::Result(query) => self.result(query),
            RpcMethod::List { scope, limit } => {
                if limit == 0 || limit > MAX_LIST_JOBS {
                    return Err(RpcError::new(
                        RpcErrorCode::Validation,
                        "list limit is outside the allowed range",
                    ));
                }
                let jobs = self
                    .store
                    .list_legacy_jobs_scoped(scope.into(), limit)
                    .map_err(map_store)?
                    .into_iter()
                    .map(JobView::from)
                    .collect();
                Ok(RpcSuccess::Listed { jobs })
            }
            RpcMethod::Close { agent_id } => {
                self.require_legacy_job(&agent_id)?;
                let state = self.scheduler.close_job(&agent_id).map_err(map_scheduler)?;
                Ok(RpcSuccess::Closed {
                    state: state.into(),
                })
            }
            RpcMethod::Reap { agent_id } => {
                self.require_legacy_job(&agent_id)?;
                let state = self.scheduler.reap_job(&agent_id).map_err(map_scheduler)?;
                let resources_reaped = self.require_legacy_job(&agent_id)?.reaped_at.is_some();
                Ok(RpcSuccess::Reaped {
                    state: state.into(),
                    resources_reaped,
                })
            }
            RpcMethod::TaskReviewTool(input) => {
                validate_id(&input.agent_id, "agent_id")?;
                let task = self
                    .store
                    .task_by_execution_agent_id(&input.agent_id)
                    .map_err(map_store)?
                    .ok_or_else(|| {
                        RpcError::new(RpcErrorCode::NotFound, "review task was not found")
                    })?;
                if !matches!(
                    task.task_kind,
                    TaskKind::Review | TaskKind::ReviewContinuation
                ) {
                    return Err(RpcError::new(
                        RpcErrorCode::Validation,
                        "internal review ledger is unavailable for this task kind",
                    ));
                }
                validate_text(&input.tool, "review tool", 128)?;
                let result = self
                    .scheduler
                    .call_task_review_tool(&input.agent_id, &input.tool, input.arguments)
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::ReviewTool { result })
            }
            RpcMethod::ReviewTool(input) => {
                self.require_legacy_job(&input.agent_id)?;
                validate_text(&input.tool, "review tool", 128)?;
                let result = self
                    .scheduler
                    .call_review_tool(&input.agent_id, &input.tool, input.arguments)
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::ReviewTool { result })
            }
        }
    }

    fn system_status(&self) -> SystemStatusView {
        let mut components = BTreeMap::new();
        components.insert("facade".into(), ComponentStateView::Unknown);
        components.insert("daemon".into(), ComponentStateView::Ready);
        components.insert(
            "store".into(),
            match self.store.journal_mode() {
                Ok(mode) if mode.eq_ignore_ascii_case("wal") => ComponentStateView::Ready,
                Ok(_) => ComponentStateView::Degraded,
                Err(_) => ComponentStateView::Unavailable,
            },
        );
        components.insert("scheduler".into(), ComponentStateView::Ready);
        components.insert("driver".into(), ComponentStateView::Unknown);
        components.insert("runtime".into(), ComponentStateView::Unknown);
        components.insert("model_auth".into(), ComponentStateView::Unknown);
        SystemStatusView {
            api_surface: "subagent_v2".into(),
            protocol_version: RPC_VERSION,
            service_generation: self.service_generation.clone(),
            components,
            capabilities: agent_capabilities(self.scheduler.named_checks_enabled()),
        }
    }

    fn require_task(&self, agent_id: &str) -> Result<(Job, TaskRecord), RpcError> {
        validate_id(agent_id, "agent_id")?;
        let task = self
            .store
            .get_task(agent_id)
            .map_err(map_store)?
            .ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "task was not found"))?;
        self.require_task_record(task)
    }

    fn require_task_attempt(
        &self,
        agent_id: &str,
        attempt_sequence: Option<u64>,
    ) -> Result<(Job, TaskRecord), RpcError> {
        let latest = self.require_task(agent_id)?;
        let Some(attempt_sequence) = attempt_sequence else {
            return Ok(latest);
        };
        if attempt_sequence == 0 {
            return Err(RpcError::new(
                RpcErrorCode::Validation,
                "attempt_sequence must be positive",
            ));
        }
        if latest.1.attempt_sequence == attempt_sequence {
            return Ok(latest);
        }
        let task = self
            .store
            .get_task_attempt(agent_id, attempt_sequence)
            .map_err(map_store)?
            .ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "task attempt was not found"))?;
        self.require_task_record(task)
    }

    fn require_task_record(&self, task: TaskRecord) -> Result<(Job, TaskRecord), RpcError> {
        let job = self
            .store
            .get_job(&task.execution_agent_id)
            .map_err(map_store)?
            .ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "task was not found"))?;
        let prepared_json = job
            .prepared_launch_json
            .as_deref()
            .ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "task was not found"))?;
        let prepared_repository = serde_json::from_str::<PreparedGeneralTask>(prepared_json)
            .map(|prepared| prepared.repository)
            .or_else(|_| {
                serde_json::from_str::<PreparedLaunchSpec>(prepared_json)
                    .map(|prepared| prepared.repository)
            })
            .map_err(|_| RpcError::new(RpcErrorCode::NotFound, "task was not found"))?;
        if prepared_repository.to_string_lossy() != task.repository {
            return Err(RpcError::new(RpcErrorCode::NotFound, "task was not found"));
        }
        Ok((job, task))
    }

    fn task_artifact_metadata(
        &self,
        task: &TaskRecord,
    ) -> Result<Vec<TaskArtifactMetadataView>, RpcError> {
        let result = self
            .store
            .task_result(&task.execution_agent_id)
            .map_err(map_store)?;
        if matches!(
            task.task_kind,
            TaskKind::Review | TaskKind::ReviewContinuation
        ) {
            let source_valid = result.as_ref().is_some_and(|stored| {
                stored.result.outcome == TaskOutcome::Succeeded && !stored.result.partial
            });
            if !source_valid {
                return Ok(Vec::new());
            }
            let Some(verified) = self
                .scheduler
                .verify_review_artifact(&task.execution_agent_id, 0)
                .map_err(map_scheduler)?
            else {
                return Ok(Vec::new());
            };
            if !verified.finalized || verified.integrity != ArtifactIntegrity::Valid {
                return Ok(Vec::new());
            }
            let (Some(expected_sha256), Some(expected_bytes)) =
                (verified.expected_sha256, verified.expected_bytes)
            else {
                return Ok(Vec::new());
            };
            if expected_bytes == 0 || !valid_sha256(&expected_sha256) {
                return Ok(Vec::new());
            }
            let artifact = self
                .store
                .artifacts(&task.execution_agent_id, MAX_PENDING_REQUESTS)
                .map_err(map_store)?
                .into_iter()
                .find(|artifact| {
                    artifact.artifact_type == "review_report"
                        && artifact.path == verified.locator
                        && artifact.sha256 == expected_sha256
                        && artifact.bytes == expected_bytes
                });
            return Ok(artifact
                .map(|artifact| {
                    vec![TaskArtifactMetadataView {
                        artifact_id: artifact.artifact_id,
                        kind: "report_markdown".into(),
                        sha256: artifact.sha256,
                        size_bytes: artifact.bytes,
                    }]
                })
                .unwrap_or_default());
        }
        let allowed = result
            .as_ref()
            .map(|stored| {
                stored
                    .result
                    .artifacts
                    .iter()
                    .map(|artifact| (artifact.artifact_id.as_str(), artifact.sha256.as_str()))
                    .collect::<BTreeMap<_, _>>()
            })
            .unwrap_or_default();
        let mut projected = Vec::new();
        for artifact in self
            .store
            .artifacts(&task.execution_agent_id, MAX_PENDING_REQUESTS)
            .map_err(map_store)?
        {
            let permitted = allowed
                .get(artifact.artifact_id.as_str())
                .is_some_and(|sha| *sha == artifact.sha256);
            if permitted {
                projected.push(TaskArtifactMetadataView {
                    artifact_id: artifact.artifact_id,
                    kind: public_artifact_kind(&artifact.artifact_type).into(),
                    sha256: artifact.sha256,
                    size_bytes: artifact.bytes,
                });
            }
        }
        projected.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
        Ok(projected)
    }

    fn task_result_view(
        &self,
        job: &Job,
        task: &TaskRecord,
        stored: StoredTaskResult,
        artifacts: &[TaskArtifactMetadataView],
    ) -> Result<TaskResultView, RpcError> {
        let mut view = TaskResultView::from(stored);
        if !matches!(
            task.task_kind,
            TaskKind::Review | TaskKind::ReviewContinuation
        ) || view.outcome != TaskOutcome::Succeeded
        {
            return Ok(view);
        }

        let Some(snapshot) = self
            .store
            .review_snapshot(&task.execution_agent_id)
            .map_err(map_store)?
        else {
            return Ok(view);
        };
        let Some(finalization) = snapshot.finalization.as_ref() else {
            return Ok(view);
        };
        let Some(final_signal) = snapshot.report.final_signal.as_deref() else {
            return Ok(view);
        };
        if !snapshot.report.finalized
            || finalization.status.as_deref() != Some(final_signal)
            || snapshot.report.published_revision != Some(snapshot.report.current_revision)
            || snapshot.checkpoints.is_empty()
            || snapshot.validations.is_empty()
        {
            return Ok(view);
        }
        let [artifact] = artifacts else {
            return Ok(view);
        };
        if artifact.kind != "report_markdown"
            || artifact.size_bytes == 0
            || !valid_sha256(&artifact.sha256)
        {
            return Ok(view);
        }
        let fresh_session_observed = job
            .zcode_session_id
            .as_deref()
            .is_some_and(|session| !session.trim().is_empty());
        let Ok(validations) = u64::try_from(snapshot.validations.len()) else {
            return Ok(view);
        };
        let Ok(checkpoints) = u64::try_from(snapshot.checkpoints.len()) else {
            return Ok(view);
        };
        let Ok(findings) = u64::try_from(snapshot.findings.len()) else {
            return Ok(view);
        };
        let Ok(open_findings) = u64::try_from(
            snapshot
                .findings
                .iter()
                .filter(|finding| finding.status.as_deref() == Some("open"))
                .count(),
        ) else {
            return Ok(view);
        };
        view.review_evidence = Some(TaskReviewEvidenceView {
            final_signal: final_signal.to_owned(),
            finalized: true,
            report_revision: snapshot.report.current_revision,
            finalization_revision: finalization.revision,
            artifact: artifact.clone(),
            counts: TaskReviewEvidenceCountsView {
                checkpoints,
                findings,
                open_findings,
                validations,
            },
            independence: TaskReviewIndependenceView {
                independent_evidence: task.independent_evidence,
                fresh_session_observed,
                counts_as_independent: task.independent_evidence && fresh_session_observed,
            },
            validation_provenance: TaskValidationProvenanceView {
                daemon_verification: TaskDaemonVerificationView {
                    source_integrity_verified: true,
                    finalized_report_verified: true,
                    artifact_digest_verified: true,
                    validation_records_structurally_verified: true,
                },
                model_attestation: TaskModelAttestationView {
                    present: true,
                    validation_record_count: validations,
                },
            },
        });
        Ok(view)
    }

    fn task_artifact_chunk(
        &self,
        task: &TaskRecord,
        query: &TaskArtifactQuery,
    ) -> Result<TaskArtifactChunkView, RpcError> {
        validate_id(&query.artifact_id, "artifact_id")?;
        if query.limit_bytes == 0 || query.limit_bytes > MAX_ARTIFACT_CHUNK_BYTES {
            return Err(RpcError::new(
                RpcErrorCode::Validation,
                "artifact chunk size is outside the allowed range",
            ));
        }
        let metadata = self.task_artifact_metadata(task)?;
        let expected = metadata
            .into_iter()
            .find(|artifact| artifact.artifact_id == query.artifact_id)
            .ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "artifact was not found"))?;
        if query.offset_bytes >= expected.size_bytes {
            return Err(RpcError::new(
                RpcErrorCode::Validation,
                "artifact offset does not permit non-empty progress",
            ));
        }
        let stored = self
            .store
            .artifacts(&task.execution_agent_id, MAX_PENDING_REQUESTS)
            .map_err(map_store)?
            .into_iter()
            .find(|artifact| artifact.artifact_id == query.artifact_id)
            .ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "artifact was not found"))?;
        verified_artifact_chunk(stored, expected, query.offset_bytes, query.limit_bytes)
    }

    fn task_event_page(&self, query: TaskEventQuery) -> Result<TaskEventPage, RpcError> {
        if query.limit == 0 || query.limit > MAX_PAGE_EVENTS {
            return Err(RpcError::new(
                RpcErrorCode::Validation,
                "event limit is outside the allowed range",
            ));
        }
        let (job, task) = self.require_task(&query.agent_id)?;
        let stored = self
            .store
            .task_events_after(
                &query.agent_id,
                0,
                MAX_PRIVATE_EVENTS_FOR_PUBLIC_PROJECTION + 1,
            )
            .map_err(map_store)?;
        if stored.len() > MAX_PRIVATE_EVENTS_FOR_PUBLIC_PROJECTION {
            return Err(RpcError::new(
                RpcErrorCode::Oversized,
                "private task event history exceeds the bounded public projection",
            ));
        }
        let events = self.task_high_level_events(&task, stored)?;
        let frame_budget_task = task_frame_budget_view(job, task);
        task_page_from_events(query.after, query.limit, events, &frame_budget_task)
    }

    fn task_high_level_events(
        &self,
        task: &TaskRecord,
        stored: Vec<StoredEvent>,
    ) -> Result<Vec<TaskEventView>, RpcError> {
        let mut events = Vec::new();
        if task.phase != TaskPhase::Queued {
            events.push(TaskEventView {
                sequence: 0,
                source_sequence: 0,
                attempt_sequence: task.attempt_sequence,
                event_type: "attempt_started".into(),
                payload_json: "{}".into(),
                redaction_level: "allowlisted".into(),
                stage: None,
                summary: None,
                counters: None,
                last_progress_at: None,
                semantic_idle_ms: None,
                nudge_sent: None,
            });
        }
        let progress_state = if matches!(
            task.task_kind,
            TaskKind::Review | TaskKind::ReviewContinuation
        ) {
            self.store
                .review_progress(&task.execution_agent_id)
                .map_err(map_store)?
        } else {
            None
        };
        let wall_now_ms = wall_now_millis();
        for event in stored
            .into_iter()
            .filter(|event| event.attempt_sequence == task.attempt_sequence)
        {
            let projected = if event.event_type == "review.progress"
                && matches!(
                    task.task_kind,
                    TaskKind::Review | TaskKind::ReviewContinuation
                ) {
                Some((
                    "review_progress",
                    "{}".to_owned(),
                    "allowlisted",
                    project_review_progress(task, &event, progress_state.as_ref(), wall_now_ms),
                ))
            } else {
                public_pending_request_id(&event).map(|request_id| {
                    (
                        "pending_request",
                        serde_json::json!({"request_id": request_id}).to_string(),
                        "bounded",
                        None,
                    )
                })
            };
            if let Some((event_type, payload_json, redaction_level, progress)) = projected {
                events.push(TaskEventView {
                    sequence: 0,
                    source_sequence: event.source_sequence,
                    attempt_sequence: task.attempt_sequence,
                    event_type: event_type.into(),
                    payload_json,
                    redaction_level: redaction_level.into(),
                    stage: progress.as_ref().map(|progress| progress.stage),
                    summary: progress.as_ref().map(|progress| progress.summary.clone()),
                    counters: progress
                        .as_ref()
                        .and_then(|progress| progress.counters.clone()),
                    last_progress_at: progress.as_ref().map(|progress| progress.last_progress_at),
                    semantic_idle_ms: progress.as_ref().map(|progress| progress.semantic_idle_ms),
                    nudge_sent: progress.as_ref().map(|progress| progress.nudge_sent),
                });
            }
        }
        if matches!(
            task.task_kind,
            TaskKind::Review | TaskKind::ReviewContinuation
        ) {
            let snapshot = self
                .store
                .review_snapshot(&task.execution_agent_id)
                .map_err(map_store)?;
            if let Some(snapshot) = snapshot
                .filter(|snapshot| snapshot.report.finalized && snapshot.finalization.is_some())
            {
                events.push(TaskEventView {
                    sequence: 0,
                    source_sequence: 0,
                    attempt_sequence: task.attempt_sequence,
                    event_type: "review_finalized".into(),
                    payload_json: serde_json::json!({
                        "revision": snapshot.report.current_revision,
                    })
                    .to_string(),
                    redaction_level: "allowlisted".into(),
                    stage: None,
                    summary: None,
                    counters: None,
                    last_progress_at: None,
                    semantic_idle_ms: None,
                    nudge_sent: None,
                });
            }
        }
        if task.phase == TaskPhase::Terminal {
            events.push(TaskEventView {
                sequence: 0,
                source_sequence: 0,
                attempt_sequence: task.attempt_sequence,
                event_type: "terminal".into(),
                payload_json: "{}".into(),
                redaction_level: "allowlisted".into(),
                stage: None,
                summary: None,
                counters: None,
                last_progress_at: None,
                semantic_idle_ms: None,
                nudge_sent: None,
            });
        }
        for (index, event) in events.iter_mut().enumerate() {
            event.sequence = u64::try_from(index + 1).map_err(|_| {
                RpcError::new(RpcErrorCode::Oversized, "public event sequence overflowed")
            })?;
        }
        Ok(events)
    }

    fn task_wait(&self, query: TaskWaitQuery) -> Result<RpcSuccess, RpcError> {
        if query.timeout_ms == 0 || Duration::from_millis(query.timeout_ms) > MAX_WAIT {
            return Err(RpcError::new(
                RpcErrorCode::Validation,
                "wait timeout is outside the allowed range",
            ));
        }
        let deadline = Instant::now() + Duration::from_millis(query.timeout_ms);
        loop {
            let (job, task) = self.require_task(&query.agent_id)?;
            let page = self.task_event_page(TaskEventQuery {
                agent_id: query.agent_id.clone(),
                after: query.after,
                limit: MAX_PAGE_EVENTS,
            })?;
            if !page.events.is_empty() || task.phase == TaskPhase::Terminal {
                return Ok(RpcSuccess::TaskWait {
                    task: task_view(job, task),
                    page,
                    timed_out: false,
                });
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(RpcSuccess::TaskWait {
                    task: task_view(job, task),
                    page,
                    timed_out: true,
                });
            }
            thread::sleep((deadline - now).min(Duration::from_millis(10)));
        }
    }

    fn task_poll(&self, query: TaskPollQuery) -> Result<RpcSuccess, RpcError> {
        if Duration::from_millis(query.timeout_ms) > MAX_WAIT {
            return Err(RpcError::new(
                RpcErrorCode::Validation,
                "poll timeout is outside the allowed range",
            ));
        }
        let deadline = Instant::now() + Duration::from_millis(query.timeout_ms);
        loop {
            let (job, task) = self.require_task(&query.agent_id)?;
            let policy = self.scheduler.active_policy(&task.execution_agent_id);
            let pending_requests = self
                .store
                .pending_requests_bounded(&task.execution_agent_id, MAX_PENDING_REQUESTS)
                .map_err(map_store)?
                .into_iter()
                .map(|request| pending_request_view(policy.as_deref(), request))
                .collect::<Vec<_>>();
            let result_available = self
                .store
                .task_result(&task.execution_agent_id)
                .map_err(map_store)?
                .is_some();
            let activity = self
                .scheduler
                .passive_activity_snapshot(&task.execution_agent_id);
            let revision = activity
                .as_ref()
                .map(|activity| activity.revision)
                .unwrap_or(0)
                .max(job.last_event_seq);
            let terminal = task.phase == TaskPhase::Terminal;
            let now = Instant::now();
            if revision > query.after_revision
                || !pending_requests.is_empty()
                || terminal
                || now >= deadline
            {
                let timed_out = revision <= query.after_revision
                    && pending_requests.is_empty()
                    && !terminal
                    && now >= deadline;
                return Ok(RpcSuccess::TaskPoll {
                    activity: task_activity_view(task.phase, activity),
                    task: task_view(job, task),
                    revision,
                    next_revision: revision,
                    pending_requests,
                    result_available,
                    timed_out,
                });
            }
            thread::sleep((deadline - now).min(Duration::from_millis(10)));
        }
    }

    fn require_legacy_job(&self, agent_id: &str) -> Result<Job, RpcError> {
        validate_id(agent_id, "agent_id")?;
        self.store
            .get_legacy_job(agent_id)
            .map_err(map_store)?
            .ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "job was not found"))
    }

    fn event_page(&self, query: EventQuery) -> Result<EventPage, RpcError> {
        if query.limit == 0 || query.limit > MAX_PAGE_EVENTS {
            return Err(RpcError::new(
                RpcErrorCode::Validation,
                "event limit is outside the allowed range",
            ));
        }
        let job = self.require_legacy_job(&query.agent_id)?;
        let runtime_agent_id = query.runtime_agent_id.or(job.runtime_agent_id);
        let Some(runtime_agent_id) = runtime_agent_id else {
            return Ok(EventPage {
                runtime_agent_id: None,
                events: Vec::new(),
                next_sequence: query.after,
                has_more: false,
            });
        };
        validate_id(&runtime_agent_id, "runtime_agent_id")?;
        let stored = self
            .store
            .events_after(
                &query.agent_id,
                &runtime_agent_id,
                query.after,
                query.limit + 1,
            )
            .map_err(map_store)?;
        page_from_events(Some(runtime_agent_id), query.after, query.limit, stored)
    }

    fn wait(&self, query: WaitQuery) -> Result<RpcSuccess, RpcError> {
        if query.timeout_ms == 0 || Duration::from_millis(query.timeout_ms) > MAX_WAIT {
            return Err(RpcError::new(
                RpcErrorCode::Validation,
                "wait timeout is outside the allowed range",
            ));
        }
        let deadline = Instant::now() + Duration::from_millis(query.timeout_ms);
        validate_id(&query.agent_id, "agent_id")?;
        self.require_legacy_job(&query.agent_id)?;
        if let Some(runtime_agent_id) = query.runtime_agent_id.as_deref() {
            validate_id(runtime_agent_id, "runtime_agent_id")?;
        }
        let fallback = match self
            .store
            .get_job_snapshot_until(&query.agent_id, deadline)
            .map_err(map_store)?
        {
            DeadlineRead::Ready(Some(job)) => job,
            DeadlineRead::Ready(None) => {
                return Err(RpcError::new(RpcErrorCode::NotFound, "job was not found"))
            }
            DeadlineRead::TimedOut => return Err(wait_timeout()),
        };
        let (initial, initial_page) = match self.wait_snapshot(&query, deadline) {
            Ok(snapshot) => snapshot,
            Err(error) if error.code == RpcErrorCode::Timeout => {
                return Ok(wait_timed_out(fallback, query.after))
            }
            Err(error) => return Err(error),
        };
        if !initial_page.events.is_empty() || initial.state.is_terminal() {
            return Ok(RpcSuccess::Wait {
                job: initial.into(),
                page: initial_page,
                timed_out: false,
            });
        }
        let initial_state = initial.state;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(RpcSuccess::Wait {
                    job: initial.into(),
                    page: EventPage {
                        runtime_agent_id: None,
                        events: Vec::new(),
                        next_sequence: query.after,
                        has_more: false,
                    },
                    timed_out: true,
                });
            }
            thread::sleep((deadline - now).min(Duration::from_millis(10)));
            let (job, page) = match self.wait_snapshot(&query, deadline) {
                Ok(snapshot) => snapshot,
                Err(error) if error.code == RpcErrorCode::Timeout => {
                    return Ok(wait_timed_out(initial, query.after));
                }
                Err(error) => return Err(error),
            };
            if !page.events.is_empty() || job.state.is_terminal() || job.state != initial_state {
                return Ok(RpcSuccess::Wait {
                    job: job.into(),
                    page,
                    timed_out: false,
                });
            }
        }
    }

    fn wait_snapshot(
        &self,
        query: &WaitQuery,
        deadline: Instant,
    ) -> Result<(Job, EventPage), RpcError> {
        let snapshot = match self
            .store
            .wait_snapshot_until(
                &query.agent_id,
                query.runtime_agent_id.as_deref(),
                query.after,
                MAX_PAGE_EVENTS + 1,
                deadline,
            )
            .map_err(map_store)?
        {
            DeadlineRead::Ready(snapshot) => snapshot,
            DeadlineRead::TimedOut => return Err(wait_timeout()),
        };
        let WaitSnapshot {
            job,
            runtime_agent_id,
            events,
        } = snapshot;
        let job = job.ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "job was not found"))?;
        let page = page_from_events(runtime_agent_id, query.after, MAX_PAGE_EVENTS, events)?;
        Ok((job, page))
    }

    fn result(&self, query: ResultQuery) -> Result<RpcSuccess, RpcError> {
        if query.preview_bytes > MAX_PREVIEW_BYTES {
            return Err(RpcError::new(
                RpcErrorCode::Validation,
                "preview size exceeds the transport cap",
            ));
        }
        let job = self.require_legacy_job(&query.agent_id)?;
        if let Some(verified) = self
            .scheduler
            .verify_review_artifact(&query.agent_id, query.preview_bytes)
            .map_err(map_scheduler)?
        {
            return Ok(RpcSuccess::Result {
                job: job.into(),
                artifact: Some(verified_artifact_view(verified, query.preview_bytes)),
            });
        }
        let artifact = self
            .store
            .artifacts(&query.agent_id, 1)
            .map_err(map_store)?
            .into_iter()
            .next()
            .map(|artifact| artifact_view(artifact, query.preview_bytes));
        Ok(RpcSuccess::Result {
            job: job.into(),
            artifact,
        })
    }
}

fn opaque_generation() -> Result<String, RpcServiceConfigError> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| RpcServiceConfigError::GenerationUnavailable)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn agent_capabilities(named_checks: bool) -> AgentCapabilitiesView {
    let mut profile_defaults = BTreeMap::new();
    profile_defaults.insert(
        "analysis_readonly".into(),
        GeneralProfile::AnalysisReadonly.default_budget(),
    );
    profile_defaults.insert(
        "implementation_worktree".into(),
        GeneralProfile::ImplementationWorktree.default_budget(),
    );
    profile_defaults.insert(
        "test_runner".into(),
        GeneralProfile::TestRunner.default_budget(),
    );
    let maturity = BTreeMap::from([
        (
            "structured_review".into(),
            CapabilityMaturityView::BetaReady,
        ),
        (
            "analysis_readonly".into(),
            CapabilityMaturityView::ExperimentalUnverifiedRuntime,
        ),
        (
            "implementation_worktree".into(),
            CapabilityMaturityView::ExperimentalUnverifiedRuntime,
        ),
        (
            "test_runner".into(),
            CapabilityMaturityView::ExperimentalUnverifiedRuntime,
        ),
    ]);
    AgentCapabilitiesView {
        task_kinds: vec![
            "general".into(),
            "review".into(),
            "review_continuation".into(),
        ],
        profiles: profile_defaults.keys().cloned().collect(),
        profile_defaults,
        hard_budget_caps: BudgetLimits {
            wall_time_ms: 86_400_000,
            semantic_soft_timeout_ms: 86_399_999,
            semantic_hard_timeout_ms: 86_400_000,
            max_turns: 1_024,
            max_tool_calls: 4_096,
            max_context_bytes: 16_777_216,
            max_result_bytes: 16_777_216,
            max_artifact_bytes: 268_435_456,
        },
        max_rpc_frame_bytes: MAX_FRAME_BYTES,
        max_events: MAX_PAGE_EVENTS,
        max_wait_ms: MAX_WAIT.as_millis() as u64,
        named_checks,
        maturity,
    }
}

fn readiness_components(
    result: ReadinessResultView,
) -> (ComponentStateView, ComponentStateView, ComponentStateView) {
    use ComponentStateView::{Ready, Unavailable, Unknown};
    match result {
        ReadinessResultView::Ready => (Ready, Ready, Ready),
        ReadinessResultView::ConfigInvalid | ReadinessResultView::ZcodeStartFailed => {
            (Unavailable, Unknown, Unknown)
        }
        ReadinessResultView::RuntimeProtocolFailed | ReadinessResultView::CleanupFailed => {
            (Ready, Unavailable, Unknown)
        }
        ReadinessResultView::ModelAuthFailed => (Ready, Ready, Unavailable),
        ReadinessResultView::RuntimeFailed => (Ready, Ready, Unknown),
        ReadinessResultView::NotObservedWithinTimeout => (Ready, Ready, Unknown),
    }
}

fn readiness_from_status(status: &SystemStatusView) -> bool {
    [
        "daemon",
        "store",
        "scheduler",
        "driver",
        "runtime",
        "model_auth",
    ]
    .iter()
    .all(|component| status.components.get(*component) == Some(&ComponentStateView::Ready))
}

fn general_profile_name(profile: GeneralProfile) -> &'static str {
    match profile {
        GeneralProfile::AnalysisReadonly => "analysis_readonly",
        GeneralProfile::ImplementationWorktree => "implementation_worktree",
        GeneralProfile::TestRunner => "test_runner",
    }
}

fn parse_task_cursor(cursor: &str) -> Result<u64, RpcError> {
    let value = cursor
        .strip_prefix("task:")
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| RpcError::new(RpcErrorCode::Validation, "task cursor is invalid"))?;
    Ok(value)
}

fn format_task_cursor(cursor: u64) -> String {
    format!("task:{cursor}")
}

fn public_artifact_kind(stored: &str) -> &'static str {
    match stored {
        "report_markdown" | "report" => "report_markdown",
        "changes_patch" => "changes_patch",
        "check_report" => "check_report",
        _ => "unknown",
    }
}

fn verified_artifact_chunk(
    stored: StoredArtifact,
    expected: TaskArtifactMetadataView,
    offset_bytes: u64,
    limit_bytes: usize,
) -> Result<TaskArtifactChunkView, RpcError> {
    let metadata = std::fs::symlink_metadata(&stored.path)
        .map_err(|_| RpcError::new(RpcErrorCode::ResultInvalid, "artifact is unavailable"))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.len() != expected.size_bytes
        || stored.bytes != expected.size_bytes
        || stored.sha256 != expected.sha256
    {
        return Err(RpcError::new(
            RpcErrorCode::ResultInvalid,
            "artifact metadata does not match authoritative bytes",
        ));
    }
    let mut file = File::open(&stored.path)
        .map_err(|_| RpcError::new(RpcErrorCode::ResultInvalid, "artifact is unavailable"))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| RpcError::new(RpcErrorCode::ResultInvalid, "artifact read failed"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let observed = format!("{:x}", hasher.finalize());
    if observed != expected.sha256 {
        return Err(RpcError::new(
            RpcErrorCode::ResultInvalid,
            "artifact digest does not match authoritative metadata",
        ));
    }
    file.seek(SeekFrom::Start(offset_bytes))
        .map_err(|_| RpcError::new(RpcErrorCode::ResultInvalid, "artifact seek failed"))?;
    let remaining = expected.size_bytes - offset_bytes;
    let requested = remaining.min(limit_bytes as u64) as usize;
    let mut bytes = vec![0u8; requested];
    file.read_exact(&mut bytes)
        .map_err(|_| RpcError::new(RpcErrorCode::ResultInvalid, "artifact read failed"))?;
    Ok(TaskArtifactChunkView {
        artifact_id: expected.artifact_id,
        sha256: expected.sha256,
        size_bytes: expected.size_bytes,
        offset_bytes,
        eof: offset_bytes + bytes.len() as u64 == expected.size_bytes,
        bytes,
    })
}

fn task_view(job: Job, task: TaskRecord) -> TaskView {
    let fresh_session_observed = job
        .zcode_session_id
        .as_deref()
        .is_some_and(|session| !session.trim().is_empty());
    let access_mode = job
        .prepared_launch_json
        .as_deref()
        .and_then(|json| serde_json::from_str::<PreparedGeneralTask>(json).ok())
        .map(|prepared| match prepared.profile {
            GeneralProfile::AnalysisReadonly => "read_only",
            GeneralProfile::ImplementationWorktree | GeneralProfile::TestRunner => {
                "workspace_write"
            }
        })
        .unwrap_or("read_only")
        .to_owned();
    TaskView {
        agent_id: task.public_agent_id,
        review_id: task.review_id,
        task_kind: match task.task_kind {
            TaskKind::General => "general",
            TaskKind::Review => "review",
            TaskKind::ReviewContinuation => "review_continuation",
        }
        .into(),
        access_mode,
        phase: match task.phase {
            TaskPhase::Queued => "QUEUED",
            TaskPhase::Preparing => "PREPARING",
            TaskPhase::Running => "RUNNING",
            TaskPhase::WaitingInput => "WAITING_INPUT",
            TaskPhase::Cancelling => "CANCELLING",
            TaskPhase::Terminal => "TERMINAL",
        }
        .into(),
        attempt_sequence: task.attempt_sequence,
        effective_budget: task.effective_budget,
        independent_evidence: task.independent_evidence,
        fresh_session_observed,
        stop_requested: job.stop_requested,
        close_requested: job.close_requested,
        closed: job.closed_at.is_some(),
        reaped: job.reaped_at.is_some(),
    }
}

fn task_activity_view(
    phase: TaskPhase,
    snapshot: Option<PassiveActivitySnapshot>,
) -> TaskActivityView {
    let state = match phase {
        TaskPhase::Queued => TaskActivityStateView::Queued,
        TaskPhase::Preparing => TaskActivityStateView::Preparing,
        TaskPhase::Running => TaskActivityStateView::Active,
        TaskPhase::WaitingInput => TaskActivityStateView::WaitingInput,
        TaskPhase::Cancelling => TaskActivityStateView::Cancelling,
        TaskPhase::Terminal => TaskActivityStateView::Terminal,
    };
    let Some(snapshot) = snapshot else {
        return TaskActivityView {
            state,
            last_runtime_event_at: None,
            last_activity_age_ms: None,
            model_request_active: false,
            model_request_age_ms: None,
            model_last_delta_age_ms: None,
            latest_text_tail: String::new(),
            latest_text_updated_at: None,
            latest_text_truncated: false,
            active_tools: Vec::new(),
            window_60s: ActivityWindowView::default(),
            telemetry_status: TelemetryStatusView::Unavailable,
        };
    };
    TaskActivityView {
        state,
        last_runtime_event_at: snapshot.last_runtime_event_at,
        last_activity_age_ms: snapshot.last_activity_age_ms,
        model_request_active: snapshot.model_request_active,
        model_request_age_ms: snapshot.model_request_age_ms,
        model_last_delta_age_ms: snapshot.model_last_delta_age_ms,
        latest_text_tail: snapshot.latest_text_tail,
        latest_text_updated_at: snapshot.latest_text_updated_at,
        latest_text_truncated: snapshot.latest_text_truncated,
        active_tools: snapshot
            .active_tools
            .into_iter()
            .map(|tool| ActiveToolView {
                tool_call_id: tool.tool_call_id,
                kind: match tool.kind {
                    PassiveToolKind::Read => ActivityToolKindView::Read,
                    PassiveToolKind::Bash => ActivityToolKindView::Bash,
                    PassiveToolKind::Other => ActivityToolKindView::Other,
                },
            })
            .collect(),
        window_60s: activity_window_view(snapshot.window_60s),
        telemetry_status: if snapshot.telemetry_degraded {
            TelemetryStatusView::Degraded
        } else {
            TelemetryStatusView::Healthy
        },
    }
}

fn activity_window_view(value: PassiveActivityWindow) -> ActivityWindowView {
    ActivityWindowView {
        reasoning_delta_events: value.reasoning_delta_events,
        reasoning_delta_bytes: value.reasoning_delta_bytes,
        text_delta_events: value.text_delta_events,
        text_delta_bytes: value.text_delta_bytes,
        tool_calls_started: value.tool_calls_started,
        tool_calls_completed: value.tool_calls_completed,
        tool_calls_failed: value.tool_calls_failed,
        read_calls: value.read_calls,
        bash_calls: value.bash_calls,
        other_tool_calls: value.other_tool_calls,
    }
}

fn task_frame_budget_view(job: Job, task: TaskRecord) -> TaskView {
    let mut view = task_view(job, task);
    // Budget against the longest variants and JSON booleans that can be
    // observed if task state changes between page construction and the wait
    // response. Stable identifiers and effective budgets retain their exact
    // serialized representation.
    view.task_kind = "review_continuation".into();
    view.access_mode = "workspace_write".into();
    view.phase = "WAITING_INPUT".into();
    view.independent_evidence = false;
    view.fresh_session_observed = false;
    view.stop_requested = false;
    view.close_requested = false;
    view.closed = false;
    view.reaped = false;
    view
}

impl From<StoredTaskResult> for TaskResultView {
    fn from(stored: StoredTaskResult) -> Self {
        Self {
            outcome: stored.result.outcome,
            summary: stored.result.summary,
            partial: stored.result.partial,
            retained: stored.retained,
            base_commit: stored.result.base_commit,
            head_commit: stored.result.head_commit,
            changed_files: stored.result.changed_files,
            diff_stat: stored.result.diff_stat,
            checks: stored.result.checks,
            residual_gaps: stored.result.residual_gaps,
            artifacts: stored.result.artifacts,
            result_sha256: stored.result_sha256,
            review_evidence: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReviewProgressPayload {
    stage: TaskReviewProgressStage,
    summary: String,
    #[serde(default)]
    counters: Option<BTreeMap<String, u64>>,
    attempt_sequence: u64,
    updated_at: i64,
}

struct ProjectedReviewProgress {
    stage: TaskReviewProgressStage,
    summary: String,
    counters: Option<BTreeMap<String, u64>>,
    last_progress_at: u64,
    semantic_idle_ms: u64,
    nudge_sent: bool,
}

fn project_review_progress(
    task: &TaskRecord,
    event: &StoredEvent,
    state: Option<&ReviewProgressState>,
    wall_now_ms: u64,
) -> Option<ProjectedReviewProgress> {
    if event.redaction_level != "allowlisted" {
        return None;
    }
    let state = state.filter(|state| {
        state.agent_id == task.execution_agent_id && state.attempt_sequence == task.attempt_sequence
    })?;
    let payload = serde_json::from_str::<StoredReviewProgressPayload>(&event.payload_json).ok()?;
    if payload.attempt_sequence != task.attempt_sequence
        || payload.summary.is_empty()
        || payload.summary.chars().count() > MAX_TOOL_TEXT_CHARS
        || payload.summary.contains('\0')
        || payload.counters.as_ref().is_some_and(|counters| {
            counters.len() > 16
                || counters.iter().any(|(key, value)| {
                    key.is_empty()
                        || key.len() > MAX_TOOL_ID_BYTES
                        || !key
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
                        || *value > 1_000_000_000
                })
        })
    {
        return None;
    }
    let last_progress_at = u64::try_from(payload.updated_at).ok()?;
    Some(ProjectedReviewProgress {
        stage: payload.stage,
        summary: payload.summary,
        counters: payload.counters,
        last_progress_at,
        semantic_idle_ms: wall_now_ms.saturating_sub(last_progress_at),
        nudge_sent: state.nudge_sent,
    })
}

fn wall_now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn public_pending_request_id(event: &StoredEvent) -> Option<String> {
    if event.event_type != "driver.message" {
        return None;
    }
    serde_json::from_str::<Value>(&event.payload_json)
        .ok()?
        .get("request_id")?
        .as_str()
        .filter(|request_id| !request_id.is_empty() && request_id.len() <= 256)
        .map(str::to_owned)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn task_page_from_events(
    after: u64,
    limit: usize,
    projected: Vec<TaskEventView>,
    frame_budget_task: &TaskView,
) -> Result<TaskEventPage, RpcError> {
    let start = usize::try_from(after).unwrap_or(usize::MAX);
    if start >= projected.len() {
        return Ok(TaskEventPage {
            events: Vec::new(),
            next_sequence: after,
            has_more: false,
        });
    }
    let mut events = Vec::new();
    let mut payload_bytes = 0usize;
    let remaining = projected.len() - start;
    let mut has_more = remaining > limit;
    for event in projected.into_iter().skip(start).take(limit) {
        if event.payload_json.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(RpcError::new(
                RpcErrorCode::Oversized,
                "stored event payload exceeds the transport cap",
            ));
        }
        let next_bytes = payload_bytes.saturating_add(event.payload_json.len());
        if next_bytes > MAX_PAGE_PAYLOAD_BYTES {
            has_more = true;
            break;
        }
        let mut candidate_events = events.clone();
        candidate_events.push(event.clone());
        let candidate = TaskEventPage {
            next_sequence: event.sequence,
            events: candidate_events,
            // `false` is one byte longer than `true`, so it is the
            // conservative value for the transport-frame calculation.
            has_more: false,
        };
        if !task_page_fits_frame(frame_budget_task, &candidate)? {
            if events.is_empty() {
                return Err(RpcError::new(
                    RpcErrorCode::Oversized,
                    "projected public event exceeds the RPC frame cap",
                ));
            }
            has_more = true;
            break;
        }
        payload_bytes = next_bytes;
        events.push(event);
    }
    Ok(TaskEventPage {
        next_sequence: events.last().map(|event| event.sequence).unwrap_or(after),
        events,
        has_more,
    })
}

fn task_page_fits_frame(
    frame_budget_task: &TaskView,
    page: &TaskEventPage,
) -> Result<bool, RpcError> {
    let request_id = "\u{1}".repeat(MAX_REQUEST_ID_BYTES);
    let response = RpcResponse::success(
        request_id,
        RpcSuccess::TaskWait {
            task: frame_budget_task.clone(),
            page: page.clone(),
            // `false` is the longer JSON boolean and therefore the
            // conservative representation.
            timed_out: false,
        },
    );
    serde_json::to_vec(&response)
        .map(|frame| frame.len() <= MAX_FRAME_BYTES)
        .map_err(|_| {
            RpcError::new(
                RpcErrorCode::Internal,
                "public event page could not be serialized",
            )
        })
}

fn artifact_view(artifact: StoredArtifact, requested: usize) -> ArtifactView {
    let preview_state = if requested == 0 {
        PreviewState::NotRequested
    } else {
        PreviewState::Unavailable
    };
    ArtifactView {
        artifact_id: artifact.artifact_id,
        artifact_type: artifact.artifact_type,
        locator: artifact.path,
        expected_sha256: Some(artifact.sha256),
        expected_bytes: Some(artifact.bytes),
        observed_sha256: None,
        observed_bytes: None,
        checkpoint_number: artifact.checkpoint_number,
        finalized: false,
        integrity: ArtifactIntegrityView::LegacyUnverified,
        preview_state,
        preview: None,
    }
}

fn verified_artifact_view(artifact: VerifiedArtifact, requested: usize) -> ArtifactView {
    let preview_state = if requested == 0 {
        PreviewState::NotRequested
    } else if artifact.preview.is_some() {
        PreviewState::Available
    } else {
        PreviewState::Unavailable
    };
    ArtifactView {
        artifact_id: "review-report".into(),
        artifact_type: "review_report".into(),
        locator: artifact.locator,
        expected_sha256: artifact.expected_sha256,
        expected_bytes: artifact.expected_bytes,
        observed_sha256: artifact.actual_sha256,
        observed_bytes: artifact.actual_bytes,
        checkpoint_number: Some(artifact.checkpoint_number),
        finalized: artifact.finalized,
        integrity: artifact.integrity.into(),
        preview_state,
        preview: artifact.preview,
    }
}

fn pending_request_view(
    policy: Option<&review_preparation::PolicyLauncher>,
    request: StoredPendingRequest,
) -> PendingRequestView {
    let state = match request.state {
        PendingRequestState::Pending => PendingRequestStateView::Pending,
        PendingRequestState::Sending => PendingRequestStateView::Sending,
        PendingRequestState::Responded => PendingRequestStateView::Responded,
    };
    if request.request_type != "permission" {
        return PendingRequestView {
            request_id: request.request_id,
            kind: "unsupported_input".into(),
            state,
            respondable: false,
            tool_name: None,
            operation: "user_input".into(),
            summary: "unsupported user input request".into(),
            policy_preview: "unknown".into(),
        };
    }
    let params = serde_json::from_str::<Value>(&request.payload_json).ok();
    let tool_name = params
        .as_ref()
        .and_then(|value| value.get("toolName"))
        .and_then(Value::as_str)
        .map(|value| value.chars().take(64).collect::<String>());
    let operation = tool_name
        .as_deref()
        .map(operation_category)
        .unwrap_or("unknown")
        .to_owned();
    let summary = params
        .as_ref()
        .map(sanitized_permission_summary)
        .unwrap_or_else(|| "unrecognized permission request".into());
    let policy_preview = params
        .as_ref()
        .and_then(|params| {
            let decision = policy?
                .decide_zcode_permission(params, review_preparation::ExternalDecision::Allow);
            Some(if decision.allowed {
                "externally_decidable"
            } else {
                "hard_deny"
            })
        })
        .unwrap_or("unknown")
        .to_owned();
    PendingRequestView {
        request_id: request.request_id,
        kind: "permission".into(),
        state,
        respondable: true,
        tool_name,
        operation,
        summary,
        policy_preview,
    }
}

fn operation_category(tool_name: &str) -> &'static str {
    match tool_name.to_ascii_lowercase().as_str() {
        "read" | "grep" | "glob" => "read",
        "write" | "edit" | "delete" | "move" => "write",
        "execute" | "terminal" => "command",
        "network" => "network",
        "git_ref_mutation" => "git_ref_mutation",
        _ => "unknown",
    }
}

fn sanitized_permission_summary(params: &Value) -> String {
    let input = params.get("input").unwrap_or(&Value::Null);
    let leaf = |name: &str| {
        input
            .get(name)
            .and_then(Value::as_str)
            .and_then(|value| std::path::Path::new(value).file_name())
            .map(|value| value.to_string_lossy().chars().take(96).collect::<String>())
    };
    if let Some(program) = leaf("program") {
        let count = input
            .get("args")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0);
        return format!("command {program} with {count} arguments");
    }
    if let Some(path) = leaf("path")
        .or_else(|| leaf("destination"))
        .or_else(|| leaf("source"))
    {
        return format!("target {path}");
    }
    if params
        .get("toolName")
        .and_then(Value::as_str)
        .is_some_and(|name| name.eq_ignore_ascii_case("git_ref_mutation"))
    {
        return "Git reference mutation".into();
    }
    "permission request".into()
}

fn validate_id(value: &str, field: &str) -> Result<(), RpcError> {
    validate_text(value, field, 256)
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_REQUEST_ID_BYTES && !value.contains('\0')
}

fn wait_timeout() -> RpcError {
    RpcError::new(RpcErrorCode::Timeout, "wait deadline elapsed")
}

fn wait_timed_out(job: Job, after: u64) -> RpcSuccess {
    RpcSuccess::Wait {
        job: job.into(),
        page: EventPage {
            runtime_agent_id: None,
            events: Vec::new(),
            next_sequence: after,
            has_more: false,
        },
        timed_out: true,
    }
}

fn page_from_events(
    runtime_agent_id: Option<String>,
    after: u64,
    limit: usize,
    stored: Vec<StoredEvent>,
) -> Result<EventPage, RpcError> {
    let mut events = Vec::new();
    let mut payload_bytes = 0usize;
    let mut has_more = stored.len() > limit;
    for event in stored.into_iter().take(limit) {
        if event.payload_json.len() > MAX_EVENT_PAYLOAD_BYTES {
            return Err(RpcError::new(
                RpcErrorCode::Oversized,
                "stored event payload exceeds the transport cap",
            ));
        }
        let next_bytes = payload_bytes.saturating_add(event.payload_json.len());
        if next_bytes > MAX_PAGE_PAYLOAD_BYTES {
            has_more = true;
            break;
        }
        payload_bytes = next_bytes;
        events.push(event.into());
    }
    let next_sequence = events
        .last()
        .map(|event: &EventView| event.sequence)
        .unwrap_or(after);
    Ok(EventPage {
        runtime_agent_id,
        events,
        next_sequence,
        has_more,
    })
}

fn validate_text(value: &str, field: &str, max: usize) -> Result<(), RpcError> {
    if value.is_empty() || value.len() > max || value.contains('\0') {
        return Err(RpcError::new(
            RpcErrorCode::Validation,
            format!("{field} is invalid"),
        ));
    }
    Ok(())
}

fn validate_command_ids(values: &[String], field: &str) -> Result<(), RpcError> {
    if values.len() > 128 {
        return Err(RpcError::new(
            RpcErrorCode::Validation,
            format!("{field} exceeds the selection cap"),
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for value in values {
        if value.is_empty()
            || value.len() > 256
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
            || !seen.insert(value)
        {
            return Err(RpcError::new(
                RpcErrorCode::Validation,
                format!("{field} must contain exact unique command ids"),
            ));
        }
    }
    Ok(())
}

fn map_scheduler(error: SchedulerError) -> RpcError {
    match error {
        SchedulerError::Store(error) => map_store(error),
        SchedulerError::InvalidConfig(_) => {
            RpcError::new(RpcErrorCode::Validation, "scheduler rejected the operation")
        }
        SchedulerError::RuntimeSpawn { .. } | SchedulerError::LifecycleSink { .. } => {
            RpcError::new(RpcErrorCode::RuntimeLost, "runtime operation failed")
        }
        SchedulerError::RuntimeCommand { .. } => {
            RpcError::new(RpcErrorCode::Unavailable, "runtime command failed")
        }
    }
}

fn map_orchestration(error: OrchestrationError) -> RpcError {
    match error {
        OrchestrationError::Contract("REVIEW_BASH_POLICY_UNVERIFIED") => {
            RpcError::new(RpcErrorCode::Validation, "REVIEW_BASH_POLICY_UNVERIFIED")
        }
        OrchestrationError::Contract(_) => RpcError::new(
            RpcErrorCode::Validation,
            "structured review fields are invalid",
        ),
        OrchestrationError::Conflict(_) => RpcError::new(
            RpcErrorCode::Conflict,
            "structured review conflicts with durable state",
        ),
        OrchestrationError::Preparation(message) if message.contains("idempotency conflict") => {
            RpcError::new(
                RpcErrorCode::Conflict,
                "review submission conflicts with durable state",
            )
        }
        OrchestrationError::Preparation(_) | OrchestrationError::Prompt(_) => RpcError::new(
            RpcErrorCode::Validation,
            "review preparation failed validation",
        ),
        OrchestrationError::Scheduler(error) => map_scheduler(error),
        OrchestrationError::Store(error) => map_store(error),
        OrchestrationError::Unavailable(message) => {
            RpcError::new(RpcErrorCode::Unavailable, message)
        }
    }
}

fn map_store(error: StoreError) -> RpcError {
    match error {
        StoreError::Sqlite(_) => {
            RpcError::new(RpcErrorCode::Persistence, "durable store operation failed")
        }
        StoreError::Conflict(_) => RpcError::new(RpcErrorCode::Conflict, "durable state conflict"),
        StoreError::InvalidState(_) => RpcError::new(
            RpcErrorCode::Validation,
            "durable state rejected the operation",
        ),
    }
}

#[cfg(test)]
mod tests;
