use crate::{
    MessageDisposition, PassiveActivitySnapshot, PassiveActivityWindow, PassiveToolKind,
    ResponseDisposition, Scheduler, SchedulerError,
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
    time::{Duration, Instant},
};
use zcode_agent_preparation::{
    canonical_general_repository, BudgetLimits, GeneralTaskManifest, PreparedGeneralTask,
};
use zcode_agent_store::{
    EffectiveBudget, PendingRequestState, Store, StoreError, StoredArtifact, StoredPendingRequest,
    StoredTaskResult, TaskOutcome, TaskPageFilter, TaskPhase, TaskQueryScope, TaskRecord,
    TaskResult, TaskSubmissionDisposition,
};

pub const RPC_VERSION: u16 = 12;
pub const MAX_FRAME_BYTES: usize = 128 * 1024;
const MAX_REQUEST_ID_BYTES: usize = 128;
pub const MAX_LIST_TASKS: usize = 100;
pub const MAX_PENDING_REQUESTS: usize = 100;
pub const MAX_ARTIFACT_CHUNK_BYTES: usize = 8 * 1024;
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
#[allow(clippy::large_enum_variant)]
pub enum RpcMethod {
    SystemStatus,
    SubmitGeneral { input: GeneralSubmitInput },
    TaskList(TaskListQuery),
    TaskPoll(TaskPollQuery),
    TaskMessage(MessageInput),
    TaskRespond(RespondInput),
    TaskCancel { agent_id: String },
    TaskResult { agent_id: String },
    TaskArtifact(TaskArtifactQuery),
    TaskClose { agent_id: String },
}

impl RpcMethod {
    fn is_known(name: &str) -> bool {
        matches!(
            name,
            "system_status"
                | "submit_general"
                | "task_list"
                | "task_poll"
                | "task_message"
                | "task_respond"
                | "task_cancel"
                | "task_result"
                | "task_artifact"
                | "task_close"
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskListQuery {
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub phase: Option<TaskPhaseFilter>,
    #[serde(default)]
    pub outcome: Option<TaskOutcome>,
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
    pub artifact_id: String,
    pub offset_bytes: u64,
    pub limit_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneralSubmitInput {
    pub manifest: GeneralTaskManifest,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub allowed_command_ids: Vec<String>,
    #[serde(default)]
    pub required_command_ids: Vec<String>,
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
    GeneralSubmitted {
        task: TaskView,
        disposition: SubmissionDispositionView,
    },
    TaskListed {
        tasks: Vec<TaskView>,
        next_cursor: Option<String>,
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
    Message {
        disposition: MessageDispositionView,
        task: TaskView,
    },
    Respond {
        outcome: ResponseOutcomeView,
        task: TaskView,
    },
    Stopped {
        task: TaskView,
    },
    Closed {
        task: TaskView,
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
    pub hard_budget_caps: BudgetLimits,
    pub max_rpc_frame_bytes: usize,
    pub max_wait_ms: u64,
    pub named_checks: bool,
    pub maturity: BTreeMap<String, CapabilityMaturityView>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskView {
    pub agent_id: String,
    pub phase: String,
    pub outcome: Option<TaskOutcome>,
    pub effective_budget: EffectiveBudget,
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
    pub final_text: String,
    pub partial: bool,
    pub retained: bool,
    pub base_commit: Option<String>,
    pub head_commit: Option<String>,
    pub changed_files: Vec<String>,
    pub diff_stat: Option<String>,
    pub checks: Vec<String>,
    pub residual_gaps: Vec<String>,
    pub artifacts: Vec<zcode_agent_store::ResultArtifact>,
    pub result_sha256: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_agent_id: Option<String>,
}

impl RpcError {
    pub fn new(code: RpcErrorCode, message: impl Into<String>) -> Self {
        let mut message = message.into();
        message.truncate(512);
        Self {
            code,
            message,
            active_agent_id: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageDispositionView {
    Queued,
    Delivered,
    AlreadyDelivered,
    Failed,
}

impl From<MessageDisposition> for MessageDispositionView {
    fn from(value: MessageDisposition) -> Self {
        match value {
            MessageDisposition::Queued => Self::Queued,
            MessageDisposition::Delivered => Self::Delivered,
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

#[derive(Clone)]
pub struct RpcService {
    scheduler: Scheduler,
    store: Arc<Store>,
    service_generation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcServiceConfigError {
    MismatchedStore,
    GenerationUnavailable,
}

impl RpcService {
    pub fn new(scheduler: Scheduler, store: Arc<Store>) -> Result<Self, RpcServiceConfigError> {
        let service_generation = opaque_generation()?;
        Self::new_with_service_generation(scheduler, store, service_generation)
    }

    pub(crate) fn new_with_service_generation(
        scheduler: Scheduler,
        store: Arc<Store>,
        service_generation: String,
    ) -> Result<Self, RpcServiceConfigError> {
        if !Arc::ptr_eq(&scheduler.store(), &store) {
            return Err(RpcServiceConfigError::MismatchedStore);
        }
        Ok(Self {
            scheduler,
            store,
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
            RpcMethod::SubmitGeneral { input } => {
                let manifest = input.manifest;
                if let Some(group_id) = input.group_id.as_deref() {
                    validate_text(group_id, "group_id", 256)?;
                }
                validate_command_ids(&input.allowed_command_ids, "allowed_command_ids")?;
                validate_command_ids(&input.required_command_ids, "required_command_ids")?;
                let submitted = self
                    .scheduler
                    .enqueue_general_with_commands(
                        &manifest,
                        input.group_id.as_deref(),
                        &input.allowed_command_ids,
                        &input.required_command_ids,
                    )
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::GeneralSubmitted {
                    task: task_view(submitted.task),
                    disposition: submitted.disposition.into(),
                })
            }
            RpcMethod::TaskList(query) => {
                if query.limit == 0 || query.limit > MAX_LIST_TASKS {
                    return Err(RpcError::new(
                        RpcErrorCode::Validation,
                        "task list limit is outside the allowed range",
                    ));
                }
                for (field, value, cap) in [
                    ("repository", query.repository.as_deref(), 4096usize),
                    ("group_id", query.group_id.as_deref(), 256usize),
                ] {
                    if let Some(value) = value {
                        validate_text(value, field, cap)?;
                    }
                }
                if let Some(cursor) = query.cursor.as_deref() {
                    validate_text(cursor, "cursor", 64)?;
                }
                if query.repository.is_none() && query.group_id.is_none() {
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
                let page = self
                    .store
                    .list_task_page(
                        TaskQueryScope {
                            repository: canonical_repository.as_deref(),
                            group_id: query.group_id.as_deref(),
                        },
                        TaskPageFilter {
                            phase: query.phase.map(Into::into),
                            outcome: query.outcome,
                            access_mode: None,
                        },
                        query.cursor.as_deref().map(parse_task_cursor).transpose()?,
                        query.limit,
                    )
                    .map_err(map_store)?;
                let mut views = Vec::with_capacity(page.tasks.len());
                for task in page.tasks {
                    views.push(task_view(task));
                }
                Ok(RpcSuccess::TaskListed {
                    tasks: views,
                    next_cursor: page.next_cursor.map(format_task_cursor),
                })
            }
            RpcMethod::TaskPoll(query) => self.task_poll(query),
            RpcMethod::TaskMessage(input) => {
                let task = self.require_task(&input.agent_id)?;
                validate_id(&input.message_id, "message_id")?;
                // The generic control plane only queues clarification.  A
                // terminal task must be resumed by creating a new agent;
                // interrupt-and-continue remains a legacy/private path and
                // is intentionally not reachable through TaskMessage.
                if input.mode != "queue" {
                    return Err(RpcError::new(
                        RpcErrorCode::Validation,
                        "generic agent messages must use queue mode",
                    ));
                }
                validate_text(&input.content, "content", 16 * 1024)?;
                let disposition = self
                    .scheduler
                    .queue_message(
                        &task.agent_id,
                        &input.message_id,
                        &input.mode,
                        &input.content,
                    )
                    .map_err(map_scheduler)?;
                let task = self.require_task(&input.agent_id)?;
                Ok(RpcSuccess::Message {
                    disposition: disposition.into(),
                    task: task_view(task),
                })
            }
            RpcMethod::TaskRespond(input) => {
                let task = self.require_task(&input.agent_id)?;
                validate_id(&input.request_id, "request_id")?;
                if let Some(content) = input.content.as_deref() {
                    validate_text(content, "response content", 16 * 1024)?;
                }
                let outcome = self
                    .scheduler
                    .respond_request(
                        &task.agent_id,
                        &input.request_id,
                        input.decision.as_str(),
                        input.content.as_deref(),
                    )
                    .map_err(map_scheduler)?;
                let task = self.require_task(&input.agent_id)?;
                Ok(RpcSuccess::Respond {
                    outcome: outcome.into(),
                    task: task_view(task),
                })
            }
            RpcMethod::TaskCancel { agent_id } => {
                let task = self.require_task(&agent_id)?;
                self.scheduler
                    .cancel_task(&task.agent_id)
                    .map_err(map_scheduler)?;
                let task = self.require_task(&agent_id)?;
                Ok(RpcSuccess::Stopped {
                    task: task_view(task),
                })
            }
            RpcMethod::TaskResult { agent_id } => {
                let task = self.require_task(&agent_id)?;
                let artifacts = self.task_artifact_metadata(&task)?;
                let result = self
                    .store
                    .task_result(&task.agent_id)
                    .map_err(map_store)?
                    .map(|stored| self.task_result_view(stored))
                    .transpose()?;
                Ok(RpcSuccess::TaskResult {
                    task: task_view(task),
                    result,
                    artifacts,
                })
            }
            RpcMethod::TaskArtifact(query) => {
                let task = self.require_task(&query.agent_id)?;
                Ok(RpcSuccess::TaskArtifact {
                    chunk: self.task_artifact_chunk(&task, &query)?,
                })
            }
            RpcMethod::TaskClose { agent_id } => {
                let task = self.require_task(&agent_id)?;
                self.scheduler
                    .close_task(&task.agent_id)
                    .map_err(map_scheduler)?;
                let task = self.require_task(&agent_id)?;
                Ok(RpcSuccess::Closed {
                    task: task_view(task),
                })
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
            api_surface: "generic_agent".into(),
            protocol_version: RPC_VERSION,
            service_generation: self.service_generation.clone(),
            components,
            capabilities: agent_capabilities(self.scheduler.named_checks_enabled()),
        }
    }

    fn require_task(&self, agent_id: &str) -> Result<TaskRecord, RpcError> {
        validate_id(agent_id, "agent_id")?;
        let task = self
            .store
            .get_task(agent_id)
            .map_err(map_store)?
            .ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "task was not found"))?;
        let prepared = serde_json::from_str::<PreparedGeneralTask>(&task.prepared_launch_json)
            .map_err(|_| RpcError::new(RpcErrorCode::NotFound, "task was not found"))?;
        if prepared.repository.to_string_lossy() != task.repository {
            return Err(RpcError::new(RpcErrorCode::NotFound, "task was not found"));
        }
        Ok(task)
    }

    fn task_artifact_metadata(
        &self,
        task: &TaskRecord,
    ) -> Result<Vec<TaskArtifactMetadataView>, RpcError> {
        let result = self.store.task_result(&task.agent_id).map_err(map_store)?;
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
            .artifacts(&task.agent_id, MAX_PENDING_REQUESTS)
            .map_err(map_store)?
        {
            let permitted = allowed
                .get(artifact.artifact_id.as_str())
                .is_some_and(|sha| *sha == artifact.sha256);
            if permitted {
                projected.push(TaskArtifactMetadataView {
                    artifact_id: artifact.artifact_id,
                    kind: public_artifact_kind(&artifact.artifact_type)?.into(),
                    sha256: artifact.sha256,
                    size_bytes: artifact.bytes,
                });
            }
        }
        projected.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
        Ok(projected)
    }

    fn task_result_view(&self, stored: StoredTaskResult) -> Result<TaskResultView, RpcError> {
        Ok(TaskResultView::from(stored))
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
            .artifacts(&task.agent_id, MAX_PENDING_REQUESTS)
            .map_err(map_store)?
            .into_iter()
            .find(|artifact| artifact.artifact_id == query.artifact_id)
            .ok_or_else(|| RpcError::new(RpcErrorCode::NotFound, "artifact was not found"))?;
        verified_artifact_chunk(stored, expected, query.offset_bytes, query.limit_bytes)
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
            let task = self.require_task(&query.agent_id)?;
            let policy = self.scheduler.active_policy(&task.agent_id);
            let pending_requests = self
                .store
                .pending_requests_bounded(&task.agent_id, MAX_PENDING_REQUESTS)
                .map_err(map_store)?
                .into_iter()
                .map(|request| pending_request_view(policy.as_deref(), request))
                .collect::<Vec<_>>();
            let result_available = self
                .store
                .task_result(&task.agent_id)
                .map_err(map_store)?
                .is_some();
            let activity = self.scheduler.passive_activity_snapshot(&task.agent_id);
            let revision = activity
                .as_ref()
                .map(|activity| activity.revision)
                .unwrap_or(0)
                .max(task.last_event_seq);
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
                    task: task_view(task),
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
}

fn opaque_generation() -> Result<String, RpcServiceConfigError> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| RpcServiceConfigError::GenerationUnavailable)?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn agent_capabilities(named_checks: bool) -> AgentCapabilitiesView {
    let maturity = BTreeMap::new();
    AgentCapabilitiesView {
        hard_budget_caps: BudgetLimits {
            absolute_wall_time_ms: 86_400_000,
            runtime_activity_idle_timeout_ms: 86_400_000,
            model_stream_idle_timeout_ms: 86_400_000,
            tool_call_timeout_ms: 86_400_000,
            input_wait_timeout_ms: 86_400_000,
            max_turns: 1_024,
            max_tool_calls: 4_096,
            max_context_bytes: 16_777_216,
            max_result_bytes: 16_777_216,
            max_artifact_bytes: 268_435_456,
        },
        max_rpc_frame_bytes: MAX_FRAME_BYTES,
        max_wait_ms: MAX_WAIT.as_millis() as u64,
        named_checks,
        maturity,
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

fn public_artifact_kind(stored: &str) -> Result<&'static str, RpcError> {
    match stored {
        "changes_patch" => Ok("changes_patch"),
        _ => Err(RpcError::new(
            RpcErrorCode::ResultInvalid,
            "stored artifact kind is not supported",
        )),
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

fn task_view(task: TaskRecord) -> TaskView {
    TaskView {
        agent_id: task.agent_id,
        phase: match task.phase {
            TaskPhase::Queued => "QUEUED",
            TaskPhase::Preparing => "PREPARING",
            TaskPhase::Running => "RUNNING",
            TaskPhase::WaitingInput => "WAITING_INPUT",
            TaskPhase::Cancelling => "CANCELLING",
            TaskPhase::Terminal => "TERMINAL",
        }
        .into(),
        outcome: task.outcome,
        effective_budget: task.effective_budget,
        stop_requested: task.stop_requested,
        close_requested: task.close_requested,
        closed: task.closed_at.is_some(),
        reaped: task.reaped_at.is_some(),
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

impl From<StoredTaskResult> for TaskResultView {
    fn from(stored: StoredTaskResult) -> Self {
        Self {
            outcome: stored.result.outcome,
            final_text: stored.result.final_text,
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
        }
    }
}

pub(crate) fn terminal_result_response_fits(
    task: &TaskRecord,
    result: &TaskResult,
    artifacts: &[TaskArtifactMetadataView],
) -> bool {
    let worst_case_request_id = "\u{1}".repeat(MAX_REQUEST_ID_BYTES);
    terminal_result_response_size(task, result, artifacts, &worst_case_request_id)
        .is_some_and(|size| size <= MAX_FRAME_BYTES)
}

fn terminal_result_response_size(
    task: &TaskRecord,
    result: &TaskResult,
    artifacts: &[TaskArtifactMetadataView],
    request_id: &str,
) -> Option<usize> {
    let mut task = task_view(task.clone());
    task.phase = "TERMINAL".into();
    task.outcome = Some(result.outcome);
    let response = RpcResponse::success(
        request_id.into(),
        RpcSuccess::TaskResult {
            task,
            result: Some(TaskResultView::from(StoredTaskResult {
                result: result.clone(),
                result_sha256: "0".repeat(64),
                // `false` is the longer JSON spelling, so this remains safe
                // for both retained and non-retained terminal results.
                retained: false,
            })),
            artifacts: artifacts.to_vec(),
        },
    );
    serde_json::to_vec(&response).ok().map(|frame| frame.len())
}

fn pending_request_view(
    policy: Option<&zcode_agent_preparation::PolicyLauncher>,
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
                .decide_zcode_permission(params, zcode_agent_preparation::ExternalDecision::Allow);
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

fn map_store(error: StoreError) -> RpcError {
    match error {
        StoreError::LegacySchemaUnsupported => RpcError::new(
            RpcErrorCode::Persistence,
            "STORE_SCHEMA_VERSION_UNSUPPORTED",
        ),
        StoreError::Sqlite(_) => {
            RpcError::new(RpcErrorCode::Persistence, "durable store operation failed")
        }
        StoreError::Conflict(message) if message.starts_with("WORKSPACE_BUSY") => {
            let active_agent_id = message
                .strip_prefix("WORKSPACE_BUSY active_agent_id=")
                .map(str::to_owned);
            let mut error = RpcError::new(RpcErrorCode::Conflict, "WORKSPACE_BUSY");
            error.active_agent_id = active_agent_id;
            error
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
