use crate::{MessageDisposition, ResponseDisposition, Scheduler, SchedulerError};
use review_ledger::{ArtifactIntegrity, ToolResult, VerifiedArtifact};
use review_store::{
    DeadlineRead, Job, JobState, NewJob, Store, StoreError, StoredArtifact, StoredEvent, TurnState,
    WaitSnapshot,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

pub const RPC_VERSION: u16 = 3;
pub const MAX_FRAME_BYTES: usize = 128 * 1024;
pub const MAX_PAGE_EVENTS: usize = 100;
pub const MAX_LIST_JOBS: usize = 100;
pub const MAX_EVENT_PAYLOAD_BYTES: usize = 16 * 1024;
pub const MAX_PAGE_PAYLOAD_BYTES: usize = 64 * 1024;
pub const MAX_PREVIEW_BYTES: usize = 8 * 1024;
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
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum RpcMethod {
    Enqueue { job: NewJobInput },
    Start,
    Status { agent_id: String },
    Events(EventQuery),
    Wait(WaitQuery),
    Message(MessageInput),
    Respond(RespondInput),
    Stop { agent_id: String },
    Result(ResultQuery),
    List { limit: usize },
    Close { agent_id: String },
    Reap { agent_id: String },
    ReviewTool(ReviewToolInput),
}

impl RpcMethod {
    fn is_known(name: &str) -> bool {
        matches!(
            name,
            "enqueue"
                | "start"
                | "status"
                | "events"
                | "wait"
                | "message"
                | "respond"
                | "stop"
                | "result"
                | "list"
                | "close"
                | "reap"
                | "review_tool"
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct EventQuery {
    pub agent_id: String,
    #[serde(default)]
    pub runtime_agent_id: Option<String>,
    #[serde(default)]
    pub after: u64,
    pub limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitQuery {
    pub agent_id: String,
    #[serde(default)]
    pub runtime_agent_id: Option<String>,
    #[serde(default)]
    pub after: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageInput {
    pub agent_id: String,
    pub message_id: String,
    pub mode: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    Enqueued {
        job: JobView,
    },
    Started {
        agent_ids: Vec<String>,
    },
    Status {
        job: JobView,
    },
    Events {
        page: EventPage,
    },
    Wait {
        job: JobView,
        page: EventPage,
    },
    Message {
        disposition: MessageDispositionView,
    },
    Respond {
        disposition: ResponseDispositionView,
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
    },
    ReviewTool {
        result: ToolResult,
    },
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
    pub created_at: i64,
}

impl From<Job> for JobView {
    fn from(value: Job) -> Self {
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
    pub sha256: String,
    pub bytes: u64,
    pub checkpoint_number: Option<u64>,
    pub integrity: ArtifactIntegrityView,
    pub preview_state: PreviewState,
    pub preview: Option<String>,
}

#[derive(Clone)]
pub struct RpcService {
    scheduler: Scheduler,
    store: Arc<Store>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcServiceConfigError {
    MismatchedStore,
}

impl RpcService {
    pub fn new(scheduler: Scheduler, store: Arc<Store>) -> Result<Self, RpcServiceConfigError> {
        if !Arc::ptr_eq(&scheduler.store(), &store) {
            return Err(RpcServiceConfigError::MismatchedStore);
        }
        Ok(Self { scheduler, store })
    }

    pub fn handle_bytes(&self, frame: &[u8]) -> RpcResponse {
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
                job: self.require_job(&agent_id)?.into(),
            }),
            RpcMethod::Events(query) => Ok(RpcSuccess::Events {
                page: self.event_page(query)?,
            }),
            RpcMethod::Wait(query) => self.wait(query),
            RpcMethod::Message(input) => {
                self.require_job(&input.agent_id)?;
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
                self.require_job(&input.agent_id)?;
                validate_id(&input.request_id, "request_id")?;
                if let Some(content) = input.content.as_deref() {
                    validate_text(content, "response content", 16 * 1024)?;
                }
                let disposition = self
                    .scheduler
                    .respond_job(
                        &input.agent_id,
                        &input.request_id,
                        input.decision.as_str(),
                        input.content.as_deref(),
                    )
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::Respond {
                    disposition: disposition.into(),
                })
            }
            RpcMethod::Stop { agent_id } => {
                self.require_job(&agent_id)?;
                let state = self.scheduler.stop_job(&agent_id).map_err(map_scheduler)?;
                Ok(RpcSuccess::Stopped {
                    state: state.into(),
                })
            }
            RpcMethod::Result(query) => self.result(query),
            RpcMethod::List { limit } => {
                if limit == 0 || limit > MAX_LIST_JOBS {
                    return Err(RpcError::new(
                        RpcErrorCode::Validation,
                        "list limit is outside the allowed range",
                    ));
                }
                let jobs = self
                    .store
                    .list_jobs(limit)
                    .map_err(map_store)?
                    .into_iter()
                    .map(JobView::from)
                    .collect();
                Ok(RpcSuccess::Listed { jobs })
            }
            RpcMethod::Close { agent_id } => {
                self.require_job(&agent_id)?;
                let state = self.scheduler.close_job(&agent_id).map_err(map_scheduler)?;
                Ok(RpcSuccess::Closed {
                    state: state.into(),
                })
            }
            RpcMethod::Reap { agent_id } => {
                self.require_job(&agent_id)?;
                let state = self.scheduler.reap_job(&agent_id).map_err(map_scheduler)?;
                Ok(RpcSuccess::Reaped {
                    state: state.into(),
                })
            }
            RpcMethod::ReviewTool(input) => {
                self.require_job(&input.agent_id)?;
                validate_text(&input.tool, "review tool", 128)?;
                let result = self
                    .scheduler
                    .call_review_tool(&input.agent_id, &input.tool, input.arguments)
                    .map_err(map_scheduler)?;
                Ok(RpcSuccess::ReviewTool { result })
            }
        }
    }

    fn require_job(&self, agent_id: &str) -> Result<Job, RpcError> {
        validate_id(agent_id, "agent_id")?;
        self.store
            .get_job(agent_id)
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
        let job = self.require_job(&query.agent_id)?;
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
        if let Some(runtime_agent_id) = query.runtime_agent_id.as_deref() {
            validate_id(runtime_agent_id, "runtime_agent_id")?;
        }
        let (initial, initial_page) = self.wait_snapshot(&query, deadline)?;
        if !initial_page.events.is_empty() || initial.state.is_terminal() {
            return Ok(RpcSuccess::Wait {
                job: initial.into(),
                page: initial_page,
            });
        }
        let initial_state = initial.state;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(wait_timeout());
            }
            thread::sleep((deadline - now).min(Duration::from_millis(10)));
            let (job, page) = self.wait_snapshot(&query, deadline)?;
            if !page.events.is_empty() || job.state.is_terminal() || job.state != initial_state {
                return Ok(RpcSuccess::Wait {
                    job: job.into(),
                    page,
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
        let job = self.require_job(&query.agent_id)?;
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
        sha256: artifact.sha256,
        bytes: artifact.bytes,
        checkpoint_number: artifact.checkpoint_number,
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
        sha256: artifact
            .actual_sha256
            .or(artifact.expected_sha256)
            .unwrap_or_default(),
        bytes: artifact
            .actual_bytes
            .or(artifact.expected_bytes)
            .unwrap_or(0),
        checkpoint_number: Some(artifact.checkpoint_number),
        integrity: artifact.integrity.into(),
        preview_state,
        preview: artifact.preview,
    }
}

fn validate_id(value: &str, field: &str) -> Result<(), RpcError> {
    validate_text(value, field, 256)
}

fn valid_request_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.contains('\0')
}

fn wait_timeout() -> RpcError {
    RpcError::new(RpcErrorCode::Timeout, "wait deadline elapsed")
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
