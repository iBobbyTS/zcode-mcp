use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerInfo},
    tool, tool_handler, tool_router, Json, ServerHandler, ServiceExt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use zcode_reviewd::rpc::{
    ArtifactView, EventPage, JobListScopeView, JobStateView, JobView, MessageDispositionView,
    MessageInput, PendingRequestView, RespondInput, ResponseDecision, ResponseOutcomeView,
    ResultQuery, RpcClient, RpcError, RpcErrorCode, RpcMethod, RpcOutcome, RpcRequest, RpcSuccess,
    TurnStateView, WaitQuery, RPC_VERSION,
};

pub mod v2;
pub use v2::{SubagentMcp, V2_PUBLIC_TOOLS};

pub const PUBLIC_TOOLS: [&str; 10] = [
    "zcode_review_spawn",
    "zcode_review_status",
    "zcode_review_events",
    "zcode_review_wait",
    "zcode_review_message",
    "zcode_review_respond",
    "zcode_review_stop",
    "zcode_review_result",
    "zcode_review_list",
    "zcode_review_close",
];
const MAX_MANIFEST_BYTES: u64 = 128 * 1024;
const MAX_REASON_BYTES: usize = 2048;

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicCapabilities {
    pub queue_message: bool,
    pub interrupt_and_continue: bool,
    pub permission_response: bool,
    pub user_input_response: bool,
    pub live_steer: bool,
    pub resume: bool,
    pub stop: bool,
    pub close: bool,
    pub event_page_max: u16,
    pub wait_max_ms: u16,
    pub report_preview_max_bytes: u16,
}
impl Default for PublicCapabilities {
    fn default() -> Self {
        Self {
            queue_message: true,
            interrupt_and_continue: true,
            permission_response: true,
            user_input_response: false,
            live_steer: false,
            resume: false,
            stop: true,
            close: true,
            event_page_max: 100,
            wait_max_ms: 5000,
            report_preview_max_bytes: 8192,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicJobState {
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

impl From<JobStateView> for PublicJobState {
    fn from(value: JobStateView) -> Self {
        match value {
            JobStateView::Queued => Self::Queued,
            JobStateView::Starting => Self::Starting,
            JobStateView::Running => Self::Running,
            JobStateView::Stopping => Self::Stopping,
            JobStateView::Completed => Self::Completed,
            JobStateView::Cancelled => Self::Cancelled,
            JobStateView::Failed => Self::Failed,
            JobStateView::FailedRuntimeLost => Self::FailedRuntimeLost,
            JobStateView::Orphaned => Self::Orphaned,
            JobStateView::Closed => Self::Closed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PublicTurnState {
    Idle,
    Active,
    Failed,
}

impl From<TurnStateView> for PublicTurnState {
    fn from(value: TurnStateView) -> Self {
        match value {
            TurnStateView::Idle => Self::Idle,
            TurnStateView::Active => Self::Active,
            TurnStateView::Failed => Self::Failed,
        }
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicJob {
    pub agent_id: String,
    pub state: PublicJobState,
    pub turn_state: PublicTurnState,
    pub review_kind: Option<String>,
    pub feature_id: Option<String>,
    pub section_id: Option<String>,
    pub round_kind: Option<String>,
    pub created_at_ms: i64,
    pub last_event_sequence: u64,
    pub zcode_session_id: Option<String>,
    pub fresh_session_observed: bool,
    pub failure_code: Option<String>,
    pub manifest_sha256: Option<String>,
    pub prepared_sha256: Option<String>,
    pub prompt_sha256: String,
    pub base_sha: Option<String>,
    pub head_sha: Option<String>,
    pub requested_model: Option<String>,
    pub resources_reaped: bool,
    pub capabilities: PublicCapabilities,
}
impl From<JobView> for PublicJob {
    fn from(job: JobView) -> Self {
        let provenance = job.provenance;
        Self {
            agent_id: job.agent_id,
            state: job.state.into(),
            turn_state: job.turn_state.into(),
            review_kind: job.review_kind,
            feature_id: job.feature_id,
            section_id: job.section_id,
            round_kind: job.round_kind,
            created_at_ms: job.created_at,
            last_event_sequence: job.last_event_seq,
            zcode_session_id: job.zcode_session_id,
            fresh_session_observed: job.capabilities.independent_session_observed,
            failure_code: job.failure_code,
            manifest_sha256: provenance.as_ref().map(|v| v.manifest_sha256.clone()),
            prepared_sha256: provenance.as_ref().map(|v| v.prepared_sha256.clone()),
            prompt_sha256: job.prompt_sha256,
            base_sha: provenance.as_ref().map(|v| v.base_sha.clone()),
            head_sha: provenance.as_ref().map(|v| v.head_sha.clone()),
            requested_model: provenance.and_then(|v| v.requested_model),
            resources_reaped: job.reaped,
            capabilities: PublicCapabilities::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicPendingKind {
    Permission,
    UnsupportedInput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicPendingState {
    Pending,
    Sending,
    Responded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicPolicyPreview {
    ExternallyDecidable,
    HardDeny,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicOperation {
    Read,
    Write,
    Command,
    Network,
    GitRefMutation,
    UserInput,
    Unknown,
}

#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicPendingRequest {
    pub request_id: String,
    pub kind: PublicPendingKind,
    pub state: PublicPendingState,
    pub respondable: bool,
    pub tool_name: Option<String>,
    pub operation: PublicOperation,
    pub summary: String,
    pub policy_preview: PublicPolicyPreview,
}
impl From<PendingRequestView> for PublicPendingRequest {
    fn from(v: PendingRequestView) -> Self {
        Self {
            request_id: v.request_id,
            kind: if v.kind == "permission" {
                PublicPendingKind::Permission
            } else {
                PublicPendingKind::UnsupportedInput
            },
            state: match v.state {
                zcode_reviewd::rpc::PendingRequestStateView::Pending => PublicPendingState::Pending,
                zcode_reviewd::rpc::PendingRequestStateView::Sending => PublicPendingState::Sending,
                zcode_reviewd::rpc::PendingRequestStateView::Responded => {
                    PublicPendingState::Responded
                }
            },
            respondable: v.respondable,
            tool_name: v.tool_name,
            operation: match v.operation.as_str() {
                "read" => PublicOperation::Read,
                "write" => PublicOperation::Write,
                "command" => PublicOperation::Command,
                "network" => PublicOperation::Network,
                "git_ref_mutation" => PublicOperation::GitRefMutation,
                "user_input" => PublicOperation::UserInput,
                _ => PublicOperation::Unknown,
            },
            summary: v.summary,
            policy_preview: match v.policy_preview.as_str() {
                "externally_decidable" => PublicPolicyPreview::ExternallyDecidable,
                "hard_deny" => PublicPolicyPreview::HardDeny,
                _ => PublicPolicyPreview::Unknown,
            },
        }
    }
}
#[derive(Debug, Clone, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct PublicEvent {
    pub sequence: u64,
    pub event_type: String,
    pub redaction_level: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SpawnInput {
    pub manifest_path: String,
}
#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct SpawnOutput {
    pub agent_id: String,
    pub submission_disposition: SubmissionDisposition,
    pub state: PublicJobState,
    pub last_event_sequence: u64,
    pub prompt_sha256: String,
    pub capabilities: PublicCapabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionDisposition {
    Created,
    ExistingCompatible,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentInput {
    pub agent_id: String,
}
#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct StatusOutput {
    pub job: PublicJob,
    pub pending_requests: Vec<PublicPendingRequest>,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventsInput {
    pub agent_id: String,
    pub after_sequence: u64,
    #[schemars(range(min = 1, max = 100))]
    pub limit: usize,
}
#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct EventsOutput {
    pub events: Vec<PublicEvent>,
    pub next_sequence: u64,
    pub has_more: bool,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WaitInput {
    pub agent_id: String,
    pub after_sequence: u64,
    #[schemars(range(min = 1, max = 5000))]
    pub timeout_ms: u64,
}
#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct WaitOutput {
    pub job: PublicJob,
    pub events: Vec<PublicEvent>,
    pub timed_out: bool,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicMessageMode {
    Queue,
    InterruptAndContinue,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MessageInputPublic {
    pub agent_id: String,
    pub message_id: String,
    pub mode: PublicMessageMode,
    pub content: String,
}
#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct MessageOutput {
    pub disposition: PublicMessageDisposition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicMessageDisposition {
    Queued,
    Delivered,
    InterruptedThenDelivered,
    AlreadyDelivered,
    Failed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicDecision {
    Allow,
    Deny,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RespondInputPublic {
    pub agent_id: String,
    pub request_id: String,
    pub decision: PublicDecision,
    pub reason: Option<String>,
}
#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct RespondOutput {
    pub disposition: PublicResponseDisposition,
    pub requested_decision: PublicDecision,
    pub effective_decision: PublicDecision,
    pub policy_overrode: bool,
    pub policy_reason_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicResponseDisposition {
    Responded,
    AlreadyResponded,
    InFlight,
}

#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct StateOutput {
    pub agent_id: String,
    pub state: PublicJobState,
    pub resources_reaped: bool,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultInput {
    pub agent_id: String,
    #[schemars(range(min = 0, max = 8192))]
    pub preview_bytes: usize,
}
#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct ReportSummary {
    pub finalized: bool,
    pub integrity: PublicArtifactIntegrity,
    pub expected_sha256: Option<String>,
    pub observed_sha256: Option<String>,
    pub expected_bytes: Option<u64>,
    pub observed_bytes: Option<u64>,
    pub checkpoint_number: Option<u64>,
    pub preview: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicArtifactIntegrity {
    Valid,
    Missing,
    Replaced,
    Binary,
    Invalid,
    LegacyUnverified,
}
#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct ResultOutput {
    pub job: PublicJob,
    pub report: Option<ReportSummary>,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PublicListScope {
    Active,
    Recent,
    All,
}
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListInput {
    pub scope: PublicListScope,
    #[schemars(range(min = 1, max = 100))]
    pub limit: usize,
}
#[derive(Debug, Serialize, JsonSchema)]
#[schemars(deny_unknown_fields)]
pub struct ListOutput {
    pub jobs: Vec<PublicJob>,
}

#[derive(Debug, Clone)]
pub struct ReviewMcp {
    socket: PathBuf,
    timeout: Duration,
    next_request: Arc<AtomicU64>,
    tool_router: ToolRouter<Self>,
}
impl ReviewMcp {
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
            request_id: format!("mcp-{}", self.next_request.fetch_add(1, Ordering::Relaxed)),
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
    fn job_with_pending(&self, id: &str) -> Result<StatusOutput, String> {
        let job = match self.rpc(RpcMethod::Status {
            agent_id: id.into(),
        })? {
            RpcSuccess::Status { job } => job.into(),
            _ => return Err(protocol_error()),
        };
        let pending_requests = match self.rpc(RpcMethod::Pending {
            agent_id: id.into(),
        })? {
            RpcSuccess::Pending { requests } => requests.into_iter().map(Into::into).collect(),
            _ => return Err(protocol_error()),
        };
        Ok(StatusOutput {
            job,
            pending_requests,
        })
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for ReviewMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions("Stateless facade for durable local ZCode review jobs")
    }
}

#[tool_router(router = tool_router)]
impl ReviewMcp {
    #[tool(
        name = "zcode_review_spawn",
        description = "Submit a validated review manifest",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn spawn(
        &self,
        Parameters(i): Parameters<SpawnInput>,
    ) -> Result<Json<SpawnOutput>, String> {
        let manifest = read_manifest(Path::new(&i.manifest_path))?;
        match self.rpc(RpcMethod::SubmitReview { manifest })? {
            RpcSuccess::ReviewSubmitted {
                job,
                prompt_sha256,
                resumed_existing,
                ..
            } => Ok(Json(SpawnOutput {
                agent_id: job.agent_id,
                submission_disposition: if resumed_existing {
                    SubmissionDisposition::ExistingCompatible
                } else {
                    SubmissionDisposition::Created
                },
                state: job.state.into(),
                last_event_sequence: job.last_event_seq,
                prompt_sha256,
                capabilities: PublicCapabilities::default(),
            })),
            _ => Err(protocol_error()),
        }
    }
    #[tool(
        name = "zcode_review_status",
        description = "Read review job status",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn status(
        &self,
        Parameters(i): Parameters<AgentInput>,
    ) -> Result<Json<StatusOutput>, String> {
        self.job_with_pending(&i.agent_id).map(Json)
    }
    #[tool(
        name = "zcode_review_events",
        description = "Read an ordered page of review events",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn events(
        &self,
        Parameters(i): Parameters<EventsInput>,
    ) -> Result<Json<EventsOutput>, String> {
        if !(1..=100).contains(&i.limit) {
            return Err("validation: limit must be between 1 and 100".into());
        }
        match self.rpc(RpcMethod::Events(zcode_reviewd::rpc::EventQuery {
            agent_id: i.agent_id,
            runtime_agent_id: None,
            after: i.after_sequence,
            limit: i.limit,
        }))? {
            RpcSuccess::Events { page } => Ok(Json(project_events(page))),
            _ => Err(protocol_error()),
        }
    }
    #[tool(
        name = "zcode_review_wait",
        description = "Wait boundedly for a review job change",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn wait(&self, Parameters(i): Parameters<WaitInput>) -> Result<Json<WaitOutput>, String> {
        if !(1..=5000).contains(&i.timeout_ms) {
            return Err("validation: timeout_ms must be between 1 and 5000".into());
        }
        match self.rpc(RpcMethod::Wait(WaitQuery {
            agent_id: i.agent_id,
            runtime_agent_id: None,
            after: i.after_sequence,
            timeout_ms: i.timeout_ms,
        }))? {
            RpcSuccess::Wait {
                job,
                page,
                timed_out,
            } => Ok(Json(WaitOutput {
                job: job.into(),
                events: project_events(page).events,
                timed_out,
            })),
            _ => Err(protocol_error()),
        }
    }
    #[tool(
        name = "zcode_review_message",
        description = "Queue or interrupt then queue a review instruction",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn message(
        &self,
        Parameters(i): Parameters<MessageInputPublic>,
    ) -> Result<Json<MessageOutput>, String> {
        let mode = match i.mode {
            PublicMessageMode::Queue => "queue",
            PublicMessageMode::InterruptAndContinue => "interrupt_and_continue",
        };
        match self.rpc(RpcMethod::Message(MessageInput {
            agent_id: i.agent_id,
            message_id: i.message_id,
            mode: mode.into(),
            content: i.content,
        }))? {
            RpcSuccess::Message { disposition } => Ok(Json(MessageOutput {
                disposition: disposition.into(),
            })),
            _ => Err(protocol_error()),
        }
    }
    #[tool(
        name = "zcode_review_respond",
        description = "Respond to a pending permission request",
        annotations(
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn respond(
        &self,
        Parameters(i): Parameters<RespondInputPublic>,
    ) -> Result<Json<RespondOutput>, String> {
        let decision = match i.decision {
            PublicDecision::Allow => ResponseDecision::Allow,
            PublicDecision::Deny => ResponseDecision::Deny,
        };
        if i.reason
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > MAX_REASON_BYTES || v.contains('\0'))
        {
            return Err("validation: reason is invalid".into());
        }
        match self.rpc(RpcMethod::Respond(RespondInput {
            agent_id: i.agent_id,
            request_id: i.request_id,
            decision,
            content: i.reason,
        }))? {
            RpcSuccess::Respond { outcome } => Ok(Json(project_response(outcome))),
            _ => Err(protocol_error()),
        }
    }
    #[tool(
        name = "zcode_review_stop",
        description = "Cancel a review job without reaping its history",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn stop(
        &self,
        Parameters(i): Parameters<AgentInput>,
    ) -> Result<Json<StateOutput>, String> {
        match self.rpc(RpcMethod::Stop {
            agent_id: i.agent_id.clone(),
        })? {
            RpcSuccess::Stopped { state } => Ok(Json(StateOutput {
                agent_id: i.agent_id,
                state: state.into(),
                resources_reaped: false,
            })),
            _ => Err(protocol_error()),
        }
    }
    #[tool(
        name = "zcode_review_result",
        description = "Read and revalidate a bounded review report",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn result(
        &self,
        Parameters(i): Parameters<ResultInput>,
    ) -> Result<Json<ResultOutput>, String> {
        if i.preview_bytes > 8192 {
            return Err("validation: preview_bytes exceeds 8192".into());
        }
        match self.rpc(RpcMethod::Result(ResultQuery {
            agent_id: i.agent_id,
            preview_bytes: i.preview_bytes,
        }))? {
            RpcSuccess::Result { job, artifact } => Ok(Json(ResultOutput {
                job: job.into(),
                report: artifact.map(project_report),
            })),
            _ => Err(protocol_error()),
        }
    }
    #[tool(
        name = "zcode_review_list",
        description = "List active, recent, or all review jobs",
        annotations(
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn list(&self, Parameters(i): Parameters<ListInput>) -> Result<Json<ListOutput>, String> {
        if !(1..=100).contains(&i.limit) {
            return Err("validation: limit must be between 1 and 100".into());
        }
        let scope = match i.scope {
            PublicListScope::Active => JobListScopeView::Active,
            PublicListScope::Recent => JobListScopeView::Recent,
            PublicListScope::All => JobListScopeView::All,
        };
        match self.rpc(RpcMethod::List {
            scope,
            limit: i.limit,
        })? {
            RpcSuccess::Listed { jobs } => Ok(Json(ListOutput {
                jobs: jobs.into_iter().map(Into::into).collect(),
            })),
            _ => Err(protocol_error()),
        }
    }
    #[tool(
        name = "zcode_review_close",
        description = "Cancel if needed and reap runtime resources while preserving history",
        annotations(
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn close(
        &self,
        Parameters(i): Parameters<AgentInput>,
    ) -> Result<Json<StateOutput>, String> {
        match self.rpc(RpcMethod::Reap {
            agent_id: i.agent_id.clone(),
        })? {
            RpcSuccess::Reaped {
                state,
                resources_reaped,
            } => Ok(Json(StateOutput {
                agent_id: i.agent_id,
                state: state.into(),
                resources_reaped,
            })),
            _ => Err(protocol_error()),
        }
    }
}

pub async fn serve_stdio(
    socket: PathBuf,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    ReviewMcp::new(socket, timeout)
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await?
        .waiting()
        .await?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicApiMode {
    LegacyReviewV1,
    SubagentV2,
}

impl PublicApiMode {
    pub fn parse(value: Option<&std::ffi::OsStr>) -> Result<Self, String> {
        match value.and_then(std::ffi::OsStr::to_str) {
            None => Ok(Self::LegacyReviewV1),
            Some("legacy_review_v1") => Ok(Self::LegacyReviewV1),
            Some("subagent_v2") => Ok(Self::SubagentV2),
            Some(_) => Err("ZCODE_PUBLIC_API_MODE must be legacy_review_v1 or subagent_v2".into()),
        }
    }
}

pub async fn serve_stdio_mode(
    socket: PathBuf,
    timeout: Duration,
    mode: PublicApiMode,
) -> Result<(), Box<dyn std::error::Error>> {
    match mode {
        PublicApiMode::LegacyReviewV1 => serve_stdio(socket, timeout).await,
        PublicApiMode::SubagentV2 => v2::serve_stdio_v2(socket, timeout).await,
    }
}
fn read_manifest(path: &Path) -> Result<review_preparation::ReviewManifest, String> {
    if !path.is_absolute() {
        return Err("validation: manifest_path must be absolute".into());
    }
    let m = fs::symlink_metadata(path)
        .map_err(|_| "validation: manifest_path is unavailable".to_owned())?;
    if m.file_type().is_symlink() || !m.file_type().is_file() {
        return Err("validation: manifest_path must be a regular non-symlink file".into());
    }
    if m.len() > MAX_MANIFEST_BYTES {
        return Err("validation: manifest exceeds 128 KiB".into());
    }
    let b = fs::read(path).map_err(|_| "validation: manifest could not be read".to_owned())?;
    std::str::from_utf8(&b).map_err(|_| "validation: manifest is not UTF-8".to_owned())?;
    review_preparation::ReviewManifest::from_json(&b)
        .map_err(|_| "validation: manifest JSON is invalid".into())
}
fn project_events(p: EventPage) -> EventsOutput {
    EventsOutput {
        events: p
            .events
            .into_iter()
            .map(|e| PublicEvent {
                sequence: e.sequence,
                event_type: e.event_type,
                redaction_level: e.redaction_level,
            })
            .collect(),
        next_sequence: p.next_sequence,
        has_more: p.has_more,
    }
}
fn project_response(v: ResponseOutcomeView) -> RespondOutput {
    RespondOutput {
        disposition: match v.disposition {
            zcode_reviewd::rpc::ResponseDispositionView::Responded => {
                PublicResponseDisposition::Responded
            }
            zcode_reviewd::rpc::ResponseDispositionView::AlreadyResponded => {
                PublicResponseDisposition::AlreadyResponded
            }
            zcode_reviewd::rpc::ResponseDispositionView::InFlight => {
                PublicResponseDisposition::InFlight
            }
        },
        requested_decision: if v.requested_decision == "allow" {
            PublicDecision::Allow
        } else {
            PublicDecision::Deny
        },
        effective_decision: if v.effective_decision == "allow" {
            PublicDecision::Allow
        } else {
            PublicDecision::Deny
        },
        policy_overrode: v.policy_overrode,
        policy_reason_code: v.policy_reason_code,
    }
}
fn project_report(v: ArtifactView) -> ReportSummary {
    ReportSummary {
        finalized: v.finalized,
        integrity: match v.integrity {
            zcode_reviewd::rpc::ArtifactIntegrityView::Valid => PublicArtifactIntegrity::Valid,
            zcode_reviewd::rpc::ArtifactIntegrityView::Missing => PublicArtifactIntegrity::Missing,
            zcode_reviewd::rpc::ArtifactIntegrityView::Replaced => {
                PublicArtifactIntegrity::Replaced
            }
            zcode_reviewd::rpc::ArtifactIntegrityView::Binary => PublicArtifactIntegrity::Binary,
            zcode_reviewd::rpc::ArtifactIntegrityView::Invalid => PublicArtifactIntegrity::Invalid,
            zcode_reviewd::rpc::ArtifactIntegrityView::LegacyUnverified => {
                PublicArtifactIntegrity::LegacyUnverified
            }
        },
        expected_sha256: v.expected_sha256,
        observed_sha256: v.observed_sha256,
        expected_bytes: v.expected_bytes,
        observed_bytes: v.observed_bytes,
        checkpoint_number: v.checkpoint_number,
        preview: v.preview,
    }
}
fn public_error(e: RpcError) -> String {
    let (c, m) = match e.code {
        RpcErrorCode::Malformed | RpcErrorCode::Validation => {
            ("validation", "request validation failed")
        }
        RpcErrorCode::Oversized => ("oversized", "bounded response or request was too large"),
        RpcErrorCode::UnsupportedVersion => {
            ("protocol_version_mismatch", "incompatible review daemon")
        }
        RpcErrorCode::UnknownMethod => ("protocol_error", "daemon method is unavailable"),
        RpcErrorCode::NotFound => ("not_found", "review job was not found"),
        RpcErrorCode::Conflict => ("conflict", "review operation conflicts with durable state"),
        RpcErrorCode::Timeout => ("timeout", "daemon operation timed out"),
        RpcErrorCode::RuntimeLost => ("runtime_lost", "review runtime was lost"),
        RpcErrorCode::ResultInvalid => ("result_invalid", "stored task result failed verification"),
        RpcErrorCode::Persistence | RpcErrorCode::Unavailable | RpcErrorCode::Internal => (
            "daemon_unavailable",
            "review daemon could not complete the operation",
        ),
    };
    format!("{c}: {m}")
}
fn public_transport_error(error: std::io::Error) -> String {
    String::from(match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => {
            "timeout: daemon call exceeded its bound"
        }
        std::io::ErrorKind::InvalidData => {
            "protocol_error: daemon returned an invalid or oversized frame"
        }
        _ => "daemon_unavailable: review daemon is unavailable",
    })
}
fn protocol_error() -> String {
    "protocol_error: unexpected daemon response".into()
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_bounds() {
        assert!(read_manifest(Path::new("relative.json")).is_err());
        let d = tempfile::tempdir().unwrap();
        let t = d.path().join("target.json");
        fs::write(&t, b"{}").unwrap();
        #[cfg(unix)]
        {
            let l = d.path().join("link.json");
            std::os::unix::fs::symlink(&t, &l).unwrap();
            assert!(read_manifest(&l).unwrap_err().contains("non-symlink"));
        }
        let l = d.path().join("large.json");
        fs::write(&l, vec![b'x'; MAX_MANIFEST_BYTES as usize + 1]).unwrap();
        assert!(read_manifest(&l).unwrap_err().contains("128 KiB"));
    }
    #[test]
    fn public_errors_are_stable_redacted_and_bounded() {
        let cases = [
            (
                RpcErrorCode::Validation,
                "validation: request validation failed",
            ),
            (
                RpcErrorCode::Oversized,
                "oversized: bounded response or request was too large",
            ),
            (
                RpcErrorCode::UnsupportedVersion,
                "protocol_version_mismatch: incompatible review daemon",
            ),
            (
                RpcErrorCode::NotFound,
                "not_found: review job was not found",
            ),
            (RpcErrorCode::Timeout, "timeout: daemon operation timed out"),
            (
                RpcErrorCode::RuntimeLost,
                "runtime_lost: review runtime was lost",
            ),
            (
                RpcErrorCode::Unavailable,
                "daemon_unavailable: review daemon could not complete the operation",
            ),
        ];
        for (code, expected) in cases {
            let projected = public_error(RpcError::new(code, "SECRET /private/path pid=123"));
            assert_eq!(projected, expected);
            assert!(projected.len() < 128);
            assert!(!projected.contains("SECRET"));
        }
        assert_eq!(
            public_transport_error(std::io::Error::new(std::io::ErrorKind::TimedOut, "SECRET")),
            "timeout: daemon call exceeded its bound"
        );
        assert_eq!(
            public_transport_error(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "SECRET"
            )),
            "protocol_error: daemon returned an invalid or oversized frame"
        );
        assert_eq!(
            public_transport_error(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "SECRET"
            )),
            "daemon_unavailable: review daemon is unavailable"
        );
    }

    #[cfg(unix)]
    #[test]
    fn s05_consumer_rejects_an_s04_v7_daemon_response() {
        use std::{
            io::{BufRead, BufReader, Write},
            os::unix::fs::PermissionsExt,
            os::unix::net::UnixListener,
            sync::{Arc, Barrier},
            thread,
        };
        use zcode_reviewd::rpc::RpcResponse;

        assert_eq!(RPC_VERSION, 8);
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("old-daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let ready = Arc::new(Barrier::new(2));
        let peer_ready = Arc::clone(&ready);
        let old_daemon = thread::spawn(move || {
            peer_ready.wait();
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let request: RpcRequest = serde_json::from_str(&line).unwrap();
            assert_eq!(request.version, 8);
            assert!(matches!(request.method, RpcMethod::SystemStatus));
            let mut response = RpcResponse::error(
                Some(request.request_id),
                RpcError::new(RpcErrorCode::UnsupportedVersion, "old daemon"),
            );
            response.version = 7;
            serde_json::to_writer(&mut stream, &response).unwrap();
            stream.write_all(b"\n").unwrap();
        });

        ready.wait();
        let facade = ReviewMcp::new(socket, Duration::from_secs(5));
        let result = facade.rpc(RpcMethod::SystemStatus);
        old_daemon.join().unwrap();
        assert_eq!(
            result.unwrap_err(),
            "protocol_version_mismatch: incompatible review daemon"
        );
    }
    #[test]
    fn inventory_and_schemas_are_exact() {
        let s = ReviewMcp::new(PathBuf::from("/tmp/unused"), Duration::from_secs(1));
        let tools = s.tool_router.list_all();
        let mut a = tools.iter().map(|t| t.name.as_ref()).collect::<Vec<_>>();
        a.sort_unstable();
        let mut e = PUBLIC_TOOLS.to_vec();
        e.sort_unstable();
        assert_eq!(a, e);
        assert!(tools.iter().all(|t| t.output_schema.is_some()
            && t.annotations.as_ref().and_then(|a| a.open_world_hint) == Some(false)));
        let schemas = serde_json::to_string(&tools).unwrap();
        for forbidden in [
            "workspace_path",
            "owner_epoch",
            "runtime_agent_id",
            "initial_prompt",
            "failure_message",
            "correlation_id",
            "process_group_id",
            "environment",
            "credentials",
        ] {
            assert!(
                !schemas.contains(forbidden),
                "public schema leaked {forbidden}"
            );
        }
    }
    #[test]
    fn startup_selector_is_static_strict_and_legacy_by_default() {
        use std::ffi::OsStr;

        assert_eq!(
            PublicApiMode::parse(None).unwrap(),
            PublicApiMode::LegacyReviewV1
        );
        assert_eq!(
            PublicApiMode::parse(Some(OsStr::new("legacy_review_v1"))).unwrap(),
            PublicApiMode::LegacyReviewV1
        );
        assert_eq!(
            PublicApiMode::parse(Some(OsStr::new("subagent_v2"))).unwrap(),
            PublicApiMode::SubagentV2
        );
        assert!(PublicApiMode::parse(Some(OsStr::new(""))).is_err());
        assert!(PublicApiMode::parse(Some(OsStr::new("both"))).is_err());
    }
    #[tokio::test]
    async fn official_sdk_initialization_and_discovery_work_over_stream_transport() {
        let (server_transport, client_transport) = tokio::io::duplex(64 * 1024);
        let server = ReviewMcp::new(PathBuf::from("/tmp/unused"), Duration::from_secs(1));
        let task = tokio::spawn(async move {
            let service = server.serve(server_transport).await.unwrap();
            service.waiting().await.unwrap();
        });
        let client = ().serve(client_transport).await.unwrap();
        let tools = client.peer().list_tools(None).await.unwrap().tools;
        assert_eq!(tools.len(), PUBLIC_TOOLS.len());
        assert!(tools.iter().all(|tool| tool.output_schema.is_some()));
        client.cancel().await.unwrap();
        task.await.unwrap();
    }

    #[test]
    fn recreating_facade_recovers_same_daemon_job() {
        use review_store::{NewJob, Store};
        use std::sync::Arc;
        use zcode_reviewd::rpc::{RpcServer, RpcService, ServerOptions};
        use zcode_reviewd::{CommandRuntimeFactory, RuntimeFactory, Scheduler, SchedulerConfig};
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
        store
            .enqueue_job(&NewJob::new("stable-agent", "/workspace"))
            .unwrap();
        fn unused_runtime(_: &review_store::Job) -> std::io::Result<std::process::Command> {
            Err(std::io::Error::other("unused"))
        }
        let factory = Arc::new(CommandRuntimeFactory::new(unused_runtime));
        let runtime_factory: Arc<dyn RuntimeFactory> = factory;
        let scheduler = Scheduler::new(
            "facade-test",
            Arc::clone(&store),
            runtime_factory,
            SchedulerConfig::default(),
        )
        .unwrap();
        let service = Arc::new(RpcService::new(scheduler, store).unwrap());
        let socket = directory.path().join("rpc").join("review.sock");
        let _server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
        let first = ReviewMcp::new(socket.clone(), Duration::from_secs(1))
            .job_with_pending("stable-agent")
            .unwrap();
        drop(first);
        let restarted = ReviewMcp::new(socket, Duration::from_secs(1))
            .job_with_pending("stable-agent")
            .unwrap();
        assert_eq!(restarted.job.agent_id, "stable-agent");
        assert_eq!(restarted.job.state, PublicJobState::Queued);
    }

    #[tokio::test]
    async fn public_read_wait_stop_and_close_sequence_is_bounded_and_distinct() {
        use review_store::{NewJob, Store};
        use std::sync::Arc;
        use zcode_reviewd::rpc::{RpcServer, RpcService, ServerOptions};
        use zcode_reviewd::{CommandRuntimeFactory, RuntimeFactory, Scheduler, SchedulerConfig};
        fn unused_runtime(_: &review_store::Job) -> std::io::Result<std::process::Command> {
            Err(std::io::Error::other("unused"))
        }
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
        store
            .enqueue_job(&NewJob::new("public-sequence", "/private/workspace"))
            .unwrap();
        let factory = Arc::new(CommandRuntimeFactory::new(unused_runtime));
        let runtime_factory: Arc<dyn RuntimeFactory> = factory;
        let scheduler = Scheduler::new(
            "public-sequence",
            Arc::clone(&store),
            runtime_factory,
            SchedulerConfig::default(),
        )
        .unwrap();
        let service = Arc::new(RpcService::new(scheduler, store).unwrap());
        let socket = directory.path().join("rpc").join("review.sock");
        let _server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
        let facade = ReviewMcp::new(socket, Duration::from_secs(1));
        assert_eq!(
            facade
                .status(Parameters(AgentInput {
                    agent_id: "public-sequence".into(),
                }))
                .await
                .unwrap()
                .0
                .job
                .state,
            PublicJobState::Queued
        );
        assert!(facade
            .events(Parameters(EventsInput {
                agent_id: "public-sequence".into(),
                after_sequence: 0,
                limit: 50,
            }))
            .await
            .unwrap()
            .0
            .events
            .is_empty());
        assert!(
            facade
                .wait(Parameters(WaitInput {
                    agent_id: "public-sequence".into(),
                    after_sequence: 0,
                    timeout_ms: 10,
                }))
                .await
                .unwrap()
                .0
                .timed_out
        );
        assert_eq!(
            facade
                .list(Parameters(ListInput {
                    scope: PublicListScope::Active,
                    limit: 50,
                }))
                .await
                .unwrap()
                .0
                .jobs
                .len(),
            1
        );
        assert!(facade
            .result(Parameters(ResultInput {
                agent_id: "public-sequence".into(),
                preview_bytes: 4096,
            }))
            .await
            .unwrap()
            .0
            .report
            .is_none());
        let stopped = facade
            .stop(Parameters(AgentInput {
                agent_id: "public-sequence".into(),
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(stopped.state, PublicJobState::Cancelled);
        assert!(!stopped.resources_reaped);
        let closed = facade
            .close(Parameters(AgentInput {
                agent_id: "public-sequence".into(),
            }))
            .await
            .unwrap()
            .0;
        assert_eq!(closed.state, PublicJobState::Cancelled);
        assert!(closed.resources_reaped);
    }
}
