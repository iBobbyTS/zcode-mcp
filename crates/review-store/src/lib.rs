use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::Digest;
use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const STORE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    feature_id TEXT,
    state TEXT NOT NULL,
    workspace_path TEXT NOT NULL,
    runtime_hash TEXT,
    prepared_launch_json TEXT,
    prepared_launch_sha256 TEXT,
    zcode_session_id TEXT,
    initial_prompt TEXT NOT NULL DEFAULT 'Begin task.',
    turn_state TEXT NOT NULL DEFAULT 'IDLE',
    pid INTEGER,
    process_group_id INTEGER,
    process_uid INTEGER,
    process_start_token TEXT,
    runtime_agent_id TEXT,
    owner_id TEXT,
    owner_epoch INTEGER NOT NULL DEFAULT 0,
    lease_expires_at INTEGER,
    close_requested INTEGER NOT NULL DEFAULT 0,
    stop_requested INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    last_heartbeat_at INTEGER,
    last_event_seq INTEGER NOT NULL DEFAULT 0,
    failure_code TEXT,
    failure_message TEXT,
    closed_at INTEGER,
    reaped_at INTEGER
);

CREATE INDEX IF NOT EXISTS agents_queue_idx
    ON agents(state, created_at, agent_id);
CREATE INDEX IF NOT EXISTS agents_workspace_state_idx
    ON agents(workspace_path, state);

CREATE TABLE IF NOT EXISTS agent_cursors (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    runtime_agent_id TEXT NOT NULL,
    last_seq INTEGER NOT NULL,
    PRIMARY KEY (agent_id, runtime_agent_id)
);

CREATE TABLE IF NOT EXISTS events (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    runtime_agent_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    source_seq INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    turn_id TEXT,
    payload_json TEXT NOT NULL,
    redaction_level TEXT NOT NULL,
    attempt_sequence INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (agent_id, runtime_agent_id, seq),
    UNIQUE (agent_id, runtime_agent_id, source_seq)
);

CREATE TABLE IF NOT EXISTS messages (
    message_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    mode TEXT NOT NULL,
    content TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    delivered_at INTEGER,
    target_turn_id TEXT,
    failure_code TEXT,
    failure_message TEXT
);

CREATE TABLE IF NOT EXISTS pending_requests (
    request_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    correlation_id TEXT NOT NULL,
    request_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    responded_at INTEGER,
    response_decision TEXT,
    response_content TEXT,
    UNIQUE (agent_id, correlation_id)
);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    artifact_type TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    bytes INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS lifecycle_ledger (
    ledger_id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    owner_epoch INTEGER NOT NULL,
    from_state TEXT,
    to_state TEXT NOT NULL,
    reason_code TEXT,
    recorded_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS task_attempts (
    execution_agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    public_agent_id TEXT NOT NULL,
    task_kind TEXT NOT NULL,
    phase TEXT NOT NULL DEFAULT 'QUEUED',
    attempt_sequence INTEGER NOT NULL,
    repository TEXT NOT NULL,
    feature_id TEXT NOT NULL,
    ownership_token TEXT NOT NULL,
    semantic_fingerprint TEXT NOT NULL,
    effective_budget_json TEXT NOT NULL,
    retain_partial INTEGER NOT NULL DEFAULT 0,
    UNIQUE(public_agent_id, attempt_sequence)
);
CREATE TABLE IF NOT EXISTS task_identities (
    public_agent_id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    feature_id TEXT NOT NULL,
    ownership_token TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS task_attempts_scope_idx
    ON task_attempts(repository, feature_id, ownership_token, task_kind);

CREATE TABLE IF NOT EXISTS task_results (
    execution_agent_id TEXT PRIMARY KEY REFERENCES task_attempts(execution_agent_id) ON DELETE CASCADE,
    outcome TEXT NOT NULL,
    summary TEXT NOT NULL,
    partial INTEGER NOT NULL,
    retained INTEGER NOT NULL,
    base_commit TEXT,
    head_commit TEXT,
    changed_files_json TEXT NOT NULL,
    diff_stat TEXT,
    checks_json TEXT NOT NULL,
    result_sha256 TEXT NOT NULL,
    residual_gaps_json TEXT NOT NULL,
    artifacts_json TEXT NOT NULL,
    completed_at INTEGER NOT NULL
);

"#;

const SCHEMA_VERSION: i64 = 8;

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    InvalidState(String),
    Conflict(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sqlite(error) => write!(f, "SQLite store error: {error}"),
            Self::InvalidState(message) => write!(f, "invalid store state: {message}"),
            Self::Conflict(message) => write!(f, "store conflict: {message}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Sqlite(value)
    }
}

pub type StoreResult<T> = Result<T, StoreError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    General,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmissionOwnership {
    pub execution_agent_id: String,
    pub task_kind: Option<TaskKind>,
    semantic_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskSubmissionDisposition {
    Created,
    Existing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskPhase {
    Queued,
    Preparing,
    Running,
    WaitingInput,
    Cancelling,
    Terminal,
}
impl TaskPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Preparing => "PREPARING",
            Self::Running => "RUNNING",
            Self::WaitingInput => "WAITING_INPUT",
            Self::Cancelling => "CANCELLING",
            Self::Terminal => "TERMINAL",
        }
    }
    fn parse(value: &str) -> StoreResult<Self> {
        match value {
            "QUEUED" => Ok(Self::Queued),
            "PREPARING" => Ok(Self::Preparing),
            "RUNNING" => Ok(Self::Running),
            "WAITING_INPUT" => Ok(Self::WaitingInput),
            "CANCELLING" => Ok(Self::Cancelling),
            "TERMINAL" => Ok(Self::Terminal),
            other => Err(StoreError::InvalidState(format!(
                "unknown task phase {other}"
            ))),
        }
    }
}
impl TaskKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::General => "GENERAL",
        }
    }
    fn parse(value: &str) -> StoreResult<Self> {
        match value {
            "GENERAL" => Ok(Self::General),
            other => Err(StoreError::InvalidState(format!(
                "unknown task kind {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EffectiveBudget {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetRequest {
    Omitted,
    Null,
    Limits(EffectiveBudget),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewTask {
    pub job: NewJob,
    pub public_agent_id: String,
    pub task_kind: TaskKind,
    pub repository: String,
    pub feature_id: String,
    pub ownership_token: String,
    pub budget: BudgetRequest,
    pub retain_partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    pub execution_agent_id: String,
    pub public_agent_id: String,
    pub task_kind: TaskKind,
    pub phase: TaskPhase,
    pub attempt_sequence: u64,
    pub repository: String,
    pub feature_id: String,
    pub ownership_token: String,
    pub effective_budget: EffectiveBudget,
    pub retain_partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResultArtifact {
    pub kind: ArtifactKind,
    pub artifact_id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    ChangesPatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TaskOutcome {
    Succeeded,
    Blocked,
    Failed,
    Cancelled,
    TimedOut,
    BudgetExhausted,
    RuntimeLost,
    ResultInvalid,
}
impl TaskOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "SUCCEEDED",
            Self::Blocked => "BLOCKED",
            Self::Failed => "FAILED",
            Self::Cancelled => "CANCELLED",
            Self::TimedOut => "TIMED_OUT",
            Self::BudgetExhausted => "BUDGET_EXHAUSTED",
            Self::RuntimeLost => "RUNTIME_LOST",
            Self::ResultInvalid => "RESULT_INVALID",
        }
    }
    fn parse(value: &str) -> StoreResult<Self> {
        match value {
            "SUCCEEDED" => Ok(Self::Succeeded),
            "BLOCKED" => Ok(Self::Blocked),
            "FAILED" => Ok(Self::Failed),
            "CANCELLED" => Ok(Self::Cancelled),
            "TIMED_OUT" => Ok(Self::TimedOut),
            "BUDGET_EXHAUSTED" => Ok(Self::BudgetExhausted),
            "RUNTIME_LOST" => Ok(Self::RuntimeLost),
            "RESULT_INVALID" => Ok(Self::ResultInvalid),
            other => Err(StoreError::InvalidState(format!(
                "unknown task outcome {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TaskResult {
    pub outcome: TaskOutcome,
    pub summary: String,
    pub partial: bool,
    pub base_commit: Option<String>,
    pub head_commit: Option<String>,
    pub changed_files: Vec<String>,
    pub diff_stat: Option<String>,
    pub checks: Vec<String>,
    pub residual_gaps: Vec<String>,
    pub artifacts: Vec<ResultArtifact>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredTaskResult {
    pub result: TaskResult,
    pub result_sha256: String,
    pub retained: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskQueryScope<'a> {
    pub repository: Option<&'a str>,
    pub feature_id: Option<&'a str>,
    pub ownership_token: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPageFilter<'a> {
    pub phase: Option<TaskPhase>,
    pub outcome: Option<TaskOutcome>,
    pub profile: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskPage {
    pub tasks: Vec<TaskRecord>,
    pub next_cursor: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnqueuedTask {
    pub job: Job,
    pub task: TaskRecord,
    pub disposition: TaskSubmissionDisposition,
}

const DEFAULT_BUDGET: EffectiveBudget = EffectiveBudget {
    absolute_wall_time_ms: 3_600_000,
    runtime_activity_idle_timeout_ms: 90_000,
    model_stream_idle_timeout_ms: 90_000,
    tool_call_timeout_ms: 300_000,
    input_wait_timeout_ms: 300_000,
    max_turns: 32,
    max_tool_calls: 128,
    max_context_bytes: 1_048_576,
    max_result_bytes: 1_048_576,
    max_artifact_bytes: 16_777_216,
};
const MAX_BUDGET: EffectiveBudget = EffectiveBudget {
    absolute_wall_time_ms: 86_400_000,
    runtime_activity_idle_timeout_ms: 86_400_000,
    model_stream_idle_timeout_ms: 86_400_000,
    tool_call_timeout_ms: 86_400_000,
    input_wait_timeout_ms: 86_400_000,
    max_turns: 1024,
    max_tool_calls: 4096,
    max_context_bytes: 16_777_216,
    max_result_bytes: 16_777_216,
    max_artifact_bytes: 268_435_456,
};

impl JobState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Cancelled
                | Self::Failed
                | Self::FailedRuntimeLost
                | Self::Orphaned
                | Self::Closed
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Starting => "STARTING",
            Self::Running => "RUNNING",
            Self::Stopping => "STOPPING",
            Self::Completed => "COMPLETED",
            Self::Cancelled => "CANCELLED",
            Self::Failed => "FAILED",
            Self::FailedRuntimeLost => "FAILED_RUNTIME_LOST",
            Self::Orphaned => "ORPHANED",
            Self::Closed => "CLOSED",
        }
    }

    fn parse(value: &str) -> StoreResult<Self> {
        match value {
            "QUEUED" => Ok(Self::Queued),
            "STARTING" => Ok(Self::Starting),
            "RUNNING" => Ok(Self::Running),
            "STOPPING" => Ok(Self::Stopping),
            "COMPLETED" => Ok(Self::Completed),
            "CANCELLED" => Ok(Self::Cancelled),
            "FAILED" => Ok(Self::Failed),
            "FAILED_RUNTIME_LOST" => Ok(Self::FailedRuntimeLost),
            "ORPHANED" => Ok(Self::Orphaned),
            "CLOSED" => Ok(Self::Closed),
            other => Err(StoreError::InvalidState(format!(
                "unknown job state {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewJob {
    pub agent_id: String,
    pub idempotency_key: Option<String>,
    pub feature_id: Option<String>,
    pub workspace_path: String,
    pub runtime_hash: Option<String>,
    pub prepared_launch_json: Option<String>,
    pub prepared_launch_sha256: Option<String>,
    pub initial_prompt: String,
}

impl NewJob {
    pub fn new(agent_id: impl Into<String>, workspace_path: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            idempotency_key: None,
            feature_id: None,
            workspace_path: workspace_path.into(),
            runtime_hash: None,
            prepared_launch_json: None,
            prepared_launch_sha256: None,
            initial_prompt: "Begin task.".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub agent_id: String,
    pub idempotency_key: Option<String>,
    pub state: JobState,
    pub workspace_path: String,
    pub initial_prompt: String,
    pub prepared_launch_json: Option<String>,
    pub prepared_launch_sha256: Option<String>,
    pub owner_id: Option<String>,
    pub owner_epoch: u64,
    pub close_requested: bool,
    pub stop_requested: bool,
    pub last_event_seq: u64,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
    pub runtime_agent_id: Option<String>,
    pub zcode_session_id: Option<String>,
    pub turn_state: TurnState,
    pub process_identity: Option<StoredProcessIdentity>,
    pub closed_at: Option<i64>,
    pub reaped_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnState {
    Idle,
    Active,
    Failed,
}

impl TurnState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::Active => "ACTIVE",
            Self::Failed => "FAILED",
        }
    }

    fn parse(value: &str) -> StoreResult<Self> {
        match value {
            "IDLE" => Ok(Self::Idle),
            "ACTIVE" => Ok(Self::Active),
            "FAILED" => Ok(Self::Failed),
            other => Err(StoreError::InvalidState(format!(
                "unknown turn state {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredProcessIdentity {
    pub pid: u32,
    pub process_group_id: i32,
    pub uid: u32,
    pub start_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobClaim {
    pub job: Job,
    pub owner_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleWrite {
    pub agent_id: String,
    pub runtime_agent_id: String,
    pub owner_epoch: u64,
    pub source_sequence: u64,
    pub event_type: String,
    pub turn_id: Option<String>,
    pub payload_json: String,
    pub redaction_level: String,
    pub terminal: Option<TerminalUpdate>,
    pub turn_state: Option<TurnState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalUpdate {
    pub state: JobState,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewArtifact {
    pub artifact_id: String,
    pub agent_id: String,
    pub artifact_type: String,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifact {
    pub artifact_id: String,
    pub artifact_type: String,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseDecision {
    pub state: JobState,
    pub owner_epoch: u64,
    pub needs_runtime_stop: bool,
    pub prior_stop_or_close: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageState {
    Queued,
    Sending,
    Delivered,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMessage {
    pub message_id: String,
    pub agent_id: String,
    pub mode: String,
    pub content: String,
    pub state: MessageState,
    pub target_turn_id: Option<String>,
    pub failure_code: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingRequestState {
    Pending,
    Sending,
    Responded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPendingRequest {
    pub request_id: String,
    pub agent_id: String,
    pub correlation_id: String,
    pub request_type: String,
    pub payload_json: String,
    pub state: PendingRequestState,
    pub response_decision: Option<String>,
    pub response_content: Option<String>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingResponseClaimDisposition {
    Claimed,
    AttemptStopping,
    NotPending(PendingRequestState),
    AttemptMismatch,
    NotFound,
}

pub struct Store {
    connection: Mutex<Connection>,
    database_path: PathBuf,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let mut connection = Connection::open(path.as_ref())?;
        connection.busy_timeout(STORE_BUSY_TIMEOUT)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        initialize_schema(&mut connection)?;
        let database_path = std::fs::canonicalize(path.as_ref()).map_err(|error| {
            StoreError::InvalidState(format!("database path cannot be canonicalized: {error}"))
        })?;
        Ok(Self {
            connection: Mutex::new(connection),
            database_path,
        })
    }

    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub fn journal_mode(&self) -> StoreResult<String> {
        let connection = self.connection.lock().unwrap();
        Ok(connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?)
    }

    pub fn enqueue_job(&self, job: &NewJob) -> StoreResult<Job> {
        match (
            job.prepared_launch_json.as_deref(),
            job.prepared_launch_sha256.as_deref(),
        ) {
            (Some(json), Some(hash)) if !json.is_empty() && !hash.is_empty() => {}
            (None, None) => {}
            _ => {
                return Err(StoreError::InvalidState(
                    "prepared launch JSON and SHA-256 must be supplied together".into(),
                ))
            }
        }
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(key) = &job.idempotency_key {
            if let Some(owner) = query_submission_ownership_by_idempotency(&transaction, key)? {
                if owner.task_kind.is_some() {
                    return Err(StoreError::Conflict(format!(
                        "idempotency key {key} is owned by a structured task"
                    )));
                }
                let existing = query_job(&transaction, &owner.execution_agent_id)?
                    .ok_or_else(|| StoreError::InvalidState("legacy job disappeared".into()))?;
                let compatible = match (
                    job.prepared_launch_sha256.as_deref(),
                    existing.prepared_launch_sha256.as_deref(),
                ) {
                    (None, None) => true,
                    (Some(requested), Some(stored)) => requested == stored,
                    _ => false,
                };
                if !compatible {
                    return Err(StoreError::Conflict(format!(
                        "idempotency key {key} names a different prepared launch"
                    )));
                }
                transaction.commit()?;
                return Ok(existing);
            }
        }
        if query_job(&transaction, &job.agent_id)?.is_some() {
            return Err(StoreError::Conflict(format!(
                "agent id {} already exists",
                job.agent_id
            )));
        }
        let created_at = now_millis();
        transaction.execute(
            "INSERT INTO agents (
                agent_id, idempotency_key, feature_id, state, workspace_path,
                runtime_hash, prepared_launch_json, prepared_launch_sha256,
                initial_prompt, created_at
             ) VALUES (?1, ?2, ?3, 'QUEUED', ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                job.agent_id,
                job.idempotency_key,
                job.feature_id,
                job.workspace_path,
                job.runtime_hash,
                job.prepared_launch_json,
                job.prepared_launch_sha256,
                job.initial_prompt,
                created_at,
            ],
        )?;
        insert_ledger(&transaction, &job.agent_id, 0, None, JobState::Queued, None)?;
        let stored = query_job(&transaction, &job.agent_id)?
            .ok_or_else(|| StoreError::InvalidState("inserted job could not be read".into()))?;
        transaction.commit()?;
        Ok(stored)
    }

    pub fn enqueue_task(&self, task: &NewTask) -> StoreResult<(Job, TaskRecord)> {
        let enqueued = self.enqueue_task_authoritative(task)?;
        Ok((enqueued.job, enqueued.task))
    }

    pub fn enqueue_task_authoritative(&self, task: &NewTask) -> StoreResult<EnqueuedTask> {
        validate_task(task)?;
        validate_prepared_launch(&task.job)?;
        let effective = resolve_effective_budget(&task.budget)?;
        let fingerprint = task_fingerprint(task, &effective);
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(key) = &task.job.idempotency_key {
            if let Some(owner) = query_submission_ownership_by_idempotency(&transaction, key)? {
                let Some(stored_kind) = owner.task_kind else {
                    return Err(StoreError::Conflict(format!(
                        "idempotency key {key} is owned by a legacy task"
                    )));
                };
                if stored_kind != task.task_kind {
                    return Err(StoreError::Conflict(format!(
                        "idempotency key {key} is owned by a different task family"
                    )));
                }
                if owner.execution_agent_id != task.job.agent_id {
                    return Err(StoreError::Conflict(format!(
                        "idempotency key {key} names a different task execution"
                    )));
                }
                let stored_fingerprint =
                    owner.semantic_fingerprint.as_deref().ok_or_else(|| {
                        StoreError::InvalidState(
                            "structured submission is missing its semantic fingerprint".into(),
                        )
                    })?;
                if stored_fingerprint != fingerprint {
                    return Err(StoreError::Conflict(format!(
                        "idempotency key {key} names a semantically different task"
                    )));
                }
                let job = query_job(&transaction, &owner.execution_agent_id)?
                    .ok_or_else(|| StoreError::InvalidState("task job disappeared".into()))?;
                let record = query_task_record(&transaction, &owner.execution_agent_id)?
                    .ok_or_else(|| StoreError::InvalidState("task metadata disappeared".into()))?;
                transaction.commit()?;
                return Ok(EnqueuedTask {
                    job,
                    task: record,
                    disposition: TaskSubmissionDisposition::Existing,
                });
            }
        }
        if query_job(&transaction, &task.job.agent_id)?.is_some() {
            return Err(StoreError::Conflict(format!(
                "agent id {} already exists",
                task.job.agent_id
            )));
        }
        let attempt_sequence = 1;
        bind_task_identity(&transaction, task)?;
        let created_at = now_millis();
        transaction.execute(
            "INSERT INTO agents (agent_id,idempotency_key,feature_id,state,workspace_path,runtime_hash,prepared_launch_json,prepared_launch_sha256,initial_prompt,created_at) VALUES (?1,?2,?3,'QUEUED',?4,?5,?6,?7,?8,?9)",
            params![task.job.agent_id,task.job.idempotency_key,task.job.feature_id,task.job.workspace_path,task.job.runtime_hash,task.job.prepared_launch_json,task.job.prepared_launch_sha256,task.job.initial_prompt,created_at])?;
        insert_ledger(
            &transaction,
            &task.job.agent_id,
            0,
            None,
            JobState::Queued,
            None,
        )?;
        transaction.execute(
            "INSERT INTO task_attempts (execution_agent_id,public_agent_id,task_kind,phase,attempt_sequence,repository,feature_id,ownership_token,semantic_fingerprint,effective_budget_json,retain_partial) VALUES (?1,?2,?3,'QUEUED',?4,?5,?6,?7,?8,?9,?10)",
            params![task.job.agent_id,task.public_agent_id,task.task_kind.as_str(),u64_to_i64(attempt_sequence)?,task.repository,task.feature_id,task.ownership_token,fingerprint,serde_json::to_string(&effective).map_err(|e| StoreError::InvalidState(e.to_string()))?,task.retain_partial])?;
        let job = query_job(&transaction, &task.job.agent_id)?.unwrap();
        let record = query_task_record(&transaction, &task.job.agent_id)?.unwrap();
        transaction.commit()?;
        Ok(EnqueuedTask {
            job,
            task: record,
            disposition: TaskSubmissionDisposition::Created,
        })
    }

    pub fn submission_by_idempotency(&self, key: &str) -> StoreResult<Option<SubmissionOwnership>> {
        let connection = self.connection.lock().unwrap();
        query_submission_ownership_by_idempotency(&connection, key)
    }

    pub fn get_task_scoped(
        &self,
        public_agent_id: &str,
        scope: TaskQueryScope<'_>,
    ) -> StoreResult<Option<TaskRecord>> {
        let connection = self.connection.lock().unwrap();
        query_latest_task_scoped(&connection, public_agent_id, scope)
    }

    /// Resolves a stable lifecycle handle to its latest private attempt.
    /// Scoped discovery remains on `get_task_scoped`; this is for by-ID control
    /// paths that already possess the opaque public handle.
    pub fn get_task(&self, public_agent_id: &str) -> StoreResult<Option<TaskRecord>> {
        let connection = self.connection.lock().unwrap();
        let execution_id = connection
            .query_row(
                "SELECT execution_agent_id FROM task_attempts
                 WHERE public_agent_id=?1 ORDER BY attempt_sequence DESC LIMIT 1",
                [public_agent_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        execution_id
            .map(|execution_id| query_task_record(&connection, &execution_id))
            .transpose()
            .map(Option::flatten)
    }

    pub fn get_task_attempt(
        &self,
        public_agent_id: &str,
        attempt_sequence: u64,
    ) -> StoreResult<Option<TaskRecord>> {
        if public_agent_id.is_empty() || attempt_sequence == 0 {
            return Err(StoreError::InvalidState(
                "task attempt identity must be non-empty and positive".into(),
            ));
        }
        let connection = self.connection.lock().unwrap();
        let execution_id = connection
            .query_row(
                "SELECT execution_agent_id FROM task_attempts
                 WHERE public_agent_id=?1 AND attempt_sequence=?2",
                params![public_agent_id, u64_to_i64(attempt_sequence)?],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        execution_id
            .map(|execution_id| query_task_record(&connection, &execution_id))
            .transpose()
            .map(Option::flatten)
    }

    pub fn task_by_execution_agent_id(
        &self,
        execution_agent_id: &str,
    ) -> StoreResult<Option<TaskRecord>> {
        let connection = self.connection.lock().unwrap();
        query_task_record(&connection, execution_agent_id)
    }

    pub fn list_tasks_scoped(
        &self,
        scope: TaskQueryScope<'_>,
        kind: Option<TaskKind>,
        limit: usize,
    ) -> StoreResult<Vec<TaskRecord>> {
        Ok(self
            .list_task_page(
                scope,
                kind,
                TaskPageFilter {
                    phase: None,
                    outcome: None,
                    profile: None,
                },
                None,
                limit,
            )?
            .tasks)
    }

    pub fn list_task_page(
        &self,
        scope: TaskQueryScope<'_>,
        kind: Option<TaskKind>,
        filter: TaskPageFilter<'_>,
        before_cursor: Option<u64>,
        limit: usize,
    ) -> StoreResult<TaskPage> {
        validate_scope(&scope)?;
        if limit == 0 {
            return Err(StoreError::InvalidState(
                "task page limit must be positive".into(),
            ));
        }
        if filter.profile.is_some_and(str::is_empty) {
            return Err(StoreError::InvalidState(
                "task profile filter must be non-empty".into(),
            ));
        }
        let connection = self.connection.lock().unwrap();
        let fetch_limit = limit
            .checked_add(1)
            .ok_or_else(|| StoreError::InvalidState("task page limit overflow".into()))?;
        let mut statement = connection.prepare(
            "SELECT ta.rowid, ta.execution_agent_id
             FROM task_attempts ta
             JOIN agents a ON a.agent_id=ta.execution_agent_id
             LEFT JOIN task_results tr ON tr.execution_agent_id=ta.execution_agent_id
             WHERE (?1 IS NULL OR ta.repository=?1)
               AND (?2 IS NULL OR ta.feature_id=?2)
               AND (?3 IS NULL OR ta.ownership_token=?3)
               AND (?4 IS NULL OR ta.task_kind=?4)
               AND (?5 IS NULL OR ta.phase=?5)
               AND (?6 IS NULL OR tr.outcome=?6)
               AND (?7 IS NULL OR CASE
                    WHEN json_valid(a.prepared_launch_json)
                    THEN json_extract(a.prepared_launch_json, '$.profile')
                    ELSE NULL
                   END=?7)
               AND (?8 IS NULL OR ta.rowid<?8)
             ORDER BY ta.rowid DESC
             LIMIT ?9",
        )?;
        let mut rows = statement
            .query_map(
                params![
                    scope.repository,
                    scope.feature_id,
                    scope.ownership_token,
                    kind.map(TaskKind::as_str),
                    filter.phase.map(TaskPhase::as_str),
                    filter.outcome.map(TaskOutcome::as_str),
                    filter.profile,
                    before_cursor.map(u64_to_i64).transpose()?,
                    usize_to_i64(fetch_limit)?
                ],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?)),
            )?
            .collect::<Result<Vec<_>, _>>()?;
        let has_more = rows.len() > limit;
        if has_more {
            rows.pop();
        }
        let next_cursor = has_more
            .then(|| rows.last().map(|(rowid, _)| i64_to_u64(*rowid)))
            .flatten()
            .transpose()?;
        let tasks = rows
            .into_iter()
            .map(|(_, id)| {
                query_task_record(&connection, &id)?
                    .ok_or_else(|| StoreError::InvalidState("task disappeared".into()))
            })
            .collect::<StoreResult<Vec<_>>>()?;
        Ok(TaskPage { tasks, next_cursor })
    }

    pub fn store_task_result(
        &self,
        execution_agent_id: &str,
        result: &TaskResult,
    ) -> StoreResult<()> {
        validate_result(result)?;
        let canonical =
            serde_json::to_vec(result).map_err(|e| StoreError::InvalidState(e.to_string()))?;
        let digest = format!("{:x}", sha2::Sha256::digest(&canonical));
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let task = query_task_record(&transaction, execution_agent_id)?.ok_or_else(|| {
            StoreError::InvalidState(format!("unknown task {execution_agent_id}"))
        })?;
        let (stop_requested, close_requested): (bool, bool) = transaction.query_row(
            "SELECT stop_requested, close_requested FROM agents WHERE agent_id=?1",
            [execution_agent_id],
            |row| Ok((row.get::<_, i64>(0)? != 0, row.get::<_, i64>(1)? != 0)),
        )?;
        if (stop_requested || close_requested) && result.outcome != TaskOutcome::Cancelled {
            return Err(StoreError::Conflict(
                "cancellation or close intent wins over late completion".into(),
            ));
        }
        if result.outcome == TaskOutcome::Succeeded {
            let (pending, queued): (bool, bool) = transaction.query_row(
                "SELECT
                    EXISTS(SELECT 1 FROM pending_requests WHERE agent_id=?1 AND state IN ('PENDING','SENDING')),
                    EXISTS(SELECT 1 FROM messages WHERE agent_id=?1 AND state IN ('QUEUED','SENDING'))",
                [execution_agent_id],
                |row| Ok((row.get::<_, i64>(0)? != 0, row.get::<_, i64>(1)? != 0)),
            )?;
            if pending || queued {
                return Err(StoreError::Conflict(
                    "natural completion is blocked by pending input or queued messages".into(),
                ));
            }
        }
        if canonical.len() as u64 > task.effective_budget.max_result_bytes {
            return Err(StoreError::InvalidState(
                "task result exceeds effective max_result_bytes".into(),
            ));
        }
        if let Some((existing_hash,existing_json)) = transaction
            .query_row(
                "SELECT result_sha256,summary||'|'||outcome||'|'||artifacts_json FROM task_results WHERE execution_agent_id=?1",
                [execution_agent_id],
                |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?)),
            )
            .optional()?
        {
            let _=existing_json;
            return if existing_hash == digest {
                Ok(())
            } else {
                Err(StoreError::Conflict(format!(
                    "task {execution_agent_id} already has a different immutable completion"
                )))
            };
        }
        if !matches!(
            task.phase,
            TaskPhase::Preparing
                | TaskPhase::Running
                | TaskPhase::WaitingInput
                | TaskPhase::Cancelling
        ) {
            return Err(StoreError::Conflict(
                "task completion requires a preparing/active/cancelling phase".into(),
            ));
        }
        let retained = if !result.partial {
            true
        } else {
            match result.outcome.as_str() {
                "BLOCKED" => true,
                "FAILED" | "CANCELLED" | "TIMED_OUT" | "BUDGET_EXHAUSTED" => task.retain_partial,
                _ => false,
            }
        };
        let changed = transaction.execute("INSERT INTO task_results (execution_agent_id,outcome,summary,partial,retained,base_commit,head_commit,changed_files_json,diff_stat,checks_json,result_sha256,residual_gaps_json,artifacts_json,completed_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)", params![execution_agent_id,result.outcome.as_str(),result.summary,result.partial,retained,result.base_commit,result.head_commit,serde_json::to_string(&result.changed_files).unwrap(),result.diff_stat,serde_json::to_string(&result.checks).unwrap(),digest,serde_json::to_string(&result.residual_gaps).unwrap(),serde_json::to_string(&result.artifacts).unwrap(),now_millis()])?;
        if changed != 1 {
            return Err(StoreError::Conflict(format!(
                "task {execution_agent_id} already has immutable completion"
            )));
        }
        transaction.execute(
            "UPDATE task_attempts SET phase='TERMINAL' WHERE execution_agent_id=?1",
            [execution_agent_id],
        )?;
        let (legacy_state, failure_code) = match result.outcome {
            TaskOutcome::Succeeded => ("COMPLETED", None),
            TaskOutcome::Blocked => ("COMPLETED", Some("BLOCKED")),
            TaskOutcome::Cancelled => ("CANCELLED", Some("CANCELLED")),
            TaskOutcome::RuntimeLost => ("FAILED_RUNTIME_LOST", Some("RUNTIME_LOST")),
            TaskOutcome::TimedOut => ("FAILED", Some("TIMEOUT")),
            TaskOutcome::BudgetExhausted => ("FAILED", Some("BUDGET_EXHAUSTED")),
            TaskOutcome::ResultInvalid => ("FAILED", Some("RESULT_INVALID")),
            TaskOutcome::Failed => ("FAILED", Some("FAILED")),
        };
        transaction.execute(
            "UPDATE agents SET state=?1,completed_at=?2,
             closed_at=CASE WHEN ?4=1 THEN COALESCE(closed_at,?2) ELSE closed_at END,
             failure_code=?3 WHERE agent_id=?5",
            params![
                legacy_state,
                now_millis(),
                failure_code,
                close_requested,
                execution_agent_id
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn task_result(&self, execution_agent_id: &str) -> StoreResult<Option<StoredTaskResult>> {
        let connection = self.connection.lock().unwrap();
        connection.query_row("SELECT outcome,summary,partial,retained,base_commit,head_commit,changed_files_json,diff_stat,checks_json,result_sha256,residual_gaps_json,artifacts_json FROM task_results WHERE execution_agent_id=?1",[execution_agent_id],|row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?,row.get::<_,Option<String>>(4)?,row.get::<_,Option<String>>(5)?,row.get::<_,String>(6)?,row.get::<_,Option<String>>(7)?,row.get::<_,String>(8)?,row.get::<_,String>(9)?,row.get::<_,String>(10)?,row.get::<_,String>(11)?))).optional()?.map(|r| Ok(StoredTaskResult { result:TaskResult { outcome:TaskOutcome::parse(&r.0)?,summary:r.1,partial:r.2!=0,base_commit:r.4,head_commit:r.5,changed_files:serde_json::from_str(&r.6).map_err(|e|StoreError::InvalidState(e.to_string()))?,diff_stat:r.7,checks:serde_json::from_str(&r.8).map_err(|e|StoreError::InvalidState(e.to_string()))?,residual_gaps:serde_json::from_str(&r.10).map_err(|e|StoreError::InvalidState(e.to_string()))?,artifacts:serde_json::from_str(&r.11).map_err(|e|StoreError::InvalidState(e.to_string()))? },result_sha256:r.9,retained:r.3!=0 })).transpose()
    }

    pub fn set_task_phase(&self, execution_agent_id: &str, next: TaskPhase) -> StoreResult<()> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = transaction
            .query_row(
                "SELECT phase FROM task_attempts WHERE execution_agent_id=?1",
                [execution_agent_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| {
                StoreError::InvalidState(format!("unknown task {execution_agent_id}"))
            })?;
        let current = TaskPhase::parse(&current)?;
        let allowed = matches!(
            (current, next),
            (TaskPhase::Queued, TaskPhase::Preparing)
                | (TaskPhase::Preparing, TaskPhase::Running)
                | (TaskPhase::Running, TaskPhase::WaitingInput)
                | (TaskPhase::WaitingInput, TaskPhase::Running)
                | (_, TaskPhase::Cancelling)
        );
        if !allowed || current == TaskPhase::Terminal {
            return Err(StoreError::Conflict(format!(
                "invalid task phase transition {current:?} -> {next:?}"
            )));
        }
        transaction.execute(
            "UPDATE task_attempts SET phase=?1 WHERE execution_agent_id=?2",
            params![next.as_str(), execution_agent_id],
        )?;
        let legacy = match next {
            TaskPhase::Queued => "QUEUED",
            TaskPhase::Preparing => "STARTING",
            TaskPhase::Running | TaskPhase::WaitingInput => "RUNNING",
            TaskPhase::Cancelling => "STOPPING",
            TaskPhase::Terminal => unreachable!(),
        };
        transaction.execute(
            "UPDATE agents SET state=?1 WHERE agent_id=?2",
            params![legacy, execution_agent_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn get_job(&self, agent_id: &str) -> StoreResult<Option<Job>> {
        let connection = self.connection.lock().unwrap();
        query_job(&connection, agent_id)
    }

    pub fn claim_next(
        &self,
        owner_id: &str,
        global_limit: usize,
        per_workspace_limit: usize,
    ) -> StoreResult<Option<JobClaim>> {
        if global_limit == 0 || per_workspace_limit == 0 {
            return Ok(None);
        }
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let active: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM agents WHERE state IN ('STARTING', 'RUNNING', 'STOPPING')",
            [],
            |row| row.get(0),
        )?;
        if active >= usize_to_i64(global_limit)? {
            transaction.commit()?;
            return Ok(None);
        }
        let candidate = transaction
            .query_row(
                "SELECT agent_id, workspace_path FROM agents queued
                 WHERE state = 'QUEUED' AND close_requested = 0
                   AND (SELECT COUNT(*) FROM agents active
                        WHERE active.workspace_path = queued.workspace_path
                          AND active.state IN ('STARTING', 'RUNNING', 'STOPPING')) < ?1
                 ORDER BY queued.created_at, queued.rowid LIMIT 1",
                [usize_to_i64(per_workspace_limit)?],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((agent_id, _workspace_path)) = candidate else {
            transaction.commit()?;
            return Ok(None);
        };
        let started_at = now_millis();
        let changed = transaction.execute(
            "UPDATE agents
             SET state = 'STARTING', owner_id = ?1, owner_epoch = owner_epoch + 1,
                 started_at = COALESCE(started_at, ?2), last_heartbeat_at = ?2
             WHERE agent_id = ?3 AND state = 'QUEUED' AND close_requested = 0",
            params![owner_id, started_at, agent_id],
        )?;
        if changed != 1 {
            return Err(StoreError::Conflict(format!(
                "job {agent_id} lost its queue claim"
            )));
        }
        transaction.execute("UPDATE task_attempts SET phase='PREPARING' WHERE execution_agent_id=?1 AND phase='QUEUED'",[&agent_id])?;
        let job = query_job(&transaction, &agent_id)?
            .ok_or_else(|| StoreError::InvalidState("claimed job could not be read".into()))?;
        insert_ledger(
            &transaction,
            &agent_id,
            job.owner_epoch,
            Some(JobState::Queued),
            JobState::Starting,
            Some("CLAIMED"),
        )?;
        transaction.commit()?;
        Ok(Some(JobClaim {
            owner_epoch: job.owner_epoch,
            job,
        }))
    }

    #[cfg(test)]
    fn mark_running(
        &self,
        agent_id: &str,
        owner_epoch: u64,
        runtime_agent_id: &str,
        identity: Option<&StoredProcessIdentity>,
    ) -> StoreResult<bool> {
        self.mark_session_running(
            agent_id,
            owner_epoch,
            runtime_agent_id,
            identity,
            None,
            None,
        )
    }

    pub fn mark_session_running(
        &self,
        agent_id: &str,
        owner_epoch: u64,
        runtime_agent_id: &str,
        identity: Option<&StoredProcessIdentity>,
        zcode_session_id: Option<&str>,
        turn_state: Option<TurnState>,
    ) -> StoreResult<bool> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE agents SET state = 'RUNNING', runtime_agent_id = ?1,
                 pid = ?2, process_group_id = ?3, process_uid = ?4,
                 process_start_token = ?5, last_heartbeat_at = ?6,
                 zcode_session_id = COALESCE(?7, zcode_session_id),
                 turn_state = COALESCE(?8, turn_state)
             WHERE agent_id = ?9 AND owner_epoch = ?10 AND state = 'STARTING'",
            params![
                runtime_agent_id,
                identity.map(|value| value.pid),
                identity.map(|value| value.process_group_id),
                identity.map(|value| value.uid),
                identity.map(|value| value.start_token.as_str()),
                now_millis(),
                zcode_session_id,
                turn_state.map(TurnState::as_str),
                agent_id,
                u64_to_i64(owner_epoch)?,
            ],
        )?;
        if changed == 1 {
            transaction.execute("UPDATE task_attempts SET phase='RUNNING' WHERE execution_agent_id=?1 AND phase='PREPARING'",[agent_id])?;
            insert_ledger(
                &transaction,
                agent_id,
                owner_epoch,
                Some(JobState::Starting),
                JobState::Running,
                Some("RUNTIME_STARTED"),
            )?;
        }
        transaction.commit()?;
        Ok(changed == 1)
    }

    pub fn append_lifecycle(&self, write: &LifecycleWrite) -> StoreResult<u64> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = transaction
            .query_row(
                "SELECT seq FROM events
                 WHERE agent_id = ?1 AND runtime_agent_id = ?2 AND source_seq = ?3",
                params![
                    write.agent_id,
                    write.runtime_agent_id,
                    u64_to_i64(write.source_sequence)?
                ],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
        {
            transaction.commit()?;
            return i64_to_u64(existing);
        }
        let (state, epoch, close_requested, stop_requested) =
            query_guard(&transaction, &write.agent_id)?;
        if state.is_terminal() || epoch != write.owner_epoch {
            return Err(StoreError::Conflict(format!(
                "late lifecycle record rejected for {} epoch {}",
                write.agent_id, write.owner_epoch
            )));
        }
        let last_seq: i64 = transaction.query_row(
            "SELECT CASE WHEN EXISTS(SELECT 1 FROM task_attempts WHERE execution_agent_id=?1)
             THEN COALESCE((SELECT MAX(e.seq) FROM events e JOIN task_attempts t ON t.execution_agent_id=e.agent_id WHERE t.public_agent_id=(SELECT public_agent_id FROM task_attempts WHERE execution_agent_id=?1)),0)
             ELSE (SELECT last_event_seq FROM agents WHERE agent_id=?1) END",
            [&write.agent_id], |row| row.get(0))?;
        let sequence = last_seq
            .checked_add(1)
            .ok_or_else(|| StoreError::InvalidState("event sequence overflow".into()))?;
        transaction.execute(
            "INSERT INTO events (
                agent_id, runtime_agent_id, seq, source_seq, timestamp,
                event_type, turn_id, payload_json, redaction_level, attempt_sequence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, COALESCE((SELECT attempt_sequence FROM task_attempts WHERE execution_agent_id=?1),1))",
            params![
                write.agent_id,
                write.runtime_agent_id,
                sequence,
                u64_to_i64(write.source_sequence)?,
                now_millis(),
                write.event_type,
                write.turn_id,
                write.payload_json,
                write.redaction_level,
            ],
        )?;
        transaction.execute(
            "INSERT INTO agent_cursors (agent_id, runtime_agent_id, last_seq)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(agent_id, runtime_agent_id)
             DO UPDATE SET last_seq = excluded.last_seq",
            params![write.agent_id, write.runtime_agent_id, sequence],
        )?;
        transaction.execute(
            "UPDATE agents SET last_event_seq = MAX(last_event_seq, ?1),
                 last_heartbeat_at = ?2,
                 turn_state = COALESCE(?3, turn_state)
             WHERE agent_id = ?4",
            params![
                sequence,
                now_millis(),
                write.turn_state.map(TurnState::as_str),
                write.agent_id
            ],
        )?;
        if let Some(terminal) = &write.terminal {
            apply_terminal(
                &transaction,
                &write.agent_id,
                write.owner_epoch,
                state,
                close_requested,
                stop_requested,
                terminal,
            )?;
        }
        transaction.commit()?;
        i64_to_u64(sequence)
    }

    pub fn transition_terminal(
        &self,
        agent_id: &str,
        owner_epoch: u64,
        terminal: &TerminalUpdate,
    ) -> StoreResult<JobState> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, epoch, close_requested, stop_requested) = query_guard(&transaction, agent_id)?;
        if state.is_terminal() {
            transaction.commit()?;
            return Ok(state);
        }
        if epoch != owner_epoch {
            return Err(StoreError::Conflict(format!(
                "owner epoch changed for {agent_id}"
            )));
        }
        let final_state = apply_terminal(
            &transaction,
            agent_id,
            owner_epoch,
            state,
            close_requested,
            stop_requested,
            terminal,
        )?;
        transaction.commit()?;
        Ok(final_state)
    }

    pub fn fail_claim(
        &self,
        agent_id: &str,
        owner_epoch: u64,
        failure_code: &str,
        message: &str,
    ) -> StoreResult<JobState> {
        self.transition_terminal(
            agent_id,
            owner_epoch,
            &TerminalUpdate {
                state: JobState::FailedRuntimeLost,
                failure_code: Some(failure_code.into()),
                failure_message: Some(message.into()),
            },
        )
    }

    pub fn request_close(&self, agent_id: &str) -> StoreResult<CloseDecision> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, epoch, close_requested, stop_requested) = query_guard(&transaction, agent_id)?;
        let is_v2 = transaction
            .query_row(
                "SELECT 1 FROM task_attempts WHERE execution_agent_id=?1",
                [agent_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let (next, needs_runtime_stop) = match state {
            JobState::Queued if is_v2 => (JobState::Stopping, false),
            JobState::Queued => (JobState::Cancelled, false),
            JobState::Starting | JobState::Running => (JobState::Stopping, true),
            JobState::Stopping => (JobState::Stopping, true),
            terminal => (terminal, false),
        };
        if state != next || !state.is_terminal() {
            transaction.execute(
                "UPDATE agents SET state = ?1, close_requested = 1, stop_requested = 1,
                     closed_at = CASE WHEN ?2 = 1 THEN COALESCE(closed_at, ?3)
                                      ELSE closed_at END,
                     completed_at = CASE WHEN ?2 = 1 THEN COALESCE(completed_at, ?3)
                                         ELSE completed_at END
                 WHERE agent_id = ?4",
                params![next.as_str(), next.is_terminal(), now_millis(), agent_id],
            )?;
            settle_terminal_commands(&transaction, agent_id, "CLOSE_REQUESTED")?;
            if state != next {
                insert_ledger(
                    &transaction,
                    agent_id,
                    epoch,
                    Some(state),
                    next,
                    Some("CLOSE_REQUESTED"),
                )?;
            }
        } else {
            transaction.execute(
                "UPDATE agents SET close_requested = 1,
                     closed_at = COALESCE(closed_at, ?1) WHERE agent_id = ?2",
                params![now_millis(), agent_id],
            )?;
        }
        transaction.execute("UPDATE task_attempts SET phase=CASE WHEN ?1='STOPPING' THEN 'CANCELLING' WHEN ?2=1 THEN 'TERMINAL' ELSE phase END WHERE execution_agent_id=?3",params![next.as_str(),next.is_terminal(),agent_id])?;
        transaction.commit()?;
        Ok(CloseDecision {
            state: next,
            owner_epoch: epoch,
            needs_runtime_stop,
            prior_stop_or_close: close_requested || stop_requested,
        })
    }

    pub fn request_stop(&self, agent_id: &str) -> StoreResult<CloseDecision> {
        self.request_stop_with_intent(agent_id, true)
    }

    pub fn request_runtime_stop(&self, agent_id: &str) -> StoreResult<CloseDecision> {
        self.request_stop_with_intent(agent_id, false)
    }

    fn request_stop_with_intent(
        &self,
        agent_id: &str,
        cancellation_intent: bool,
    ) -> StoreResult<CloseDecision> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, epoch, close_requested, stop_requested) = query_guard(&transaction, agent_id)?;
        let is_v2 = transaction
            .query_row(
                "SELECT 1 FROM task_attempts WHERE execution_agent_id=?1",
                [agent_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        let (next, needs_runtime_stop) = match state {
            JobState::Queued if is_v2 => (JobState::Stopping, false),
            JobState::Queued => (JobState::Cancelled, false),
            JobState::Starting | JobState::Running => (JobState::Stopping, true),
            JobState::Stopping => (JobState::Stopping, true),
            terminal => (terminal, false),
        };
        if !state.is_terminal() {
            transaction.execute(
                "UPDATE agents SET state = ?1,
                     stop_requested = CASE WHEN ?2 = 1 THEN 1 ELSE stop_requested END,
                     completed_at = CASE WHEN ?3 = 1 THEN COALESCE(completed_at, ?4)
                                         ELSE completed_at END
                 WHERE agent_id = ?5",
                params![
                    next.as_str(),
                    cancellation_intent,
                    next.is_terminal(),
                    now_millis(),
                    agent_id
                ],
            )?;
            settle_terminal_commands(&transaction, agent_id, "STOP_REQUESTED")?;
            if state != next {
                insert_ledger(
                    &transaction,
                    agent_id,
                    epoch,
                    Some(state),
                    next,
                    Some("STOP_REQUESTED"),
                )?;
            }
        }
        transaction.execute("UPDATE task_attempts SET phase=CASE WHEN ?1='STOPPING' THEN 'CANCELLING' WHEN ?2=1 THEN 'TERMINAL' ELSE phase END WHERE execution_agent_id=?3",params![next.as_str(),next.is_terminal(),agent_id])?;
        transaction.commit()?;
        Ok(CloseDecision {
            state: next,
            owner_epoch: epoch,
            needs_runtime_stop,
            prior_stop_or_close: close_requested || stop_requested,
        })
    }

    pub fn reap_job(&self, agent_id: &str) -> StoreResult<JobState> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, _, _, _) = query_guard(&transaction, agent_id)?;
        if !state.is_terminal() {
            return Err(StoreError::InvalidState(format!(
                "cannot reap nonterminal job {agent_id}"
            )));
        }
        transaction.execute(
            "UPDATE agents SET owner_id = NULL, lease_expires_at = NULL,
                 reaped_at = COALESCE(reaped_at, ?1) WHERE agent_id = ?2",
            params![now_millis(), agent_id],
        )?;
        transaction.commit()?;
        Ok(state)
    }

    pub fn reconcile_startup(&self) -> StoreResult<Vec<(String, JobState)>> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let rows = {
            let mut statement = transaction.prepare(
                "SELECT agent_id, state, owner_epoch FROM agents
                 WHERE state IN ('STARTING', 'RUNNING', 'STOPPING')
                 ORDER BY created_at, rowid",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            rows
        };
        let mut reconciled = Vec::with_capacity(rows.len());
        for (agent_id, state, epoch) in rows {
            let old = JobState::parse(&state)?;
            let (next, code) = (JobState::FailedRuntimeLost, "DAEMON_RESTART_RUNTIME_LOST");
            let restart_result = TaskResult {
                outcome: TaskOutcome::RuntimeLost,
                summary: "daemon restarted; live session reconnect is unsupported".into(),
                partial: true,
                base_commit: None,
                head_commit: None,
                changed_files: Vec::new(),
                diff_stat: None,
                checks: Vec::new(),
                residual_gaps: vec!["DAEMON_RESTARTED".into()],
                artifacts: Vec::new(),
            };
            let result_json = serde_json::to_vec(&restart_result)
                .map_err(|error| StoreError::InvalidState(error.to_string()))?;
            let result_sha256 = format!("{:x}", sha2::Sha256::digest(&result_json));
            transaction.execute(
                "UPDATE agents SET state = ?1, completed_at = COALESCE(completed_at, ?2),
                     failure_code = ?3, failure_message = ?4
                 WHERE agent_id = ?5 AND state = ?6",
                params![
                    next.as_str(),
                    now_millis(),
                    code,
                    "daemon restarted; live session reconnect is unsupported",
                    agent_id,
                    old.as_str(),
                ],
            )?;
            transaction.execute(
                "INSERT INTO task_results (
                    execution_agent_id,outcome,summary,partial,retained,base_commit,
                    head_commit,changed_files_json,diff_stat,checks_json,result_sha256,
                    residual_gaps_json,artifacts_json,completed_at
                 )
                 SELECT ?1,'RUNTIME_LOST',?2,1,0,NULL,NULL,'[]',NULL,'[]',?3,?4,'[]',?5
                 WHERE EXISTS (
                    SELECT 1 FROM task_attempts
                    WHERE execution_agent_id=?1
                      AND phase IN ('PREPARING','RUNNING','WAITING_INPUT','CANCELLING')
                 )",
                params![
                    agent_id,
                    restart_result.summary,
                    result_sha256,
                    serde_json::to_string(&restart_result.residual_gaps)
                        .map_err(|error| StoreError::InvalidState(error.to_string()))?,
                    now_millis(),
                ],
            )?;
            transaction.execute(
                "UPDATE task_attempts SET phase='TERMINAL'
                 WHERE execution_agent_id=?1
                   AND phase IN ('PREPARING','RUNNING','WAITING_INPUT','CANCELLING')",
                [&agent_id],
            )?;
            settle_terminal_commands(&transaction, &agent_id, "DAEMON_RESTART_RUNTIME_LOST")?;
            insert_ledger(
                &transaction,
                &agent_id,
                i64_to_u64(epoch)?,
                Some(old),
                next,
                Some(code),
            )?;
            reconciled.push((agent_id, next));
        }
        transaction.commit()?;
        Ok(reconciled)
    }

    pub fn insert_message(
        &self,
        message_id: &str,
        agent_id: &str,
        mode: &str,
        content: &str,
    ) -> StoreResult<bool> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = query_message(&transaction, message_id)? {
            if existing.agent_id != agent_id || existing.mode != mode || existing.content != content
            {
                return Err(StoreError::Conflict(format!(
                    "message id {message_id} was reused with different content"
                )));
            }
            let job = query_job(&transaction, agent_id)?
                .ok_or_else(|| StoreError::InvalidState(format!("unknown job {agent_id}")))?;
            if job.state.is_terminal()
                && matches!(existing.state, MessageState::Queued | MessageState::Sending)
            {
                settle_terminal_commands(&transaction, agent_id, "JOB_ALREADY_TERMINAL")?;
            }
            transaction.commit()?;
            return Ok(false);
        }
        let job = query_job(&transaction, agent_id)?
            .ok_or_else(|| StoreError::InvalidState(format!("unknown job {agent_id}")))?;
        if job.state.is_terminal() {
            return Err(StoreError::InvalidState(format!(
                "cannot message terminal job {agent_id}"
            )));
        }
        let changed = transaction.execute(
            "INSERT OR IGNORE INTO messages
             (message_id, agent_id, mode, content, state, created_at)
             VALUES (?1, ?2, ?3, ?4, 'QUEUED', ?5)",
            params![message_id, agent_id, mode, content, now_millis()],
        )?;
        transaction.commit()?;
        Ok(changed == 1)
    }

    pub fn insert_pending_request(
        &self,
        request_id: &str,
        agent_id: &str,
        correlation_id: &str,
        request_type: &str,
        payload_json: &str,
    ) -> StoreResult<bool> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = query_pending_request(&transaction, request_id)? {
            if existing.agent_id != agent_id
                || existing.correlation_id != correlation_id
                || existing.request_type != request_type
                || existing.payload_json != payload_json
            {
                return Err(StoreError::Conflict(format!(
                    "pending request id {request_id} was reused"
                )));
            }
            transaction.commit()?;
            return Ok(false);
        }
        let changed = transaction.execute(
            "INSERT OR IGNORE INTO pending_requests
             (request_id, agent_id, correlation_id, request_type, payload_json, state, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, 'PENDING', ?6)",
            params![
                request_id,
                agent_id,
                correlation_id,
                request_type,
                payload_json,
                now_millis()
            ],
        )?;
        transaction.commit()?;
        Ok(changed == 1)
    }

    pub fn message(&self, message_id: &str) -> StoreResult<Option<StoredMessage>> {
        let connection = self.connection.lock().unwrap();
        query_message(&connection, message_id)
    }

    pub fn claim_next_message(&self, agent_id: &str) -> StoreResult<Option<StoredMessage>> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let message_id = transaction
            .query_row(
                "SELECT messages.message_id FROM messages
                 JOIN agents ON agents.agent_id = messages.agent_id
                 WHERE messages.agent_id = ?1 AND messages.state = 'QUEUED'
                   AND agents.state = 'RUNNING'
                   AND agents.stop_requested = 0 AND agents.close_requested = 0
                 ORDER BY messages.created_at, messages.rowid LIMIT 1",
                [agent_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(message_id) = message_id else {
            transaction.commit()?;
            return Ok(None);
        };
        transaction.execute(
            "UPDATE messages SET state = 'SENDING'
             WHERE message_id = ?1 AND state = 'QUEUED'",
            [&message_id],
        )?;
        let message = query_message(&transaction, &message_id)?;
        transaction.commit()?;
        Ok(message)
    }

    pub fn complete_message(
        &self,
        message_id: &str,
        target_turn_id: Option<&str>,
    ) -> StoreResult<bool> {
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "UPDATE messages SET state = 'DELIVERED', delivered_at = ?1,
                 target_turn_id = ?2, failure_code = NULL, failure_message = NULL
             WHERE message_id = ?3 AND state = 'SENDING'",
            params![now_millis(), target_turn_id, message_id],
        )?;
        Ok(changed == 1)
    }

    pub fn fail_message(
        &self,
        message_id: &str,
        failure_code: &str,
        failure_message: &str,
    ) -> StoreResult<bool> {
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "UPDATE messages SET state = 'FAILED', failure_code = ?1,
                 failure_message = ?2 WHERE message_id = ?3 AND state = 'SENDING'",
            params![failure_code, failure_message, message_id],
        )?;
        Ok(changed == 1)
    }

    #[cfg(test)]
    fn deliver_message(&self, message_id: &str) -> StoreResult<bool> {
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "UPDATE messages SET state = 'DELIVERED', delivered_at = ?1
             WHERE message_id = ?2 AND state = 'QUEUED'",
            params![now_millis(), message_id],
        )?;
        Ok(changed == 1)
    }

    pub fn pending_request(
        &self,
        agent_id: &str,
        request_id: &str,
    ) -> StoreResult<Option<StoredPendingRequest>> {
        let connection = self.connection.lock().unwrap();
        let request = query_pending_request(&connection, request_id)?;
        Ok(request.filter(|request| request.agent_id == agent_id))
    }

    pub fn pending_requests(&self, agent_id: &str) -> StoreResult<Vec<StoredPendingRequest>> {
        self.pending_requests_bounded(agent_id, i64::MAX as usize)
    }

    pub fn completion_blockers(&self, agent_id: &str) -> StoreResult<(bool, bool)> {
        let connection = self.connection.lock().unwrap();
        connection
            .query_row(
                "SELECT
                    EXISTS(SELECT 1 FROM pending_requests WHERE agent_id=?1 AND state IN ('PENDING','SENDING')),
                    EXISTS(SELECT 1 FROM messages WHERE agent_id=?1 AND state IN ('QUEUED','SENDING'))",
                [agent_id],
                |row| Ok((row.get::<_, i64>(0)? != 0, row.get::<_, i64>(1)? != 0)),
            )
            .map_err(StoreError::from)
    }

    pub fn pending_requests_bounded(
        &self,
        agent_id: &str,
        limit: usize,
    ) -> StoreResult<Vec<StoredPendingRequest>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            "SELECT request_id FROM pending_requests
             WHERE agent_id = ?1
             ORDER BY CASE state WHEN 'PENDING' THEN 0 WHEN 'SENDING' THEN 1 ELSE 2 END,
                      created_at DESC, rowid DESC
             LIMIT ?2",
        )?;
        let limit = usize_to_i64(limit)?;
        let ids = statement
            .query_map(params![agent_id, limit], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        ids.into_iter()
            .map(|request_id| {
                query_pending_request(&connection, &request_id)?.ok_or_else(|| {
                    StoreError::InvalidState(format!("pending request {request_id} disappeared"))
                })
            })
            .collect()
    }

    pub fn claim_pending_response_if_attempt_accepting(
        &self,
        execution_agent_id: &str,
        request_id: &str,
        expected_attempt_sequence: u64,
        decision: &str,
        content: Option<&str>,
    ) -> StoreResult<PendingResponseClaimDisposition> {
        if expected_attempt_sequence == 0 {
            return Err(StoreError::InvalidState(
                "expected attempt sequence must be positive".into(),
            ));
        }
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let Some(request) = query_pending_request(&transaction, request_id)? else {
            transaction.commit()?;
            return Ok(PendingResponseClaimDisposition::NotFound);
        };
        if request.agent_id != execution_agent_id {
            transaction.commit()?;
            return Ok(PendingResponseClaimDisposition::NotFound);
        }
        if request.state != PendingRequestState::Pending
            && (request.response_decision.as_deref() != Some(decision)
                || request.response_content.as_deref() != content)
        {
            return Err(StoreError::Conflict(format!(
                "request {request_id} response was changed"
            )));
        }
        if request.state != PendingRequestState::Pending {
            let state = request.state;
            transaction.commit()?;
            return Ok(PendingResponseClaimDisposition::NotPending(state));
        }

        let attempt = transaction
            .query_row(
                "SELECT attempt_sequence, phase, public_agent_id
                 FROM task_attempts WHERE execution_agent_id=?1",
                [execution_agent_id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                },
            )
            .optional()?;
        let attempt_accepting = match attempt {
            Some((attempt_sequence, phase, public_agent_id)) => {
                if i64_to_u64(attempt_sequence)? != expected_attempt_sequence {
                    transaction.commit()?;
                    return Ok(PendingResponseClaimDisposition::AttemptMismatch);
                }
                let latest: i64 = transaction.query_row(
                    "SELECT MAX(attempt_sequence) FROM task_attempts WHERE public_agent_id=?1",
                    [&public_agent_id],
                    |row| row.get(0),
                )?;
                if i64_to_u64(latest)? != expected_attempt_sequence {
                    transaction.commit()?;
                    return Ok(PendingResponseClaimDisposition::AttemptMismatch);
                }
                matches!(phase.as_str(), "RUNNING" | "WAITING_INPUT")
            }
            None if expected_attempt_sequence == 1 => true,
            None => {
                transaction.commit()?;
                return Ok(PendingResponseClaimDisposition::AttemptMismatch);
            }
        };
        let (state, _, close_requested, stop_requested) =
            query_guard(&transaction, execution_agent_id)?;
        if !attempt_accepting || state != JobState::Running || stop_requested || close_requested {
            transaction.commit()?;
            return Ok(PendingResponseClaimDisposition::AttemptStopping);
        }
        let changed = transaction.execute(
            "UPDATE pending_requests SET state = 'SENDING',
                 response_decision = ?1, response_content = ?2
             WHERE request_id = ?3 AND agent_id = ?4 AND state = 'PENDING'",
            params![decision, content, request_id, execution_agent_id],
        )?;
        let claim = if changed == 1 {
            PendingResponseClaimDisposition::Claimed
        } else {
            PendingResponseClaimDisposition::NotPending(
                query_pending_request(&transaction, request_id)?
                    .map(|request| request.state)
                    .unwrap_or(PendingRequestState::Pending),
            )
        };
        transaction.commit()?;
        Ok(claim)
    }

    pub fn complete_pending_response(&self, agent_id: &str, request_id: &str) -> StoreResult<bool> {
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "UPDATE pending_requests SET state = 'RESPONDED', responded_at = ?1
             WHERE agent_id = ?2 AND request_id = ?3 AND state = 'SENDING'",
            params![now_millis(), agent_id, request_id],
        )?;
        Ok(changed == 1)
    }

    pub fn release_pending_response(&self, agent_id: &str, request_id: &str) -> StoreResult<bool> {
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "UPDATE pending_requests SET state = 'PENDING',
                 response_decision = NULL, response_content = NULL
             WHERE agent_id = ?1 AND request_id = ?2 AND state = 'SENDING'",
            params![agent_id, request_id],
        )?;
        Ok(changed == 1)
    }

    #[cfg(test)]
    fn respond_pending_request(&self, agent_id: &str, correlation_id: &str) -> StoreResult<bool> {
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "UPDATE pending_requests SET state = 'RESPONDED', responded_at = ?1
             WHERE agent_id = ?2 AND correlation_id = ?3 AND state = 'PENDING'",
            params![now_millis(), agent_id, correlation_id],
        )?;
        Ok(changed == 1)
    }

    #[cfg(test)]
    fn respond_pending_request_by_id(&self, agent_id: &str, request_id: &str) -> StoreResult<bool> {
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "UPDATE pending_requests SET state = 'RESPONDED', responded_at = ?1
             WHERE agent_id = ?2 AND request_id = ?3 AND state = 'PENDING'",
            params![now_millis(), agent_id, request_id],
        )?;
        Ok(changed == 1)
    }

    pub fn insert_artifact(&self, artifact: &NewArtifact) -> StoreResult<bool> {
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "INSERT OR IGNORE INTO artifacts
             (artifact_id, agent_id, artifact_type, path, sha256, bytes, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                artifact.artifact_id,
                artifact.agent_id,
                artifact.artifact_type,
                artifact.path,
                artifact.sha256,
                u64_to_i64(artifact.bytes)?,
                now_millis(),
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn cursor(&self, agent_id: &str, runtime_agent_id: &str) -> StoreResult<u64> {
        let connection = self.connection.lock().unwrap();
        let value = connection
            .query_row(
                "SELECT last_seq FROM agent_cursors
                 WHERE agent_id = ?1 AND runtime_agent_id = ?2",
                params![agent_id, runtime_agent_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0);
        i64_to_u64(value)
    }

    pub fn artifact_count(&self, agent_id: &str) -> StoreResult<u64> {
        self.count_for(
            "SELECT COUNT(*) FROM artifacts WHERE agent_id = ?1",
            agent_id,
        )
    }

    pub fn artifacts(&self, agent_id: &str, limit: usize) -> StoreResult<Vec<StoredArtifact>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            "SELECT artifact_id, artifact_type, path, sha256, bytes, created_at
             FROM artifacts WHERE agent_id = ?1
             ORDER BY created_at DESC, artifact_id DESC
             LIMIT ?2",
        )?;
        let rows = statement
            .query_map(params![agent_id, usize_to_i64(limit)?], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(artifact_id, artifact_type, path, sha256, bytes, created_at)| {
                    Ok(StoredArtifact {
                        artifact_id,
                        artifact_type,
                        path,
                        sha256,
                        bytes: i64_to_u64(bytes)?,
                        created_at,
                    })
                },
            )
            .collect()
    }

    pub fn active_count(&self) -> StoreResult<u64> {
        let connection = self.connection.lock().unwrap();
        let count = connection.query_row(
            "SELECT COUNT(*) FROM agents WHERE state IN ('STARTING', 'RUNNING', 'STOPPING')",
            [],
            |row| row.get::<_, i64>(0),
        )?;
        i64_to_u64(count)
    }

    fn count_for(&self, sql: &str, agent_id: &str) -> StoreResult<u64> {
        let connection = self.connection.lock().unwrap();
        let count = connection.query_row(sql, [agent_id], |row| row.get::<_, i64>(0))?;
        i64_to_u64(count)
    }

    #[cfg(test)]
    fn set_query_only(&self, enabled: bool) -> StoreResult<()> {
        let connection = self.connection.lock().unwrap();
        connection.pragma_update(None, "query_only", enabled)?;
        Ok(())
    }
}

fn validate_task(task: &NewTask) -> StoreResult<()> {
    if task.public_agent_id.is_empty()
        || task.repository.is_empty()
        || task.feature_id.is_empty()
        || task.ownership_token.is_empty()
    {
        return Err(StoreError::InvalidState(
            "task identity and query scope must be non-empty".into(),
        ));
    }
    if task
        .job
        .feature_id
        .as_deref()
        .is_some_and(|value| value != task.feature_id)
    {
        return Err(StoreError::Conflict(
            "duplicated legacy/new task identity fields disagree".into(),
        ));
    }
    Ok(())
}

fn validate_prepared_launch(job: &NewJob) -> StoreResult<()> {
    match (
        job.prepared_launch_json.as_deref(),
        job.prepared_launch_sha256.as_deref(),
    ) {
        (Some(json), Some(hash)) if !json.is_empty() && !hash.is_empty() => Ok(()),
        (None, None) => Ok(()),
        _ => Err(StoreError::InvalidState(
            "prepared launch JSON and SHA-256 must be supplied together".into(),
        )),
    }
}

fn bind_task_identity(connection: &Connection, task: &NewTask) -> StoreResult<()> {
    if let Some(existing) = connection
        .query_row(
            "SELECT repository,feature_id,ownership_token FROM task_identities WHERE public_agent_id=?1",
            [&task.public_agent_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
        )
        .optional()?
    {
        if existing
            != (
                task.repository.clone(),
                task.feature_id.clone(),
                task.ownership_token.clone(),
            )
        {
            return Err(StoreError::Conflict(
                "public agent identity is already bound to different semantics".into(),
            ));
        }
        return Ok(());
    }
    connection.execute(
        "INSERT INTO task_identities (public_agent_id,repository,feature_id,ownership_token) VALUES (?1,?2,?3,?4)",
        params![task.public_agent_id, task.repository, task.feature_id, task.ownership_token],
    )?;
    Ok(())
}

fn validate_scope(scope: &TaskQueryScope<'_>) -> StoreResult<()> {
    if scope.repository.is_none() && scope.feature_id.is_none() && scope.ownership_token.is_none() {
        Err(StoreError::InvalidState(
            "at least one task query scope is required".into(),
        ))
    } else {
        Ok(())
    }
}

/// Resolves an optional task budget through the Store-owned defaults and hard
/// caps. Callers that compare idempotent submissions use this projection
/// instead of copying the durable budget rules.
pub fn resolve_effective_budget(request: &BudgetRequest) -> StoreResult<EffectiveBudget> {
    let value = match request {
        BudgetRequest::Omitted => DEFAULT_BUDGET,
        BudgetRequest::Null => {
            return Err(StoreError::InvalidState(
                "budget null is not omission".into(),
            ))
        }
        BudgetRequest::Limits(value) => value.clone(),
    };
    let pairs = [
        (
            value.absolute_wall_time_ms,
            MAX_BUDGET.absolute_wall_time_ms,
        ),
        (
            value.runtime_activity_idle_timeout_ms,
            MAX_BUDGET.runtime_activity_idle_timeout_ms,
        ),
        (
            value.model_stream_idle_timeout_ms,
            MAX_BUDGET.model_stream_idle_timeout_ms,
        ),
        (value.tool_call_timeout_ms, MAX_BUDGET.tool_call_timeout_ms),
        (
            value.input_wait_timeout_ms,
            MAX_BUDGET.input_wait_timeout_ms,
        ),
        (value.max_turns, MAX_BUDGET.max_turns),
        (value.max_tool_calls, MAX_BUDGET.max_tool_calls),
        (value.max_context_bytes, MAX_BUDGET.max_context_bytes),
        (value.max_result_bytes, MAX_BUDGET.max_result_bytes),
        (value.max_artifact_bytes, MAX_BUDGET.max_artifact_bytes),
    ];
    if pairs.iter().any(|(value, cap)| *value == 0 || value > cap) {
        return Err(StoreError::InvalidState(
            "budget limit is zero or above hard cap".into(),
        ));
    }
    Ok(value)
}

fn task_fingerprint(task: &NewTask, budget: &EffectiveBudget) -> String {
    use sha2::{Digest, Sha256};
    let canonical = format!(
        "v2|{:?}|{:?}",
        (
            task.task_kind,
            &task.public_agent_id,
            &task.job.workspace_path,
            &task.repository,
            &task.feature_id,
            &task.ownership_token,
            &task.job.initial_prompt,
            budget
        ),
        (
            &task.job.prepared_launch_json,
            &task.job.prepared_launch_sha256,
            &task.job.runtime_hash,
            &task.job.feature_id,
            task.retain_partial,
            task.job.idempotency_key.as_deref()
        )
    );
    format!("{:x}", Sha256::digest(canonical.as_bytes()))
}

fn validate_result(result: &TaskResult) -> StoreResult<()> {
    if result.summary.is_empty() {
        return Err(StoreError::InvalidState("invalid task completion".into()));
    }
    if result.partial && result.outcome == TaskOutcome::Succeeded {
        return Err(StoreError::InvalidState(
            "partial result cannot be successful".into(),
        ));
    }
    Ok(())
}

fn query_task_record(connection: &Connection, id: &str) -> StoreResult<Option<TaskRecord>> {
    connection.query_row("SELECT execution_agent_id,public_agent_id,task_kind,phase,attempt_sequence,repository,feature_id,ownership_token,effective_budget_json,retain_partial FROM task_attempts WHERE execution_agent_id=?1",[id],|row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?,row.get::<_,i64>(4)?,row.get::<_,String>(5)?,row.get::<_,String>(6)?,row.get::<_,String>(7)?,row.get::<_,String>(8)?,row.get::<_,i64>(9)?))).optional()?.map(|r| Ok(TaskRecord { execution_agent_id:r.0,public_agent_id:r.1,task_kind:TaskKind::parse(&r.2)?,phase:TaskPhase::parse(&r.3)?,attempt_sequence:i64_to_u64(r.4)?,repository:r.5,feature_id:r.6,ownership_token:r.7,effective_budget:serde_json::from_str(&r.8).map_err(|e| StoreError::InvalidState(format!("invalid effective budget: {e}")))?,retain_partial:r.9 != 0 })).transpose()
}

fn query_latest_task_scoped(
    connection: &Connection,
    public_id: &str,
    scope: TaskQueryScope<'_>,
) -> StoreResult<Option<TaskRecord>> {
    validate_scope(&scope)?;
    let id=connection.query_row("SELECT execution_agent_id FROM task_attempts WHERE public_agent_id=?1 AND (?2 IS NULL OR repository=?2) AND (?3 IS NULL OR feature_id=?3) AND (?4 IS NULL OR ownership_token=?4) ORDER BY attempt_sequence DESC LIMIT 1",params![public_id,scope.repository,scope.feature_id,scope.ownership_token],|row| row.get::<_,String>(0)).optional()?;
    id.map(|id| query_task_record(connection, &id))
        .transpose()
        .map(Option::flatten)
}

fn initialize_schema(connection: &mut Connection) -> StoreResult<()> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version != 0 && version != SCHEMA_VERSION {
        return Err(StoreError::InvalidState(format!(
            "store schema version {version} predates the generic control plane"
        )));
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    transaction.execute_batch(SCHEMA)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn query_message(connection: &Connection, message_id: &str) -> StoreResult<Option<StoredMessage>> {
    let row = connection
        .query_row(
            "SELECT message_id, agent_id, mode, content, state, target_turn_id,
                    failure_code FROM messages WHERE message_id = ?1",
            [message_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(message_id, agent_id, mode, content, state, target_turn_id, failure_code)| {
            let state = match state.as_str() {
                "QUEUED" => MessageState::Queued,
                "SENDING" => MessageState::Sending,
                "DELIVERED" => MessageState::Delivered,
                "FAILED" => MessageState::Failed,
                other => {
                    return Err(StoreError::InvalidState(format!(
                        "unknown message state {other}"
                    )))
                }
            };
            Ok(StoredMessage {
                message_id,
                agent_id,
                mode,
                content,
                state,
                target_turn_id,
                failure_code,
            })
        },
    )
    .transpose()
}

fn query_pending_request(
    connection: &Connection,
    request_id: &str,
) -> StoreResult<Option<StoredPendingRequest>> {
    let row = connection
        .query_row(
            "SELECT request_id, agent_id, correlation_id, request_type,
                    payload_json, state, response_decision, response_content, created_at
             FROM pending_requests WHERE request_id = ?1",
            [request_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            request_id,
            agent_id,
            correlation_id,
            request_type,
            payload_json,
            state,
            response_decision,
            response_content,
            created_at,
        )| {
            let state = match state.as_str() {
                "PENDING" => PendingRequestState::Pending,
                "SENDING" => PendingRequestState::Sending,
                "RESPONDED" => PendingRequestState::Responded,
                other => {
                    return Err(StoreError::InvalidState(format!(
                        "unknown pending request state {other}"
                    )))
                }
            };
            Ok(StoredPendingRequest {
                request_id,
                agent_id,
                correlation_id,
                request_type,
                payload_json,
                state,
                response_decision,
                response_content,
                created_at,
            })
        },
    )
    .transpose()
}

fn query_job(connection: &Connection, agent_id: &str) -> StoreResult<Option<Job>> {
    let row = connection
        .query_row(
            "SELECT agent_id, idempotency_key, state, workspace_path, initial_prompt, owner_id,
                    owner_epoch, close_requested, stop_requested, last_event_seq,
                    failure_code, failure_message, runtime_agent_id,
                    zcode_session_id, turn_state, pid, process_group_id,
                    process_uid, process_start_token, closed_at, reaped_at, created_at,
                    prepared_launch_json, prepared_launch_sha256
             FROM agents WHERE agent_id = ?1",
            [agent_id],
            map_job_row,
        )
        .optional()?;
    row.map(convert_job_row).transpose()
}

fn query_submission_ownership_by_idempotency(
    connection: &Connection,
    key: &str,
) -> StoreResult<Option<SubmissionOwnership>> {
    let row = connection
        .query_row(
            "SELECT a.agent_id,t.task_kind,t.semantic_fingerprint
         FROM agents a
         LEFT JOIN task_attempts t ON t.execution_agent_id=a.agent_id
         WHERE a.idempotency_key = ?1
         ORDER BY a.created_at,a.rowid
         LIMIT 1",
            [key],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?;
    row.map(|(execution_agent_id, task_kind, semantic_fingerprint)| {
        Ok(SubmissionOwnership {
            execution_agent_id,
            task_kind: task_kind.map(|kind| TaskKind::parse(&kind)).transpose()?,
            semantic_fingerprint,
        })
    })
    .transpose()
}

type JobRow = (
    String,
    Option<String>,
    String,
    String,
    String,
    Option<String>,
    i64,
    i64,
    i64,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    String,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    i64,
    Option<String>,
    Option<String>,
);

fn map_job_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
        row.get(15)?,
        row.get(16)?,
        row.get(17)?,
        row.get(18)?,
        row.get(19)?,
        row.get(20)?,
        row.get(21)?,
        row.get(22)?,
        row.get(23)?,
    ))
}

fn convert_job_row(row: JobRow) -> StoreResult<Job> {
    let identity = match (row.15, row.16, row.17, row.18) {
        (Some(pid), Some(process_group_id), Some(uid), Some(start_token)) => {
            Some(StoredProcessIdentity {
                pid: u32::try_from(pid)
                    .map_err(|_| StoreError::InvalidState("stored pid is invalid".into()))?,
                process_group_id: i32::try_from(process_group_id).map_err(|_| {
                    StoreError::InvalidState("stored process group is invalid".into())
                })?,
                uid: u32::try_from(uid)
                    .map_err(|_| StoreError::InvalidState("stored uid is invalid".into()))?,
                start_token,
            })
        }
        (None, None, None, None) => None,
        _ => {
            return Err(StoreError::InvalidState(
                "stored process identity is incomplete".into(),
            ))
        }
    };
    Ok(Job {
        agent_id: row.0,
        idempotency_key: row.1,
        state: JobState::parse(&row.2)?,
        workspace_path: row.3,
        initial_prompt: row.4,
        prepared_launch_json: row.22,
        prepared_launch_sha256: row.23,
        owner_id: row.5,
        owner_epoch: i64_to_u64(row.6)?,
        close_requested: row.7 != 0,
        stop_requested: row.8 != 0,
        last_event_seq: i64_to_u64(row.9)?,
        failure_code: row.10,
        failure_message: row.11,
        runtime_agent_id: row.12,
        zcode_session_id: row.13,
        turn_state: TurnState::parse(&row.14)?,
        process_identity: identity,
        closed_at: row.19,
        reaped_at: row.20,
        created_at: row.21,
    })
}

fn query_guard(
    transaction: &Transaction<'_>,
    agent_id: &str,
) -> StoreResult<(JobState, u64, bool, bool)> {
    let value = transaction
        .query_row(
            "SELECT state, owner_epoch, close_requested, stop_requested
             FROM agents WHERE agent_id = ?1",
            [agent_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StoreError::InvalidState(format!("unknown job {agent_id}")))?;
    Ok((
        JobState::parse(&value.0)?,
        i64_to_u64(value.1)?,
        value.2 != 0,
        value.3 != 0,
    ))
}

fn apply_terminal(
    transaction: &Transaction<'_>,
    agent_id: &str,
    owner_epoch: u64,
    from_state: JobState,
    close_requested: bool,
    stop_requested: bool,
    terminal: &TerminalUpdate,
) -> StoreResult<JobState> {
    if !terminal.state.is_terminal() {
        return Err(StoreError::InvalidState(
            "terminal update must select a terminal state".into(),
        ));
    }
    let final_state =
        if (stop_requested || close_requested) && terminal.state == JobState::Completed {
            JobState::Cancelled
        } else {
            terminal.state
        };
    let changed = transaction.execute(
        "UPDATE agents SET state = ?1, completed_at = COALESCE(completed_at, ?2),
             failure_code = ?3, failure_message = ?4,
             turn_state = CASE WHEN ?1 IN ('FAILED', 'FAILED_RUNTIME_LOST', 'ORPHANED')
                               THEN 'FAILED' ELSE 'IDLE' END,
             closed_at = CASE WHEN close_requested = 1
                              THEN COALESCE(closed_at, ?2) ELSE closed_at END
         WHERE agent_id = ?5 AND owner_epoch = ?6
           AND state IN ('STARTING', 'RUNNING', 'STOPPING')",
        params![
            final_state.as_str(),
            now_millis(),
            terminal.failure_code,
            terminal.failure_message,
            agent_id,
            u64_to_i64(owner_epoch)?,
        ],
    )?;
    if changed != 1 {
        return Err(StoreError::Conflict(format!(
            "terminal transition lost for {agent_id} epoch {owner_epoch}"
        )));
    }
    settle_terminal_commands(
        transaction,
        agent_id,
        terminal.failure_code.as_deref().unwrap_or("JOB_TERMINATED"),
    )?;
    transaction.execute(
        "UPDATE task_attempts SET phase='TERMINAL' WHERE execution_agent_id=?1",
        [agent_id],
    )?;
    insert_ledger(
        transaction,
        agent_id,
        owner_epoch,
        Some(from_state),
        final_state,
        terminal.failure_code.as_deref(),
    )?;
    Ok(final_state)
}

fn settle_terminal_commands(
    transaction: &Transaction<'_>,
    agent_id: &str,
    reason_code: &str,
) -> StoreResult<()> {
    transaction.execute(
        "UPDATE messages SET state = 'FAILED', failure_code = ?1,
             failure_message = 'runtime is no longer available'
         WHERE agent_id = ?2 AND state IN ('QUEUED', 'SENDING')",
        params![reason_code, agent_id],
    )?;
    transaction.execute(
        "UPDATE pending_requests SET state = 'PENDING',
             response_decision = NULL, response_content = NULL
         WHERE agent_id = ?1 AND state = 'SENDING'",
        [agent_id],
    )?;
    Ok(())
}

fn insert_ledger(
    transaction: &Transaction<'_>,
    agent_id: &str,
    owner_epoch: u64,
    from_state: Option<JobState>,
    to_state: JobState,
    reason_code: Option<&str>,
) -> StoreResult<()> {
    transaction.execute(
        "INSERT INTO lifecycle_ledger
         (agent_id, owner_epoch, from_state, to_state, reason_code, recorded_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            agent_id,
            u64_to_i64(owner_epoch)?,
            from_state.map(JobState::as_str),
            to_state.as_str(),
            reason_code,
            now_millis(),
        ],
    )?;
    Ok(())
}

fn usize_to_i64(value: usize) -> StoreResult<i64> {
    i64::try_from(value).map_err(|_| StoreError::InvalidState("value exceeds SQLite i64".into()))
}

fn u64_to_i64(value: u64) -> StoreResult<i64> {
    i64::try_from(value).map_err(|_| StoreError::InvalidState("value exceeds SQLite i64".into()))
}

fn i64_to_u64(value: i64) -> StoreResult<u64> {
    u64::try_from(value).map_err(|_| StoreError::InvalidState("negative SQLite value".into()))
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, thread};
    use tempfile::TempDir;

    fn file_store() -> (TempDir, std::path::PathBuf, Store) {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("review.sqlite3");
        let store = Store::open(&path).unwrap();
        (directory, path, store)
    }

    fn enqueue(store: &Store, id: &str, workspace: &str) -> Job {
        let mut job = NewJob::new(id, workspace);
        job.idempotency_key = Some(format!("key-{id}"));
        store.enqueue_job(&job).unwrap()
    }

    fn claim(store: &Store, id: &str) -> JobClaim {
        let claim = store.claim_next("daemon-1", 8, 8).unwrap().unwrap();
        assert_eq!(claim.job.agent_id, id);
        claim
    }

    fn event(job: &str, runtime: &str, epoch: u64, source: u64) -> LifecycleWrite {
        LifecycleWrite {
            agent_id: job.into(),
            runtime_agent_id: runtime.into(),
            owner_epoch: epoch,
            source_sequence: source,
            event_type: "driver.event".into(),
            turn_id: None,
            payload_json: "{}".into(),
            redaction_level: "safe".into(),
            terminal: None,
            turn_state: None,
        }
    }

    #[test]
    fn wal_schema_reopens_and_retains_all_durable_rows() {
        let (_directory, path, store) = file_store();
        assert_eq!(store.journal_mode().unwrap().to_ascii_lowercase(), "wal");
        let original = enqueue(&store, "job-1", "/workspace");
        let duplicate = store
            .enqueue_job(&NewJob {
                agent_id: "different-id".into(),
                idempotency_key: original.idempotency_key.clone(),
                feature_id: None,
                workspace_path: "/different".into(),
                runtime_hash: None,
                prepared_launch_json: None,
                prepared_launch_sha256: None,
                initial_prompt: "Begin task.".into(),
            })
            .unwrap();
        assert_eq!(duplicate.agent_id, "job-1");
        assert!(store
            .insert_message("msg-1", "job-1", "queue", "hello")
            .unwrap());
        assert!(!store
            .insert_message("msg-1", "job-1", "queue", "hello")
            .unwrap());
        assert!(store.deliver_message("msg-1").unwrap());
        assert!(!store.deliver_message("msg-1").unwrap());
        assert!(store
            .insert_pending_request("req-1", "job-1", "corr-1", "permission", "{}")
            .unwrap());
        assert!(!store
            .insert_pending_request("req-2", "job-1", "corr-1", "permission", "{}")
            .unwrap());
        assert!(store.respond_pending_request("job-1", "corr-1").unwrap());
        assert!(!store.respond_pending_request("job-1", "corr-1").unwrap());
        assert!(store
            .insert_pending_request("req-3", "job-1", "corr-3", "input", "{}")
            .unwrap());
        assert!(store
            .respond_pending_request_by_id("job-1", "req-3")
            .unwrap());
        assert!(!store
            .respond_pending_request_by_id("job-1", "req-3")
            .unwrap());
        assert!(store
            .insert_artifact(&NewArtifact {
                artifact_id: "artifact-1".into(),
                agent_id: "job-1".into(),
                artifact_type: "changes_patch".into(),
                path: "/changes.patch".into(),
                sha256: "abc".into(),
                bytes: 12,
            })
            .unwrap());
        let claimed = claim(&store, "job-1");
        assert!(store
            .mark_running("job-1", claimed.owner_epoch, "runtime-1", None)
            .unwrap());
        assert_eq!(
            store
                .append_lifecycle(&event("job-1", "runtime-1", claimed.owner_epoch, 9))
                .unwrap(),
            1
        );
        drop(store);

        let reopened = Store::open(path).unwrap();
        assert_eq!(
            reopened.get_job("job-1").unwrap().unwrap().last_event_seq,
            1
        );
        assert_eq!(reopened.cursor("job-1", "runtime-1").unwrap(), 1);
        assert_eq!(reopened.artifact_count("job-1").unwrap(), 1);
        assert_eq!(reopened.artifacts("job-1", 1).unwrap()[0].sha256, "abc");
    }

    #[test]
    fn prepared_launch_is_persisted_before_claim_and_conflicting_idempotency_fails() {
        let (_directory, _path, store) = file_store();
        let mut first = NewJob::new("prepared-1", "/prepared/worktree");
        first.idempotency_key = Some("prepared-key".into());
        first.prepared_launch_json = Some("{\"head_sha\":\"a\"}".into());
        first.prepared_launch_sha256 = Some("digest-a".into());
        let stored = store.enqueue_job(&first).unwrap();
        assert_eq!(
            stored.prepared_launch_json.as_deref(),
            Some("{\"head_sha\":\"a\"}")
        );
        assert_eq!(stored.prepared_launch_sha256.as_deref(), Some("digest-a"));
        assert_eq!(stored.state, JobState::Queued);

        let mut same = first.clone();
        same.agent_id = "prepared-same".into();
        assert_eq!(store.enqueue_job(&same).unwrap().agent_id, "prepared-1");

        let mut conflict = first.clone();
        conflict.agent_id = "prepared-conflict".into();
        conflict.prepared_launch_json = Some("{\"head_sha\":\"b\"}".into());
        conflict.prepared_launch_sha256 = Some("digest-b".into());
        assert!(matches!(
            store.enqueue_job(&conflict),
            Err(StoreError::Conflict(_))
        ));

        let mut incomplete = NewJob::new("incomplete", "/prepared/worktree");
        incomplete.prepared_launch_json = Some("{}".into());
        assert!(matches!(
            store.enqueue_job(&incomplete),
            Err(StoreError::InvalidState(_))
        ));
        assert!(matches!(
            store.get_task_scoped(
                "missing-public",
                TaskQueryScope {
                    repository: None,
                    feature_id: None,
                    ownership_token: None
                }
            ),
            Err(StoreError::InvalidState(_))
        ));
    }

    #[test]
    fn every_task_outcome_has_exact_legacy_projection() {
        for (index, outcome, state, code) in [
            (1, TaskOutcome::Succeeded, JobState::Completed, None),
            (
                2,
                TaskOutcome::Blocked,
                JobState::Completed,
                Some("BLOCKED"),
            ),
            (3, TaskOutcome::Failed, JobState::Failed, Some("FAILED")),
            (
                4,
                TaskOutcome::Cancelled,
                JobState::Cancelled,
                Some("CANCELLED"),
            ),
            (5, TaskOutcome::TimedOut, JobState::Failed, Some("TIMEOUT")),
            (
                6,
                TaskOutcome::BudgetExhausted,
                JobState::Failed,
                Some("BUDGET_EXHAUSTED"),
            ),
            (
                7,
                TaskOutcome::RuntimeLost,
                JobState::FailedRuntimeLost,
                Some("RUNTIME_LOST"),
            ),
            (
                8,
                TaskOutcome::ResultInvalid,
                JobState::Failed,
                Some("RESULT_INVALID"),
            ),
        ] {
            let (_directory, _path, store) = file_store();
            let id = format!("projection-{index}");
            let task = general_task(
                &id,
                &format!("projection-public-{index}"),
                &format!("projection-key-{index}"),
            );
            store.enqueue_task(&task).unwrap();
            store.set_task_phase(&id, TaskPhase::Preparing).unwrap();
            store.set_task_phase(&id, TaskPhase::Running).unwrap();
            store
                .store_task_result(
                    &id,
                    &TaskResult {
                        outcome,
                        summary: "done".into(),
                        partial: false,
                        base_commit: None,
                        head_commit: None,
                        changed_files: vec![],
                        diff_stat: None,
                        checks: vec![],
                        residual_gaps: vec![],
                        artifacts: vec![],
                    },
                )
                .unwrap();
            let job = store.get_job(&id).unwrap().unwrap();
            assert_eq!(job.state, state);
            assert_eq!(job.failure_code.as_deref(), code);
        }
    }

    #[test]
    fn concurrent_claim_is_fifo_bounded_and_single_owner() {
        let (_directory, _path, store) = file_store();
        for (id, workspace) in [
            ("job-1", "a"),
            ("job-2", "a"),
            ("job-3", "b"),
            ("job-4", "c"),
        ] {
            enqueue(&store, id, workspace);
        }
        let store = Arc::new(store);
        let mut workers = Vec::new();
        for owner in 0..4 {
            let store = Arc::clone(&store);
            workers.push(thread::spawn(move || {
                store.claim_next(&format!("owner-{owner}"), 2, 1).unwrap()
            }));
        }
        let claims: Vec<_> = workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(claims.len(), 2);
        let mut claimed_ids = claims
            .iter()
            .map(|claim| claim.job.agent_id.as_str())
            .collect::<Vec<_>>();
        claimed_ids.sort_unstable();
        assert_eq!(claimed_ids, vec!["job-1", "job-3"]);
        assert_eq!(store.active_count().unwrap(), 2);
        assert_eq!(claims[0].owner_epoch, 1);
        assert_eq!(claims[1].owner_epoch, 1);
    }

    #[test]
    fn concurrent_duplicate_enqueue_returns_one_stable_job() {
        let (_directory, _path, store) = file_store();
        let store = Arc::new(store);
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let mut workers = Vec::new();
        for index in 0..8 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                let mut job = NewJob::new(format!("candidate-{index}"), "workspace");
                job.idempotency_key = Some("stable-key".into());
                barrier.wait();
                store.enqueue_job(&job).unwrap().agent_id
            }));
        }
        barrier.wait();
        let ids = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert!(ids.iter().all(|agent_id| agent_id == &ids[0]));
        assert_eq!(
            store
                .claim_next("owner", 8, 8)
                .unwrap()
                .unwrap()
                .job
                .agent_id,
            ids[0]
        );
        assert!(store.claim_next("owner", 8, 8).unwrap().is_none());
    }

    #[test]
    fn bounded_pending_requests_prioritize_actionable_rows() {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(directory.path().join("pending.sqlite3")).unwrap();
        store
            .enqueue_job(&NewJob::new("pending-bounded", "/workspace"))
            .unwrap();
        for index in 0..120 {
            let request_id = format!("responded-{index:03}");
            store
                .insert_pending_request(
                    &request_id,
                    "pending-bounded",
                    &format!("corr-{index}"),
                    "permission",
                    "{}",
                )
                .unwrap();
            assert!(store
                .respond_pending_request_by_id("pending-bounded", &request_id)
                .unwrap());
        }
        store
            .insert_pending_request(
                "actionable",
                "pending-bounded",
                "corr-actionable",
                "permission",
                "{}",
            )
            .unwrap();
        let requests = store
            .pending_requests_bounded("pending-bounded", 100)
            .unwrap();
        assert_eq!(requests.len(), 100);
        assert_eq!(requests[0].request_id, "actionable");
        assert_eq!(requests[0].state, PendingRequestState::Pending);
    }

    #[test]
    fn lifecycle_cursor_is_store_assigned_idempotent_and_terminal_guarded() {
        let (_directory, _path, store) = file_store();
        enqueue(&store, "job-1", "a");
        let claimed = claim(&store, "job-1");
        store
            .mark_running("job-1", claimed.owner_epoch, "runtime-1", None)
            .unwrap();
        let first = event("job-1", "runtime-1", claimed.owner_epoch, 40);
        assert_eq!(store.append_lifecycle(&first).unwrap(), 1);
        assert_eq!(store.append_lifecycle(&first).unwrap(), 1);
        let mut terminal = event("job-1", "runtime-1", claimed.owner_epoch, 41);
        terminal.terminal = Some(TerminalUpdate {
            state: JobState::Completed,
            failure_code: None,
            failure_message: None,
        });
        assert_eq!(store.append_lifecycle(&terminal).unwrap(), 2);
        assert_eq!(
            store.get_job("job-1").unwrap().unwrap().state,
            JobState::Completed
        );
        assert!(matches!(
            store.append_lifecycle(&event("job-1", "runtime-1", claimed.owner_epoch, 42)),
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(store.get_job("job-1").unwrap().unwrap().last_event_seq, 2);
    }

    #[test]
    fn restart_and_close_retain_partial_events_and_artifacts() {
        let (_directory, path, store) = file_store();
        enqueue(&store, "queued", "a");
        enqueue(&store, "running", "b");
        let claim = store.claim_next("daemon", 8, 8).unwrap().unwrap();
        assert_eq!(claim.job.agent_id, "queued");
        store
            .mark_running("queued", claim.owner_epoch, "runtime", None)
            .unwrap();
        store
            .append_lifecycle(&event("queued", "runtime", claim.owner_epoch, 1))
            .unwrap();
        store
            .insert_artifact(&NewArtifact {
                artifact_id: "artifact".into(),
                agent_id: "queued".into(),
                artifact_type: "changes_patch".into(),
                path: "/changes.patch".into(),
                sha256: "sha".into(),
                bytes: 5,
            })
            .unwrap();
        drop(store);

        let reopened = Store::open(path).unwrap();
        let changed = reopened.reconcile_startup().unwrap();
        assert_eq!(changed.len(), 1);
        assert_eq!(
            reopened.get_job("queued").unwrap().unwrap().state,
            JobState::FailedRuntimeLost
        );
        assert_eq!(
            reopened.get_job("running").unwrap().unwrap().state,
            JobState::Queued
        );
        assert_eq!(reopened.cursor("queued", "runtime").unwrap(), 1);
        assert_eq!(reopened.artifact_count("queued").unwrap(), 1);
        assert_eq!(
            reopened.request_close("queued").unwrap().state,
            JobState::FailedRuntimeLost
        );
        assert_eq!(
            reopened.reap_job("queued").unwrap(),
            JobState::FailedRuntimeLost
        );
        assert_eq!(
            reopened.reap_job("queued").unwrap(),
            JobState::FailedRuntimeLost
        );
    }

    #[test]
    fn startup_reconciliation_atomically_terminalizes_v2_attempts_and_preserves_legacy_rows() {
        let (_directory, _path, store) = file_store();
        let general = general_task("restart-general", "public-general", "restart-general-key");
        store.enqueue_task(&general).unwrap();
        store
            .enqueue_job(&NewJob::new("restart-legacy", "/legacy-workspace"))
            .unwrap();

        let general_claim = store.claim_next("daemon-old", 8, 8).unwrap().unwrap();
        assert_eq!(general_claim.job.agent_id, "restart-general");
        store
            .mark_running(
                "restart-general",
                general_claim.owner_epoch,
                "runtime-general",
                None,
            )
            .unwrap();
        let legacy_claim = store.claim_next("daemon-old", 8, 8).unwrap().unwrap();
        assert_eq!(legacy_claim.job.agent_id, "restart-legacy");

        let reconciled = store.reconcile_startup().unwrap();
        assert_eq!(reconciled.len(), 2);
        for execution_id in ["restart-general"] {
            let job = store.get_job(execution_id).unwrap().unwrap();
            assert_eq!(job.state, JobState::FailedRuntimeLost);
            assert_eq!(
                job.failure_code.as_deref(),
                Some("DAEMON_RESTART_RUNTIME_LOST")
            );
            let task = store
                .get_task_scoped(
                    "public-general",
                    TaskQueryScope {
                        repository: Some("repo"),
                        feature_id: None,
                        ownership_token: None,
                    },
                )
                .unwrap()
                .unwrap();
            assert_eq!(task.phase, TaskPhase::Terminal);
            let result = store.task_result(execution_id).unwrap().unwrap();
            assert_eq!(result.result.outcome, TaskOutcome::RuntimeLost);
            assert_eq!(result.result.residual_gaps, vec!["DAEMON_RESTARTED"]);
            assert!(!result.retained);
        }

        let legacy = store.get_job("restart-legacy").unwrap().unwrap();
        assert_eq!(legacy.state, JobState::FailedRuntimeLost);
        assert_eq!(
            legacy.failure_code.as_deref(),
            Some("DAEMON_RESTART_RUNTIME_LOST")
        );
        assert!(store.task_result("restart-legacy").unwrap().is_none());
    }

    #[test]
    fn forced_sqlite_write_failures_are_explicit_on_all_transaction_paths() {
        let (_directory, _path, store) = file_store();
        enqueue(&store, "job-1", "a");
        let claim = claim(&store, "job-1");
        enqueue(&store, "job-2", "b");
        store.set_query_only(true).unwrap();
        assert!(matches!(
            store.claim_next("owner", 2, 1),
            Err(StoreError::Sqlite(_))
        ));
        assert!(matches!(
            store.append_lifecycle(&event("job-1", "runtime", claim.owner_epoch, 1)),
            Err(StoreError::Sqlite(_))
        ));
        assert!(matches!(
            store.fail_claim("job-1", claim.owner_epoch, "FAIL", "failure"),
            Err(StoreError::Sqlite(_))
        ));
        assert!(matches!(
            store.request_close("job-1"),
            Err(StoreError::Sqlite(_))
        ));
        assert!(matches!(
            store.reconcile_startup(),
            Err(StoreError::Sqlite(_))
        ));
        store.set_query_only(false).unwrap();
        assert_eq!(
            store.get_job("job-1").unwrap().unwrap().state,
            JobState::Starting
        );
    }

    #[test]
    fn forward_unknown_schema_fails_before_creating_current_tables() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("future.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch("CREATE TABLE future_only(value TEXT); PRAGMA user_version=99;")
            .unwrap();
        drop(connection);
        assert!(matches!(
            Store::open(&path),
            Err(StoreError::InvalidState(_))
        ));
        let connection = Connection::open(path).unwrap();
        let agents: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='agents'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(agents, 0);
    }

    #[test]
    fn pre_generic_schema_is_rejected_without_compatibility_migration() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("pre-generic.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection.pragma_update(None, "user_version", 7).unwrap();
        drop(connection);
        assert!(matches!(
            Store::open(path),
            Err(StoreError::InvalidState(_))
        ));
    }

    #[test]
    fn delivery_claims_are_fifo_and_idempotent_without_false_completion() {
        let (_directory, _path, store) = file_store();
        enqueue(&store, "delivery-job", "/workspace");
        let claim = claim(&store, "delivery-job");
        store
            .mark_running("delivery-job", claim.owner_epoch, "runtime", None)
            .unwrap();
        store
            .insert_message("message-1", "delivery-job", "queue", "first")
            .unwrap();
        store
            .insert_message("message-2", "delivery-job", "queue", "second")
            .unwrap();
        let first = store.claim_next_message("delivery-job").unwrap().unwrap();
        assert_eq!(first.message_id, "message-1");
        assert_eq!(first.state, MessageState::Sending);
        assert!(store.complete_message("message-1", Some("turn-1")).unwrap());
        assert_eq!(
            store
                .claim_next_message("delivery-job")
                .unwrap()
                .unwrap()
                .message_id,
            "message-2"
        );

        store
            .insert_pending_request(
                "request-1",
                "delivery-job",
                "\"wire-1\"",
                "permission",
                "{}",
            )
            .unwrap();
        assert_eq!(
            store
                .claim_pending_response_if_attempt_accepting(
                    "delivery-job",
                    "request-1",
                    1,
                    "allow",
                    None,
                )
                .unwrap(),
            PendingResponseClaimDisposition::Claimed
        );
        assert_eq!(
            store
                .pending_request("delivery-job", "request-1")
                .unwrap()
                .unwrap()
                .state,
            PendingRequestState::Sending
        );
        assert!(store
            .complete_pending_response("delivery-job", "request-1")
            .unwrap());
        assert_eq!(
            store
                .claim_pending_response_if_attempt_accepting(
                    "delivery-job",
                    "request-1",
                    1,
                    "allow",
                    None,
                )
                .unwrap(),
            PendingResponseClaimDisposition::NotPending(PendingRequestState::Responded)
        );
        assert!(matches!(
            store.claim_pending_response_if_attempt_accepting(
                "delivery-job",
                "request-1",
                1,
                "deny",
                None,
            ),
            Err(StoreError::Conflict(_))
        ));
    }

    #[test]
    fn conditional_pending_response_claim_is_attempt_and_stop_aware() {
        let (_directory, _path, store) = file_store();
        let task = general_task("conditional-claim", "conditional-public", "conditional-key");
        let (_, task_record) = store.enqueue_task(&task).unwrap();
        let claim = claim(&store, "conditional-claim");
        store
            .mark_running("conditional-claim", claim.owner_epoch, "runtime", None)
            .unwrap();
        store
            .insert_pending_request(
                "conditional-request",
                "conditional-claim",
                "conditional-wire",
                "permission",
                "{}",
            )
            .unwrap();

        assert_eq!(
            store
                .claim_pending_response_if_attempt_accepting(
                    "conditional-claim",
                    "conditional-request",
                    task_record.attempt_sequence + 1,
                    "allow",
                    None,
                )
                .unwrap(),
            PendingResponseClaimDisposition::AttemptMismatch
        );
        assert_eq!(
            store
                .claim_pending_response_if_attempt_accepting(
                    "conditional-claim",
                    "missing-request",
                    task_record.attempt_sequence,
                    "allow",
                    None,
                )
                .unwrap(),
            PendingResponseClaimDisposition::NotFound
        );
        assert_eq!(
            store
                .claim_pending_response_if_attempt_accepting(
                    "conditional-claim",
                    "conditional-request",
                    task_record.attempt_sequence,
                    "allow",
                    None,
                )
                .unwrap(),
            PendingResponseClaimDisposition::Claimed
        );
        assert_eq!(
            store
                .claim_pending_response_if_attempt_accepting(
                    "conditional-claim",
                    "conditional-request",
                    task_record.attempt_sequence,
                    "allow",
                    None,
                )
                .unwrap(),
            PendingResponseClaimDisposition::NotPending(PendingRequestState::Sending)
        );
        assert!(store
            .release_pending_response("conditional-claim", "conditional-request")
            .unwrap());
        let runtime_stop = store.request_runtime_stop("conditional-claim").unwrap();
        assert_eq!(runtime_stop.state, JobState::Stopping);
        assert!(!runtime_stop.prior_stop_or_close);
        let runtime_stopping_job = store.get_job("conditional-claim").unwrap().unwrap();
        assert!(!runtime_stopping_job.stop_requested);
        assert!(!runtime_stopping_job.close_requested);
        assert!(
            !store
                .request_stop("conditional-claim")
                .unwrap()
                .prior_stop_or_close
        );
        assert!(
            store
                .request_stop("conditional-claim")
                .unwrap()
                .prior_stop_or_close
        );
        assert_eq!(
            store
                .claim_pending_response_if_attempt_accepting(
                    "conditional-claim",
                    "conditional-request",
                    task_record.attempt_sequence,
                    "allow",
                    None,
                )
                .unwrap(),
            PendingResponseClaimDisposition::AttemptStopping
        );
        assert_eq!(
            store
                .pending_request("conditional-claim", "conditional-request")
                .unwrap()
                .unwrap()
                .state,
            PendingRequestState::Pending
        );
    }

    #[test]
    fn restart_terminalizes_queued_and_sending_messages_without_future_delivery_claim() {
        let (_directory, _path, store) = file_store();
        enqueue(&store, "restart-job", "/workspace");
        let claim = claim(&store, "restart-job");
        store
            .mark_running("restart-job", claim.owner_epoch, "runtime", None)
            .unwrap();
        store
            .insert_message("sending-message", "restart-job", "queue", "first")
            .unwrap();
        store
            .insert_message("queued-message", "restart-job", "queue", "second")
            .unwrap();
        assert_eq!(
            store
                .claim_next_message("restart-job")
                .unwrap()
                .unwrap()
                .state,
            MessageState::Sending
        );

        assert_eq!(store.reconcile_startup().unwrap().len(), 1);
        for message_id in ["sending-message", "queued-message"] {
            let message = store.message(message_id).unwrap().unwrap();
            assert_eq!(message.state, MessageState::Failed);
            assert_eq!(
                message.failure_code.as_deref(),
                Some("DAEMON_RESTART_RUNTIME_LOST")
            );
        }
        assert!(store.claim_next_message("restart-job").unwrap().is_none());
        assert!(!store
            .insert_message("queued-message", "restart-job", "queue", "second")
            .unwrap());
        assert_eq!(
            store.message("queued-message").unwrap().unwrap().state,
            MessageState::Failed
        );
    }

    #[test]
    fn stop_intent_prevents_a_queued_message_from_being_claimed() {
        let (_directory, _path, store) = file_store();
        enqueue(&store, "stopping-job", "/workspace");
        let claim = claim(&store, "stopping-job");
        store
            .mark_running("stopping-job", claim.owner_epoch, "runtime", None)
            .unwrap();
        store
            .insert_message("never-send", "stopping-job", "queue", "content")
            .unwrap();

        assert_eq!(
            store.request_stop("stopping-job").unwrap().state,
            JobState::Stopping
        );
        assert!(store.claim_next_message("stopping-job").unwrap().is_none());
        let message = store.message("never-send").unwrap().unwrap();
        assert_eq!(message.state, MessageState::Failed);
        assert_eq!(message.failure_code.as_deref(), Some("STOP_REQUESTED"));
    }

    fn general_task(execution: &str, public: &str, key: &str) -> NewTask {
        let mut job = NewJob::new(execution, "/workspace");
        job.idempotency_key = Some(key.into());
        NewTask {
            job,
            public_agent_id: public.into(),
            task_kind: TaskKind::General,
            repository: "repo".into(),
            feature_id: "feature".into(),
            ownership_token: "owner".into(),
            budget: BudgetRequest::Omitted,
            retain_partial: false,
        }
    }

    fn cancelled_task_result(summary: &str) -> TaskResult {
        TaskResult {
            outcome: TaskOutcome::Cancelled,
            summary: summary.into(),
            partial: true,
            base_commit: None,
            head_commit: None,
            changed_files: Vec::new(),
            diff_stat: None,
            checks: Vec::new(),
            residual_gaps: vec!["CANCELLED".into()],
            artifacts: Vec::new(),
        }
    }

    #[test]
    fn queued_v2_cancel_remains_converging_until_precise_result_is_stored() {
        let (_directory, _path, store) = file_store();
        store
            .enqueue_task(&general_task("queued-v2", "public-v2", "queued-v2-key"))
            .unwrap();

        let decision = store.request_stop("queued-v2").unwrap();
        assert_eq!(decision.state, JobState::Stopping);
        assert!(!decision.needs_runtime_stop);
        assert_eq!(
            store
                .task_by_execution_agent_id("queued-v2")
                .unwrap()
                .unwrap()
                .phase,
            TaskPhase::Cancelling
        );
        assert!(store.task_result("queued-v2").unwrap().is_none());

        let result = cancelled_task_result("cancelled before launch");
        store.store_task_result("queued-v2", &result).unwrap();
        assert_eq!(
            store.get_job("queued-v2").unwrap().unwrap().state,
            JobState::Cancelled
        );
        assert_eq!(
            store
                .task_by_execution_agent_id("queued-v2")
                .unwrap()
                .unwrap()
                .phase,
            TaskPhase::Terminal
        );
        assert_eq!(
            store.task_result("queued-v2").unwrap().unwrap().result,
            result
        );
    }

    #[test]
    fn task_identity_idempotency_scope_and_budget_are_durable() {
        let (_directory, path, store) = file_store();
        let task = general_task("execution-1", "public-1", "key-1");
        let first_submission = store.enqueue_task_authoritative(&task).unwrap();
        assert_eq!(
            first_submission.disposition,
            TaskSubmissionDisposition::Created
        );
        let first = first_submission.task;
        assert_eq!(first.task_kind, TaskKind::General);
        assert_eq!(first.effective_budget, DEFAULT_BUDGET);
        let replay = store.enqueue_task_authoritative(&task).unwrap();
        assert_eq!(replay.disposition, TaskSubmissionDisposition::Existing);
        assert_eq!(replay.task, first);
        let mut conflict = task.clone();
        conflict.repository = "other".into();
        assert!(matches!(
            store.enqueue_task(&conflict),
            Err(StoreError::Conflict(_))
        ));
        assert!(store
            .get_task_scoped(
                "public-1",
                TaskQueryScope {
                    repository: Some("repo"),
                    feature_id: Some("feature"),
                    ownership_token: Some("owner")
                }
            )
            .unwrap()
            .is_some());
        assert!(store
            .get_task_scoped(
                "public-1",
                TaskQueryScope {
                    repository: Some("repo"),
                    feature_id: Some("feature"),
                    ownership_token: Some("wrong")
                }
            )
            .unwrap()
            .is_none());
        drop(store);
        let reopened = Store::open(path).unwrap();
        assert_eq!(
            reopened
                .get_task_scoped(
                    "public-1",
                    TaskQueryScope {
                        repository: Some("repo"),
                        feature_id: Some("feature"),
                        ownership_token: Some("owner")
                    }
                )
                .unwrap()
                .unwrap(),
            first
        );
        reopened
            .set_task_phase("execution-1", TaskPhase::Preparing)
            .unwrap();
        reopened
            .set_task_phase("execution-1", TaskPhase::Running)
            .unwrap();
        assert_eq!(
            reopened
                .get_task_scoped(
                    "public-1",
                    TaskQueryScope {
                        repository: Some("repo"),
                        feature_id: Some("feature"),
                        ownership_token: Some("owner")
                    }
                )
                .unwrap()
                .unwrap()
                .phase,
            TaskPhase::Running
        );
    }

    #[test]
    fn budget_null_zero_and_above_cap_fail_before_enqueue() {
        let (_directory, _path, store) = file_store();
        assert_eq!(
            resolve_effective_budget(&BudgetRequest::Omitted).unwrap(),
            DEFAULT_BUDGET
        );
        assert!(resolve_effective_budget(&BudgetRequest::Null).is_err());
        let mut task = general_task("bad-budget", "public", "budget-key");
        task.budget = BudgetRequest::Null;
        assert!(matches!(
            store.enqueue_task(&task),
            Err(StoreError::InvalidState(_))
        ));
        task.budget = BudgetRequest::Limits(EffectiveBudget {
            absolute_wall_time_ms: 0,
            ..DEFAULT_BUDGET
        });
        assert!(matches!(
            store.enqueue_task(&task),
            Err(StoreError::InvalidState(_))
        ));
        task.budget = BudgetRequest::Limits(EffectiveBudget {
            max_turns: MAX_BUDGET.max_turns + 1,
            ..DEFAULT_BUDGET
        });
        assert!(matches!(
            store.enqueue_task(&task),
            Err(StoreError::InvalidState(_))
        ));
        assert!(store.get_job("bad-budget").unwrap().is_none());
    }

    #[test]
    fn completion_is_immutable_and_artifact_kinds_are_closed() {
        let (_directory, _path, store) = file_store();
        store
            .enqueue_task(&general_task("result-task", "public", "result-key"))
            .unwrap();
        store
            .set_task_phase("result-task", TaskPhase::Preparing)
            .unwrap();
        store
            .set_task_phase("result-task", TaskPhase::Running)
            .unwrap();
        let result = TaskResult {
            outcome: TaskOutcome::Blocked,
            summary: "bounded result".into(),
            partial: true,
            base_commit: Some("base".into()),
            head_commit: Some("head".into()),
            changed_files: vec!["src/lib.rs".into()],
            diff_stat: Some("1 file".into()),
            checks: vec!["cargo test".into()],
            residual_gaps: vec!["auth unavailable".into()],
            artifacts: vec![ResultArtifact {
                kind: ArtifactKind::ChangesPatch,
                artifact_id: "artifact-1".into(),
                sha256: "def".into(),
            }],
        };
        store.store_task_result("result-task", &result).unwrap();
        store.store_task_result("result-task", &result).unwrap();
        let mut conflicting = result.clone();
        conflicting.summary = "different".into();
        assert!(matches!(
            store.store_task_result("result-task", &conflicting),
            Err(StoreError::Conflict(_))
        ));
        let stored = store.task_result("result-task").unwrap().unwrap();
        assert_eq!(stored.result, result);
        assert!(stored.retained);
        assert_eq!(stored.result_sha256.len(), 64);
    }

    #[test]
    fn complete_is_atomic_with_scheduler_and_rejects_pre_running_result() {
        let (_directory, _path, store) = file_store();
        let task = general_task("atomic-exec", "atomic-public", "atomic-key");
        store.enqueue_task(&task).unwrap();
        let result = TaskResult {
            outcome: TaskOutcome::Succeeded,
            summary: "done".into(),
            partial: false,
            base_commit: None,
            head_commit: None,
            changed_files: vec![],
            diff_stat: None,
            checks: vec![],
            residual_gaps: vec![],
            artifacts: vec![],
        };
        assert!(matches!(
            store.store_task_result("atomic-exec", &result),
            Err(StoreError::Conflict(_))
        ));
        store
            .set_task_phase("atomic-exec", TaskPhase::Preparing)
            .unwrap();
        store
            .set_task_phase("atomic-exec", TaskPhase::Running)
            .unwrap();
        store.store_task_result("atomic-exec", &result).unwrap();
        assert_eq!(
            store.get_job("atomic-exec").unwrap().unwrap().state,
            JobState::Completed
        );
        assert!(store.claim_next("owner", 1, 1).unwrap().is_none());
    }

    #[test]
    fn successful_completion_atomically_requires_empty_pending_and_message_queues() {
        let (_directory, _path, store) = file_store();
        let task = general_task("gate-exec", "gate-public", "gate-key");
        store.enqueue_task(&task).unwrap();
        let claim = store.claim_next("owner", 1, 1).unwrap().unwrap();
        store
            .mark_running("gate-exec", claim.owner_epoch, "runtime", None)
            .unwrap();
        let result = TaskResult {
            outcome: TaskOutcome::Succeeded,
            summary: "done".into(),
            partial: false,
            base_commit: None,
            head_commit: None,
            changed_files: Vec::new(),
            diff_stat: None,
            checks: Vec::new(),
            residual_gaps: Vec::new(),
            artifacts: Vec::new(),
        };

        store
            .insert_message("gate-message", "gate-exec", "queue", "continue")
            .unwrap();
        assert_eq!(
            store.completion_blockers("gate-exec").unwrap(),
            (false, true)
        );
        assert!(matches!(
            store.store_task_result("gate-exec", &result),
            Err(StoreError::Conflict(_))
        ));
        store.claim_next_message("gate-exec").unwrap().unwrap();
        store
            .complete_message("gate-message", Some("turn-2"))
            .unwrap();

        store
            .insert_pending_request(
                "gate-request",
                "gate-exec",
                "correlation",
                "permission",
                "{}",
            )
            .unwrap();
        assert_eq!(
            store.completion_blockers("gate-exec").unwrap(),
            (true, false)
        );
        assert!(matches!(
            store.store_task_result("gate-exec", &result),
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(
            store
                .claim_pending_response_if_attempt_accepting(
                    "gate-exec",
                    "gate-request",
                    1,
                    "deny",
                    None,
                )
                .unwrap(),
            PendingResponseClaimDisposition::Claimed
        );
        store
            .complete_pending_response("gate-exec", "gate-request")
            .unwrap();
        assert_eq!(
            store.completion_blockers("gate-exec").unwrap(),
            (false, false)
        );
        store.store_task_result("gate-exec", &result).unwrap();
    }

    #[test]
    fn complete_fingerprint_covers_prepared_provenance_and_pair_validation() {
        let (_directory, _path, store) = file_store();
        let mut task = general_task("fingerprint", "fingerprint-public", "fingerprint-key");
        task.job.prepared_launch_json = Some("{}".into());
        task.job.prepared_launch_sha256 = Some("one".into());
        store.enqueue_task(&task).unwrap();
        let mut changed = task.clone();
        changed.job.prepared_launch_sha256 = Some("two".into());
        assert!(matches!(
            store.enqueue_task(&changed),
            Err(StoreError::Conflict(_))
        ));
        let mut incomplete =
            general_task("incomplete-launch", "incomplete-public", "incomplete-key");
        incomplete.job.prepared_launch_json = Some("{}".into());
        assert!(matches!(
            store.enqueue_task(&incomplete),
            Err(StoreError::InvalidState(_))
        ));
    }

    #[test]
    fn optional_store_scopes_filter_before_limit_and_reject_unscoped() {
        let (_directory, _path, store) = file_store();
        for (index, repo, feature, owner) in [
            (1, "r1", "f1", "o1"),
            (2, "r2", "f1", "o2"),
            (3, "r1", "f2", "o2"),
        ] {
            let mut task = general_task(
                &format!("scope-{index}"),
                &format!("public-{index}"),
                &format!("key-{index}"),
            );
            task.repository = repo.into();
            task.feature_id = feature.into();
            task.ownership_token = owner.into();
            store.enqueue_task(&task).unwrap();
        }
        assert_eq!(
            store
                .list_tasks_scoped(
                    TaskQueryScope {
                        repository: Some("r1"),
                        feature_id: None,
                        ownership_token: None
                    },
                    None,
                    1
                )
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .list_tasks_scoped(
                    TaskQueryScope {
                        repository: None,
                        feature_id: Some("f1"),
                        ownership_token: None
                    },
                    None,
                    10
                )
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            store
                .list_tasks_scoped(
                    TaskQueryScope {
                        repository: None,
                        feature_id: None,
                        ownership_token: Some("o2")
                    },
                    None,
                    10
                )
                .unwrap()
                .len(),
            2
        );
        assert!(matches!(
            store.list_tasks_scoped(
                TaskQueryScope {
                    repository: None,
                    feature_id: None,
                    ownership_token: None
                },
                None,
                10
            ),
            Err(StoreError::InvalidState(_))
        ));
    }

    #[test]
    fn task_page_filters_before_limit_paginates_stably_and_point_lookup_has_no_recent_cap() {
        let (_directory, _path, store) = file_store();
        let complete = |store: &Store, execution_id: &str| {
            store
                .set_task_phase(execution_id, TaskPhase::Preparing)
                .unwrap();
            store
                .set_task_phase(execution_id, TaskPhase::Running)
                .unwrap();
            store
                .store_task_result(
                    execution_id,
                    &TaskResult {
                        outcome: TaskOutcome::Succeeded,
                        summary: "complete".into(),
                        partial: false,
                        base_commit: None,
                        head_commit: None,
                        changed_files: Vec::new(),
                        diff_stat: None,
                        checks: Vec::new(),
                        residual_gaps: Vec::new(),
                        artifacts: Vec::new(),
                    },
                )
                .unwrap();
        };

        for index in 1..=3 {
            let mut task = general_task(
                &format!("page-match-{index}"),
                &format!("page-public-{index}"),
                &format!("page-key-{index}"),
            );
            task.feature_id = "page-feature".into();
            task.job.prepared_launch_json = Some(r#"{"profile":"analysis_readonly"}"#.into());
            task.job.prepared_launch_sha256 = Some("profile-fixture".into());
            store.enqueue_task(&task).unwrap();
            complete(&store, &task.job.agent_id);
        }
        for index in 0..101 {
            let mut task = general_task(
                &format!("page-noise-{index:03}"),
                &format!("page-noise-public-{index:03}"),
                &format!("page-noise-key-{index:03}"),
            );
            task.feature_id = "page-feature".into();
            task.job.prepared_launch_json = Some(r#"{"profile":"test_runner"}"#.into());
            task.job.prepared_launch_sha256 = Some("profile-fixture".into());
            store.enqueue_task(&task).unwrap();
        }
        let mut malformed = general_task(
            "page-malformed-preparation",
            "page-malformed-public",
            "page-malformed-key",
        );
        malformed.feature_id = "page-feature".into();
        malformed.job.prepared_launch_json = Some("not-json".into());
        malformed.job.prepared_launch_sha256 = Some("profile-fixture".into());
        store.enqueue_task(&malformed).unwrap();
        let filter = TaskPageFilter {
            phase: Some(TaskPhase::Terminal),
            outcome: Some(TaskOutcome::Succeeded),
            profile: Some("analysis_readonly"),
        };
        let first = store
            .list_task_page(
                TaskQueryScope {
                    repository: None,
                    feature_id: Some("page-feature"),
                    ownership_token: None,
                },
                None,
                filter.clone(),
                None,
                2,
            )
            .unwrap();
        assert_eq!(
            first
                .tasks
                .iter()
                .map(|task| task.execution_agent_id.as_str())
                .collect::<Vec<_>>(),
            vec!["page-match-3", "page-match-2"]
        );
        let cursor = first.next_cursor.expect("first page must continue");
        let second = store
            .list_task_page(
                TaskQueryScope {
                    repository: None,
                    feature_id: Some("page-feature"),
                    ownership_token: None,
                },
                None,
                filter,
                Some(cursor),
                2,
            )
            .unwrap();
        assert_eq!(second.tasks.len(), 1);
        assert_eq!(second.tasks[0].execution_agent_id, "page-match-1");
        assert_eq!(second.next_cursor, None);
    }

    #[test]
    fn partial_retention_uses_submission_policy_and_outcome_matrix() {
        for (index, outcome, opt_in, expected) in [
            (1, TaskOutcome::Blocked, false, true),
            (2, TaskOutcome::Failed, false, false),
            (3, TaskOutcome::Failed, true, true),
            (4, TaskOutcome::RuntimeLost, true, false),
            (5, TaskOutcome::ResultInvalid, true, false),
        ] {
            let (_directory, _path, store) = file_store();
            let mut task = general_task(
                &format!("retain-{index}"),
                &format!("retain-public-{index}"),
                &format!("retain-key-{index}"),
            );
            task.retain_partial = opt_in;
            store.enqueue_task(&task).unwrap();
            store
                .set_task_phase(&task.job.agent_id, TaskPhase::Preparing)
                .unwrap();
            store
                .set_task_phase(&task.job.agent_id, TaskPhase::Running)
                .unwrap();
            let result = TaskResult {
                outcome,
                summary: "partial".into(),
                partial: true,
                base_commit: None,
                head_commit: None,
                changed_files: vec![],
                diff_stat: None,
                checks: vec![],
                residual_gaps: vec![],
                artifacts: vec![],
            };
            store
                .store_task_result(&task.job.agent_id, &result)
                .unwrap();
            assert_eq!(
                store
                    .task_result(&task.job.agent_id)
                    .unwrap()
                    .unwrap()
                    .retained,
                expected
            );
        }
    }

    #[test]
    fn cancellation_and_close_win_against_late_success_or_blocked_completion() {
        for (index, close) in [(1, false), (2, true)] {
            let (_directory, _path, store) = file_store();
            let id = format!("cancel-race-{index}");
            let task = general_task(
                &id,
                &format!("cancel-public-{index}"),
                &format!("cancel-key-{index}"),
            );
            store.enqueue_task(&task).unwrap();
            store.set_task_phase(&id, TaskPhase::Preparing).unwrap();
            store.set_task_phase(&id, TaskPhase::Running).unwrap();
            if close {
                store.request_close(&id).unwrap();
            } else {
                store.request_stop(&id).unwrap();
            }
            for outcome in [TaskOutcome::Succeeded, TaskOutcome::Blocked] {
                let result = TaskResult {
                    outcome,
                    summary: "late".into(),
                    partial: false,
                    base_commit: None,
                    head_commit: None,
                    changed_files: vec![],
                    diff_stat: None,
                    checks: vec![],
                    residual_gaps: vec![],
                    artifacts: vec![],
                };
                assert!(matches!(
                    store.store_task_result(&id, &result),
                    Err(StoreError::Conflict(_))
                ));
            }
            let cancelled = TaskResult {
                outcome: TaskOutcome::Cancelled,
                summary: "cancelled".into(),
                partial: false,
                base_commit: None,
                head_commit: None,
                changed_files: vec![],
                diff_stat: None,
                checks: vec![],
                residual_gaps: vec![],
                artifacts: vec![],
            };
            store.store_task_result(&id, &cancelled).unwrap();
            let job = store.get_job(&id).unwrap().unwrap();
            assert_eq!(job.state, JobState::Cancelled);
            if close {
                assert!(job.closed_at.is_some());
            }
            assert_eq!(store.store_task_result(&id, &cancelled).unwrap(), ());
        }
    }
}
