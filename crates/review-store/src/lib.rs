use rusqlite::{
    params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior,
};
use std::{
    fmt,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock, TryLockError},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const STORE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_REVIEW_REPORT_BYTES: u64 = 4 * 1024 * 1024;

const SCHEMA: &str = r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    parent_agent_id TEXT,
    review_kind TEXT,
    feature_id TEXT,
    section_id TEXT,
    round_kind TEXT,
    state TEXT NOT NULL,
    workspace_path TEXT NOT NULL,
    report_path TEXT,
    runtime_hash TEXT,
    prepared_launch_json TEXT,
    prepared_launch_sha256 TEXT,
    zcode_session_id TEXT,
    initial_prompt TEXT NOT NULL DEFAULT 'Begin review.',
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
    checkpoint_number INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS compatibility_runs (
    runtime_hash TEXT NOT NULL,
    runtime_version TEXT NOT NULL,
    node_version TEXT,
    tested_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    details_json TEXT NOT NULL,
    PRIMARY KEY (runtime_hash, tested_at)
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

CREATE TABLE IF NOT EXISTS ledger_entries (
    entry_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    entry_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    checkpoint_number INTEGER,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS review_reports (
    agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    expected_path TEXT NOT NULL,
    report_root TEXT NOT NULL,
    current_revision INTEGER NOT NULL DEFAULT 0,
    published_revision INTEGER,
    sha256 TEXT,
    bytes INTEGER,
    finalized INTEGER NOT NULL DEFAULT 0,
    final_signal TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS review_provenance (
    agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    manifest_sha256 TEXT NOT NULL,
    prepared_sha256 TEXT NOT NULL,
    base_sha TEXT NOT NULL,
    head_sha TEXT NOT NULL,
    runtime_sha256 TEXT,
    zcode_session_id TEXT,
    requested_model TEXT,
    observed_model TEXT
);

CREATE TABLE IF NOT EXISTS review_checkpoints (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    checkpoint_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    revision INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, checkpoint_id),
    UNIQUE (agent_id, revision)
);

CREATE TABLE IF NOT EXISTS review_findings (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    revision INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, finding_id)
);

CREATE TABLE IF NOT EXISTS review_finding_history (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    revision INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, finding_id, version),
    UNIQUE (agent_id, revision)
);

CREATE TABLE IF NOT EXISTS review_validations (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    validation_id TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    revision INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, validation_id),
    UNIQUE (agent_id, revision)
);

CREATE TABLE IF NOT EXISTS review_finalizations (
    agent_id TEXT PRIMARY KEY REFERENCES agents(agent_id) ON DELETE CASCADE,
    signal TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    revision INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS review_report_events (
    agent_id TEXT NOT NULL REFERENCES agents(agent_id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (agent_id, revision)
);

"#;

const SCHEMA_VERSION: i64 = 4;

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
pub enum JobListScope {
    Active,
    Recent,
    All,
}

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
    pub parent_agent_id: Option<String>,
    pub review_kind: Option<String>,
    pub feature_id: Option<String>,
    pub section_id: Option<String>,
    pub round_kind: Option<String>,
    pub workspace_path: String,
    pub report_path: Option<String>,
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
            parent_agent_id: None,
            review_kind: None,
            feature_id: None,
            section_id: None,
            round_kind: None,
            workspace_path: workspace_path.into(),
            report_path: None,
            runtime_hash: None,
            prepared_launch_json: None,
            prepared_launch_sha256: None,
            initial_prompt: "Begin review.".into(),
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
pub struct StoredEvent {
    pub runtime_agent_id: String,
    pub sequence: u64,
    pub source_sequence: u64,
    pub event_type: String,
    pub payload_json: String,
    pub redaction_level: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitSnapshot {
    pub job: Option<Job>,
    pub runtime_agent_id: Option<String>,
    pub events: Vec<StoredEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeadlineRead<T> {
    Ready(T),
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewArtifact {
    pub artifact_id: String,
    pub agent_id: String,
    pub artifact_type: String,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub checkpoint_number: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredArtifact {
    pub artifact_id: String,
    pub artifact_type: String,
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub checkpoint_number: Option<u64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewInitialization {
    pub agent_id: String,
    pub expected_path: String,
    pub report_root: String,
    pub manifest_sha256: String,
    pub prepared_sha256: String,
    pub base_sha: String,
    pub head_sha: String,
    pub runtime_sha256: Option<String>,
    pub requested_model: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewMutationDisposition {
    Applied,
    Duplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewMutationResult {
    pub disposition: ReviewMutationDisposition,
    pub revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewReportState {
    pub agent_id: String,
    pub expected_path: String,
    pub report_root: String,
    pub current_revision: u64,
    pub published_revision: Option<u64>,
    pub sha256: Option<String>,
    pub bytes: Option<u64>,
    pub finalized: bool,
    pub final_signal: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewProvenanceRecord {
    pub manifest_sha256: String,
    pub prepared_sha256: String,
    pub base_sha: String,
    pub head_sha: String,
    pub runtime_sha256: Option<String>,
    pub zcode_session_id: Option<String>,
    pub requested_model: Option<String>,
    pub observed_model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewEntryRecord {
    pub stable_id: String,
    pub status: Option<String>,
    pub payload_json: String,
    pub revision: u64,
    pub recorded_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewSnapshot {
    pub report: ReviewReportState,
    pub provenance: ReviewProvenanceRecord,
    pub checkpoints: Vec<ReviewEntryRecord>,
    pub findings: Vec<ReviewEntryRecord>,
    pub validations: Vec<ReviewEntryRecord>,
    pub finalization: Option<ReviewEntryRecord>,
}

pub type ReviewSnapshotProjector = fn(&ReviewSnapshot) -> Result<u64, String>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewReportEvent {
    pub revision: u64,
    pub event_type: String,
    pub payload_json: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseDecision {
    pub state: JobState,
    pub owner_epoch: u64,
    pub needs_runtime_stop: bool,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryClaim {
    Claimed,
    AlreadyDelivered,
    InFlight,
}

pub struct Store {
    connection: Mutex<Connection>,
    database_path: PathBuf,
    review_snapshot_projector: OnceLock<ReviewSnapshotProjector>,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let mut connection = Connection::open(path.as_ref())?;
        connection.busy_timeout(STORE_BUSY_TIMEOUT)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(SCHEMA)?;
        migrate_to_v4(&mut connection)?;
        let database_path = std::fs::canonicalize(path.as_ref()).map_err(|error| {
            StoreError::InvalidState(format!("database path cannot be canonicalized: {error}"))
        })?;
        Ok(Self {
            connection: Mutex::new(connection),
            database_path,
            review_snapshot_projector: OnceLock::new(),
        })
    }

    pub fn install_review_snapshot_projector(&self, projector: ReviewSnapshotProjector) {
        let _ = self.review_snapshot_projector.set(projector);
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
            if let Some(existing) = query_job_by_idempotency(&transaction, key)? {
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
                agent_id, idempotency_key, parent_agent_id, review_kind,
                feature_id, section_id, round_kind, state, workspace_path,
                report_path, runtime_hash, prepared_launch_json,
                prepared_launch_sha256, initial_prompt, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'QUEUED', ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                job.agent_id,
                job.idempotency_key,
                job.parent_agent_id,
                job.review_kind,
                job.feature_id,
                job.section_id,
                job.round_kind,
                job.workspace_path,
                job.report_path,
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

    pub fn get_job(&self, agent_id: &str) -> StoreResult<Option<Job>> {
        let connection = self.connection.lock().unwrap();
        query_job(&connection, agent_id)
    }

    pub fn get_job_snapshot_until(
        &self,
        agent_id: &str,
        deadline: Instant,
    ) -> StoreResult<DeadlineRead<Option<Job>>> {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(DeadlineRead::TimedOut);
        };
        let connection = Connection::open_with_flags(
            &self.database_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        connection.busy_timeout(remaining)?;
        if Instant::now() >= deadline {
            return Ok(DeadlineRead::TimedOut);
        }
        query_job(&connection, agent_id).map(DeadlineRead::Ready)
    }

    pub fn wait_snapshot_until(
        &self,
        agent_id: &str,
        requested_runtime_agent_id: Option<&str>,
        after: u64,
        limit: usize,
        deadline: Instant,
    ) -> StoreResult<DeadlineRead<WaitSnapshot>> {
        let after = u64_to_i64(after)?;
        let limit = usize_to_i64(limit)?;
        let connection = loop {
            match self.connection.try_lock() {
                Ok(connection) => break connection,
                Err(TryLockError::Poisoned(error)) => break error.into_inner(),
                Err(TryLockError::WouldBlock) => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Ok(DeadlineRead::TimedOut);
                    }
                    thread::sleep((deadline - now).min(Duration::from_millis(1)));
                }
            }
        };
        let now = Instant::now();
        if now >= deadline {
            return Ok(DeadlineRead::TimedOut);
        }
        connection.busy_timeout(deadline - now)?;
        let snapshot = (|| {
            let job = query_job(&connection, agent_id)?;
            let runtime_agent_id = requested_runtime_agent_id
                .map(str::to_owned)
                .or_else(|| job.as_ref().and_then(|job| job.runtime_agent_id.clone()));
            let events = match runtime_agent_id.as_deref() {
                Some(runtime_agent_id) => {
                    query_events_after(&connection, agent_id, runtime_agent_id, after, limit)?
                }
                None => Vec::new(),
            };
            Ok(WaitSnapshot {
                job,
                runtime_agent_id,
                events,
            })
        })();
        let restore = connection.busy_timeout(STORE_BUSY_TIMEOUT);
        restore?;
        if Instant::now() >= deadline {
            return Ok(DeadlineRead::TimedOut);
        }
        snapshot.map(DeadlineRead::Ready)
    }

    pub fn list_jobs(&self, limit: usize) -> StoreResult<Vec<Job>> {
        self.list_jobs_scoped(JobListScope::Recent, limit)
    }

    pub fn list_jobs_scoped(&self, scope: JobListScope, limit: usize) -> StoreResult<Vec<Job>> {
        let connection = self.connection.lock().unwrap();
        let where_clause = match scope {
            JobListScope::Active => "WHERE state IN ('QUEUED', 'STARTING', 'RUNNING', 'STOPPING')",
            JobListScope::Recent | JobListScope::All => "",
        };
        let sql = format!(
            "SELECT agent_id, idempotency_key, state, workspace_path, initial_prompt, owner_id,
                    owner_epoch, close_requested, stop_requested, last_event_seq,
                    failure_code, failure_message, runtime_agent_id,
                    zcode_session_id, turn_state, pid, process_group_id,
                    process_uid, process_start_token, closed_at, reaped_at, created_at,
                    prepared_launch_json, prepared_launch_sha256
             FROM agents {where_clause} ORDER BY created_at DESC, rowid DESC LIMIT ?1"
        );
        let mut statement = connection.prepare(&sql)?;
        let rows = statement
            .query_map([usize_to_i64(limit)?], map_job_row)?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter().map(convert_job_row).collect()
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
        let last_seq: i64 = transaction
            .query_row(
                "SELECT last_seq FROM agent_cursors
                 WHERE agent_id = ?1 AND runtime_agent_id = ?2",
                params![write.agent_id, write.runtime_agent_id],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let sequence = last_seq
            .checked_add(1)
            .ok_or_else(|| StoreError::InvalidState("event sequence overflow".into()))?;
        transaction.execute(
            "INSERT INTO events (
                agent_id, runtime_agent_id, seq, source_seq, timestamp,
                event_type, turn_id, payload_json, redaction_level
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
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
        let (state, epoch, _, _) = query_guard(&transaction, agent_id)?;
        let (next, needs_runtime_stop) = match state {
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
        transaction.commit()?;
        Ok(CloseDecision {
            state: next,
            owner_epoch: epoch,
            needs_runtime_stop,
        })
    }

    pub fn request_stop(&self, agent_id: &str) -> StoreResult<CloseDecision> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, epoch, _, _) = query_guard(&transaction, agent_id)?;
        let (next, needs_runtime_stop) = match state {
            JobState::Queued => (JobState::Cancelled, false),
            JobState::Starting | JobState::Running => (JobState::Stopping, true),
            JobState::Stopping => (JobState::Stopping, true),
            terminal => (terminal, false),
        };
        if !state.is_terminal() {
            transaction.execute(
                "UPDATE agents SET state = ?1, stop_requested = 1,
                     completed_at = CASE WHEN ?2 = 1 THEN COALESCE(completed_at, ?3)
                                         ELSE completed_at END
                 WHERE agent_id = ?4",
                params![next.as_str(), next.is_terminal(), now_millis(), agent_id],
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
        transaction.commit()?;
        Ok(CloseDecision {
            state: next,
            owner_epoch: epoch,
            needs_runtime_stop,
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

    pub fn claim_pending_response(
        &self,
        agent_id: &str,
        request_id: &str,
        decision: &str,
        content: Option<&str>,
    ) -> StoreResult<DeliveryClaim> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let request = query_pending_request(&transaction, request_id)?
            .filter(|request| request.agent_id == agent_id)
            .ok_or_else(|| StoreError::InvalidState(format!("unknown request {request_id}")))?;
        if request.state != PendingRequestState::Pending
            && (request.response_decision.as_deref() != Some(decision)
                || request.response_content.as_deref() != content)
        {
            return Err(StoreError::Conflict(format!(
                "request {request_id} response was changed"
            )));
        }
        let claim = match request.state {
            PendingRequestState::Pending => {
                transaction.execute(
                    "UPDATE pending_requests SET state = 'SENDING',
                         response_decision = ?1, response_content = ?2
                     WHERE request_id = ?3 AND agent_id = ?4 AND state = 'PENDING'",
                    params![decision, content, request_id, agent_id],
                )?;
                DeliveryClaim::Claimed
            }
            PendingRequestState::Sending => DeliveryClaim::InFlight,
            PendingRequestState::Responded => DeliveryClaim::AlreadyDelivered,
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
             (artifact_id, agent_id, artifact_type, path, sha256, bytes,
              checkpoint_number, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                artifact.artifact_id,
                artifact.agent_id,
                artifact.artifact_type,
                artifact.path,
                artifact.sha256,
                u64_to_i64(artifact.bytes)?,
                artifact.checkpoint_number.map(u64_to_i64).transpose()?,
                now_millis(),
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn insert_ledger_entry(
        &self,
        entry_id: &str,
        agent_id: &str,
        entry_type: &str,
        payload_json: &str,
        checkpoint_number: Option<u64>,
    ) -> StoreResult<bool> {
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "INSERT OR IGNORE INTO ledger_entries
             (entry_id, agent_id, entry_type, payload_json, checkpoint_number, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry_id,
                agent_id,
                entry_type,
                payload_json,
                checkpoint_number.map(u64_to_i64).transpose()?,
                now_millis(),
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn initialize_review(
        &self,
        initialization: &ReviewInitialization,
    ) -> StoreResult<ReviewReportState> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = now_millis();
        transaction.execute(
            "INSERT OR IGNORE INTO review_reports (
                agent_id, expected_path, report_root, current_revision,
                finalized, created_at, updated_at
             ) VALUES (?1, ?2, ?3, 0, 0, ?4, ?4)",
            params![
                initialization.agent_id,
                initialization.expected_path,
                initialization.report_root,
                now
            ],
        )?;
        transaction.execute(
            "INSERT OR IGNORE INTO review_provenance (
                agent_id, manifest_sha256, prepared_sha256, base_sha, head_sha,
                runtime_sha256, requested_model
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                initialization.agent_id,
                initialization.manifest_sha256,
                initialization.prepared_sha256,
                initialization.base_sha,
                initialization.head_sha,
                initialization.runtime_sha256,
                initialization.requested_model,
            ],
        )?;
        let stored = query_review_initialization(&transaction, &initialization.agent_id)?
            .ok_or_else(|| StoreError::InvalidState("initialized review is missing".into()))?;
        if stored.report.expected_path != initialization.expected_path
            || stored.report.report_root != initialization.report_root
            || stored.manifest_sha256 != initialization.manifest_sha256
            || stored.prepared_sha256 != initialization.prepared_sha256
            || stored.base_sha != initialization.base_sha
            || stored.head_sha != initialization.head_sha
            || stored.requested_model != initialization.requested_model
        {
            return Err(StoreError::Conflict(format!(
                "job {} already owns different review provenance",
                initialization.agent_id
            )));
        }
        self.validate_projected_review(&transaction, &initialization.agent_id)?;
        transaction.commit()?;
        Ok(stored.report_state())
    }

    pub fn review_report_state(&self, agent_id: &str) -> StoreResult<Option<ReviewReportState>> {
        let connection = self.connection.lock().unwrap();
        query_review_report_state(&connection, agent_id)
    }

    pub fn review_report_agent_ids(&self) -> StoreResult<Vec<String>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection
            .prepare("SELECT agent_id FROM review_reports ORDER BY created_at, agent_id")?;
        let agent_ids = statement
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(agent_ids)
    }

    pub fn record_review_runtime(
        &self,
        agent_id: &str,
        runtime_sha256: Option<&str>,
        zcode_session_id: &str,
        observed_model: Option<&str>,
    ) -> StoreResult<ReviewMutationResult> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_review_mutable(&transaction, agent_id)?;
        let current = transaction
            .query_row(
                "SELECT runtime_sha256, zcode_session_id, observed_model
                 FROM review_provenance WHERE agent_id = ?1",
                [agent_id],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or_else(|| StoreError::InvalidState(format!("unknown review {agent_id}")))?;
        let desired_runtime = runtime_sha256.map(str::to_owned).or(current.0.clone());
        let desired_session = Some(zcode_session_id.to_owned());
        let desired_model = observed_model.map(str::to_owned).or(current.2.clone());
        if current
            == (
                desired_runtime.clone(),
                desired_session.clone(),
                desired_model.clone(),
            )
        {
            let revision = review_current_revision(&transaction, agent_id)?;
            transaction.commit()?;
            return Ok(ReviewMutationResult {
                disposition: ReviewMutationDisposition::Duplicate,
                revision,
            });
        }
        transaction.execute(
            "UPDATE review_provenance SET runtime_sha256 = ?1,
                 zcode_session_id = ?2, observed_model = ?3 WHERE agent_id = ?4",
            params![desired_runtime, desired_session, desired_model, agent_id],
        )?;
        let revision = advance_review_revision(&transaction, agent_id)?;
        self.validate_projected_review(&transaction, agent_id)?;
        transaction.commit()?;
        Ok(ReviewMutationResult {
            disposition: ReviewMutationDisposition::Applied,
            revision,
        })
    }

    pub fn apply_review_checkpoint(
        &self,
        agent_id: &str,
        checkpoint_id: &str,
        payload_json: &str,
        payload_sha256: &str,
    ) -> StoreResult<ReviewMutationResult> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_review_mutable(&transaction, agent_id)?;
        if let Some(existing) = query_review_entry_hash(
            &transaction,
            "review_checkpoints",
            "checkpoint_id",
            agent_id,
            checkpoint_id,
        )? {
            if existing != payload_sha256 {
                return Err(StoreError::Conflict(format!(
                    "checkpoint {checkpoint_id} already has different content"
                )));
            }
            let revision = review_current_revision(&transaction, agent_id)?;
            transaction.commit()?;
            return Ok(ReviewMutationResult {
                disposition: ReviewMutationDisposition::Duplicate,
                revision,
            });
        }
        let revision = advance_review_revision(&transaction, agent_id)?;
        transaction.execute(
            "INSERT INTO review_checkpoints (
                agent_id, checkpoint_id, payload_json, payload_sha256, revision, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                agent_id,
                checkpoint_id,
                payload_json,
                payload_sha256,
                u64_to_i64(revision)?,
                now_millis()
            ],
        )?;
        self.validate_projected_review(&transaction, agent_id)?;
        transaction.commit()?;
        Ok(ReviewMutationResult {
            disposition: ReviewMutationDisposition::Applied,
            revision,
        })
    }

    pub fn upsert_review_finding(
        &self,
        agent_id: &str,
        finding_id: &str,
        status: &str,
        payload_json: &str,
        payload_sha256: &str,
    ) -> StoreResult<ReviewMutationResult> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_review_mutable(&transaction, agent_id)?;
        let existing = transaction
            .query_row(
                "SELECT payload_sha256 FROM review_findings
                 WHERE agent_id = ?1 AND finding_id = ?2",
                params![agent_id, finding_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if existing.as_deref() == Some(payload_sha256) {
            let revision = review_current_revision(&transaction, agent_id)?;
            transaction.commit()?;
            return Ok(ReviewMutationResult {
                disposition: ReviewMutationDisposition::Duplicate,
                revision,
            });
        }
        let version: i64 = transaction.query_row(
            "SELECT COALESCE(MAX(version), 0) + 1 FROM review_finding_history
             WHERE agent_id = ?1 AND finding_id = ?2",
            params![agent_id, finding_id],
            |row| row.get(0),
        )?;
        let revision = advance_review_revision(&transaction, agent_id)?;
        let now = now_millis();
        transaction.execute(
            "INSERT INTO review_finding_history (
                agent_id, finding_id, version, status, payload_json,
                payload_sha256, revision, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                agent_id,
                finding_id,
                version,
                status,
                payload_json,
                payload_sha256,
                u64_to_i64(revision)?,
                now
            ],
        )?;
        transaction.execute(
            "INSERT INTO review_findings (
                agent_id, finding_id, status, payload_json, payload_sha256,
                revision, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(agent_id, finding_id) DO UPDATE SET
                status = excluded.status,
                payload_json = excluded.payload_json,
                payload_sha256 = excluded.payload_sha256,
                revision = excluded.revision,
                updated_at = excluded.updated_at",
            params![
                agent_id,
                finding_id,
                status,
                payload_json,
                payload_sha256,
                u64_to_i64(revision)?,
                now
            ],
        )?;
        self.validate_projected_review(&transaction, agent_id)?;
        transaction.commit()?;
        Ok(ReviewMutationResult {
            disposition: ReviewMutationDisposition::Applied,
            revision,
        })
    }

    pub fn apply_review_validation(
        &self,
        agent_id: &str,
        validation_id: &str,
        payload_json: &str,
        payload_sha256: &str,
    ) -> StoreResult<ReviewMutationResult> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_review_mutable(&transaction, agent_id)?;
        if let Some(existing) = query_review_entry_hash(
            &transaction,
            "review_validations",
            "validation_id",
            agent_id,
            validation_id,
        )? {
            if existing != payload_sha256 {
                return Err(StoreError::Conflict(format!(
                    "validation {validation_id} already has different content"
                )));
            }
            let revision = review_current_revision(&transaction, agent_id)?;
            transaction.commit()?;
            return Ok(ReviewMutationResult {
                disposition: ReviewMutationDisposition::Duplicate,
                revision,
            });
        }
        let revision = advance_review_revision(&transaction, agent_id)?;
        transaction.execute(
            "INSERT INTO review_validations (
                agent_id, validation_id, payload_json, payload_sha256, revision, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                agent_id,
                validation_id,
                payload_json,
                payload_sha256,
                u64_to_i64(revision)?,
                now_millis()
            ],
        )?;
        self.validate_projected_review(&transaction, agent_id)?;
        transaction.commit()?;
        Ok(ReviewMutationResult {
            disposition: ReviewMutationDisposition::Applied,
            revision,
        })
    }

    pub fn finalize_review(
        &self,
        agent_id: &str,
        signal: &str,
        payload_json: &str,
        payload_sha256: &str,
    ) -> StoreResult<ReviewMutationResult> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = transaction
            .query_row(
                "SELECT signal, payload_sha256, revision FROM review_finalizations
                 WHERE agent_id = ?1",
                [agent_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
        {
            if existing.0 == signal && existing.1 == payload_sha256 {
                transaction.commit()?;
                return Ok(ReviewMutationResult {
                    disposition: ReviewMutationDisposition::Duplicate,
                    revision: i64_to_u64(existing.2)?,
                });
            }
            return Err(StoreError::Conflict(format!(
                "review {agent_id} is already finalized"
            )));
        }
        ensure_review_mutable(&transaction, agent_id)?;
        let revision = advance_review_revision(&transaction, agent_id)?;
        transaction.execute(
            "INSERT INTO review_finalizations (
                agent_id, signal, payload_json, payload_sha256, revision, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                agent_id,
                signal,
                payload_json,
                payload_sha256,
                u64_to_i64(revision)?,
                now_millis()
            ],
        )?;
        transaction.execute(
            "UPDATE review_reports SET finalized = 1, final_signal = ?1,
                 updated_at = ?2 WHERE agent_id = ?3",
            params![signal, now_millis(), agent_id],
        )?;
        self.validate_projected_review(&transaction, agent_id)?;
        transaction.commit()?;
        Ok(ReviewMutationResult {
            disposition: ReviewMutationDisposition::Applied,
            revision,
        })
    }

    pub fn review_snapshot(&self, agent_id: &str) -> StoreResult<Option<ReviewSnapshot>> {
        let connection = self.connection.lock().unwrap();
        query_review_snapshot(&connection, agent_id)
    }

    fn validate_projected_review(
        &self,
        connection: &Connection,
        agent_id: &str,
    ) -> StoreResult<()> {
        let projector = self
            .review_snapshot_projector
            .get()
            .copied()
            .ok_or_else(|| {
                StoreError::InvalidState("review snapshot projector is not installed".into())
            })?;
        let snapshot = query_review_snapshot(connection, agent_id)?
            .ok_or_else(|| StoreError::InvalidState(format!("unknown review {agent_id}")))?;
        let bytes = projector(&snapshot).map_err(StoreError::InvalidState)?;
        if bytes > MAX_REVIEW_REPORT_BYTES {
            return Err(StoreError::InvalidState(format!(
                "projected review report exceeds {MAX_REVIEW_REPORT_BYTES} bytes"
            )));
        }
        Ok(())
    }

    pub fn review_finding_history(
        &self,
        agent_id: &str,
        finding_id: &str,
    ) -> StoreResult<Vec<ReviewEntryRecord>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            "SELECT version, status, payload_json, revision, created_at
             FROM review_finding_history
             WHERE agent_id = ?1 AND finding_id = ?2 ORDER BY version",
        )?;
        let history = statement
            .query_map(params![agent_id, finding_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })?
            .map(|row| {
                let (version, status, payload_json, revision, recorded_at) = row?;
                Ok(ReviewEntryRecord {
                    stable_id: format!("{finding_id}:v{}", i64_to_u64(version)?),
                    status: Some(status),
                    payload_json,
                    revision: i64_to_u64(revision)?,
                    recorded_at,
                })
            })
            .collect();
        history
    }

    pub fn publish_review_report(
        &self,
        agent_id: &str,
        revision: u64,
        sha256: &str,
        bytes: u64,
        event_payload_json: Option<&str>,
    ) -> StoreResult<ReviewReportState> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = review_current_revision(&transaction, agent_id)?;
        if current != revision {
            return Err(StoreError::Conflict(format!(
                "review {agent_id} advanced while report revision {revision} rendered"
            )));
        }
        let now = now_millis();
        transaction.execute(
            "UPDATE review_reports SET published_revision = ?1, sha256 = ?2,
                 bytes = ?3, updated_at = ?4 WHERE agent_id = ?5",
            params![
                u64_to_i64(revision)?,
                sha256,
                u64_to_i64(bytes)?,
                now,
                agent_id
            ],
        )?;
        if let Some(event_payload_json) = event_payload_json {
            transaction.execute(
                "INSERT OR IGNORE INTO review_report_events (
                    agent_id, revision, event_type, payload_json, created_at
                 ) VALUES (?1, ?2, 'report.checkpoint', ?3, ?4)",
                params![agent_id, u64_to_i64(revision)?, event_payload_json, now],
            )?;
        }
        let report = query_review_report_state(&transaction, agent_id)?
            .ok_or_else(|| StoreError::InvalidState("published review is missing".into()))?;
        transaction.execute(
            "INSERT INTO artifacts (
                artifact_id, agent_id, artifact_type, path, sha256, bytes,
                checkpoint_number, created_at
             ) VALUES (?1, ?2, 'review_report', ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(artifact_id) DO UPDATE SET
                path = excluded.path,
                sha256 = excluded.sha256,
                bytes = excluded.bytes,
                checkpoint_number = excluded.checkpoint_number,
                created_at = excluded.created_at",
            params![
                format!("review-report:{agent_id}"),
                agent_id,
                report.expected_path,
                sha256,
                u64_to_i64(bytes)?,
                u64_to_i64(revision)?,
                now
            ],
        )?;
        transaction.commit()?;
        Ok(report)
    }

    pub fn review_report_events(&self, agent_id: &str) -> StoreResult<Vec<ReviewReportEvent>> {
        let connection = self.connection.lock().unwrap();
        let mut statement = connection.prepare(
            "SELECT revision, event_type, payload_json, created_at
             FROM review_report_events WHERE agent_id = ?1 ORDER BY revision",
        )?;
        let events = statement
            .query_map([agent_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })?
            .map(|row| {
                let (revision, event_type, payload_json, created_at) = row?;
                Ok(ReviewReportEvent {
                    revision: i64_to_u64(revision)?,
                    event_type,
                    payload_json,
                    created_at,
                })
            })
            .collect();
        events
    }

    pub fn record_compatibility_run(
        &self,
        runtime_hash: &str,
        runtime_version: &str,
        node_version: Option<&str>,
        tested_at: i64,
        status: &str,
        details_json: &str,
    ) -> StoreResult<bool> {
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "INSERT OR IGNORE INTO compatibility_runs
             (runtime_hash, runtime_version, node_version, tested_at, status, details_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                runtime_hash,
                runtime_version,
                node_version,
                tested_at,
                status,
                details_json
            ],
        )?;
        Ok(changed == 1)
    }

    pub fn events_after(
        &self,
        agent_id: &str,
        runtime_agent_id: &str,
        after: u64,
        limit: usize,
    ) -> StoreResult<Vec<StoredEvent>> {
        let connection = self.connection.lock().unwrap();
        query_events_after(
            &connection,
            agent_id,
            runtime_agent_id,
            u64_to_i64(after)?,
            usize_to_i64(limit)?,
        )
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
            "SELECT artifact_id, artifact_type, path, sha256, bytes,
                    checkpoint_number, created_at
             FROM artifacts WHERE agent_id = ?1
             ORDER BY checkpoint_number DESC, created_at DESC, artifact_id DESC
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
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(
                |(
                    artifact_id,
                    artifact_type,
                    path,
                    sha256,
                    bytes,
                    checkpoint_number,
                    created_at,
                )| {
                    Ok(StoredArtifact {
                        artifact_id,
                        artifact_type,
                        path,
                        sha256,
                        bytes: i64_to_u64(bytes)?,
                        checkpoint_number: checkpoint_number.map(i64_to_u64).transpose()?,
                        created_at,
                    })
                },
            )
            .collect()
    }

    pub fn ledger_entry_count(&self, agent_id: &str) -> StoreResult<u64> {
        self.count_for(
            "SELECT COUNT(*) FROM ledger_entries WHERE agent_id = ?1",
            agent_id,
        )
    }

    pub fn compatibility_count(&self) -> StoreResult<u64> {
        let connection = self.connection.lock().unwrap();
        let count = connection.query_row("SELECT COUNT(*) FROM compatibility_runs", [], |row| {
            row.get::<_, i64>(0)
        })?;
        i64_to_u64(count)
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

struct StoredReviewInitialization {
    report: ReviewReportState,
    manifest_sha256: String,
    prepared_sha256: String,
    base_sha: String,
    head_sha: String,
    requested_model: Option<String>,
}

impl StoredReviewInitialization {
    fn report_state(self) -> ReviewReportState {
        self.report
    }
}

fn query_review_snapshot(
    connection: &Connection,
    agent_id: &str,
) -> StoreResult<Option<ReviewSnapshot>> {
    let Some(report) = query_review_report_state(connection, agent_id)? else {
        return Ok(None);
    };
    let provenance = query_review_provenance(connection, agent_id)?
        .ok_or_else(|| StoreError::InvalidState("review provenance is missing".into()))?;
    let checkpoints = query_review_entries(
        connection,
        "review_checkpoints",
        "checkpoint_id",
        false,
        agent_id,
    )?;
    let findings =
        query_review_entries(connection, "review_findings", "finding_id", true, agent_id)?;
    let validations = query_review_entries(
        connection,
        "review_validations",
        "validation_id",
        false,
        agent_id,
    )?;
    let finalization = connection
        .query_row(
            "SELECT signal, payload_json, revision, created_at
             FROM review_finalizations WHERE agent_id = ?1",
            [agent_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()?
        .map(|(signal, payload_json, revision, recorded_at)| {
            Ok::<ReviewEntryRecord, StoreError>(ReviewEntryRecord {
                stable_id: "final".into(),
                status: Some(signal),
                payload_json,
                revision: i64_to_u64(revision)?,
                recorded_at,
            })
        })
        .transpose()?;
    Ok(Some(ReviewSnapshot {
        report,
        provenance,
        checkpoints,
        findings,
        validations,
        finalization,
    }))
}

fn query_review_initialization(
    connection: &Connection,
    agent_id: &str,
) -> StoreResult<Option<StoredReviewInitialization>> {
    let row = connection
        .query_row(
            "SELECT r.expected_path, r.report_root, r.current_revision,
                    r.published_revision, r.sha256, r.bytes, r.finalized,
                    r.final_signal, r.created_at, r.updated_at,
                    p.manifest_sha256, p.prepared_sha256, p.base_sha, p.head_sha,
                    p.requested_model
             FROM review_reports r
             JOIN review_provenance p ON p.agent_id = r.agent_id
             WHERE r.agent_id = ?1",
            [agent_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                    row.get::<_, String>(10)?,
                    row.get::<_, String>(11)?,
                    row.get::<_, String>(12)?,
                    row.get::<_, String>(13)?,
                    row.get::<_, Option<String>>(14)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            expected_path,
            report_root,
            current_revision,
            published_revision,
            sha256,
            bytes,
            finalized,
            final_signal,
            created_at,
            updated_at,
            manifest_sha256,
            prepared_sha256,
            base_sha,
            head_sha,
            requested_model,
        )| {
            Ok(StoredReviewInitialization {
                report: ReviewReportState {
                    agent_id: agent_id.to_owned(),
                    expected_path,
                    report_root,
                    current_revision: i64_to_u64(current_revision)?,
                    published_revision: published_revision.map(i64_to_u64).transpose()?,
                    sha256,
                    bytes: bytes.map(i64_to_u64).transpose()?,
                    finalized: finalized != 0,
                    final_signal,
                    created_at,
                    updated_at,
                },
                manifest_sha256,
                prepared_sha256,
                base_sha,
                head_sha,
                requested_model,
            })
        },
    )
    .transpose()
}

fn query_review_report_state(
    connection: &Connection,
    agent_id: &str,
) -> StoreResult<Option<ReviewReportState>> {
    let row = connection
        .query_row(
            "SELECT expected_path, report_root, current_revision, published_revision,
                    sha256, bytes, finalized, final_signal, created_at, updated_at
             FROM review_reports WHERE agent_id = ?1",
            [agent_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Option<String>>(7)?,
                    row.get::<_, i64>(8)?,
                    row.get::<_, i64>(9)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(
            expected_path,
            report_root,
            current_revision,
            published_revision,
            sha256,
            bytes,
            finalized,
            final_signal,
            created_at,
            updated_at,
        )| {
            Ok(ReviewReportState {
                agent_id: agent_id.to_owned(),
                expected_path,
                report_root,
                current_revision: i64_to_u64(current_revision)?,
                published_revision: published_revision.map(i64_to_u64).transpose()?,
                sha256,
                bytes: bytes.map(i64_to_u64).transpose()?,
                finalized: finalized != 0,
                final_signal,
                created_at,
                updated_at,
            })
        },
    )
    .transpose()
}

fn query_review_provenance(
    connection: &Connection,
    agent_id: &str,
) -> StoreResult<Option<ReviewProvenanceRecord>> {
    connection
        .query_row(
            "SELECT manifest_sha256, prepared_sha256, base_sha, head_sha,
                    runtime_sha256, zcode_session_id, requested_model, observed_model
             FROM review_provenance WHERE agent_id = ?1",
            [agent_id],
            |row| {
                Ok(ReviewProvenanceRecord {
                    manifest_sha256: row.get(0)?,
                    prepared_sha256: row.get(1)?,
                    base_sha: row.get(2)?,
                    head_sha: row.get(3)?,
                    runtime_sha256: row.get(4)?,
                    zcode_session_id: row.get(5)?,
                    requested_model: row.get(6)?,
                    observed_model: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(StoreError::from)
}

fn query_review_entries(
    connection: &Connection,
    table: &str,
    id_column: &str,
    has_status: bool,
    agent_id: &str,
) -> StoreResult<Vec<ReviewEntryRecord>> {
    let status = if has_status { "status" } else { "NULL" };
    let timestamp = if table == "review_findings" {
        "updated_at"
    } else {
        "created_at"
    };
    let sql = format!(
        "SELECT {id_column}, {status}, payload_json, revision, {timestamp}
         FROM {table} WHERE agent_id = ?1 ORDER BY revision, {id_column}"
    );
    let mut statement = connection.prepare(&sql)?;
    let entries = statement
        .query_map([agent_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<String>>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?
        .map(|row| {
            let (stable_id, status, payload_json, revision, recorded_at) = row?;
            Ok(ReviewEntryRecord {
                stable_id,
                status,
                payload_json,
                revision: i64_to_u64(revision)?,
                recorded_at,
            })
        })
        .collect();
    entries
}

fn query_review_entry_hash(
    connection: &Connection,
    table: &str,
    id_column: &str,
    agent_id: &str,
    stable_id: &str,
) -> StoreResult<Option<String>> {
    connection
        .query_row(
            &format!(
                "SELECT payload_sha256 FROM {table}
                 WHERE agent_id = ?1 AND {id_column} = ?2"
            ),
            params![agent_id, stable_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(StoreError::from)
}

fn review_current_revision(connection: &Connection, agent_id: &str) -> StoreResult<u64> {
    let revision = connection
        .query_row(
            "SELECT current_revision FROM review_reports WHERE agent_id = ?1",
            [agent_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| StoreError::InvalidState(format!("unknown review {agent_id}")))?;
    i64_to_u64(revision)
}

fn ensure_review_mutable(connection: &Connection, agent_id: &str) -> StoreResult<()> {
    let finalized = connection
        .query_row(
            "SELECT finalized FROM review_reports WHERE agent_id = ?1",
            [agent_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .ok_or_else(|| StoreError::InvalidState(format!("unknown review {agent_id}")))?;
    if finalized != 0 {
        return Err(StoreError::Conflict(format!(
            "review {agent_id} is finalized"
        )));
    }
    Ok(())
}

fn advance_review_revision(connection: &Connection, agent_id: &str) -> StoreResult<u64> {
    let changed = connection.execute(
        "UPDATE review_reports SET current_revision = current_revision + 1,
             published_revision = NULL, sha256 = NULL, bytes = NULL, updated_at = ?1
         WHERE agent_id = ?2",
        params![now_millis(), agent_id],
    )?;
    if changed != 1 {
        return Err(StoreError::InvalidState(format!(
            "unknown review {agent_id}"
        )));
    }
    review_current_revision(connection, agent_id)
}

fn migrate_to_v4(connection: &mut Connection) -> StoreResult<()> {
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > SCHEMA_VERSION {
        return Err(StoreError::InvalidState(format!(
            "store schema version {version} is newer than supported {SCHEMA_VERSION}"
        )));
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    for (table, column, definition) in [
        (
            "agents",
            "initial_prompt",
            "initial_prompt TEXT NOT NULL DEFAULT 'Begin review.'",
        ),
        (
            "agents",
            "turn_state",
            "turn_state TEXT NOT NULL DEFAULT 'IDLE'",
        ),
        (
            "agents",
            "stop_requested",
            "stop_requested INTEGER NOT NULL DEFAULT 0",
        ),
        ("agents", "closed_at", "closed_at INTEGER"),
        ("messages", "failure_code", "failure_code TEXT"),
        ("messages", "failure_message", "failure_message TEXT"),
        (
            "pending_requests",
            "response_decision",
            "response_decision TEXT",
        ),
        (
            "pending_requests",
            "response_content",
            "response_content TEXT",
        ),
        (
            "agents",
            "prepared_launch_json",
            "prepared_launch_json TEXT",
        ),
        (
            "agents",
            "prepared_launch_sha256",
            "prepared_launch_sha256 TEXT",
        ),
    ] {
        if !table_has_column(&transaction, table, column)? {
            transaction.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {definition}"))?;
        }
    }
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn table_has_column(connection: &Connection, table: &str, expected: &str) -> StoreResult<bool> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(columns.iter().any(|column| column == expected))
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
                    payload_json, state, response_decision, response_content
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
            })
        },
    )
    .transpose()
}

fn query_events_after(
    connection: &Connection,
    agent_id: &str,
    runtime_agent_id: &str,
    after: i64,
    limit: i64,
) -> StoreResult<Vec<StoredEvent>> {
    let mut statement = connection.prepare(
        "SELECT runtime_agent_id, seq, source_seq, event_type, payload_json, redaction_level
         FROM events WHERE agent_id = ?1 AND runtime_agent_id = ?2 AND seq > ?3
         ORDER BY seq LIMIT ?4",
    )?;
    let events = statement
        .query_map(params![agent_id, runtime_agent_id, after, limit], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    events
        .into_iter()
        .map(
            |(
                runtime_agent_id,
                sequence,
                source_sequence,
                event_type,
                payload_json,
                redaction_level,
            )| {
                Ok(StoredEvent {
                    runtime_agent_id,
                    sequence: i64_to_u64(sequence)?,
                    source_sequence: i64_to_u64(source_sequence)?,
                    event_type,
                    payload_json,
                    redaction_level,
                })
            },
        )
        .collect()
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

fn query_job_by_idempotency(connection: &Connection, key: &str) -> StoreResult<Option<Job>> {
    let row = connection
        .query_row(
            "SELECT agent_id, idempotency_key, state, workspace_path, initial_prompt, owner_id,
                    owner_epoch, close_requested, stop_requested, last_event_seq,
                    failure_code, failure_message, runtime_agent_id,
                    zcode_session_id, turn_state, pid, process_group_id,
                    process_uid, process_start_token, closed_at, reaped_at, created_at,
                    prepared_launch_json, prepared_launch_sha256
             FROM agents WHERE idempotency_key = ?1",
            [key],
            map_job_row,
        )
        .optional()?;
    row.map(convert_job_row).transpose()
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

    #[test]
    fn active_list_filters_in_sql_before_limit() {
        let (_directory, _path, store) = file_store();
        enqueue(&store, "old-active", "/workspace/active");
        let claim = store.claim_next("daemon", 200, 200).unwrap().unwrap();
        assert_eq!(claim.job.agent_id, "old-active");
        for index in 0..101 {
            let id = format!("terminal-{index:03}");
            enqueue(&store, &id, &format!("/workspace/{index}"));
            assert_eq!(store.request_stop(&id).unwrap().state, JobState::Cancelled);
        }
        let active = store.list_jobs_scoped(JobListScope::Active, 100).unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].agent_id, "old-active");
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
                parent_agent_id: None,
                review_kind: None,
                feature_id: None,
                section_id: None,
                round_kind: None,
                workspace_path: "/different".into(),
                report_path: None,
                runtime_hash: None,
                prepared_launch_json: None,
                prepared_launch_sha256: None,
                initial_prompt: "Begin review.".into(),
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
                artifact_type: "report".into(),
                path: "/report".into(),
                sha256: "abc".into(),
                bytes: 12,
                checkpoint_number: Some(1),
            })
            .unwrap());
        assert!(store
            .insert_ledger_entry("ledger-1", "job-1", "checkpoint", "{}", Some(1))
            .unwrap());
        assert!(!store
            .insert_ledger_entry("ledger-1", "job-1", "checkpoint", "{}", Some(1))
            .unwrap());
        assert!(store
            .record_compatibility_run("hash", "version", Some("node"), 7, "OK", "{}")
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
        assert_eq!(reopened.list_jobs(10).unwrap()[0].agent_id, "job-1");
        assert_eq!(reopened.ledger_entry_count("job-1").unwrap(), 1);
        assert_eq!(reopened.compatibility_count().unwrap(), 1);
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
    fn wait_snapshot_deadline_includes_store_mutex_contention() {
        let (_directory, _path, store) = file_store();
        enqueue(&store, "job-1", "a");
        let connection = store.connection.lock().unwrap();
        let started = Instant::now();
        let result = store
            .wait_snapshot_until(
                "job-1",
                None,
                0,
                10,
                Instant::now() + Duration::from_millis(20),
            )
            .unwrap();
        assert_eq!(result, DeadlineRead::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(200));
        drop(connection);
    }

    #[test]
    fn readonly_job_snapshot_remains_bounded_during_store_mutex_contention() {
        let (_directory, _path, store) = file_store();
        enqueue(&store, "job-readonly", "a");
        let connection = store.connection.lock().unwrap();
        let started = Instant::now();
        let snapshot = store
            .get_job_snapshot_until("job-readonly", Instant::now() + Duration::from_millis(50))
            .unwrap();
        assert!(
            matches!(snapshot, DeadlineRead::Ready(Some(ref job)) if job.agent_id == "job-readonly")
        );
        assert!(started.elapsed() < Duration::from_millis(200));
        drop(connection);
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
            store
                .claim_pending_response("pending-bounded", &request_id, "deny", None)
                .unwrap();
            store
                .complete_pending_response("pending-bounded", &request_id)
                .unwrap();
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
        assert_eq!(
            store
                .events_after("job-1", "runtime-1", 0, 10)
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn restart_and_close_retain_partial_events_artifacts_and_compatibility() {
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
                artifact_type: "report".into(),
                path: "/report".into(),
                sha256: "sha".into(),
                bytes: 5,
                checkpoint_number: None,
            })
            .unwrap();
        store
            .record_compatibility_run("hash", "version", None, 1, "OK", "{}")
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
        assert_eq!(
            reopened
                .events_after("queued", "runtime", 0, 10)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(reopened.artifact_count("queued").unwrap(), 1);
        assert_eq!(reopened.compatibility_count().unwrap(), 1);
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
    fn accepted_v1_rows_events_and_artifacts_migrate_in_place() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("v1.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                r#"
                PRAGMA user_version = 1;
                PRAGMA foreign_keys = ON;
                CREATE TABLE agents (
                    agent_id TEXT PRIMARY KEY, idempotency_key TEXT UNIQUE,
                    parent_agent_id TEXT, review_kind TEXT, feature_id TEXT,
                    section_id TEXT, round_kind TEXT, state TEXT NOT NULL,
                    workspace_path TEXT NOT NULL, report_path TEXT, runtime_hash TEXT,
                    zcode_session_id TEXT, pid INTEGER, process_group_id INTEGER,
                    process_uid INTEGER, process_start_token TEXT, runtime_agent_id TEXT,
                    owner_id TEXT, owner_epoch INTEGER NOT NULL DEFAULT 0,
                    lease_expires_at INTEGER, close_requested INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL, started_at INTEGER, completed_at INTEGER,
                    last_heartbeat_at INTEGER, last_event_seq INTEGER NOT NULL DEFAULT 0,
                    failure_code TEXT, failure_message TEXT, reaped_at INTEGER
                );
                CREATE TABLE events (
                    agent_id TEXT NOT NULL, runtime_agent_id TEXT NOT NULL,
                    seq INTEGER NOT NULL, source_seq INTEGER NOT NULL,
                    timestamp INTEGER NOT NULL, event_type TEXT NOT NULL,
                    turn_id TEXT, payload_json TEXT NOT NULL, redaction_level TEXT NOT NULL,
                    PRIMARY KEY (agent_id, runtime_agent_id, seq),
                    UNIQUE (agent_id, runtime_agent_id, source_seq)
                );
                CREATE TABLE artifacts (
                    artifact_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
                    artifact_type TEXT NOT NULL, path TEXT NOT NULL, sha256 TEXT NOT NULL,
                    bytes INTEGER NOT NULL, checkpoint_number INTEGER, created_at INTEGER NOT NULL
                );
                CREATE TABLE messages (
                    message_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, mode TEXT NOT NULL,
                    content TEXT NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL,
                    delivered_at INTEGER, target_turn_id TEXT
                );
                CREATE TABLE pending_requests (
                    request_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL,
                    correlation_id TEXT NOT NULL, request_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL, state TEXT NOT NULL,
                    created_at INTEGER NOT NULL, responded_at INTEGER,
                    UNIQUE (agent_id, correlation_id)
                );
                INSERT INTO agents (
                    agent_id, idempotency_key, state, workspace_path, runtime_agent_id,
                    owner_epoch, created_at, completed_at, last_event_seq
                ) VALUES ('v1-job', 'v1-key', 'COMPLETED', '/v1', 'v1-runtime', 3, 1, 2, 1);
                INSERT INTO events VALUES (
                    'v1-job', 'v1-runtime', 1, 1, 1, 'driver.event', NULL,
                    '{"preserved":true}', 'allowlisted'
                );
                INSERT INTO artifacts VALUES (
                    'v1-artifact', 'v1-job', 'report', '/v1/report.md', 'abc', 7, 1, 2
                );
                INSERT INTO messages VALUES (
                    'v1-message', 'v1-job', 'queue', 'preserved message',
                    'DELIVERED', 1, 2, 'v1-turn'
                );
                INSERT INTO pending_requests VALUES (
                    'v1-request', 'v1-job', '"wire-1"', 'permission', '{}',
                    'RESPONDED', 1, 2
                );
                "#,
            )
            .unwrap();
        drop(connection);

        let store = Store::open(&path).unwrap();
        let job = store.get_job("v1-job").unwrap().unwrap();
        assert_eq!(job.state, JobState::Completed);
        assert_eq!(job.initial_prompt, "Begin review.");
        assert_eq!(job.turn_state, TurnState::Idle);
        assert_eq!(job.zcode_session_id, None);
        assert_eq!(
            store.events_after("v1-job", "v1-runtime", 0, 10).unwrap()[0].payload_json,
            "{\"preserved\":true}"
        );
        assert_eq!(store.artifacts("v1-job", 10).unwrap()[0].bytes, 7);
        assert_eq!(
            store.message("v1-message").unwrap().unwrap().state,
            MessageState::Delivered
        );
        assert_eq!(
            store
                .pending_request("v1-job", "v1-request")
                .unwrap()
                .unwrap()
                .state,
            PendingRequestState::Responded
        );
        let version: i64 = store
            .connection
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn accepted_v3_job_rows_migrate_to_empty_v4_review_tables() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("v3.sqlite3");
        let connection = Connection::open(&path).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        connection.pragma_update(None, "user_version", 3).unwrap();
        connection
            .execute(
                "INSERT INTO agents (
                    agent_id, state, workspace_path, initial_prompt, turn_state, created_at
                 ) VALUES ('v3-job', 'QUEUED', '/v3', 'preserved', 'IDLE', 1)",
                [],
            )
            .unwrap();
        drop(connection);

        let store = Store::open(&path).unwrap();
        assert_eq!(
            store.get_job("v3-job").unwrap().unwrap().initial_prompt,
            "preserved"
        );
        assert!(store.review_report_state("v3-job").unwrap().is_none());
        assert!(store.review_report_agent_ids().unwrap().is_empty());
        let version: i64 = store
            .connection
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, 4);
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
                .claim_pending_response("delivery-job", "request-1", "allow", None)
                .unwrap(),
            DeliveryClaim::Claimed
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
                .claim_pending_response("delivery-job", "request-1", "allow", None)
                .unwrap(),
            DeliveryClaim::AlreadyDelivered
        );
        assert!(matches!(
            store.claim_pending_response("delivery-job", "request-1", "deny", None),
            Err(StoreError::Conflict(_))
        ));
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
}
