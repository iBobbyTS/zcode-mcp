use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use std::{
    fmt,
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

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
    zcode_session_id TEXT,
    pid INTEGER,
    process_group_id INTEGER,
    process_uid INTEGER,
    process_start_token TEXT,
    runtime_agent_id TEXT,
    owner_id TEXT,
    owner_epoch INTEGER NOT NULL DEFAULT 0,
    lease_expires_at INTEGER,
    close_requested INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    started_at INTEGER,
    completed_at INTEGER,
    last_heartbeat_at INTEGER,
    last_event_seq INTEGER NOT NULL DEFAULT 0,
    failure_code TEXT,
    failure_message TEXT,
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
    target_turn_id TEXT
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

PRAGMA user_version = 1;
"#;

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
    FailedRuntimeLost,
    Orphaned,
    Closed,
}

impl JobState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::FailedRuntimeLost | Self::Orphaned | Self::Closed
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "QUEUED",
            Self::Starting => "STARTING",
            Self::Running => "RUNNING",
            Self::Stopping => "STOPPING",
            Self::Completed => "COMPLETED",
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
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    pub agent_id: String,
    pub idempotency_key: Option<String>,
    pub state: JobState,
    pub workspace_path: String,
    pub owner_id: Option<String>,
    pub owner_epoch: u64,
    pub close_requested: bool,
    pub last_event_seq: u64,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
    pub runtime_agent_id: Option<String>,
    pub process_identity: Option<StoredProcessIdentity>,
    pub created_at: i64,
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
pub struct CloseDecision {
    pub state: JobState,
    pub owner_epoch: u64,
    pub needs_runtime_stop: bool,
}

pub struct Store {
    connection: Mutex<Connection>,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> StoreResult<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.execute_batch(SCHEMA)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    pub fn journal_mode(&self) -> StoreResult<String> {
        let connection = self.connection.lock().unwrap();
        Ok(connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?)
    }

    pub fn enqueue_job(&self, job: &NewJob) -> StoreResult<Job> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(key) = &job.idempotency_key {
            if let Some(existing) = query_job_by_idempotency(&transaction, key)? {
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
                report_path, runtime_hash, created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'QUEUED', ?8, ?9, ?10, ?11)",
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
                 ORDER BY created_at, rowid LIMIT 1",
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

    pub fn mark_running(
        &self,
        agent_id: &str,
        owner_epoch: u64,
        runtime_agent_id: &str,
        identity: Option<&StoredProcessIdentity>,
    ) -> StoreResult<bool> {
        let mut connection = self.connection.lock().unwrap();
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE agents SET state = 'RUNNING', runtime_agent_id = ?1,
                 pid = ?2, process_group_id = ?3, process_uid = ?4,
                 process_start_token = ?5, last_heartbeat_at = ?6
             WHERE agent_id = ?7 AND owner_epoch = ?8 AND state = 'STARTING'",
            params![
                runtime_agent_id,
                identity.map(|value| value.pid),
                identity.map(|value| value.process_group_id),
                identity.map(|value| value.uid),
                identity.map(|value| value.start_token.as_str()),
                now_millis(),
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
        let (state, epoch, close_requested) = query_guard(&transaction, &write.agent_id)?;
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
                 last_heartbeat_at = ?2 WHERE agent_id = ?3",
            params![sequence, now_millis(), write.agent_id],
        )?;
        if let Some(terminal) = &write.terminal {
            apply_terminal(
                &transaction,
                &write.agent_id,
                write.owner_epoch,
                state,
                close_requested,
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
        let (state, epoch, close_requested) = query_guard(&transaction, agent_id)?;
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
        let (state, epoch, _) = query_guard(&transaction, agent_id)?;
        let (next, needs_runtime_stop) = match state {
            JobState::Queued => (JobState::Closed, false),
            JobState::Starting | JobState::Running => (JobState::Stopping, true),
            JobState::Stopping => (JobState::Stopping, true),
            terminal => (terminal, false),
        };
        if state != next || !state.is_terminal() {
            transaction.execute(
                "UPDATE agents SET state = ?1, close_requested = 1,
                     completed_at = CASE WHEN ?2 = 1 THEN COALESCE(completed_at, ?3)
                                         ELSE completed_at END
                 WHERE agent_id = ?4",
                params![next.as_str(), next.is_terminal(), now_millis(), agent_id],
            )?;
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
        let (state, _, _) = query_guard(&transaction, agent_id)?;
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
                 WHERE state IN ('QUEUED', 'STARTING', 'RUNNING', 'STOPPING')
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
            let (next, code) = match old {
                JobState::Queued => (JobState::Orphaned, "DAEMON_RESTART_BEFORE_START"),
                JobState::Starting | JobState::Running | JobState::Stopping => {
                    (JobState::FailedRuntimeLost, "DAEMON_RESTART_RUNTIME_LOST")
                }
                _ => continue,
            };
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
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "INSERT OR IGNORE INTO messages
             (message_id, agent_id, mode, content, state, created_at)
             VALUES (?1, ?2, ?3, ?4, 'QUEUED', ?5)",
            params![message_id, agent_id, mode, content, now_millis()],
        )?;
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
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
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
        Ok(changed == 1)
    }

    pub fn deliver_message(&self, message_id: &str) -> StoreResult<bool> {
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "UPDATE messages SET state = 'DELIVERED', delivered_at = ?1
             WHERE message_id = ?2 AND state = 'QUEUED'",
            params![now_millis(), message_id],
        )?;
        Ok(changed == 1)
    }

    pub fn respond_pending_request(
        &self,
        agent_id: &str,
        correlation_id: &str,
    ) -> StoreResult<bool> {
        let connection = self.connection.lock().unwrap();
        let changed = connection.execute(
            "UPDATE pending_requests SET state = 'RESPONDED', responded_at = ?1
             WHERE agent_id = ?2 AND correlation_id = ?3 AND state = 'PENDING'",
            params![now_millis(), agent_id, correlation_id],
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
        let mut statement = connection.prepare(
            "SELECT runtime_agent_id, seq, source_seq, event_type, payload_json, redaction_level
             FROM events WHERE agent_id = ?1 AND runtime_agent_id = ?2 AND seq > ?3
             ORDER BY seq LIMIT ?4",
        )?;
        let events = statement
            .query_map(
                params![
                    agent_id,
                    runtime_agent_id,
                    u64_to_i64(after)?,
                    usize_to_i64(limit)?
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )?
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

fn query_job(connection: &Connection, agent_id: &str) -> StoreResult<Option<Job>> {
    let row = connection
        .query_row(
            "SELECT agent_id, idempotency_key, state, workspace_path, owner_id,
                    owner_epoch, close_requested, last_event_seq, failure_code,
                    failure_message, runtime_agent_id, pid, process_group_id,
                    process_uid, process_start_token, created_at
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
            "SELECT agent_id, idempotency_key, state, workspace_path, owner_id,
                    owner_epoch, close_requested, last_event_seq, failure_code,
                    failure_message, runtime_agent_id, pid, process_group_id,
                    process_uid, process_start_token, created_at
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
    Option<String>,
    i64,
    i64,
    i64,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<i64>,
    Option<i64>,
    Option<String>,
    i64,
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
    ))
}

fn convert_job_row(row: JobRow) -> StoreResult<Job> {
    let identity = match (row.11, row.12, row.13, row.14) {
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
        owner_id: row.4,
        owner_epoch: i64_to_u64(row.5)?,
        close_requested: row.6 != 0,
        last_event_seq: i64_to_u64(row.7)?,
        failure_code: row.8,
        failure_message: row.9,
        runtime_agent_id: row.10,
        process_identity: identity,
        created_at: row.15,
    })
}

fn query_guard(
    transaction: &Transaction<'_>,
    agent_id: &str,
) -> StoreResult<(JobState, u64, bool)> {
    let value = transaction
        .query_row(
            "SELECT state, owner_epoch, close_requested FROM agents WHERE agent_id = ?1",
            [agent_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or_else(|| StoreError::InvalidState(format!("unknown job {agent_id}")))?;
    Ok((
        JobState::parse(&value.0)?,
        i64_to_u64(value.1)?,
        value.2 != 0,
    ))
}

fn apply_terminal(
    transaction: &Transaction<'_>,
    agent_id: &str,
    owner_epoch: u64,
    from_state: JobState,
    close_requested: bool,
    terminal: &TerminalUpdate,
) -> StoreResult<JobState> {
    if !terminal.state.is_terminal() {
        return Err(StoreError::InvalidState(
            "terminal update must select a terminal state".into(),
        ));
    }
    let final_state = if close_requested {
        JobState::Closed
    } else {
        terminal.state
    };
    let changed = transaction.execute(
        "UPDATE agents SET state = ?1, completed_at = COALESCE(completed_at, ?2),
             failure_code = ?3, failure_message = ?4
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
        assert_eq!(reopened.ledger_entry_count("job-1").unwrap(), 1);
        assert_eq!(reopened.compatibility_count().unwrap(), 1);
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
        assert_eq!(changed.len(), 2);
        assert_eq!(
            reopened.get_job("queued").unwrap().unwrap().state,
            JobState::FailedRuntimeLost
        );
        assert_eq!(
            reopened.get_job("running").unwrap().unwrap().state,
            JobState::Orphaned
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
}
