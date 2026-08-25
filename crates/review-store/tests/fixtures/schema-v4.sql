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
