use review_ledger::{LedgerError, LedgerManager, ToolResult, VerifiedArtifact, REVIEW_FINALIZE};
use review_store::{
    DeliveryClaim, Job, JobClaim, JobState, LifecycleWrite, MessageState, NewJob, Store,
    StoreError, StoredMessage, StoredProcessIdentity, TerminalUpdate, TurnState,
};
use std::{
    collections::HashMap,
    fmt, io,
    path::PathBuf,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use zcode_driver::{
    observe_process, observe_process_group, ChildExit, Driver, Inbound, ProcessIdentity,
    RequestError, StopOutcome,
};
use zcode_protocol::{
    event_type, session_id_from_result, turn_id_from_result, CreateSessionParams, LifecycleOrder,
    SendParams, SessionParams, StdioMcpServer, SubscribeParams, WireId, WireMessage, WorkspaceRef,
    INTERACTION_REQUEST_PERMISSION, INTERACTION_REQUEST_USER_INPUT, SESSION_CREATE, SESSION_SEND,
    SESSION_STOP, SESSION_SUBSCRIBE, WORKSPACE_READ_STATE,
};

pub mod ledger_mcp;
pub mod orchestration;
pub mod prompts;
pub mod rpc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeLoss {
    InvalidIdentity,
    UnsupportedIdentity,
    MissingLeader,
    IdentityMismatch,
    UnknownMembership,
    SessionLost,
    StopFailed(String),
    EventStreamLost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewFailure {
    PreparedLaunchInvalid,
    MissingFinalization,
    EvidenceIncomplete,
    ReportMissing,
    ReportInvalid,
    ProvenanceMismatch,
    SourceIntegrity,
    CleanupFailed,
    LedgerMalformed,
    FinalizationConflict,
}

impl ReviewFailure {
    fn code(self) -> &'static str {
        match self {
            Self::PreparedLaunchInvalid => "PREPARED_LAUNCH_INVALID",
            Self::MissingFinalization => "REVIEW_NOT_FINALIZED",
            Self::EvidenceIncomplete => "REVIEW_EVIDENCE_INCOMPLETE",
            Self::ReportMissing => "REVIEW_REPORT_MISSING",
            Self::ReportInvalid => "REVIEW_REPORT_INVALID",
            Self::ProvenanceMismatch => "REVIEW_PROVENANCE_MISMATCH",
            Self::SourceIntegrity => "SOURCE_INTEGRITY_FAILED",
            Self::CleanupFailed => "WORKTREE_CLEANUP_FAILED",
            Self::LedgerMalformed => "REVIEW_LEDGER_INVALID",
            Self::FinalizationConflict => "REVIEW_FINALIZE_CONFLICT",
        }
    }

    fn reason(self) -> &'static str {
        match self {
            Self::PreparedLaunchInvalid => "prepared_launch_invalid",
            Self::MissingFinalization => "review_not_finalized",
            Self::EvidenceIncomplete => "review_evidence_incomplete",
            Self::ReportMissing => "review_report_missing",
            Self::ReportInvalid => "review_report_invalid",
            Self::ProvenanceMismatch => "review_provenance_mismatch",
            Self::SourceIntegrity => "source_integrity_failed",
            Self::CleanupFailed => "worktree_cleanup_failed",
            Self::LedgerMalformed => "review_ledger_invalid",
            Self::FinalizationConflict => "review_finalize_conflict",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeTerminal {
    Stopped(StopOutcome),
    Completed(StopOutcome),
    FailedTurn(StopOutcome),
    Exited(ChildExit),
    FailedRuntimeLost(RuntimeLoss),
    Orphaned(RuntimeLoss),
    ReviewFailed(ReviewFailure),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TurnBoundary {
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TurnSnapshot {
    pub generation: u64,
    pub active: bool,
    pub boundary: Option<TurnBoundary>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionReady {
    pub session_id: String,
    pub initial_turn_id: Option<String>,
    pub observed_model: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InternalLedgerMcpConfig {
    pub command: PathBuf,
    pub socket: PathBuf,
    pub runtime_sha256: Option<String>,
}

impl InternalLedgerMcpConfig {
    pub fn server_for(&self, agent_id: &str) -> StdioMcpServer {
        StdioMcpServer {
            name: "review-ledger".into(),
            command: self.command.to_string_lossy().into_owned(),
            args: vec![
                "--ledger-mcp".into(),
                "--socket".into(),
                self.socket.to_string_lossy().into_owned(),
                "--agent-id".into(),
                agent_id.into(),
            ],
            env: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeCommandError {
    Unsupported,
    Timeout,
    Transport(String),
    Remote(serde_json::Value),
    InvalidSession(String),
}

impl fmt::Display for RuntimeCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => write!(f, "runtime command plane is unsupported"),
            Self::Timeout => write!(f, "runtime command deadline elapsed"),
            Self::Transport(_) => write!(f, "runtime command transport failed"),
            Self::Remote(_) => write!(f, "runtime command was rejected"),
            Self::InvalidSession(message) => write!(f, "invalid session response: {message}"),
        }
    }
}

impl std::error::Error for RuntimeCommandError {}

impl From<RequestError> for RuntimeCommandError {
    fn from(error: RequestError) -> Self {
        match error {
            RequestError::Timeout => Self::Timeout,
            RequestError::Remote(value) => Self::Remote(value),
            other => Self::Transport(other.to_string()),
        }
    }
}

#[derive(Debug)]
struct TurnTrackerState {
    generation: u64,
    active: bool,
    boundary: Option<TurnBoundary>,
}

struct TurnTracker {
    state: Mutex<TurnTrackerState>,
    changed: Condvar,
}

impl TurnTracker {
    fn new() -> Self {
        Self {
            state: Mutex::new(TurnTrackerState {
                generation: 0,
                active: false,
                boundary: None,
            }),
            changed: Condvar::new(),
        }
    }

    fn observe(&self, inbound: &Inbound) {
        let Inbound::Message(WireMessage::Event(event)) = inbound else {
            return;
        };
        let Some(kind) = event_type(event) else {
            return;
        };
        let mut state = self.state.lock().unwrap();
        match kind {
            "turn.started" => {
                state.generation = state.generation.saturating_add(1);
                state.active = true;
                state.boundary = None;
            }
            "turn.completed" if state.active => {
                state.active = false;
                state.boundary = Some(TurnBoundary::Completed);
            }
            "turn.failed" if state.active => {
                state.active = false;
                state.boundary = Some(TurnBoundary::Failed);
            }
            _ => return,
        }
        self.changed.notify_all();
    }

    fn snapshot(&self) -> TurnSnapshot {
        let state = self.state.lock().unwrap();
        TurnSnapshot {
            generation: state.generation,
            active: state.active,
            boundary: state.boundary,
        }
    }

    fn wait_started_after(
        &self,
        previous_generation: u64,
        timeout: Duration,
    ) -> Result<TurnSnapshot, RuntimeCommandError> {
        self.wait_until(timeout, |state| state.generation > previous_generation)
    }

    fn wait_boundary_after(
        &self,
        generation: u64,
        timeout: Duration,
    ) -> Result<TurnSnapshot, RuntimeCommandError> {
        self.wait_until(timeout, |state| {
            state.generation >= generation && !state.active && state.boundary.is_some()
        })
    }

    fn wait_until(
        &self,
        timeout: Duration,
        predicate: impl Fn(&TurnTrackerState) -> bool,
    ) -> Result<TurnSnapshot, RuntimeCommandError> {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().unwrap();
        loop {
            if predicate(&state) {
                return Ok(TurnSnapshot {
                    generation: state.generation,
                    active: state.active,
                    boundary: state.boundary,
                });
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(RuntimeCommandError::Timeout);
            }
            let (next, result) = self.changed.wait_timeout(state, deadline - now).unwrap();
            state = next;
            if result.timed_out() && !predicate(&state) {
                return Err(RuntimeCommandError::Timeout);
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeEvent {
    Driver(Inbound),
    Terminal(RuntimeTerminal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleRecord {
    pub sequence: u64,
    pub event: RuntimeEvent,
}

pub trait LifecycleSink: Send + Sync + 'static {
    fn emit(&self, record: LifecycleRecord);
}

#[derive(Debug)]
enum OwnerState {
    Running,
    Stopping,
    Terminal(RuntimeTerminal),
}

#[derive(Debug)]
struct PublisherState {
    next_sequence: u64,
    owner: OwnerState,
    exit_boundary_delivered: bool,
}

struct Publisher {
    sink: Arc<dyn LifecycleSink>,
    state: Mutex<PublisherState>,
    changed: Condvar,
}

impl Publisher {
    fn new(sink: Arc<dyn LifecycleSink>) -> Self {
        Self {
            sink,
            state: Mutex::new(PublisherState {
                next_sequence: 1,
                owner: OwnerState::Running,
                exit_boundary_delivered: false,
            }),
            changed: Condvar::new(),
        }
    }

    fn emit_driver(&self, event: Inbound, exit_terminal: Option<RuntimeTerminal>) {
        let mut state = self.state.lock().unwrap();
        if matches!(state.owner, OwnerState::Terminal(_)) {
            return;
        }
        let is_exit_boundary = matches!(event, Inbound::ChildExited(_));
        self.emit_locked(&mut state, RuntimeEvent::Driver(event));
        if is_exit_boundary {
            state.exit_boundary_delivered = true;
            self.changed.notify_all();
        }
        if let Some(terminal) = exit_terminal {
            if matches!(state.owner, OwnerState::Running) {
                self.publish_terminal_locked(&mut state, terminal);
            }
        }
    }

    fn begin_stopping(&self) -> Option<RuntimeTerminal> {
        let mut state = self.state.lock().unwrap();
        match &state.owner {
            OwnerState::Terminal(terminal) => Some(terminal.clone()),
            OwnerState::Running => {
                state.owner = OwnerState::Stopping;
                None
            }
            OwnerState::Stopping => None,
        }
    }

    fn publish_terminal(&self, terminal: RuntimeTerminal) -> RuntimeTerminal {
        let mut state = self.state.lock().unwrap();
        if let OwnerState::Terminal(existing) = &state.owner {
            return existing.clone();
        }
        self.publish_terminal_locked(&mut state, terminal.clone());
        terminal
    }

    fn wait_for_exit_boundary(&self) -> Option<RuntimeTerminal> {
        let mut state = self.state.lock().unwrap();
        loop {
            if state.exit_boundary_delivered {
                return None;
            }
            if let OwnerState::Terminal(terminal) = &state.owner {
                return Some(terminal.clone());
            }
            state = self.changed.wait(state).unwrap();
        }
    }

    fn publish_terminal_locked(&self, state: &mut PublisherState, terminal: RuntimeTerminal) {
        state.owner = OwnerState::Terminal(terminal.clone());
        self.emit_locked(state, RuntimeEvent::Terminal(terminal));
        self.changed.notify_all();
    }

    fn emit_locked(&self, state: &mut PublisherState, event: RuntimeEvent) {
        let record = LifecycleRecord {
            sequence: state.next_sequence,
            event,
        };
        state.next_sequence = state.next_sequence.saturating_add(1);
        self.sink.emit(record);
    }

    fn wait_terminal(&self, timeout: Duration) -> Option<RuntimeTerminal> {
        let deadline = Instant::now().checked_add(timeout)?;
        let mut state = self.state.lock().unwrap();
        loop {
            if let OwnerState::Terminal(terminal) = &state.owner {
                return Some(terminal.clone());
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            let (next, wait) = self.changed.wait_timeout(state, deadline - now).unwrap();
            state = next;
            if wait.timed_out() && !matches!(state.owner, OwnerState::Terminal(_)) {
                return None;
            }
        }
    }
}

pub struct RuntimeOwner {
    driver: Arc<Driver>,
    publisher: Arc<Publisher>,
    shutdown_pump: Arc<AtomicBool>,
    turn_tracker: Arc<TurnTracker>,
    session_id: Mutex<Option<String>>,
}

impl RuntimeOwner {
    pub fn spawn(command: Command, sink: Arc<dyn LifecycleSink>) -> io::Result<Self> {
        let driver = Arc::new(Driver::spawn(command)?);
        let publisher = Arc::new(Publisher::new(sink));
        let shutdown_pump = Arc::new(AtomicBool::new(false));
        let turn_tracker = Arc::new(TurnTracker::new());
        spawn_event_pump(
            Arc::clone(&driver),
            Arc::clone(&publisher),
            Arc::clone(&shutdown_pump),
            Arc::clone(&turn_tracker),
        );
        Ok(Self {
            driver,
            publisher,
            shutdown_pump,
            turn_tracker,
            session_id: Mutex::new(None),
        })
    }

    pub fn bootstrap_session(
        &self,
        workspace_path: &str,
        initial_prompt: &str,
        timeout: Duration,
    ) -> Result<SessionReady, RuntimeCommandError> {
        self.bootstrap_session_with_mcp(workspace_path, initial_prompt, &[], timeout)
    }

    pub fn bootstrap_session_with_mcp(
        &self,
        workspace_path: &str,
        initial_prompt: &str,
        mcp_servers: &[StdioMcpServer],
        timeout: Duration,
    ) -> Result<SessionReady, RuntimeCommandError> {
        self.driver
            .request(WORKSPACE_READ_STATE, serde_json::json!({}), timeout)?;
        let create_params = serde_json::to_value(CreateSessionParams {
            workspace: WorkspaceRef {
                workspace_key: workspace_path,
                workspace_path,
            },
            mcp_servers,
        })
        .map_err(|error| RuntimeCommandError::Transport(error.to_string()))?;
        let created = self
            .driver
            .request(SESSION_CREATE, create_params, timeout)?;
        let result = created.result.as_ref().ok_or_else(|| {
            RuntimeCommandError::InvalidSession("session/create result is missing".into())
        })?;
        let session_id = session_id_from_result(result)
            .filter(|value| !value.is_empty() && value.len() <= 512 && !value.contains('\0'))
            .ok_or_else(|| {
                RuntimeCommandError::InvalidSession("session/create returned no session id".into())
            })?
            .to_owned();
        let observed_model = observed_model_from_result(result).map(str::to_owned);
        let subscribe_params = serde_json::to_value(SubscribeParams {
            session_id: &session_id,
            delivery_kind: "desktop-continuous",
            include_snapshot: false,
        })
        .map_err(|error| RuntimeCommandError::Transport(error.to_string()))?;
        self.driver
            .request(SESSION_SUBSCRIBE, subscribe_params, timeout)?;
        *self.session_id.lock().unwrap() = Some(session_id.clone());
        let initial_turn_id = self.send_turn(&session_id, initial_prompt, timeout)?;
        Ok(SessionReady {
            session_id,
            initial_turn_id,
            observed_model,
        })
    }

    pub fn send_turn(
        &self,
        session_id: &str,
        content: &str,
        timeout: Duration,
    ) -> Result<Option<String>, RuntimeCommandError> {
        self.validate_session(session_id)?;
        let previous = self.turn_tracker.snapshot().generation;
        let params = serde_json::to_value(SendParams {
            session_id,
            content,
        })
        .map_err(|error| RuntimeCommandError::Transport(error.to_string()))?;
        let response = self.driver.request(SESSION_SEND, params, timeout)?;
        let turn_id = response
            .result
            .as_ref()
            .and_then(turn_id_from_result)
            .map(str::to_owned);
        self.turn_tracker.wait_started_after(previous, timeout)?;
        Ok(turn_id)
    }

    pub fn stop_turn(
        &self,
        session_id: &str,
        timeout: Duration,
    ) -> Result<TurnSnapshot, RuntimeCommandError> {
        self.validate_session(session_id)?;
        let current = self.turn_tracker.snapshot();
        if !current.active {
            return Ok(current);
        }
        let params = serde_json::to_value(SessionParams { session_id })
            .map_err(|error| RuntimeCommandError::Transport(error.to_string()))?;
        self.driver.request(SESSION_STOP, params, timeout)?;
        self.turn_tracker
            .wait_boundary_after(current.generation, timeout)
    }

    pub fn respond_request(
        &self,
        correlation_id: &str,
        decision: &str,
        content: Option<&str>,
    ) -> Result<(), RuntimeCommandError> {
        let id = serde_json::from_str::<WireId>(correlation_id).map_err(|_| {
            RuntimeCommandError::InvalidSession("stored request correlation is invalid".into())
        })?;
        if !matches!(decision, "allow" | "deny") {
            return Err(RuntimeCommandError::Unsupported);
        }
        let mut result = serde_json::json!({"decision": decision});
        if let Some(reason) = content {
            result
                .as_object_mut()
                .expect("permission result is an object")
                .insert("reason".into(), reason.into());
        }
        self.driver
            .respond(id, result)
            .map_err(|error| RuntimeCommandError::Transport(error.to_string()))
    }

    pub fn close_session(
        &self,
        session_id: &str,
        timeout: Duration,
    ) -> Result<(), RuntimeCommandError> {
        self.validate_session(session_id)?;
        let params = serde_json::to_value(SessionParams { session_id })
            .map_err(|error| RuntimeCommandError::Transport(error.to_string()))?;
        self.driver
            .request(zcode_protocol::SESSION_CLOSE, params, timeout)?;
        Ok(())
    }

    pub fn turn_snapshot(&self) -> TurnSnapshot {
        self.turn_tracker.snapshot()
    }

    fn validate_session(&self, session_id: &str) -> Result<(), RuntimeCommandError> {
        if self.session_id.lock().unwrap().as_deref() == Some(session_id) {
            Ok(())
        } else {
            Err(RuntimeCommandError::InvalidSession(
                "session id does not belong to this runtime".into(),
            ))
        }
    }

    pub fn identity(&self) -> ProcessIdentity {
        self.driver.identity()
    }

    pub fn stop(&self, grace: Duration) -> RuntimeTerminal {
        self.finish_process(grace, None)
    }

    pub fn finish_turn(&self, boundary: TurnBoundary, grace: Duration) -> RuntimeTerminal {
        self.finish_process(grace, Some(boundary))
    }

    fn finish_process(&self, grace: Duration, boundary: Option<TurnBoundary>) -> RuntimeTerminal {
        if let Some(terminal) = self.publisher.begin_stopping() {
            return terminal;
        }
        let terminal = match self.driver.stop_and_reap(grace) {
            Ok(outcome) => match self.publisher.wait_for_exit_boundary() {
                Some(terminal) => terminal,
                None => match boundary {
                    Some(TurnBoundary::Completed) => RuntimeTerminal::Completed(outcome),
                    Some(TurnBoundary::Failed) => RuntimeTerminal::FailedTurn(outcome),
                    None => RuntimeTerminal::Stopped(outcome),
                },
            },
            Err(error) => {
                RuntimeTerminal::FailedRuntimeLost(RuntimeLoss::StopFailed(error.to_string()))
            }
        };
        self.publisher.publish_terminal(terminal)
    }

    pub fn close(&self, grace: Duration) -> RuntimeTerminal {
        self.stop(grace)
    }

    pub fn wait_terminal(&self, timeout: Duration) -> Option<RuntimeTerminal> {
        self.publisher.wait_terminal(timeout)
    }
}

fn observed_model_from_result(result: &serde_json::Value) -> Option<&str> {
    result
        .get("modelId")
        .and_then(serde_json::Value::as_str)
        .or_else(|| {
            result
                .get("session")
                .and_then(|session| session.get("modelId"))
                .and_then(serde_json::Value::as_str)
        })
}

impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        let _ = self.stop(Duration::from_secs(1));
        self.shutdown_pump.store(true, Ordering::Release);
    }
}

fn spawn_event_pump(
    driver: Arc<Driver>,
    publisher: Arc<Publisher>,
    shutdown: Arc<AtomicBool>,
    turn_tracker: Arc<TurnTracker>,
) {
    thread::spawn(move || loop {
        if shutdown.load(Ordering::Acquire) {
            return;
        }
        match driver.recv_timeout(Duration::from_millis(20)) {
            Ok(event) => {
                turn_tracker.observe(&event);
                let is_exit_boundary = matches!(event, Inbound::ChildExited(_));
                let terminal = match &event {
                    Inbound::ChildExited(exit) => {
                        match observe_process_group(driver.identity().pgid) {
                            Ok(members) if members.is_empty() => match exit {
                                ChildExit::Exited(Some(0)) => {
                                    let turn = turn_tracker.snapshot();
                                    if !turn.active
                                        && turn.boundary == Some(TurnBoundary::Completed)
                                    {
                                        Some(RuntimeTerminal::Completed(
                                            StopOutcome::AlreadyExited(exit.clone()),
                                        ))
                                    } else {
                                        Some(RuntimeTerminal::FailedRuntimeLost(
                                            RuntimeLoss::EventStreamLost,
                                        ))
                                    }
                                }
                                _ => Some(RuntimeTerminal::Exited(exit.clone())),
                            },
                            Ok(_) | Err(_) => {
                                Some(RuntimeTerminal::Orphaned(RuntimeLoss::UnknownMembership))
                            }
                        }
                    }
                    _ => None,
                };
                publisher.emit_driver(event, terminal);
                if is_exit_boundary {
                    return;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                publisher.publish_terminal(RuntimeTerminal::FailedRuntimeLost(
                    RuntimeLoss::EventStreamLost,
                ));
                return;
            }
        }
    });
}

pub fn classify_restart(identity: &ProcessIdentity) -> RuntimeTerminal {
    if identity.pid <= 1
        || identity.pgid <= 1
        || identity.pid as i32 != identity.pgid
        || identity.start_token.is_empty()
    {
        return RuntimeTerminal::Orphaned(RuntimeLoss::InvalidIdentity);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = identity;
        return RuntimeTerminal::Orphaned(RuntimeLoss::UnsupportedIdentity);
    }

    #[cfg(target_os = "macos")]
    {
        let first = match observe_process(identity.pid) {
            Ok(observed) => observed,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return RuntimeTerminal::Orphaned(RuntimeLoss::MissingLeader);
            }
            Err(_) => return RuntimeTerminal::Orphaned(RuntimeLoss::UnsupportedIdentity),
        };
        if &first != identity {
            return RuntimeTerminal::Orphaned(RuntimeLoss::IdentityMismatch);
        }
        let members = match observe_process_group(identity.pgid) {
            Ok(members) => members,
            Err(_) => return RuntimeTerminal::Orphaned(RuntimeLoss::UnknownMembership),
        };
        if members.is_empty()
            || !members.iter().any(|member| member == identity)
            || members.iter().any(|member| {
                member.pgid != identity.pgid
                    || member.uid != identity.uid
                    || member.start_token.is_empty()
            })
        {
            return RuntimeTerminal::Orphaned(RuntimeLoss::UnknownMembership);
        }
        match observe_process(identity.pid) {
            Ok(second) if second == first => {
                RuntimeTerminal::FailedRuntimeLost(RuntimeLoss::SessionLost)
            }
            Ok(_) => RuntimeTerminal::Orphaned(RuntimeLoss::IdentityMismatch),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                RuntimeTerminal::Orphaned(RuntimeLoss::MissingLeader)
            }
            Err(_) => RuntimeTerminal::Orphaned(RuntimeLoss::UnsupportedIdentity),
        }
    }
}

pub trait ManagedRuntime: Send + Sync + 'static {
    fn identity(&self) -> Option<ProcessIdentity>;
    fn stop(&self, grace: Duration) -> RuntimeTerminal;
    fn wait_terminal(&self, timeout: Duration) -> Option<RuntimeTerminal>;
    fn bootstrap_session(
        &self,
        _job: &Job,
        _timeout: Duration,
    ) -> Result<SessionReady, RuntimeCommandError> {
        Err(RuntimeCommandError::Unsupported)
    }
    fn bootstrap_session_with_mcp(
        &self,
        job: &Job,
        _mcp_servers: &[StdioMcpServer],
        timeout: Duration,
    ) -> Result<SessionReady, RuntimeCommandError> {
        self.bootstrap_session(job, timeout)
    }
    fn send_turn(
        &self,
        _session_id: &str,
        _content: &str,
        _timeout: Duration,
    ) -> Result<Option<String>, RuntimeCommandError> {
        Err(RuntimeCommandError::Unsupported)
    }
    fn stop_turn(
        &self,
        _session_id: &str,
        _timeout: Duration,
    ) -> Result<TurnSnapshot, RuntimeCommandError> {
        Err(RuntimeCommandError::Unsupported)
    }
    fn respond_request(
        &self,
        _correlation_id: &str,
        _decision: &str,
        _content: Option<&str>,
    ) -> Result<(), RuntimeCommandError> {
        Err(RuntimeCommandError::Unsupported)
    }
    fn close_session(
        &self,
        _session_id: &str,
        _timeout: Duration,
    ) -> Result<(), RuntimeCommandError> {
        Ok(())
    }
    fn turn_snapshot(&self) -> TurnSnapshot {
        TurnSnapshot {
            generation: 0,
            active: false,
            boundary: None,
        }
    }
    fn finish_turn(&self, boundary: TurnBoundary, grace: Duration) -> RuntimeTerminal {
        let _ = boundary;
        self.stop(grace)
    }
}

impl ManagedRuntime for RuntimeOwner {
    fn identity(&self) -> Option<ProcessIdentity> {
        Some(self.identity())
    }

    fn stop(&self, grace: Duration) -> RuntimeTerminal {
        self.stop(grace)
    }

    fn wait_terminal(&self, timeout: Duration) -> Option<RuntimeTerminal> {
        self.wait_terminal(timeout)
    }

    fn bootstrap_session(
        &self,
        job: &Job,
        timeout: Duration,
    ) -> Result<SessionReady, RuntimeCommandError> {
        self.bootstrap_session(&job.workspace_path, &job.initial_prompt, timeout)
    }

    fn bootstrap_session_with_mcp(
        &self,
        job: &Job,
        mcp_servers: &[StdioMcpServer],
        timeout: Duration,
    ) -> Result<SessionReady, RuntimeCommandError> {
        self.bootstrap_session_with_mcp(
            &job.workspace_path,
            &job.initial_prompt,
            mcp_servers,
            timeout,
        )
    }

    fn send_turn(
        &self,
        session_id: &str,
        content: &str,
        timeout: Duration,
    ) -> Result<Option<String>, RuntimeCommandError> {
        self.send_turn(session_id, content, timeout)
    }

    fn stop_turn(
        &self,
        session_id: &str,
        timeout: Duration,
    ) -> Result<TurnSnapshot, RuntimeCommandError> {
        self.stop_turn(session_id, timeout)
    }

    fn respond_request(
        &self,
        correlation_id: &str,
        decision: &str,
        content: Option<&str>,
    ) -> Result<(), RuntimeCommandError> {
        self.respond_request(correlation_id, decision, content)
    }

    fn close_session(
        &self,
        session_id: &str,
        timeout: Duration,
    ) -> Result<(), RuntimeCommandError> {
        self.close_session(session_id, timeout)
    }

    fn turn_snapshot(&self) -> TurnSnapshot {
        self.turn_snapshot()
    }

    fn finish_turn(&self, boundary: TurnBoundary, grace: Duration) -> RuntimeTerminal {
        self.finish_turn(boundary, grace)
    }
}

pub trait RuntimeFactory: Send + Sync + 'static {
    fn spawn(&self, job: &Job, sink: Arc<dyn LifecycleSink>)
        -> io::Result<Arc<dyn ManagedRuntime>>;
}

pub struct CommandRuntimeFactory<F> {
    command: F,
    require_prepared: bool,
}

impl<F> CommandRuntimeFactory<F> {
    pub fn new(command: F) -> Self {
        Self {
            command,
            require_prepared: false,
        }
    }

    pub fn new_prepared(command: F) -> Self {
        Self {
            command,
            require_prepared: true,
        }
    }
}

impl<F> RuntimeFactory for CommandRuntimeFactory<F>
where
    F: Fn(&Job) -> io::Result<Command> + Send + Sync + 'static,
{
    fn spawn(
        &self,
        job: &Job,
        sink: Arc<dyn LifecycleSink>,
    ) -> io::Result<Arc<dyn ManagedRuntime>> {
        if self.require_prepared {
            let json = job.prepared_launch_json.as_deref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "prepared launch is required")
            })?;
            let prepared: review_preparation::PreparedLaunchSpec = serde_json::from_str(json)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            prepared
                .validate_for_launch()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
            if job.prepared_launch_sha256.as_deref() != Some(prepared.prepared_sha256.as_str())
                || job.workspace_path != prepared.worktree.path.to_string_lossy()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "stored job does not match its prepared launch",
                ));
            }
        }
        let command = (self.command)(job)?;
        Ok(Arc::new(RuntimeOwner::spawn(command, sink)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerConfig {
    pub global_max_agents: usize,
    pub per_workspace_max_agents: usize,
    pub stop_grace: Duration,
    pub command_timeout: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            global_max_agents: 2,
            per_workspace_max_agents: 1,
            stop_grace: Duration::from_secs(1),
            command_timeout: Duration::from_secs(2),
        }
    }
}

#[derive(Debug)]
pub enum SchedulerError {
    Store(StoreError),
    InvalidConfig(String),
    RuntimeSpawn { agent_id: String, message: String },
    LifecycleSink { agent_id: String, message: String },
    RuntimeCommand { agent_id: String, message: String },
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => write!(f, "{error}"),
            Self::InvalidConfig(message) => write!(f, "invalid scheduler config: {message}"),
            Self::RuntimeSpawn { agent_id, message } => {
                write!(f, "runtime spawn failed for {agent_id}: {message}")
            }
            Self::LifecycleSink { agent_id, message } => {
                write!(f, "lifecycle sink failed for {agent_id}: {message}")
            }
            Self::RuntimeCommand { agent_id, message } => {
                write!(f, "runtime command failed for {agent_id}: {message}")
            }
        }
    }
}

impl std::error::Error for SchedulerError {}

impl From<StoreError> for SchedulerError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

#[derive(Clone)]
pub struct Scheduler {
    inner: Arc<SchedulerInner>,
}

struct SchedulerInner {
    owner_id: String,
    store: Arc<Store>,
    factory: Arc<dyn RuntimeFactory>,
    config: SchedulerConfig,
    ledger: Option<Arc<LedgerManager>>,
    ledger_mcp: Option<InternalLedgerMcpConfig>,
    review_completion: Option<Arc<orchestration::ReviewCompletionGate>>,
    state: Mutex<SchedulerState>,
}

#[derive(Default)]
struct SchedulerState {
    active: HashMap<String, ActiveRuntime>,
    failures: HashMap<String, String>,
}

struct ActiveRuntime {
    owner_epoch: u64,
    runtime: Arc<dyn ManagedRuntime>,
    sink: Arc<StoreLifecycleSink>,
    session_id: String,
    operation: Arc<Mutex<()>>,
}

type ActiveSession = (u64, Arc<dyn ManagedRuntime>, String, Arc<Mutex<()>>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageDisposition {
    Queued,
    Delivered,
    InterruptedThenDelivered,
    AlreadyDelivered,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseDisposition {
    Responded,
    AlreadyResponded,
    InFlight,
}

struct StoreLifecycleSink {
    store: Arc<Store>,
    agent_id: String,
    runtime_agent_id: String,
    owner_epoch: u64,
    write_state: Mutex<SinkWriteState>,
}

#[derive(Default)]
struct SinkWriteState {
    first_error: Option<String>,
    last_source_sequence: u64,
    pending_terminal_sequence: Option<u64>,
    terminal_written: bool,
}

struct LifecycleProjection {
    event_type: &'static str,
    payload_json: String,
    redaction_level: &'static str,
}

impl StoreLifecycleSink {
    fn new(
        store: Arc<Store>,
        agent_id: String,
        runtime_agent_id: String,
        owner_epoch: u64,
    ) -> Self {
        Self {
            store,
            agent_id,
            runtime_agent_id,
            owner_epoch,
            write_state: Mutex::new(SinkWriteState::default()),
        }
    }

    fn finish(&self, terminal: &RuntimeTerminal) -> Result<JobState, StoreError> {
        let mut state = self.write_state.lock().unwrap();
        if let Some(error) = &state.first_error {
            return self.store.fail_claim(
                &self.agent_id,
                self.owner_epoch,
                "LIFECYCLE_SINK_FAILED",
                error,
            );
        }
        if state.terminal_written {
            return self
                .store
                .get_job(&self.agent_id)?
                .map(|job| job.state)
                .ok_or_else(|| StoreError::InvalidState("terminal job disappeared".into()));
        }
        let source_sequence = state
            .pending_terminal_sequence
            .unwrap_or_else(|| state.last_source_sequence.saturating_add(1));
        let projection = lifecycle_projection(&RuntimeEvent::Terminal(terminal.clone()), None);
        let write = LifecycleWrite {
            agent_id: self.agent_id.clone(),
            runtime_agent_id: self.runtime_agent_id.clone(),
            owner_epoch: self.owner_epoch,
            source_sequence,
            event_type: projection.event_type.into(),
            turn_id: None,
            payload_json: projection.payload_json,
            redaction_level: projection.redaction_level.into(),
            terminal: Some(terminal_update(terminal)),
            turn_state: None,
        };
        self.store.append_lifecycle(&write)?;
        state.terminal_written = true;
        self.store
            .get_job(&self.agent_id)?
            .map(|job| job.state)
            .ok_or_else(|| StoreError::InvalidState("terminal job disappeared".into()))
    }

    fn error(&self) -> Option<String> {
        self.write_state.lock().unwrap().first_error.clone()
    }
}

impl LifecycleSink for StoreLifecycleSink {
    fn emit(&self, record: LifecycleRecord) {
        let mut state = self.write_state.lock().unwrap();
        if state.first_error.is_some() {
            return;
        }
        state.last_source_sequence = state.last_source_sequence.max(record.sequence);
        if matches!(record.event, RuntimeEvent::Terminal(_)) {
            state.pending_terminal_sequence = Some(record.sequence);
            return;
        }
        let pending_request_id = match &record.event {
            RuntimeEvent::Driver(Inbound::Message(WireMessage::Request(request)))
                if matches!(
                    request.method.as_str(),
                    INTERACTION_REQUEST_PERMISSION | INTERACTION_REQUEST_USER_INPUT
                ) =>
            {
                let request_id = format!("{}:request:{}", self.agent_id, record.sequence);
                let correlation_id = match serde_json::to_string(&request.id) {
                    Ok(value) => value,
                    Err(error) => {
                        state.first_error = Some(error.to_string());
                        return;
                    }
                };
                let request_type = if request.method == INTERACTION_REQUEST_PERMISSION {
                    "permission"
                } else {
                    "unsupported_input"
                };
                if let Err(error) = self.store.insert_pending_request(
                    &request_id,
                    &self.agent_id,
                    &correlation_id,
                    request_type,
                    &request.params.to_string(),
                ) {
                    state.first_error = Some(error.to_string());
                    return;
                }
                Some(request_id)
            }
            _ => None,
        };
        let projection = lifecycle_projection(&record.event, pending_request_id.as_deref());
        let write = LifecycleWrite {
            agent_id: self.agent_id.clone(),
            runtime_agent_id: self.runtime_agent_id.clone(),
            owner_epoch: self.owner_epoch,
            source_sequence: record.sequence,
            event_type: projection.event_type.into(),
            turn_id: None,
            payload_json: projection.payload_json,
            redaction_level: projection.redaction_level.into(),
            terminal: None,
            turn_state: match &record.event {
                RuntimeEvent::Driver(Inbound::Lifecycle { method, .. }) => match method.as_str() {
                    "turn.started" => Some(TurnState::Active),
                    "turn.completed" => Some(TurnState::Idle),
                    "turn.failed" => Some(TurnState::Failed),
                    _ => None,
                },
                _ => None,
            },
        };
        if let Err(error) = self.store.append_lifecycle(&write) {
            state.first_error = Some(error.to_string());
        }
    }
}

fn lifecycle_projection(
    event: &RuntimeEvent,
    pending_request_id: Option<&str>,
) -> LifecycleProjection {
    let (event_type, payload, redaction_level) = match event {
        RuntimeEvent::Driver(Inbound::Message(WireMessage::Request(request))) => (
            "driver.message",
            serde_json::json!({
                "kind": "request",
                "method": request.method,
                "request_id": pending_request_id,
            }),
            "redacted",
        ),
        RuntimeEvent::Driver(Inbound::Message(WireMessage::Response(response))) => (
            "driver.message",
            serde_json::json!({
                "kind": "response",
                "outcome": if response.error.is_some() { "error" } else { "result" },
            }),
            "redacted",
        ),
        RuntimeEvent::Driver(Inbound::Message(WireMessage::Event(message))) => (
            "driver.message",
            serde_json::json!({
                "kind": "event",
                "method": message.method,
                "type": event_type(message),
            }),
            "redacted",
        ),
        RuntimeEvent::Driver(Inbound::Message(WireMessage::UnknownEvent { .. })) => (
            "raw.unknown",
            serde_json::json!({"kind": "unknown_event", "raw": "[REDACTED]"}),
            "redacted",
        ),
        RuntimeEvent::Driver(Inbound::Lifecycle {
            sequence,
            method,
            order,
        }) => (
            "driver.lifecycle",
            serde_json::json!({
                "kind": "lifecycle",
                "sequence": sequence,
                "method": method,
                "order": lifecycle_order_name(order),
            }),
            "allowlisted",
        ),
        RuntimeEvent::Driver(Inbound::Malformed(_)) => (
            "driver.malformed",
            serde_json::json!({"kind": "malformed", "detail": "[REDACTED]"}),
            "redacted",
        ),
        RuntimeEvent::Driver(Inbound::OversizedLine { bytes }) => (
            "driver.oversized_line",
            serde_json::json!({"kind": "oversized_line", "bytes": bytes}),
            "allowlisted",
        ),
        RuntimeEvent::Driver(Inbound::ChildExited(exit)) => (
            "driver.child_exited",
            serde_json::json!({"kind": "child_exited", "outcome": child_exit_name(exit)}),
            "allowlisted",
        ),
        RuntimeEvent::Driver(Inbound::UnmatchedResponse { id: _, outcome }) => (
            "driver.unmatched_response",
            serde_json::json!({"kind": "unmatched_response", "outcome": outcome}),
            "redacted",
        ),
        RuntimeEvent::Terminal(RuntimeTerminal::Stopped(outcome)) => (
            "runtime.stopped",
            serde_json::json!({"kind": "stopped", "outcome": stop_outcome_name(outcome)}),
            "allowlisted",
        ),
        RuntimeEvent::Terminal(RuntimeTerminal::Completed(outcome)) => (
            "runtime.completed",
            serde_json::json!({"kind": "completed", "outcome": stop_outcome_name(outcome)}),
            "allowlisted",
        ),
        RuntimeEvent::Terminal(RuntimeTerminal::FailedTurn(outcome)) => (
            "runtime.turn_failed",
            serde_json::json!({"kind": "turn_failed", "outcome": stop_outcome_name(outcome)}),
            "allowlisted",
        ),
        RuntimeEvent::Terminal(RuntimeTerminal::Exited(exit)) => (
            "runtime.exited",
            serde_json::json!({"kind": "exited", "outcome": child_exit_name(exit)}),
            "allowlisted",
        ),
        RuntimeEvent::Terminal(RuntimeTerminal::FailedRuntimeLost(loss)) => (
            "runtime.failed_runtime_lost",
            serde_json::json!({"kind": "failed_runtime_lost", "reason": runtime_loss_name(loss)}),
            runtime_loss_redaction(loss),
        ),
        RuntimeEvent::Terminal(RuntimeTerminal::Orphaned(loss)) => (
            "runtime.orphaned",
            serde_json::json!({"kind": "orphaned", "reason": runtime_loss_name(loss)}),
            runtime_loss_redaction(loss),
        ),
        RuntimeEvent::Terminal(RuntimeTerminal::ReviewFailed(failure)) => (
            "runtime.review_failed",
            serde_json::json!({"kind": "review_failed", "reason": failure.reason()}),
            "allowlisted",
        ),
    };
    LifecycleProjection {
        event_type,
        payload_json: payload.to_string(),
        redaction_level,
    }
}

fn lifecycle_order_name(order: &LifecycleOrder) -> &'static str {
    match order {
        LifecycleOrder::NotLifecycle => "not_lifecycle",
        LifecycleOrder::InOrder => "in_order",
        LifecycleOrder::OutOfOrder { .. } => "out_of_order",
    }
}

fn child_exit_name(exit: &ChildExit) -> &'static str {
    match exit {
        ChildExit::Exited(Some(0)) => "exited_success",
        ChildExit::Exited(Some(_)) => "exited_failure",
        ChildExit::Exited(None) => "exited_unknown",
        ChildExit::Signaled(_) => "signaled",
        ChildExit::Unknown => "unknown",
    }
}

fn stop_outcome_name(outcome: &StopOutcome) -> &'static str {
    match outcome {
        StopOutcome::AlreadyExited(_) => "already_exited",
        StopOutcome::Terminated(_) => "terminated",
    }
}

fn runtime_loss_name(loss: &RuntimeLoss) -> &'static str {
    match loss {
        RuntimeLoss::InvalidIdentity => "invalid_identity",
        RuntimeLoss::UnsupportedIdentity => "unsupported_identity",
        RuntimeLoss::MissingLeader => "missing_leader",
        RuntimeLoss::IdentityMismatch => "identity_mismatch",
        RuntimeLoss::UnknownMembership => "unknown_membership",
        RuntimeLoss::SessionLost => "session_lost",
        RuntimeLoss::StopFailed(_) => "stop_failed",
        RuntimeLoss::EventStreamLost => "event_stream_lost",
    }
}

fn runtime_loss_redaction(loss: &RuntimeLoss) -> &'static str {
    if matches!(loss, RuntimeLoss::StopFailed(_)) {
        "redacted"
    } else {
        "allowlisted"
    }
}

fn terminal_update(terminal: &RuntimeTerminal) -> TerminalUpdate {
    match terminal {
        RuntimeTerminal::Stopped(_) => TerminalUpdate {
            state: JobState::Completed,
            failure_code: None,
            failure_message: None,
        },
        RuntimeTerminal::Completed(_) => TerminalUpdate {
            state: JobState::Completed,
            failure_code: None,
            failure_message: None,
        },
        RuntimeTerminal::FailedTurn(_) => TerminalUpdate {
            state: JobState::Failed,
            failure_code: Some("TURN_FAILED".into()),
            failure_message: Some("turn_failed".into()),
        },
        RuntimeTerminal::Exited(exit) => TerminalUpdate {
            state: JobState::FailedRuntimeLost,
            failure_code: Some("RUNTIME_EXITED".into()),
            failure_message: Some(child_exit_name(exit).into()),
        },
        RuntimeTerminal::FailedRuntimeLost(loss) => TerminalUpdate {
            state: JobState::FailedRuntimeLost,
            failure_code: Some("FAILED_RUNTIME_LOST".into()),
            failure_message: Some(runtime_loss_name(loss).into()),
        },
        RuntimeTerminal::Orphaned(loss) => TerminalUpdate {
            state: JobState::Orphaned,
            failure_code: Some("ORPHANED".into()),
            failure_message: Some(runtime_loss_name(loss).into()),
        },
        RuntimeTerminal::ReviewFailed(failure) => TerminalUpdate {
            state: JobState::Failed,
            failure_code: Some(failure.code().into()),
            failure_message: Some(failure.reason().into()),
        },
    }
}

impl Scheduler {
    pub fn new(
        owner_id: impl Into<String>,
        store: Arc<Store>,
        factory: Arc<dyn RuntimeFactory>,
        config: SchedulerConfig,
    ) -> Result<Self, SchedulerError> {
        if config.global_max_agents == 0
            || config.per_workspace_max_agents == 0
            || config.command_timeout.is_zero()
        {
            return Err(SchedulerError::InvalidConfig(
                "global and per-workspace limits must be positive".into(),
            ));
        }
        Ok(Self {
            inner: Arc::new(SchedulerInner {
                owner_id: owner_id.into(),
                store,
                factory,
                config,
                ledger: None,
                ledger_mcp: None,
                review_completion: None,
                state: Mutex::new(SchedulerState::default()),
            }),
        })
    }

    pub fn with_ledger(
        mut self,
        ledger: Arc<LedgerManager>,
        config: InternalLedgerMcpConfig,
    ) -> Result<Self, SchedulerError> {
        if !Arc::ptr_eq(&ledger.store(), &self.inner.store) {
            return Err(SchedulerError::InvalidConfig(
                "ledger and scheduler must share one store".into(),
            ));
        }
        if !config.command.is_absolute() || !config.socket.is_absolute() {
            return Err(SchedulerError::InvalidConfig(
                "internal ledger command and socket must be absolute".into(),
            ));
        }
        let inner = Arc::get_mut(&mut self.inner).ok_or_else(|| {
            SchedulerError::InvalidConfig("ledger must attach before scheduler cloning".into())
        })?;
        inner.review_completion = Some(Arc::new(orchestration::ReviewCompletionGate::new(
            Arc::clone(&ledger),
        )));
        inner.ledger = Some(ledger);
        inner.ledger_mcp = Some(config);
        Ok(self)
    }

    pub fn ledger(&self) -> Option<Arc<LedgerManager>> {
        self.inner.ledger.as_ref().map(Arc::clone)
    }

    pub(crate) fn review_completion_enabled(&self) -> bool {
        self.inner.review_completion.is_some()
    }

    pub fn store(&self) -> Arc<Store> {
        Arc::clone(&self.inner.store)
    }

    pub fn enqueue(&self, job: &NewJob) -> Result<Job, SchedulerError> {
        Ok(self.inner.store.enqueue_job(job)?)
    }

    pub fn enqueue_prepared(
        &self,
        agent_id: impl Into<String>,
        initial_prompt: impl Into<String>,
        prepared: &review_preparation::PreparedLaunchSpec,
    ) -> Result<Job, SchedulerError> {
        prepared
            .validate_for_launch()
            .map_err(|error| SchedulerError::InvalidConfig(error.to_string()))?;
        let workspace = std::fs::canonicalize(&prepared.worktree.path)
            .map_err(|error| SchedulerError::InvalidConfig(error.to_string()))?;
        if workspace != prepared.worktree.path
            || !workspace.starts_with(&prepared.worktree.scratch_worktrees_root)
        {
            return Err(SchedulerError::InvalidConfig(
                "prepared worktree identity is no longer valid".into(),
            ));
        }
        let agent_id = agent_id.into();
        let initial_prompt = initial_prompt.into();
        if agent_id.is_empty() || initial_prompt.is_empty() {
            return Err(SchedulerError::InvalidConfig(
                "prepared job requires an agent id and initial prompt".into(),
            ));
        }
        let mut job = NewJob::new(agent_id, workspace.to_string_lossy());
        job.idempotency_key = Some(prepared.idempotency_key.clone());
        job.review_kind = Some(prepared.review_kind.as_str().into());
        job.feature_id = Some(prepared.feature_id.clone());
        job.section_id = Some(prepared.section_id.clone());
        job.round_kind = Some(prepared.round_kind.as_str().into());
        job.report_path = Some(prepared.report_target.to_string_lossy().into_owned());
        job.runtime_hash = self
            .inner
            .ledger_mcp
            .as_ref()
            .and_then(|config| config.runtime_sha256.clone());
        job.initial_prompt = initial_prompt;
        job.prepared_launch_json = Some(
            prepared
                .canonical_json()
                .map_err(|error| SchedulerError::InvalidConfig(error.to_string()))?,
        );
        job.prepared_launch_sha256 = Some(prepared.prepared_sha256.clone());
        let stored = self.enqueue(&job)?;
        if let Some(ledger) = &self.inner.ledger {
            ledger
                .initialize(&stored.agent_id, prepared, job.runtime_hash.as_deref())
                .map_err(|error| SchedulerError::InvalidConfig(error.to_string()))?;
        }
        Ok(stored)
    }

    pub fn reconcile_startup(&self) -> Result<Vec<(String, JobState)>, SchedulerError> {
        // Startup reconciliation is valid only before this scheduler owns a runtime.
        // Persisted process identity is never used to signal or reconnect here.
        let active = self.inner.state.lock().unwrap().active.is_empty();
        if !active {
            return Err(SchedulerError::InvalidConfig(
                "startup reconciliation requires an empty active set".into(),
            ));
        }
        if let Some(ledger) = &self.inner.ledger {
            ledger
                .recover_all()
                .map_err(|error| SchedulerError::InvalidConfig(error.to_string()))?;
        }
        Ok(self.inner.store.reconcile_startup()?)
    }

    pub fn start_ready(&self) -> Result<Vec<String>, SchedulerError> {
        let mut started = Vec::new();
        loop {
            let claim = self.inner.store.claim_next(
                &self.inner.owner_id,
                self.inner.config.global_max_agents,
                self.inner.config.per_workspace_max_agents,
            )?;
            let Some(claim) = claim else {
                return Ok(started);
            };
            let agent_id = claim.job.agent_id.clone();
            match self.start_claim(claim) {
                Ok(true) => started.push(agent_id),
                Ok(false) => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn ensure_job_ledger(&self, job: &Job) -> Result<(), SchedulerError> {
        let Some(ledger) = &self.inner.ledger else {
            return Ok(());
        };
        let prepared_json = job.prepared_launch_json.as_deref().ok_or_else(|| {
            SchedulerError::InvalidConfig("ledger job requires a prepared launch".into())
        })?;
        let prepared: review_preparation::PreparedLaunchSpec = serde_json::from_str(prepared_json)
            .map_err(|error| {
                SchedulerError::InvalidConfig(format!("stored prepared launch is invalid: {error}"))
            })?;
        ledger
            .initialize(
                &job.agent_id,
                &prepared,
                self.inner
                    .ledger_mcp
                    .as_ref()
                    .and_then(|config| config.runtime_sha256.as_deref()),
            )
            .map_err(|error| SchedulerError::InvalidConfig(error.to_string()))?;
        Ok(())
    }

    fn start_claim(&self, claim: JobClaim) -> Result<bool, SchedulerError> {
        if let Err(error) = self.ensure_job_ledger(&claim.job) {
            let message = error.to_string();
            self.inner.store.fail_claim(
                &claim.job.agent_id,
                claim.owner_epoch,
                "REPORT_INITIALIZATION_FAILED",
                &message,
            )?;
            return Err(error);
        }
        let runtime_agent_id = format!("{}:{}", claim.job.agent_id, claim.owner_epoch);
        let sink = Arc::new(StoreLifecycleSink::new(
            Arc::clone(&self.inner.store),
            claim.job.agent_id.clone(),
            runtime_agent_id.clone(),
            claim.owner_epoch,
        ));
        let lifecycle_sink: Arc<dyn LifecycleSink> = sink.clone();
        let runtime = match self.inner.factory.spawn(&claim.job, lifecycle_sink) {
            Ok(runtime) => runtime,
            Err(error) => {
                let message = error.to_string();
                if let Err(store_error) = self.inner.store.fail_claim(
                    &claim.job.agent_id,
                    claim.owner_epoch,
                    "RUNTIME_SPAWN_FAILED",
                    &message,
                ) {
                    self.record_failure(&claim.job.agent_id, store_error.to_string());
                }
                return Err(SchedulerError::RuntimeSpawn {
                    agent_id: claim.job.agent_id,
                    message,
                });
            }
        };
        let mcp_servers = self
            .inner
            .ledger_mcp
            .as_ref()
            .map(|config| vec![config.server_for(&claim.job.agent_id)])
            .unwrap_or_default();
        let session = match runtime.bootstrap_session_with_mcp(
            &claim.job,
            &mcp_servers,
            self.inner.config.command_timeout,
        ) {
            Ok(session) => session,
            Err(error) => {
                let message = error.to_string();
                if let Err(store_error) = self.inner.store.fail_claim(
                    &claim.job.agent_id,
                    claim.owner_epoch,
                    "SESSION_START_FAILED",
                    &message,
                ) {
                    self.record_failure(&claim.job.agent_id, store_error.to_string());
                }
                let _ = runtime.stop(self.inner.config.stop_grace);
                return Err(SchedulerError::RuntimeCommand {
                    agent_id: claim.job.agent_id,
                    message,
                });
            }
        };
        let identity = runtime.identity().map(|identity| StoredProcessIdentity {
            pid: identity.pid,
            process_group_id: identity.pgid,
            uid: identity.uid,
            start_token: identity.start_token,
        });
        let operation = Arc::new(Mutex::new(()));
        let ready_turn_state = match runtime.turn_snapshot() {
            TurnSnapshot { active: true, .. } => TurnState::Active,
            TurnSnapshot {
                boundary: Some(TurnBoundary::Failed),
                ..
            } => TurnState::Failed,
            _ => TurnState::Idle,
        };
        {
            let mut state = self.inner.state.lock().unwrap();
            state.active.insert(
                claim.job.agent_id.clone(),
                ActiveRuntime {
                    owner_epoch: claim.owner_epoch,
                    runtime: Arc::clone(&runtime),
                    sink: Arc::clone(&sink),
                    session_id: session.session_id.clone(),
                    operation: Arc::clone(&operation),
                },
            );
        }
        let marked = match self.inner.store.mark_session_running(
            &claim.job.agent_id,
            claim.owner_epoch,
            &runtime_agent_id,
            identity.as_ref(),
            Some(&session.session_id),
            Some(ready_turn_state),
        ) {
            Ok(marked) => marked,
            Err(error) => {
                let _ = self.cleanup_registered_runtime(
                    &claim.job.agent_id,
                    claim.owner_epoch,
                    &runtime,
                    &sink,
                    Some(("STORE_START_FAILED", error.to_string())),
                );
                return Err(SchedulerError::Store(error));
            }
        };
        if !marked {
            let current = match self.inner.store.get_job(&claim.job.agent_id) {
                Ok(current) => current,
                Err(error) => {
                    let _ = self.cleanup_registered_runtime(
                        &claim.job.agent_id,
                        claim.owner_epoch,
                        &runtime,
                        &sink,
                        Some(("POST_REGISTRATION_READ_FAILED", error.to_string())),
                    );
                    return Err(SchedulerError::Store(error));
                }
            };
            if current.as_ref().is_some_and(|job| {
                job.stop_requested
                    || job.close_requested
                    || job.state == JobState::Stopping
                    || job.state.is_terminal()
            }) {
                self.cleanup_registered_runtime(
                    &claim.job.agent_id,
                    claim.owner_epoch,
                    &runtime,
                    &sink,
                    None,
                )?;
                return Ok(false);
            }
            let message = "running transition was not applied";
            self.cleanup_registered_runtime(
                &claim.job.agent_id,
                claim.owner_epoch,
                &runtime,
                &sink,
                Some(("RUNTIME_START_RACE", message.into())),
            )?;
            return Ok(false);
        }
        if let Some(ledger) = &self.inner.ledger {
            if let Err(error) = ledger.record_runtime(
                &claim.job.agent_id,
                self.inner
                    .ledger_mcp
                    .as_ref()
                    .and_then(|config| config.runtime_sha256.as_deref()),
                &session.session_id,
                session.observed_model.as_deref(),
            ) {
                let _ = self.cleanup_registered_runtime(
                    &claim.job.agent_id,
                    claim.owner_epoch,
                    &runtime,
                    &sink,
                    Some(("REPORT_PROVENANCE_FAILED", error.to_string())),
                );
                return Err(SchedulerError::InvalidConfig(error.to_string()));
            }
        }
        let current = match self.inner.store.get_job(&claim.job.agent_id) {
            Ok(current) => current,
            Err(error) => {
                let _ = self.cleanup_registered_runtime(
                    &claim.job.agent_id,
                    claim.owner_epoch,
                    &runtime,
                    &sink,
                    Some(("POST_REGISTRATION_READ_FAILED", error.to_string())),
                );
                return Err(SchedulerError::Store(error));
            }
        };
        if current.as_ref().is_some_and(|job| {
            job.stop_requested || job.close_requested || job.state != JobState::Running
        }) {
            let state = self.cleanup_registered_runtime(
                &claim.job.agent_id,
                claim.owner_epoch,
                &runtime,
                &sink,
                None,
            )?;
            debug_assert!(state.is_terminal());
            return Ok(false);
        }
        self.spawn_monitor(
            claim.job.agent_id,
            claim.owner_epoch,
            runtime,
            sink,
            session.session_id,
            operation,
        );
        Ok(true)
    }

    fn cleanup_registered_runtime(
        &self,
        agent_id: &str,
        owner_epoch: u64,
        runtime: &Arc<dyn ManagedRuntime>,
        sink: &Arc<StoreLifecycleSink>,
        failure: Option<(&str, String)>,
    ) -> Result<JobState, SchedulerError> {
        let preclassified = failure.map(|(code, message)| {
            self.inner
                .store
                .fail_claim(agent_id, owner_epoch, code, &message)
        });
        let terminal = runtime.stop(self.inner.config.stop_grace);
        let terminal = self.review_terminal(agent_id, terminal, false);
        let finished = sink.finish(&terminal);
        self.release_active(agent_id, owner_epoch);

        if let Some(result) = preclassified {
            match result {
                Ok(state) => return Ok(state),
                Err(error) => {
                    self.record_failure(agent_id, error.to_string());
                    return Err(SchedulerError::Store(error));
                }
            }
        }
        match finished {
            Ok(state) => Ok(state),
            Err(error) => {
                self.record_failure(agent_id, error.to_string());
                match self.inner.store.fail_claim(
                    agent_id,
                    owner_epoch,
                    "TERMINAL_WRITE_FAILED",
                    &error.to_string(),
                ) {
                    Ok(state) => Ok(state),
                    Err(fallback) => {
                        self.record_failure(agent_id, fallback.to_string());
                        Err(SchedulerError::Store(fallback))
                    }
                }
            }
        }
    }

    fn review_terminal(
        &self,
        agent_id: &str,
        terminal: RuntimeTerminal,
        natural_completion: bool,
    ) -> RuntimeTerminal {
        let Some(gate) = &self.inner.review_completion else {
            return terminal;
        };
        let job = match self.inner.store.get_job(agent_id) {
            Ok(Some(job)) => job,
            Ok(None) | Err(_) if natural_completion => {
                return RuntimeTerminal::ReviewFailed(ReviewFailure::ReportMissing)
            }
            Ok(None) | Err(_) => return terminal,
        };
        if natural_completion && matches!(terminal, RuntimeTerminal::Completed(_)) {
            return match gate.complete(&job) {
                Ok(()) => terminal,
                Err(failure) => RuntimeTerminal::ReviewFailed(failure),
            };
        }
        if let Err(error) = gate.cleanup_nonclean(&job) {
            self.record_failure(agent_id, error.reason().into());
        }
        terminal
    }

    fn spawn_monitor(
        &self,
        agent_id: String,
        owner_epoch: u64,
        runtime: Arc<dyn ManagedRuntime>,
        sink: Arc<StoreLifecycleSink>,
        session_id: String,
        operation: Arc<Mutex<()>>,
    ) {
        let scheduler = self.clone();
        thread::spawn(move || {
            let mut handled_generation = 0;
            loop {
                if let Some(terminal) = runtime.wait_terminal(Duration::from_millis(50)) {
                    let terminal = scheduler.review_terminal(&agent_id, terminal, false);
                    if let Some(error) = sink.error() {
                        if let Err(store_error) = scheduler.inner.store.fail_claim(
                            &agent_id,
                            owner_epoch,
                            "LIFECYCLE_SINK_FAILED",
                            &error,
                        ) {
                            scheduler.record_failure(&agent_id, store_error.to_string());
                        }
                        scheduler.record_failure(&agent_id, error);
                    } else if let Err(error) = sink.finish(&terminal) {
                        scheduler.record_failure(&agent_id, error.to_string());
                    }
                    scheduler.release_active(&agent_id, owner_epoch);
                    if let Err(error) = scheduler.start_ready() {
                        scheduler.record_failure(&agent_id, error.to_string());
                    }
                    return;
                }
                if let Some(error) = sink.error() {
                    let _ = runtime.stop(scheduler.inner.config.stop_grace);
                    if let Err(store_error) = scheduler.inner.store.fail_claim(
                        &agent_id,
                        owner_epoch,
                        "LIFECYCLE_SINK_FAILED",
                        &error,
                    ) {
                        scheduler.record_failure(&agent_id, store_error.to_string());
                    }
                    scheduler.record_failure(&agent_id, error);
                    scheduler.release_active(&agent_id, owner_epoch);
                    return;
                }
                let turn = runtime.turn_snapshot();
                if !turn.active && turn.generation > handled_generation {
                    let Some(boundary) = turn.boundary else {
                        continue;
                    };
                    let _guard = operation.lock().unwrap();
                    let current = runtime.turn_snapshot();
                    if current.active
                        || current.generation != turn.generation
                        || current.boundary != Some(boundary)
                    {
                        continue;
                    }
                    handled_generation = turn.generation;
                    match scheduler.deliver_next_message(&agent_id, &session_id, &runtime) {
                        Ok(Some(_)) => {}
                        Ok(None) => {
                            let terminal =
                                runtime.finish_turn(boundary, scheduler.inner.config.stop_grace);
                            let terminal = scheduler.review_terminal(
                                &agent_id,
                                terminal,
                                boundary == TurnBoundary::Completed,
                            );
                            if let Err(error) = sink.finish(&terminal) {
                                scheduler.record_failure(&agent_id, error.to_string());
                            }
                            scheduler.release_active(&agent_id, owner_epoch);
                            if let Err(error) = scheduler.start_ready() {
                                scheduler.record_failure(&agent_id, error.to_string());
                            }
                            return;
                        }
                        Err(error) => {
                            scheduler.record_failure(&agent_id, error.to_string());
                            let terminal = runtime.finish_turn(
                                TurnBoundary::Failed,
                                scheduler.inner.config.stop_grace,
                            );
                            let terminal = scheduler.review_terminal(&agent_id, terminal, false);
                            let _ = sink.finish(&terminal);
                            scheduler.release_active(&agent_id, owner_epoch);
                            return;
                        }
                    }
                }
            }
        });
    }

    fn deliver_next_message(
        &self,
        agent_id: &str,
        session_id: &str,
        runtime: &Arc<dyn ManagedRuntime>,
    ) -> Result<Option<StoredMessage>, SchedulerError> {
        let Some(message) = self.inner.store.claim_next_message(agent_id)? else {
            return Ok(None);
        };
        match runtime.send_turn(
            session_id,
            &message.content,
            self.inner.config.command_timeout,
        ) {
            Ok(turn_id) => {
                if !self
                    .inner
                    .store
                    .complete_message(&message.message_id, turn_id.as_deref())?
                {
                    return Err(SchedulerError::Store(StoreError::Conflict(format!(
                        "message {} lost its delivery claim",
                        message.message_id
                    ))));
                }
                Ok(self.inner.store.message(&message.message_id)?)
            }
            Err(error) => {
                self.inner.store.fail_message(
                    &message.message_id,
                    "SESSION_SEND_FAILED",
                    &error.to_string(),
                )?;
                Err(SchedulerError::RuntimeCommand {
                    agent_id: agent_id.into(),
                    message: error.to_string(),
                })
            }
        }
    }

    pub fn call_review_tool(
        &self,
        agent_id: &str,
        tool: &str,
        arguments: serde_json::Value,
    ) -> Result<ToolResult, SchedulerError> {
        self.inner.store.get_job(agent_id)?.ok_or_else(|| {
            SchedulerError::Store(StoreError::InvalidState(format!("unknown job {agent_id}")))
        })?;
        let ledger = self.inner.ledger.as_ref().ok_or_else(|| {
            SchedulerError::InvalidConfig("internal review ledger is unavailable".into())
        })?;
        match ledger.call_tool(agent_id, tool, arguments) {
            Ok(result) => Ok(result),
            Err(error) => {
                let failure =
                    if tool == REVIEW_FINALIZE && matches!(&error, LedgerError::Conflict(_)) {
                        ReviewFailure::FinalizationConflict
                    } else {
                        ReviewFailure::LedgerMalformed
                    };
                self.fail_active_review(agent_id, failure);
                Err(SchedulerError::InvalidConfig(error.to_string()))
            }
        }
    }

    fn fail_active_review(&self, agent_id: &str, failure: ReviewFailure) {
        let Some((owner_epoch, runtime, _session_id, operation)) = self.active_session(agent_id)
        else {
            return;
        };
        let _guard = operation.lock().unwrap();
        let sink = {
            let state = self.inner.state.lock().unwrap();
            state
                .active
                .get(agent_id)
                .map(|active| Arc::clone(&active.sink))
        };
        let update = terminal_update(&RuntimeTerminal::ReviewFailed(failure));
        if let Err(error) = self
            .inner
            .store
            .transition_terminal(agent_id, owner_epoch, &update)
        {
            self.record_failure(agent_id, error.to_string());
        }
        let terminal = runtime.stop(self.inner.config.stop_grace);
        let terminal = self.review_terminal(agent_id, terminal, false);
        if let Some(sink) = sink {
            let _ = sink.finish(&terminal);
        }
        self.release_active(agent_id, owner_epoch);
    }

    pub fn verify_review_artifact(
        &self,
        agent_id: &str,
        preview_bytes: usize,
    ) -> Result<Option<VerifiedArtifact>, SchedulerError> {
        let Some(ledger) = &self.inner.ledger else {
            return Ok(None);
        };
        if self.inner.store.review_report_state(agent_id)?.is_none() {
            return Ok(None);
        }
        ledger
            .verify_artifact(agent_id, preview_bytes)
            .map(Some)
            .map_err(|error| SchedulerError::InvalidConfig(error.to_string()))
    }

    pub fn message_job(
        &self,
        agent_id: &str,
        message_id: &str,
        mode: &str,
        content: &str,
    ) -> Result<MessageDisposition, SchedulerError> {
        let active = self.active_session(agent_id);
        let operation = active
            .as_ref()
            .map(|(_, _, _, operation)| Arc::clone(operation));
        let _operation = operation
            .as_ref()
            .map(|operation| operation.lock().unwrap());
        let created = self
            .inner
            .store
            .insert_message(message_id, agent_id, mode, content)?;
        if !created {
            return Ok(
                match self
                    .inner
                    .store
                    .message(message_id)?
                    .map(|message| message.state)
                {
                    Some(MessageState::Delivered) => MessageDisposition::AlreadyDelivered,
                    Some(MessageState::Failed) => MessageDisposition::Failed,
                    _ => MessageDisposition::Queued,
                },
            );
        }
        if mode != "interrupt_and_continue" {
            return Ok(MessageDisposition::Queued);
        }
        let Some((_epoch, runtime, session_id, _)) = active else {
            return Ok(MessageDisposition::Queued);
        };
        let turn = runtime.turn_snapshot();
        if turn.active {
            runtime
                .stop_turn(&session_id, self.inner.config.command_timeout)
                .map_err(|error| SchedulerError::RuntimeCommand {
                    agent_id: agent_id.into(),
                    message: error.to_string(),
                })?;
        }
        let delivered = self.deliver_next_message(agent_id, &session_id, &runtime)?;
        Ok(match delivered {
            Some(message) if message.message_id == message_id => {
                MessageDisposition::InterruptedThenDelivered
            }
            Some(_) | None => MessageDisposition::Queued,
        })
    }

    pub fn respond_job(
        &self,
        agent_id: &str,
        request_id: &str,
        decision: &str,
        content: Option<&str>,
    ) -> Result<ResponseDisposition, SchedulerError> {
        let request = self
            .inner
            .store
            .pending_request(agent_id, request_id)?
            .ok_or_else(|| {
                SchedulerError::Store(StoreError::InvalidState(format!(
                    "unknown request {request_id}"
                )))
            })?;
        let valid = match request.request_type.as_str() {
            "permission" => matches!(decision, "allow" | "deny"),
            _ => false,
        };
        if !valid {
            return Err(SchedulerError::InvalidConfig(
                if request.request_type == "unsupported_input" {
                    "user-input response is unsupported by the pinned app-server seam".into()
                } else {
                    "response decision does not match the pending request type".into()
                },
            ));
        }
        let mut effective_decision = decision;
        let mut policy_reason = None;
        if request.request_type == "permission" && decision == "allow" {
            let job = self.inner.store.get_job(agent_id)?.ok_or_else(|| {
                SchedulerError::Store(StoreError::InvalidState(format!("unknown job {agent_id}")))
            })?;
            if let Some(prepared_json) = job.prepared_launch_json.as_deref() {
                let prepared: review_preparation::PreparedLaunchSpec =
                    serde_json::from_str(prepared_json).map_err(|error| {
                        SchedulerError::InvalidConfig(format!(
                            "stored prepared launch is invalid: {error}"
                        ))
                    })?;
                let launcher = prepared.launcher().map_err(|error| {
                    SchedulerError::InvalidConfig(format!(
                        "stored prepared policy is invalid: {error}"
                    ))
                })?;
                let params: serde_json::Value = serde_json::from_str(&request.payload_json)
                    .map_err(|error| {
                        SchedulerError::InvalidConfig(format!(
                            "permission request payload is invalid: {error}"
                        ))
                    })?;
                let policy = launcher
                    .decide_zcode_permission(&params, review_preparation::ExternalDecision::Allow);
                if !policy.allowed {
                    effective_decision = "deny";
                    policy_reason = Some(policy.reason.to_owned());
                }
            }
        }
        let effective_content = policy_reason.as_deref().or(content);
        match self.inner.store.claim_pending_response(
            agent_id,
            request_id,
            effective_decision,
            effective_content,
        )? {
            DeliveryClaim::AlreadyDelivered => return Ok(ResponseDisposition::AlreadyResponded),
            DeliveryClaim::InFlight => return Ok(ResponseDisposition::InFlight),
            DeliveryClaim::Claimed => {}
        }
        let Some((_epoch, runtime, _session_id, operation)) = self.active_session(agent_id) else {
            self.inner
                .store
                .release_pending_response(agent_id, request_id)?;
            return Err(SchedulerError::RuntimeCommand {
                agent_id: agent_id.into(),
                message: "runtime is not active".into(),
            });
        };
        let _guard = operation.lock().unwrap();
        let current = self.inner.store.get_job(agent_id)?;
        if current.as_ref().is_none_or(|job| {
            job.state != JobState::Running || job.stop_requested || job.close_requested
        }) {
            self.inner
                .store
                .release_pending_response(agent_id, request_id)?;
            return Err(SchedulerError::RuntimeCommand {
                agent_id: agent_id.into(),
                message: "runtime is stopping or no longer active".into(),
            });
        }
        if let Err(error) = runtime.respond_request(
            &request.correlation_id,
            effective_decision,
            effective_content,
        ) {
            self.inner
                .store
                .release_pending_response(agent_id, request_id)?;
            return Err(SchedulerError::RuntimeCommand {
                agent_id: agent_id.into(),
                message: error.to_string(),
            });
        }
        if !self
            .inner
            .store
            .complete_pending_response(agent_id, request_id)?
        {
            return Err(SchedulerError::Store(StoreError::Conflict(format!(
                "request {request_id} lost its response claim"
            ))));
        }
        Ok(ResponseDisposition::Responded)
    }

    pub fn stop_job(&self, agent_id: &str) -> Result<JobState, SchedulerError> {
        self.request_stop_or_close(agent_id, false)
    }

    pub fn close_job(&self, agent_id: &str) -> Result<JobState, SchedulerError> {
        self.request_stop_or_close(agent_id, true)
    }

    fn request_stop_or_close(
        &self,
        agent_id: &str,
        close_session: bool,
    ) -> Result<JobState, SchedulerError> {
        let active = self.active_session(agent_id);
        let operation = active
            .as_ref()
            .map(|(_, _, _, operation)| Arc::clone(operation));
        let _guard = operation
            .as_ref()
            .map(|operation| operation.lock().unwrap());
        let decision = if close_session {
            self.inner.store.request_close(agent_id)?
        } else {
            self.inner.store.request_stop(agent_id)?
        };
        if !decision.needs_runtime_stop {
            return Ok(decision.state);
        }
        let Some((owner_epoch, runtime, session_id, operation)) = active else {
            return Ok(decision.state);
        };
        if owner_epoch != decision.owner_epoch {
            return Ok(decision.state);
        }
        let sink = {
            let state = self.inner.state.lock().unwrap();
            state
                .active
                .get(agent_id)
                .map(|active| Arc::clone(&active.sink))
        }
        .ok_or_else(|| SchedulerError::RuntimeCommand {
            agent_id: agent_id.into(),
            message: "active runtime disappeared".into(),
        })?;
        let _ = operation;
        if runtime.turn_snapshot().active {
            let _ = runtime.stop_turn(&session_id, self.inner.config.command_timeout);
        }
        let close_error = if close_session {
            runtime
                .close_session(&session_id, self.inner.config.command_timeout)
                .err()
        } else {
            None
        };
        let terminal = runtime.stop(self.inner.config.stop_grace);
        let terminal = self.review_terminal(agent_id, terminal, false);
        let result = if let Some(message) = sink.error() {
            let fallback = self.inner.store.fail_claim(
                agent_id,
                decision.owner_epoch,
                "LIFECYCLE_SINK_FAILED",
                &message,
            );
            self.record_failure(agent_id, message.clone());
            match fallback {
                Ok(_) => Err(SchedulerError::LifecycleSink {
                    agent_id: agent_id.into(),
                    message,
                }),
                Err(error) => {
                    self.record_failure(agent_id, error.to_string());
                    Err(SchedulerError::Store(error))
                }
            }
        } else {
            match sink.finish(&terminal) {
                Ok(state) => Ok(state),
                Err(error) => {
                    self.record_failure(agent_id, error.to_string());
                    match self.inner.store.fail_claim(
                        agent_id,
                        decision.owner_epoch,
                        "LIFECYCLE_SINK_FAILED",
                        &error.to_string(),
                    ) {
                        Ok(_) => Err(SchedulerError::LifecycleSink {
                            agent_id: agent_id.into(),
                            message: error.to_string(),
                        }),
                        Err(fallback) => {
                            self.record_failure(agent_id, fallback.to_string());
                            Err(SchedulerError::Store(fallback))
                        }
                    }
                }
            }
        };
        self.release_active(agent_id, decision.owner_epoch);
        if let Some(error) = close_error {
            self.record_failure(agent_id, error.to_string());
        }
        result
    }

    fn active_session(&self, agent_id: &str) -> Option<ActiveSession> {
        let state = self.inner.state.lock().unwrap();
        state.active.get(agent_id).map(|active| {
            (
                active.owner_epoch,
                Arc::clone(&active.runtime),
                active.session_id.clone(),
                Arc::clone(&active.operation),
            )
        })
    }

    pub fn reap_job(&self, agent_id: &str) -> Result<JobState, SchedulerError> {
        let state = self.close_job(agent_id)?;
        if !state.is_terminal() {
            return Ok(state);
        }
        Ok(self.inner.store.reap_job(agent_id)?)
    }

    pub fn active_count(&self) -> usize {
        self.inner.state.lock().unwrap().active.len()
    }

    pub fn last_error(&self, agent_id: &str) -> Option<String> {
        self.inner
            .state
            .lock()
            .unwrap()
            .failures
            .get(agent_id)
            .cloned()
    }

    pub fn shutdown_all(&self) {
        let agent_ids = self
            .inner
            .state
            .lock()
            .unwrap()
            .active
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for agent_id in agent_ids {
            if let Err(error) = self.close_job(&agent_id) {
                self.record_failure(&agent_id, error.to_string());
            }
        }
    }

    fn release_active(&self, agent_id: &str, owner_epoch: u64) {
        let mut state = self.inner.state.lock().unwrap();
        if state
            .active
            .get(agent_id)
            .is_some_and(|active| active.owner_epoch == owner_epoch)
        {
            state.active.remove(agent_id);
        }
    }

    fn record_failure(&self, agent_id: &str, message: String) {
        self.inner
            .state
            .lock()
            .unwrap()
            .failures
            .entry(agent_id.into())
            .or_insert(message);
    }
}

#[cfg(unix)]
pub struct Daemon {
    scheduler: Scheduler,
    shutdown_requested: Arc<AtomicBool>,
    shutdown_started: AtomicBool,
    claim_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    server: Mutex<Option<rpc::RpcServer>>,
    _singleton_lock: SingletonLock,
}

#[cfg(unix)]
struct SingletonLock {
    _file: std::fs::File,
}

#[cfg(unix)]
impl SingletonLock {
    fn acquire(database: &std::path::Path) -> io::Result<Self> {
        use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};

        let mut lock_name = database.as_os_str().to_os_string();
        lock_name.push(".lock");
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(std::path::PathBuf::from(lock_name))?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error
                .raw_os_error()
                .is_some_and(|code| code == libc::EWOULDBLOCK || code == libc::EAGAIN)
            {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "review database already has a lifecycle owner",
                ));
            }
            return Err(error);
        }
        Ok(Self { _file: file })
    }
}

#[cfg(unix)]
impl Daemon {
    pub fn start(
        socket: impl AsRef<std::path::Path>,
        scheduler: Scheduler,
        server_options: rpc::ServerOptions,
        claim_interval: Duration,
    ) -> io::Result<Self> {
        Self::start_with_shutdown(
            socket,
            scheduler,
            server_options,
            claim_interval,
            Arc::new(AtomicBool::new(false)),
        )
    }

    pub fn start_with_shutdown(
        socket: impl AsRef<std::path::Path>,
        scheduler: Scheduler,
        server_options: rpc::ServerOptions,
        claim_interval: Duration,
        shutdown_requested: Arc<AtomicBool>,
    ) -> io::Result<Self> {
        Self::start_inner(
            socket,
            scheduler,
            server_options,
            claim_interval,
            shutdown_requested,
            || {},
        )
    }

    fn start_inner<F>(
        socket: impl AsRef<std::path::Path>,
        scheduler: Scheduler,
        server_options: rpc::ServerOptions,
        claim_interval: Duration,
        shutdown_requested: Arc<AtomicBool>,
        before_reconcile: F,
    ) -> io::Result<Self>
    where
        F: FnOnce(),
    {
        if claim_interval.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "claim interval must be positive",
            ));
        }
        check_startup_shutdown(&shutdown_requested)?;
        let singleton_lock = SingletonLock::acquire(scheduler.store().database_path())?;
        check_startup_shutdown(&shutdown_requested)?;
        before_reconcile();
        check_startup_shutdown(&shutdown_requested)?;
        scheduler
            .reconcile_startup()
            .map_err(|error| io::Error::other(error.to_string()))?;
        check_startup_shutdown(&shutdown_requested)?;
        let service = Arc::new(
            rpc::RpcService::new(scheduler.clone(), scheduler.store())
                .map_err(|_| io::Error::other("scheduler store ownership mismatch"))?,
        );
        let server = rpc::RpcServer::bind(socket, service, server_options)?;
        if let Err(error) = check_startup_shutdown(&shutdown_requested) {
            server.shutdown();
            return Err(error);
        }
        let loop_shutdown = Arc::clone(&shutdown_requested);
        let loop_scheduler = scheduler.clone();
        let claim_thread = thread::spawn(move || {
            while !loop_shutdown.load(Ordering::Acquire) {
                if let Err(error) = loop_scheduler.start_ready() {
                    let _ = error;
                }
                thread::sleep(claim_interval);
            }
        });
        Ok(Self {
            scheduler,
            shutdown_requested,
            shutdown_started: AtomicBool::new(false),
            claim_thread: Mutex::new(Some(claim_thread)),
            server: Mutex::new(Some(server)),
            _singleton_lock: singleton_lock,
        })
    }

    pub fn shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::Release);
        if self.shutdown_started.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(server) = self.server.lock().unwrap().take() {
            server.shutdown();
        }
        if let Some(claim_thread) = self.claim_thread.lock().unwrap().take() {
            let _ = claim_thread.join();
        }
        self.scheduler.shutdown_all();
    }
}

#[cfg(unix)]
fn check_startup_shutdown(shutdown_requested: &AtomicBool) -> io::Result<()> {
    if shutdown_requested.load(Ordering::Acquire) {
        Err(io::Error::new(
            io::ErrorKind::Interrupted,
            "daemon shutdown requested during startup",
        ))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for Daemon {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use review_store::NewArtifact;
    use std::sync::Barrier;
    use zcode_protocol::{EventEnvelope, RequestEnvelope, ResponseEnvelope, WireId};

    #[derive(Default)]
    struct MemorySink {
        records: Mutex<Vec<LifecycleRecord>>,
        changed: Condvar,
    }

    impl LifecycleSink for MemorySink {
        fn emit(&self, record: LifecycleRecord) {
            self.records.lock().unwrap().push(record);
            self.changed.notify_all();
        }
    }

    impl MemorySink {
        fn wait_for<F>(&self, timeout: Duration, predicate: F) -> bool
        where
            F: Fn(&[LifecycleRecord]) -> bool,
        {
            let deadline = Instant::now() + timeout;
            let mut records = self.records.lock().unwrap();
            loop {
                if predicate(&records) {
                    return true;
                }
                let now = Instant::now();
                if now >= deadline {
                    return false;
                }
                let (next, wait) = self.changed.wait_timeout(records, deadline - now).unwrap();
                records = next;
                if wait.timed_out() && !predicate(&records) {
                    return false;
                }
            }
        }

        fn snapshot(&self) -> Vec<LifecycleRecord> {
            self.records.lock().unwrap().clone()
        }
    }

    #[derive(Default)]
    struct GatedSink {
        records: Mutex<Vec<LifecycleRecord>>,
        changed: Condvar,
        released_through: Mutex<u64>,
        released: Condvar,
    }

    impl LifecycleSink for GatedSink {
        fn emit(&self, record: LifecycleRecord) {
            let sequence = record.sequence;
            self.records.lock().unwrap().push(record);
            self.changed.notify_all();

            let mut released = self.released_through.lock().unwrap();
            while *released < sequence {
                released = self.released.wait(released).unwrap();
            }
        }
    }

    impl GatedSink {
        fn wait_for_len(&self, expected: usize, timeout: Duration) -> bool {
            let deadline = Instant::now() + timeout;
            let mut records = self.records.lock().unwrap();
            while records.len() < expected {
                let now = Instant::now();
                if now >= deadline {
                    return false;
                }
                let (next, wait) = self.changed.wait_timeout(records, deadline - now).unwrap();
                records = next;
                if wait.timed_out() && records.len() < expected {
                    return false;
                }
            }
            true
        }

        fn release_through(&self, sequence: u64) {
            *self.released_through.lock().unwrap() = sequence;
            self.released.notify_all();
        }

        fn snapshot(&self) -> Vec<LifecycleRecord> {
            self.records.lock().unwrap().clone()
        }
    }

    #[test]
    fn queued_driver_events_are_delivered_before_explicit_stop_terminal() {
        let sink = Arc::new(GatedSink::default());
        let publisher = Arc::new(Publisher::new(sink.clone()));
        assert_eq!(publisher.begin_stopping(), None);

        let pump_publisher = Arc::clone(&publisher);
        let pump = thread::spawn(move || {
            pump_publisher.emit_driver(Inbound::Malformed("queued-1".into()), None);
            pump_publisher.emit_driver(Inbound::Malformed("queued-2".into()), None);
            pump_publisher.emit_driver(
                Inbound::ChildExited(ChildExit::Exited(Some(0))),
                Some(RuntimeTerminal::Exited(ChildExit::Exited(Some(0)))),
            );
        });

        let terminal_publisher = Arc::clone(&publisher);
        let terminal = thread::spawn(move || {
            assert_eq!(terminal_publisher.wait_for_exit_boundary(), None);
            terminal_publisher.publish_terminal(RuntimeTerminal::Stopped(
                StopOutcome::AlreadyExited(ChildExit::Exited(Some(0))),
            ))
        });

        for sequence in 1..=3 {
            assert!(sink.wait_for_len(sequence as usize, Duration::from_secs(2)));
            assert!(sink
                .snapshot()
                .iter()
                .all(|record| matches!(record.event, RuntimeEvent::Driver(_))));
            sink.release_through(sequence);
        }

        assert!(sink.wait_for_len(4, Duration::from_secs(2)));
        let records = sink.snapshot();
        assert_eq!(
            records
                .iter()
                .map(|record| record.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert!(matches!(
            records.last().map(|record| &record.event),
            Some(RuntimeEvent::Terminal(RuntimeTerminal::Stopped(_)))
        ));
        sink.release_through(4);

        pump.join().unwrap();
        assert!(matches!(
            terminal.join().unwrap(),
            RuntimeTerminal::Stopped(_)
        ));
    }

    #[test]
    fn runtime_owner_drains_real_driver_backlog_before_stop_terminal() {
        let sink = Arc::new(GatedSink::default());
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "printf '%s\n' '{\"id\":1,\"result\":{}}' '{\"id\":2,\"result\":{}}' '{\"id\":3,\"result\":{}}'; trap '' TERM; exec tail -f /dev/null",
        ]);
        let owner = Arc::new(RuntimeOwner::spawn(command, sink.clone()).unwrap());
        assert!(sink.wait_for_len(1, Duration::from_secs(2)));

        let stop_owner = Arc::clone(&owner);
        let stop = thread::spawn(move || stop_owner.stop(Duration::from_millis(100)));

        for sequence in 1..=4 {
            assert!(sink.wait_for_len(sequence as usize, Duration::from_secs(2)));
            assert!(sink
                .snapshot()
                .iter()
                .all(|record| matches!(record.event, RuntimeEvent::Driver(_))));
            sink.release_through(sequence);
        }

        assert!(sink.wait_for_len(5, Duration::from_secs(2)));
        let records = sink.snapshot();
        assert_eq!(
            records
                .iter()
                .map(|record| record.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4, 5]
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| matches!(record.event, RuntimeEvent::Terminal(_)))
                .count(),
            1
        );
        assert!(matches!(
            records.last().map(|record| &record.event),
            Some(RuntimeEvent::Terminal(RuntimeTerminal::Stopped(_)))
        ));
        sink.release_through(5);
        assert!(matches!(stop.join().unwrap(), RuntimeTerminal::Stopped(_)));
    }

    #[test]
    fn partial_events_precede_one_concurrent_stop_terminal() {
        let sink = Arc::new(MemorySink::default());
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "printf '%s\\n' '{\"method\":\"session/event\",\"params\":{\"type\":\"turn.started\"}}'; trap '' TERM; exec tail -f /dev/null",
        ]);
        let owner = Arc::new(RuntimeOwner::spawn(command, sink.clone()).unwrap());
        assert!(sink.wait_for(Duration::from_secs(2), |records| {
            records
                .iter()
                .any(|record| matches!(record.event, RuntimeEvent::Driver(Inbound::Message(_))))
        }));

        let barrier = Arc::new(Barrier::new(3));
        let first_owner = Arc::clone(&owner);
        let first_barrier = Arc::clone(&barrier);
        let first = thread::spawn(move || {
            first_barrier.wait();
            first_owner.stop(Duration::from_millis(100))
        });
        let second_owner = Arc::clone(&owner);
        let second_barrier = Arc::clone(&barrier);
        let second = thread::spawn(move || {
            second_barrier.wait();
            second_owner.close(Duration::from_millis(100))
        });
        barrier.wait();
        let first = first.join().unwrap();
        let second = second.join().unwrap();
        assert_eq!(first, second);
        assert!(matches!(first, RuntimeTerminal::Stopped(_)));

        let records = sink.snapshot();
        assert!(records
            .windows(2)
            .all(|pair| pair[0].sequence < pair[1].sequence));
        assert_eq!(
            records
                .iter()
                .filter(|record| matches!(record.event, RuntimeEvent::Terminal(_)))
                .count(),
            1
        );
        assert!(matches!(
            records.last().map(|record| &record.event),
            Some(RuntimeEvent::Terminal(RuntimeTerminal::Stopped(_)))
        ));
    }

    #[test]
    fn spontaneous_exit_has_one_typed_terminal() {
        let sink = Arc::new(MemorySink::default());
        let mut command = Command::new("sh");
        command.args(["-c", "exit 7"]);
        let owner = RuntimeOwner::spawn(command, sink.clone()).unwrap();
        assert_eq!(
            owner.wait_terminal(Duration::from_secs(2)),
            Some(RuntimeTerminal::Exited(ChildExit::Exited(Some(7))))
        );
        assert_eq!(
            sink.snapshot()
                .iter()
                .filter(|record| matches!(record.event, RuntimeEvent::Terminal(_)))
                .count(),
            1
        );
    }

    #[test]
    fn exit_zero_during_active_turn_is_runtime_loss_without_completion_boundary() {
        let sink = Arc::new(MemorySink::default());
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "printf '%s\\n' '{\"method\":\"session/event\",\"params\":{\"type\":\"turn.started\"}}'",
        ]);
        let owner = RuntimeOwner::spawn(command, sink).unwrap();
        assert_eq!(
            owner.wait_terminal(Duration::from_secs(2)),
            Some(RuntimeTerminal::FailedRuntimeLost(
                RuntimeLoss::EventStreamLost
            ))
        );
    }

    #[test]
    fn exit_zero_after_observed_completion_boundary_is_successful() {
        let sink = Arc::new(MemorySink::default());
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "printf '%s\\n' '{\"method\":\"session/event\",\"params\":{\"type\":\"turn.started\"}}' '{\"method\":\"session/event\",\"params\":{\"type\":\"turn.completed\"}}'",
        ]);
        let owner = RuntimeOwner::spawn(command, sink).unwrap();
        assert!(matches!(
            owner.wait_terminal(Duration::from_secs(2)),
            Some(RuntimeTerminal::Completed(StopOutcome::AlreadyExited(
                ChildExit::Exited(Some(0))
            )))
        ));
    }

    #[test]
    fn spontaneous_leader_exit_with_stdout_descendant_is_bounded_and_fail_closed() {
        let pid_path = std::env::temp_dir().join(format!(
            "zcode-reviewd-stdout-descendant-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let sink = Arc::new(MemorySink::default());
        let mut command = Command::new("sh");
        command.env("DESCENDANT_PID_FILE", &pid_path).args([
            "-c",
            "sleep 3 & child=$!; printf '%s' \"$child\" > \"$DESCENDANT_PID_FILE\"; sleep 0.1; exit 7",
        ]);
        let owner = RuntimeOwner::spawn(command, sink.clone()).unwrap();
        let descendant = wait_for_pid_file(&pid_path);

        assert_eq!(
            owner.wait_terminal(Duration::from_secs(2)),
            Some(RuntimeTerminal::Orphaned(RuntimeLoss::UnknownMembership))
        );
        assert!(observe_process(descendant).is_ok());
        let records = sink.snapshot();
        assert_eq!(
            records
                .iter()
                .filter(|record| matches!(record.event, RuntimeEvent::Terminal(_)))
                .count(),
            1
        );
        assert!(matches!(
            records.last().map(|record| &record.event),
            Some(RuntimeEvent::Terminal(RuntimeTerminal::Orphaned(
                RuntimeLoss::UnknownMembership
            )))
        ));

        wait_for_process_exit(descendant);
        std::fs::remove_file(pid_path).unwrap();
    }

    fn wait_for_pid_file(path: &std::path::Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(contents) = std::fs::read_to_string(path) {
                if let Ok(pid) = contents.parse() {
                    return pid;
                }
            }
            assert!(
                Instant::now() < deadline,
                "descendant pid was not published"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_process_exit(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(4);
        while observe_process(pid).is_ok() {
            assert!(Instant::now() < deadline, "descendant did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn restart_classification_is_fail_closed() {
        let malformed = ProcessIdentity {
            pid: 42,
            pgid: 0,
            uid: 1,
            start_token: String::new(),
        };
        assert_eq!(
            classify_restart(&malformed),
            RuntimeTerminal::Orphaned(RuntimeLoss::InvalidIdentity)
        );

        let mut command = Command::new("sh");
        command.args(["-c", "trap '' TERM; exec tail -f /dev/null"]);
        let driver = Driver::spawn(command).unwrap();
        let identity = driver.identity();

        #[cfg(target_os = "macos")]
        assert_eq!(
            classify_restart(&identity),
            RuntimeTerminal::FailedRuntimeLost(RuntimeLoss::SessionLost)
        );
        #[cfg(not(target_os = "macos"))]
        assert_eq!(
            classify_restart(&identity),
            RuntimeTerminal::Orphaned(RuntimeLoss::UnsupportedIdentity)
        );

        let mut reused = identity.clone();
        reused.start_token.push_str(":reused");
        #[cfg(target_os = "macos")]
        assert_eq!(
            classify_restart(&reused),
            RuntimeTerminal::Orphaned(RuntimeLoss::IdentityMismatch)
        );

        driver.stop_and_reap(Duration::from_millis(100)).unwrap();
        #[cfg(target_os = "macos")]
        assert_eq!(
            classify_restart(&identity),
            RuntimeTerminal::Orphaned(RuntimeLoss::MissingLeader)
        );
    }

    struct FakeRuntime {
        sink: Arc<dyn LifecycleSink>,
        next_sequence: std::sync::atomic::AtomicU64,
        terminal: Mutex<Option<RuntimeTerminal>>,
        changed: Condvar,
        stop_calls: std::sync::atomic::AtomicUsize,
        turn: Mutex<TurnSnapshot>,
    }

    impl FakeRuntime {
        fn new(sink: Arc<dyn LifecycleSink>) -> Self {
            Self {
                sink,
                next_sequence: std::sync::atomic::AtomicU64::new(1),
                terminal: Mutex::new(None),
                changed: Condvar::new(),
                stop_calls: std::sync::atomic::AtomicUsize::new(0),
                turn: Mutex::new(TurnSnapshot {
                    generation: 0,
                    active: false,
                    boundary: None,
                }),
            }
        }

        fn emit_partial(&self, value: &str) {
            self.emit_event(RuntimeEvent::Driver(Inbound::Malformed(value.into())));
        }

        fn emit_event(&self, event: RuntimeEvent) {
            let sequence = self
                .next_sequence
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.sink.emit(LifecycleRecord { sequence, event });
        }

        fn finish(&self, requested: RuntimeTerminal) -> RuntimeTerminal {
            let mut terminal = self.terminal.lock().unwrap();
            if let Some(existing) = &*terminal {
                return existing.clone();
            }
            let sequence = self
                .next_sequence
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.sink.emit(LifecycleRecord {
                sequence,
                event: RuntimeEvent::Terminal(requested.clone()),
            });
            *terminal = Some(requested.clone());
            self.changed.notify_all();
            requested
        }

        fn stop_calls(&self) -> usize {
            self.stop_calls.load(std::sync::atomic::Ordering::Acquire)
        }
    }

    impl ManagedRuntime for FakeRuntime {
        fn identity(&self) -> Option<ProcessIdentity> {
            None
        }

        fn stop(&self, _grace: Duration) -> RuntimeTerminal {
            self.stop_calls
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.finish(RuntimeTerminal::Stopped(StopOutcome::AlreadyExited(
                ChildExit::Exited(Some(0)),
            )))
        }

        fn wait_terminal(&self, timeout: Duration) -> Option<RuntimeTerminal> {
            let terminal = self.terminal.lock().unwrap();
            if terminal.is_some() {
                return terminal.clone();
            }
            self.changed
                .wait_timeout(terminal, timeout)
                .unwrap()
                .0
                .clone()
        }

        fn bootstrap_session(
            &self,
            job: &Job,
            _timeout: Duration,
        ) -> Result<SessionReady, RuntimeCommandError> {
            *self.turn.lock().unwrap() = TurnSnapshot {
                generation: 1,
                active: true,
                boundary: None,
            };
            Ok(SessionReady {
                session_id: format!("session-{}", job.agent_id),
                initial_turn_id: Some("turn-1".into()),
                observed_model: None,
            })
        }

        fn send_turn(
            &self,
            _session_id: &str,
            _content: &str,
            _timeout: Duration,
        ) -> Result<Option<String>, RuntimeCommandError> {
            let mut turn = self.turn.lock().unwrap();
            turn.generation = turn.generation.saturating_add(1);
            turn.active = true;
            turn.boundary = None;
            Ok(Some(format!("turn-{}", turn.generation)))
        }

        fn stop_turn(
            &self,
            _session_id: &str,
            _timeout: Duration,
        ) -> Result<TurnSnapshot, RuntimeCommandError> {
            let mut turn = self.turn.lock().unwrap();
            turn.active = false;
            turn.boundary = Some(TurnBoundary::Completed);
            Ok(turn.clone())
        }

        fn respond_request(
            &self,
            _correlation_id: &str,
            _decision: &str,
            _content: Option<&str>,
        ) -> Result<(), RuntimeCommandError> {
            Ok(())
        }

        fn turn_snapshot(&self) -> TurnSnapshot {
            self.turn.lock().unwrap().clone()
        }
    }

    #[derive(Default)]
    struct FakeFactory {
        runtimes: Mutex<HashMap<String, Arc<FakeRuntime>>>,
        fail_for: Mutex<Vec<String>>,
    }

    impl FakeFactory {
        fn fail(&self, agent_id: &str) {
            self.fail_for.lock().unwrap().push(agent_id.into());
        }

        fn runtime(&self, agent_id: &str) -> Arc<FakeRuntime> {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                if let Some(runtime) = self.runtimes.lock().unwrap().get(agent_id).cloned() {
                    return runtime;
                }
                assert!(Instant::now() < deadline, "runtime was not spawned");
                thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl RuntimeFactory for FakeFactory {
        fn spawn(
            &self,
            job: &Job,
            sink: Arc<dyn LifecycleSink>,
        ) -> io::Result<Arc<dyn ManagedRuntime>> {
            if self
                .fail_for
                .lock()
                .unwrap()
                .iter()
                .any(|agent_id| agent_id == &job.agent_id)
            {
                return Err(io::Error::other("scripted spawn failure"));
            }
            let runtime = Arc::new(FakeRuntime::new(sink));
            self.runtimes
                .lock()
                .unwrap()
                .insert(job.agent_id.clone(), Arc::clone(&runtime));
            Ok(runtime)
        }
    }

    fn scheduler_fixture(
        global: usize,
        per_workspace: usize,
    ) -> (tempfile::TempDir, Arc<Store>, Arc<FakeFactory>, Scheduler) {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
        let factory = Arc::new(FakeFactory::default());
        let scheduler = Scheduler::new(
            "daemon-test",
            Arc::clone(&store),
            factory.clone(),
            SchedulerConfig {
                global_max_agents: global,
                per_workspace_max_agents: per_workspace,
                stop_grace: Duration::from_millis(25),
                command_timeout: Duration::from_secs(1),
            },
        )
        .unwrap();
        (directory, store, factory, scheduler)
    }

    fn wait_for_job_state(store: &Store, agent_id: &str, expected: JobState) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let state = store.get_job(agent_id).unwrap().unwrap().state;
            if state == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "job {agent_id} remained {state:?} instead of {expected:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn scheduler_persists_partial_events_and_releases_slots_fifo() {
        let (_directory, store, factory, scheduler) = scheduler_fixture(2, 1);
        scheduler
            .enqueue(&NewJob::new("job-1", "workspace-a"))
            .unwrap();
        scheduler
            .enqueue(&NewJob::new("job-2", "workspace-a"))
            .unwrap();
        scheduler
            .enqueue(&NewJob::new("job-3", "workspace-b"))
            .unwrap();
        assert_eq!(scheduler.start_ready().unwrap(), vec!["job-1", "job-3"]);
        assert_eq!(scheduler.active_count(), 2);

        let first = factory.runtime("job-1");
        first.emit_partial("partial-review");
        first.finish(RuntimeTerminal::Completed(StopOutcome::AlreadyExited(
            ChildExit::Exited(Some(0)),
        )));
        wait_for_job_state(&store, "job-1", JobState::Completed);
        let second = factory.runtime("job-2");
        assert_eq!(
            store.events_after("job-1", "job-1:1", 0, 10).unwrap().len(),
            2
        );
        assert_eq!(store.cursor("job-1", "job-1:1").unwrap(), 2);
        assert_eq!(scheduler.active_count(), 2);

        second.finish(RuntimeTerminal::Completed(StopOutcome::AlreadyExited(
            ChildExit::Exited(Some(0)),
        )));
        factory
            .runtime("job-3")
            .finish(RuntimeTerminal::Completed(StopOutcome::AlreadyExited(
                ChildExit::Exited(Some(0)),
            )));
        wait_for_job_state(&store, "job-2", JobState::Completed);
        wait_for_job_state(&store, "job-3", JobState::Completed);
        let deadline = Instant::now() + Duration::from_secs(2);
        while scheduler.active_count() != 0 {
            assert!(Instant::now() < deadline, "active slots were not released");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn spawn_failure_is_typed_durable_and_does_not_leak_a_slot() {
        let (_directory, store, factory, scheduler) = scheduler_fixture(1, 1);
        factory.fail("job-fail");
        scheduler
            .enqueue(&NewJob::new("job-fail", "workspace"))
            .unwrap();
        assert!(matches!(
            scheduler.start_ready(),
            Err(SchedulerError::RuntimeSpawn { .. })
        ));
        let job = store.get_job("job-fail").unwrap().unwrap();
        assert_eq!(job.state, JobState::FailedRuntimeLost);
        assert_eq!(job.failure_code.as_deref(), Some("RUNTIME_SPAWN_FAILED"));
        assert_eq!(scheduler.active_count(), 0);
        assert_eq!(store.active_count().unwrap(), 0);
    }

    #[test]
    fn lifecycle_sink_failure_stops_runtime_and_records_durable_failure() {
        let (directory, store, factory, scheduler) = scheduler_fixture(1, 1);
        scheduler
            .enqueue(&NewJob::new("job-sink-fail", "workspace"))
            .unwrap();
        scheduler.start_ready().unwrap();
        let runtime = factory.runtime("job-sink-fail");
        let raw = rusqlite::Connection::open(directory.path().join("review.sqlite3")).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER fail_lifecycle_events BEFORE INSERT ON events
             BEGIN SELECT RAISE(FAIL, 'scripted event write failure'); END;",
        )
        .unwrap();

        runtime.emit_partial("cannot-persist");
        wait_for_job_state(&store, "job-sink-fail", JobState::FailedRuntimeLost);
        let job = store.get_job("job-sink-fail").unwrap().unwrap();
        assert_eq!(job.failure_code.as_deref(), Some("LIFECYCLE_SINK_FAILED"));
        assert!(runtime.stop_calls() >= 1);
        assert!(scheduler.last_error("job-sink-fail").is_some());
        let deadline = Instant::now() + Duration::from_secs(2);
        while scheduler.active_count() != 0 {
            assert!(
                Instant::now() < deadline,
                "failed sink leaked an active slot"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn post_registration_read_failure_stops_runtime_terminalizes_and_releases_slot() {
        let (directory, store, factory, scheduler) = scheduler_fixture(1, 1);
        scheduler
            .enqueue(&NewJob::new("job-read-fault", "workspace"))
            .unwrap();
        let raw = rusqlite::Connection::open(directory.path().join("review.sqlite3")).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER corrupt_running_turn_state AFTER UPDATE OF state ON agents
             WHEN NEW.agent_id = 'job-read-fault' AND NEW.state = 'RUNNING'
             BEGIN
                 UPDATE agents SET turn_state = 'BROKEN' WHERE agent_id = NEW.agent_id;
             END;",
        )
        .unwrap();

        assert!(matches!(
            scheduler.start_ready(),
            Err(SchedulerError::Store(_))
        ));
        let runtime = factory.runtime("job-read-fault");
        assert!(runtime.stop_calls() >= 1);
        assert_eq!(scheduler.active_count(), 0);
        assert_eq!(store.active_count().unwrap(), 0);
        let job = store.get_job("job-read-fault").unwrap().unwrap();
        assert_eq!(job.state, JobState::FailedRuntimeLost);
        assert_eq!(
            job.failure_code.as_deref(),
            Some("POST_REGISTRATION_READ_FAILED")
        );
    }

    #[test]
    fn terminal_write_failure_falls_back_and_releases_exact_active_epoch() {
        let (directory, store, factory, scheduler) = scheduler_fixture(1, 1);
        scheduler
            .enqueue(&NewJob::new("job-terminal-fault", "workspace"))
            .unwrap();
        scheduler.start_ready().unwrap();
        let runtime = factory.runtime("job-terminal-fault");
        let raw = rusqlite::Connection::open(directory.path().join("review.sqlite3")).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER reject_success_terminal_ledger BEFORE INSERT ON lifecycle_ledger
             WHEN NEW.agent_id = 'job-terminal-fault' AND NEW.reason_code IS NULL
             BEGIN SELECT RAISE(FAIL, 'scripted terminal write failure'); END;",
        )
        .unwrap();

        assert!(scheduler.stop_job("job-terminal-fault").is_err());
        assert!(runtime.stop_calls() >= 1);
        let deadline = Instant::now() + Duration::from_secs(2);
        while scheduler.active_count() != 0 {
            assert!(
                Instant::now() < deadline,
                "terminal fault leaked active epoch"
            );
            thread::sleep(Duration::from_millis(5));
        }
        let job = store.get_job("job-terminal-fault").unwrap().unwrap();
        assert_eq!(job.state, JobState::FailedRuntimeLost);
        assert_eq!(job.failure_code.as_deref(), Some("LIFECYCLE_SINK_FAILED"));
    }

    #[test]
    fn responded_request_replay_remains_idempotent_after_job_terminal() {
        let (_directory, store, _factory, scheduler) = scheduler_fixture(1, 1);
        scheduler
            .enqueue(&NewJob::new("responded-job", "workspace"))
            .unwrap();
        let claim = store.claim_next("manual-owner", 1, 1).unwrap().unwrap();
        store
            .mark_session_running(
                "responded-job",
                claim.owner_epoch,
                "runtime",
                None,
                None,
                None,
            )
            .unwrap();
        store
            .insert_pending_request(
                "request-1",
                "responded-job",
                "\"server-1\"",
                "permission",
                "{}",
            )
            .unwrap();
        assert_eq!(
            store
                .claim_pending_response("responded-job", "request-1", "allow", None)
                .unwrap(),
            DeliveryClaim::Claimed
        );
        assert!(store
            .complete_pending_response("responded-job", "request-1")
            .unwrap());
        store
            .transition_terminal(
                "responded-job",
                claim.owner_epoch,
                &TerminalUpdate {
                    state: JobState::Completed,
                    failure_code: None,
                    failure_message: None,
                },
            )
            .unwrap();

        assert_eq!(
            scheduler
                .respond_job("responded-job", "request-1", "allow", None)
                .unwrap(),
            ResponseDisposition::AlreadyResponded
        );
    }

    #[test]
    fn transient_lifecycle_failure_cannot_be_overwritten_by_success_terminal() {
        let (directory, store, factory, scheduler) = scheduler_fixture(1, 1);
        scheduler
            .enqueue(&NewJob::new("job-transient-sink-fail", "workspace"))
            .unwrap();
        scheduler.start_ready().unwrap();
        let runtime = factory.runtime("job-transient-sink-fail");
        let raw = rusqlite::Connection::open(directory.path().join("review.sqlite3")).unwrap();
        raw.execute_batch(
            "CREATE TRIGGER fail_one_event_type BEFORE INSERT ON events
             WHEN NEW.event_type = 'driver.malformed'
             BEGIN SELECT RAISE(FAIL, 'scripted transient event failure'); END;",
        )
        .unwrap();

        runtime.emit_event(RuntimeEvent::Driver(Inbound::OversizedLine { bytes: 17 }));
        runtime.emit_partial("this record is rejected");
        runtime.finish(RuntimeTerminal::Exited(ChildExit::Exited(Some(0))));

        wait_for_job_state(
            &store,
            "job-transient-sink-fail",
            JobState::FailedRuntimeLost,
        );
        let job = store.get_job("job-transient-sink-fail").unwrap().unwrap();
        assert_eq!(job.failure_code.as_deref(), Some("LIFECYCLE_SINK_FAILED"));
        assert_ne!(job.state, JobState::Completed);
        let events = store
            .events_after(
                "job-transient-sink-fail",
                "job-transient-sink-fail:1",
                0,
                10,
            )
            .unwrap();
        assert_eq!(events.len(), 1, "the committed partial event is retained");
        assert_eq!(events[0].event_type, "driver.oversized_line");
        assert_eq!(
            store
                .cursor("job-transient-sink-fail", "job-transient-sink-fail:1")
                .unwrap(),
            1
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while scheduler.active_count() != 0 {
            assert!(
                Instant::now() < deadline,
                "failed sink leaked an active slot"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(store.active_count().unwrap(), 0);
    }

    #[test]
    fn store_sink_persists_only_allowlisted_or_redacted_lifecycle_fields() {
        const REASONING: &str = "SENTINEL_PRIVATE_REASONING";
        const TOKEN: &str = "SENTINEL_SECRET_TOKEN";
        const PATH: &str = "/private/SENTINEL_PATH";
        const TOOL_ARGS: &str = "SENTINEL_TOOL_ARGUMENTS";

        let (_directory, store, factory, scheduler) = scheduler_fixture(1, 1);
        scheduler
            .enqueue(&NewJob::new("job-redaction", "workspace"))
            .unwrap();
        scheduler.start_ready().unwrap();
        let runtime = factory.runtime("job-redaction");
        runtime.emit_event(RuntimeEvent::Driver(Inbound::Message(
            WireMessage::Request(RequestEnvelope {
                id: WireId::String(TOKEN.into()),
                method: "tool/call".into(),
                params: serde_json::json!({"path": PATH, "arguments": TOOL_ARGS}),
            }),
        )));
        runtime.emit_event(RuntimeEvent::Driver(Inbound::Message(
            WireMessage::Response(ResponseEnvelope {
                id: WireId::String(TOKEN.into()),
                result: Some(serde_json::json!({"reasoning": REASONING, "path": PATH})),
                error: None,
            }),
        )));
        runtime.emit_event(RuntimeEvent::Driver(Inbound::Message(WireMessage::Event(
            EventEnvelope {
                method: "session/event".into(),
                params: serde_json::json!({
                    "type": "turn.completed",
                    "reasoning": REASONING,
                    "token": TOKEN
                }),
            },
        ))));
        runtime.emit_event(RuntimeEvent::Driver(Inbound::Message(
            WireMessage::UnknownEvent {
                method: "future/event".into(),
                raw: serde_json::json!({
                    "method": "future/event",
                    "reasoning": REASONING,
                    "token": TOKEN,
                    "path": PATH,
                    "tool_args": TOOL_ARGS,
                }),
            },
        )));
        runtime.finish(RuntimeTerminal::FailedRuntimeLost(RuntimeLoss::StopFailed(
            format!("runtime failed at {PATH} with {TOKEN}"),
        )));

        wait_for_job_state(&store, "job-redaction", JobState::FailedRuntimeLost);
        let events = store
            .events_after("job-redaction", "job-redaction:1", 0, 10)
            .unwrap();
        assert_eq!(events.len(), 5);
        assert_eq!(events[3].event_type, "raw.unknown");
        assert_eq!(events[3].redaction_level, "redacted");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&events[3].payload_json).unwrap(),
            serde_json::json!({"kind": "unknown_event", "raw": "[REDACTED]"})
        );
        assert_eq!(events[4].redaction_level, "redacted");
        for event in &events {
            assert!(["redacted", "allowlisted"].contains(&event.redaction_level.as_str()));
            for sentinel in [REASONING, TOKEN, PATH, TOOL_ARGS] {
                assert!(
                    !event.payload_json.contains(sentinel),
                    "durable payload leaked {sentinel}: {}",
                    event.payload_json
                );
            }
        }
        let job = store.get_job("job-redaction").unwrap().unwrap();
        assert_eq!(job.failure_message.as_deref(), Some("stop_failed"));
        assert!(!job.failure_message.unwrap().contains(TOKEN));
    }

    #[test]
    fn concurrent_close_and_reap_converge_and_retain_durable_rows() {
        let (_directory, store, factory, scheduler) = scheduler_fixture(1, 1);
        scheduler
            .enqueue(&NewJob::new("job-close", "workspace"))
            .unwrap();
        store
            .insert_artifact(&NewArtifact {
                artifact_id: "artifact".into(),
                agent_id: "job-close".into(),
                artifact_type: "report".into(),
                path: "/report".into(),
                sha256: "sha".into(),
                bytes: 10,
                checkpoint_number: None,
            })
            .unwrap();
        scheduler.start_ready().unwrap();
        let runtime = factory.runtime("job-close");
        runtime.emit_partial("partial");

        let barrier = Arc::new(Barrier::new(5));
        let mut workers = Vec::new();
        for _ in 0..4 {
            let scheduler = scheduler.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                scheduler.close_job("job-close")
            }));
        }
        barrier.wait();
        for worker in workers {
            assert_eq!(worker.join().unwrap().unwrap(), JobState::Cancelled);
        }
        assert!(runtime.stop_calls() >= 1);
        assert_eq!(
            scheduler.reap_job("job-close").unwrap(),
            JobState::Cancelled
        );
        assert_eq!(
            scheduler.reap_job("job-close").unwrap(),
            JobState::Cancelled
        );
        assert_eq!(store.artifact_count("job-close").unwrap(), 1);
        assert_eq!(
            store
                .events_after("job-close", "job-close:1", 0, 10)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            store.get_job("job-close").unwrap().unwrap().state,
            JobState::Cancelled
        );
        assert_eq!(scheduler.active_count(), 0);
    }

    #[test]
    fn session_bootstrap_failure_cannot_be_reclassified_as_completion() {
        struct BootstrapFailure {
            inner: FakeRuntime,
        }

        impl ManagedRuntime for BootstrapFailure {
            fn identity(&self) -> Option<ProcessIdentity> {
                None
            }

            fn stop(&self, grace: Duration) -> RuntimeTerminal {
                self.inner.stop(grace)
            }

            fn wait_terminal(&self, timeout: Duration) -> Option<RuntimeTerminal> {
                self.inner.wait_terminal(timeout)
            }

            fn bootstrap_session(
                &self,
                _job: &Job,
                _timeout: Duration,
            ) -> Result<SessionReady, RuntimeCommandError> {
                Err(RuntimeCommandError::InvalidSession(
                    "scripted invalid session".into(),
                ))
            }
        }

        struct BootstrapFailureFactory;

        impl RuntimeFactory for BootstrapFailureFactory {
            fn spawn(
                &self,
                _job: &Job,
                sink: Arc<dyn LifecycleSink>,
            ) -> io::Result<Arc<dyn ManagedRuntime>> {
                Ok(Arc::new(BootstrapFailure {
                    inner: FakeRuntime::new(sink),
                }))
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(directory.path().join("bootstrap.sqlite3")).unwrap());
        let scheduler = Scheduler::new(
            "bootstrap-failure",
            Arc::clone(&store),
            Arc::new(BootstrapFailureFactory),
            SchedulerConfig::default(),
        )
        .unwrap();
        scheduler
            .enqueue(&NewJob::new("bootstrap-job", "/workspace"))
            .unwrap();
        assert!(matches!(
            scheduler.start_ready(),
            Err(SchedulerError::RuntimeCommand { .. })
        ));
        let job = store.get_job("bootstrap-job").unwrap().unwrap();
        assert_eq!(job.state, JobState::FailedRuntimeLost);
        assert_eq!(job.failure_code.as_deref(), Some("SESSION_START_FAILED"));
        assert_eq!(scheduler.active_count(), 0);
        assert_eq!(store.active_count().unwrap(), 0);
    }

    #[test]
    fn concurrent_enqueue_start_and_close_has_no_slot_or_terminal_leak() {
        let (_directory, store, _factory, scheduler) = scheduler_fixture(3, 1);
        let enqueue_barrier = Arc::new(Barrier::new(13));
        let mut enqueuers = Vec::new();
        for index in 0..12 {
            let scheduler = scheduler.clone();
            let barrier = Arc::clone(&enqueue_barrier);
            enqueuers.push(thread::spawn(move || {
                barrier.wait();
                scheduler.enqueue(&NewJob::new(
                    format!("concurrent-{index}"),
                    format!("workspace-{}", index % 4),
                ))
            }));
        }
        enqueue_barrier.wait();
        for worker in enqueuers {
            worker.join().unwrap().unwrap();
        }

        let start_barrier = Arc::new(Barrier::new(5));
        let mut starters = Vec::new();
        for _ in 0..4 {
            let scheduler = scheduler.clone();
            let barrier = Arc::clone(&start_barrier);
            starters.push(thread::spawn(move || {
                barrier.wait();
                scheduler.start_ready()
            }));
        }
        start_barrier.wait();
        for worker in starters {
            worker.join().unwrap().unwrap();
        }
        assert_eq!(scheduler.active_count(), 3);
        assert_eq!(store.active_count().unwrap(), 3);

        let close_barrier = Arc::new(Barrier::new(13));
        let mut closers = Vec::new();
        for index in 0..12 {
            let scheduler = scheduler.clone();
            let barrier = Arc::clone(&close_barrier);
            closers.push(thread::spawn(move || {
                barrier.wait();
                scheduler.close_job(&format!("concurrent-{index}"))
            }));
        }
        close_barrier.wait();
        for worker in closers {
            worker.join().unwrap().unwrap();
        }
        for index in 0..12 {
            wait_for_job_state(&store, &format!("concurrent-{index}"), JobState::Cancelled);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while scheduler.active_count() != 0 || store.active_count().unwrap() != 0 {
            assert!(Instant::now() < deadline, "concurrent close leaked a slot");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn scheduler_restart_reconciliation_never_spawns_or_signals() {
        let (directory, store, _factory, scheduler) = scheduler_fixture(2, 2);
        scheduler.enqueue(&NewJob::new("queued", "a")).unwrap();
        scheduler.enqueue(&NewJob::new("starting", "b")).unwrap();
        store.claim_next("dead-daemon", 1, 1).unwrap().unwrap();
        drop(scheduler);
        drop(store);

        let reopened = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
        let factory = Arc::new(FakeFactory::default());
        let scheduler = Scheduler::new(
            "new-daemon",
            Arc::clone(&reopened),
            factory.clone(),
            SchedulerConfig::default(),
        )
        .unwrap();
        assert_eq!(scheduler.reconcile_startup().unwrap().len(), 1);
        assert_eq!(factory.runtimes.lock().unwrap().len(), 0);
        assert_eq!(
            reopened.get_job("queued").unwrap().unwrap().state,
            JobState::FailedRuntimeLost
        );
        assert_eq!(
            reopened.get_job("starting").unwrap().unwrap().state,
            JobState::Queued
        );
    }

    #[cfg(unix)]
    #[test]
    fn daemon_does_not_publish_socket_or_start_runtime_before_reconciliation() {
        let (directory, store, factory, scheduler) = scheduler_fixture(1, 1);
        scheduler
            .enqueue(&NewJob::new("recovering-job", "workspace"))
            .unwrap();
        let claim = store.claim_next("old-owner", 1, 1).unwrap().unwrap();
        store
            .mark_session_running(
                "recovering-job",
                claim.owner_epoch,
                "old-runtime",
                None,
                None,
                None,
            )
            .unwrap();
        let socket = directory.path().join("gated").join("review.sock");
        let thread_socket = socket.clone();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let thread_entered = Arc::clone(&entered);
        let thread_release = Arc::clone(&release);
        let start_scheduler = scheduler.clone();
        let starter = thread::spawn(move || {
            Daemon::start_inner(
                thread_socket,
                start_scheduler,
                rpc::ServerOptions::default(),
                Duration::from_millis(20),
                Arc::new(AtomicBool::new(false)),
                || {
                    thread_entered.wait();
                    thread_release.wait();
                },
            )
        });

        entered.wait();
        assert!(
            !socket.exists(),
            "socket became ready before reconciliation"
        );
        assert!(std::os::unix::net::UnixStream::connect(&socket).is_err());
        assert!(factory.runtimes.lock().unwrap().is_empty());
        assert_eq!(scheduler.active_count(), 0);
        release.wait();

        let daemon = starter.join().unwrap().unwrap();
        assert_eq!(
            store.get_job("recovering-job").unwrap().unwrap().state,
            JobState::FailedRuntimeLost
        );
        daemon.shutdown();
    }

    #[cfg(unix)]
    #[test]
    fn daemon_startup_honors_shutdown_request_before_reconcile_or_publication() {
        let (directory, store, factory, scheduler) = scheduler_fixture(1, 1);
        scheduler
            .enqueue(&NewJob::new("startup-stop-job", "workspace"))
            .unwrap();
        let socket = directory.path().join("stopped").join("review.sock");
        let shutdown_requested = Arc::new(AtomicBool::new(false));
        let request = Arc::clone(&shutdown_requested);

        let error = Daemon::start_inner(
            &socket,
            scheduler.clone(),
            rpc::ServerOptions::default(),
            Duration::from_millis(20),
            shutdown_requested,
            move || request.store(true, Ordering::Release),
        )
        .err()
        .expect("shutdown request must stop daemon startup");

        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(!socket.exists());
        assert!(factory.runtimes.lock().unwrap().is_empty());
        assert_eq!(scheduler.active_count(), 0);
        assert_eq!(store.active_count().unwrap(), 0);
        assert_eq!(
            store.get_job("startup-stop-job").unwrap().unwrap().state,
            JobState::Queued
        );
    }

    #[test]
    fn close_during_bootstrap_cannot_leave_stopping_runtime_or_slot() {
        struct GatedRuntime {
            inner: FakeRuntime,
            entered: Arc<Barrier>,
            release: Arc<Barrier>,
        }

        impl ManagedRuntime for GatedRuntime {
            fn identity(&self) -> Option<ProcessIdentity> {
                None
            }

            fn stop(&self, grace: Duration) -> RuntimeTerminal {
                self.inner.stop(grace)
            }

            fn wait_terminal(&self, timeout: Duration) -> Option<RuntimeTerminal> {
                self.inner.wait_terminal(timeout)
            }

            fn bootstrap_session(
                &self,
                job: &Job,
                timeout: Duration,
            ) -> Result<SessionReady, RuntimeCommandError> {
                self.entered.wait();
                self.release.wait();
                self.inner.bootstrap_session(job, timeout)
            }

            fn turn_snapshot(&self) -> TurnSnapshot {
                self.inner.turn_snapshot()
            }
        }

        struct GatedFactory {
            entered: Arc<Barrier>,
            release: Arc<Barrier>,
        }

        impl RuntimeFactory for GatedFactory {
            fn spawn(
                &self,
                _job: &Job,
                sink: Arc<dyn LifecycleSink>,
            ) -> io::Result<Arc<dyn ManagedRuntime>> {
                Ok(Arc::new(GatedRuntime {
                    inner: FakeRuntime::new(sink),
                    entered: Arc::clone(&self.entered),
                    release: Arc::clone(&self.release),
                }))
            }
        }

        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(Store::open(directory.path().join("race.sqlite3")).unwrap());
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let scheduler = Scheduler::new(
            "race-owner",
            Arc::clone(&store),
            Arc::new(GatedFactory {
                entered: Arc::clone(&entered),
                release: Arc::clone(&release),
            }),
            SchedulerConfig::default(),
        )
        .unwrap();
        scheduler
            .enqueue(&NewJob::new("race-job", "/workspace"))
            .unwrap();
        let starter = {
            let scheduler = scheduler.clone();
            thread::spawn(move || scheduler.start_ready())
        };
        entered.wait();
        assert_eq!(scheduler.close_job("race-job").unwrap(), JobState::Stopping);
        assert_eq!(store.active_count().unwrap(), 1);
        assert_eq!(scheduler.active_count(), 0);
        release.wait();
        assert!(starter.join().unwrap().unwrap().is_empty());
        wait_for_job_state(&store, "race-job", JobState::Cancelled);
        assert_eq!(scheduler.active_count(), 0);
        assert_eq!(store.active_count().unwrap(), 0);
        let job = store.get_job("race-job").unwrap().unwrap();
        assert!(job.close_requested);
        assert!(job.closed_at.is_some());
    }

    #[test]
    fn stop_cancel_is_durable_before_distinct_close_and_reap() {
        let (_directory, store, _factory, scheduler) = scheduler_fixture(1, 1);
        scheduler
            .enqueue(&NewJob::new("stop-close-job", "/workspace"))
            .unwrap();
        scheduler.start_ready().unwrap();
        assert_eq!(
            scheduler.stop_job("stop-close-job").unwrap(),
            JobState::Cancelled
        );
        let stopped = store.get_job("stop-close-job").unwrap().unwrap();
        assert!(stopped.stop_requested);
        assert_eq!(stopped.closed_at, None);
        assert_eq!(stopped.reaped_at, None);
        assert_eq!(
            scheduler.close_job("stop-close-job").unwrap(),
            JobState::Cancelled
        );
        let closed = store.get_job("stop-close-job").unwrap().unwrap();
        assert!(closed.closed_at.is_some());
        assert_eq!(closed.reaped_at, None);
        assert_eq!(
            scheduler.reap_job("stop-close-job").unwrap(),
            JobState::Cancelled
        );
        assert!(store
            .get_job("stop-close-job")
            .unwrap()
            .unwrap()
            .reaped_at
            .is_some());
    }
}
