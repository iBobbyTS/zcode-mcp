use review_store::{
    Job, JobClaim, JobState, LifecycleWrite, NewJob, Store, StoreError, StoredProcessIdentity,
    TerminalUpdate,
};
use std::{
    collections::HashMap,
    fmt, io,
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
    StopOutcome,
};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeTerminal {
    Stopped(StopOutcome),
    Exited(ChildExit),
    FailedRuntimeLost(RuntimeLoss),
    Orphaned(RuntimeLoss),
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
}

impl RuntimeOwner {
    pub fn spawn(command: Command, sink: Arc<dyn LifecycleSink>) -> io::Result<Self> {
        let driver = Arc::new(Driver::spawn(command)?);
        let publisher = Arc::new(Publisher::new(sink));
        let shutdown_pump = Arc::new(AtomicBool::new(false));
        spawn_event_pump(
            Arc::clone(&driver),
            Arc::clone(&publisher),
            Arc::clone(&shutdown_pump),
        );
        Ok(Self {
            driver,
            publisher,
            shutdown_pump,
        })
    }

    pub fn send_request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> io::Result<serde_json::Value> {
        self.driver.send_request(method, params)
    }

    pub fn identity(&self) -> ProcessIdentity {
        self.driver.identity()
    }

    pub fn stop(&self, grace: Duration) -> RuntimeTerminal {
        if let Some(terminal) = self.publisher.begin_stopping() {
            return terminal;
        }
        let terminal = match self.driver.stop_and_reap(grace) {
            Ok(outcome) => match self.publisher.wait_for_exit_boundary() {
                Some(terminal) => terminal,
                None => RuntimeTerminal::Stopped(outcome),
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

impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        let _ = self.stop(Duration::from_secs(1));
        self.shutdown_pump.store(true, Ordering::Release);
    }
}

fn spawn_event_pump(driver: Arc<Driver>, publisher: Arc<Publisher>, shutdown: Arc<AtomicBool>) {
    thread::spawn(move || loop {
        if shutdown.load(Ordering::Acquire) {
            return;
        }
        match driver.recv_timeout(Duration::from_millis(20)) {
            Ok(event) => {
                let is_exit_boundary = matches!(event, Inbound::ChildExited(_));
                let terminal = match &event {
                    Inbound::ChildExited(exit) => {
                        match observe_process_group(driver.identity().pgid) {
                            Ok(members) if members.is_empty() => {
                                Some(RuntimeTerminal::Exited(exit.clone()))
                            }
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
}

pub trait RuntimeFactory: Send + Sync + 'static {
    fn spawn(&self, job: &Job, sink: Arc<dyn LifecycleSink>)
        -> io::Result<Arc<dyn ManagedRuntime>>;
}

pub struct CommandRuntimeFactory<F> {
    command: F,
}

impl<F> CommandRuntimeFactory<F> {
    pub fn new(command: F) -> Self {
        Self { command }
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
        let command = (self.command)(job)?;
        Ok(Arc::new(RuntimeOwner::spawn(command, sink)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulerConfig {
    pub global_max_agents: usize,
    pub per_workspace_max_agents: usize,
    pub stop_grace: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            global_max_agents: 2,
            per_workspace_max_agents: 1,
            stop_grace: Duration::from_secs(1),
        }
    }
}

#[derive(Debug)]
pub enum SchedulerError {
    Store(StoreError),
    InvalidConfig(String),
    RuntimeSpawn { agent_id: String, message: String },
    LifecycleSink { agent_id: String, message: String },
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
}

struct StoreLifecycleSink {
    store: Arc<Store>,
    agent_id: String,
    runtime_agent_id: String,
    owner_epoch: u64,
    last_error: Mutex<Option<String>>,
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
            last_error: Mutex::new(None),
        }
    }

    fn finish(&self, terminal: &RuntimeTerminal) -> Result<JobState, StoreError> {
        self.store
            .transition_terminal(&self.agent_id, self.owner_epoch, &terminal_update(terminal))
    }

    fn error(&self) -> Option<String> {
        self.last_error.lock().unwrap().clone()
    }

    fn record_error(&self, error: &StoreError) {
        let mut last = self.last_error.lock().unwrap();
        if last.is_none() {
            *last = Some(error.to_string());
        }
    }
}

impl LifecycleSink for StoreLifecycleSink {
    fn emit(&self, record: LifecycleRecord) {
        let event_type = match &record.event {
            RuntimeEvent::Driver(Inbound::Message(_)) => "driver.message",
            RuntimeEvent::Driver(Inbound::Lifecycle { .. }) => "driver.lifecycle",
            RuntimeEvent::Driver(Inbound::Malformed(_)) => "driver.malformed",
            RuntimeEvent::Driver(Inbound::OversizedLine { .. }) => "driver.oversized_line",
            RuntimeEvent::Driver(Inbound::ChildExited(_)) => "driver.child_exited",
            RuntimeEvent::Terminal(RuntimeTerminal::Stopped(_)) => "runtime.stopped",
            RuntimeEvent::Terminal(RuntimeTerminal::Exited(_)) => "runtime.exited",
            RuntimeEvent::Terminal(RuntimeTerminal::FailedRuntimeLost(_)) => {
                "runtime.failed_runtime_lost"
            }
            RuntimeEvent::Terminal(RuntimeTerminal::Orphaned(_)) => "runtime.orphaned",
        };
        let terminal = match &record.event {
            RuntimeEvent::Terminal(terminal) => Some(terminal_update(terminal)),
            _ => None,
        };
        let write = LifecycleWrite {
            agent_id: self.agent_id.clone(),
            runtime_agent_id: self.runtime_agent_id.clone(),
            owner_epoch: self.owner_epoch,
            source_sequence: record.sequence,
            event_type: event_type.into(),
            turn_id: None,
            payload_json: serde_json::json!({"debug": format!("{:?}", record.event)}).to_string(),
            redaction_level: "safe".into(),
            terminal,
        };
        if let Err(error) = self.store.append_lifecycle(&write) {
            self.record_error(&error);
        }
    }
}

fn terminal_update(terminal: &RuntimeTerminal) -> TerminalUpdate {
    match terminal {
        RuntimeTerminal::Stopped(_) => TerminalUpdate {
            state: JobState::Completed,
            failure_code: None,
            failure_message: None,
        },
        RuntimeTerminal::Exited(ChildExit::Exited(Some(0))) => TerminalUpdate {
            state: JobState::Completed,
            failure_code: None,
            failure_message: None,
        },
        RuntimeTerminal::Exited(exit) => TerminalUpdate {
            state: JobState::FailedRuntimeLost,
            failure_code: Some("RUNTIME_EXITED".into()),
            failure_message: Some(format!("{exit:?}")),
        },
        RuntimeTerminal::FailedRuntimeLost(loss) => TerminalUpdate {
            state: JobState::FailedRuntimeLost,
            failure_code: Some("FAILED_RUNTIME_LOST".into()),
            failure_message: Some(format!("{loss:?}")),
        },
        RuntimeTerminal::Orphaned(loss) => TerminalUpdate {
            state: JobState::Orphaned,
            failure_code: Some("ORPHANED".into()),
            failure_message: Some(format!("{loss:?}")),
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
        if config.global_max_agents == 0 || config.per_workspace_max_agents == 0 {
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
                state: Mutex::new(SchedulerState::default()),
            }),
        })
    }

    pub fn enqueue(&self, job: &NewJob) -> Result<Job, SchedulerError> {
        Ok(self.inner.store.enqueue_job(job)?)
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

    fn start_claim(&self, claim: JobClaim) -> Result<bool, SchedulerError> {
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
        let identity = runtime.identity().map(|identity| StoredProcessIdentity {
            pid: identity.pid,
            process_group_id: identity.pgid,
            uid: identity.uid,
            start_token: identity.start_token,
        });
        let marked = match self.inner.store.mark_running(
            &claim.job.agent_id,
            claim.owner_epoch,
            &runtime_agent_id,
            identity.as_ref(),
        ) {
            Ok(marked) => marked,
            Err(error) => {
                let _ = runtime.stop(self.inner.config.stop_grace);
                if let Err(failure_error) = self.inner.store.fail_claim(
                    &claim.job.agent_id,
                    claim.owner_epoch,
                    "STORE_START_FAILED",
                    &error.to_string(),
                ) {
                    self.record_failure(&claim.job.agent_id, failure_error.to_string());
                }
                return Err(SchedulerError::Store(error));
            }
        };
        if !marked {
            let current = self.inner.store.get_job(&claim.job.agent_id)?;
            if current
                .as_ref()
                .is_some_and(|job| job.close_requested || job.state.is_terminal())
            {
                let terminal = runtime.stop(self.inner.config.stop_grace);
                if let Err(error) = sink.finish(&terminal) {
                    self.record_failure(&claim.job.agent_id, error.to_string());
                }
                return Ok(false);
            }
            let terminal = runtime.stop(self.inner.config.stop_grace);
            let message = format!("running transition was not applied: {terminal:?}");
            self.inner.store.fail_claim(
                &claim.job.agent_id,
                claim.owner_epoch,
                "RUNTIME_START_RACE",
                &message,
            )?;
            return Ok(false);
        }

        {
            // Lock order: scheduler state is never held during SQLite, factory,
            // spawn, wait, stop, or LifecycleSink calls.
            let mut state = self.inner.state.lock().unwrap();
            state.active.insert(
                claim.job.agent_id.clone(),
                ActiveRuntime {
                    owner_epoch: claim.owner_epoch,
                    runtime: Arc::clone(&runtime),
                    sink: Arc::clone(&sink),
                },
            );
        }
        self.spawn_monitor(claim.job.agent_id, claim.owner_epoch, runtime, sink);
        Ok(true)
    }

    fn spawn_monitor(
        &self,
        agent_id: String,
        owner_epoch: u64,
        runtime: Arc<dyn ManagedRuntime>,
        sink: Arc<StoreLifecycleSink>,
    ) {
        let scheduler = self.clone();
        thread::spawn(move || loop {
            if let Some(terminal) = runtime.wait_terminal(Duration::from_millis(50)) {
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
        });
    }

    pub fn close_job(&self, agent_id: &str) -> Result<JobState, SchedulerError> {
        let decision = self.inner.store.request_close(agent_id)?;
        if !decision.needs_runtime_stop {
            return Ok(decision.state);
        }
        let active = {
            let state = self.inner.state.lock().unwrap();
            state
                .active
                .get(agent_id)
                .filter(|active| active.owner_epoch == decision.owner_epoch)
                .map(|active| (Arc::clone(&active.runtime), Arc::clone(&active.sink)))
        };
        let Some((runtime, sink)) = active else {
            return Ok(decision.state);
        };
        let terminal = runtime.stop(self.inner.config.stop_grace);
        if let Some(message) = sink.error() {
            if let Err(error) = self.inner.store.fail_claim(
                agent_id,
                decision.owner_epoch,
                "LIFECYCLE_SINK_FAILED",
                &message,
            ) {
                self.record_failure(agent_id, error.to_string());
                return Err(SchedulerError::Store(error));
            }
            self.record_failure(agent_id, message.clone());
            self.release_active(agent_id, decision.owner_epoch);
            return Err(SchedulerError::LifecycleSink {
                agent_id: agent_id.into(),
                message,
            });
        }
        let state = sink.finish(&terminal)?;
        self.release_active(agent_id, decision.owner_epoch);
        Ok(state)
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

#[cfg(test)]
mod tests {
    use super::*;
    use review_store::NewArtifact;
    use std::sync::Barrier;

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
            "read line; printf '%s\\n' '{\"method\":\"turn/started\",\"params\":{}}'; trap '' TERM; exec tail -f /dev/null",
        ]);
        let owner = Arc::new(RuntimeOwner::spawn(command, sink.clone()).unwrap());
        owner
            .send_request("turn/start", serde_json::json!({}))
            .unwrap();
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
    }

    impl FakeRuntime {
        fn new(sink: Arc<dyn LifecycleSink>) -> Self {
            Self {
                sink,
                next_sequence: std::sync::atomic::AtomicU64::new(1),
                terminal: Mutex::new(None),
                changed: Condvar::new(),
                stop_calls: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn emit_partial(&self, value: &str) {
            let sequence = self
                .next_sequence
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.sink.emit(LifecycleRecord {
                sequence,
                event: RuntimeEvent::Driver(Inbound::Malformed(value.into())),
            });
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
            },
        )
        .unwrap();
        (directory, store, factory, scheduler)
    }

    fn wait_for_job_state(store: &Store, agent_id: &str, expected: JobState) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if store.get_job(agent_id).unwrap().unwrap().state == expected {
                return;
            }
            assert!(Instant::now() < deadline, "job did not reach {expected:?}");
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
        first.finish(RuntimeTerminal::Exited(ChildExit::Exited(Some(0))));
        wait_for_job_state(&store, "job-1", JobState::Completed);
        let second = factory.runtime("job-2");
        assert_eq!(
            store.events_after("job-1", "job-1:1", 0, 10).unwrap().len(),
            2
        );
        assert_eq!(store.cursor("job-1", "job-1:1").unwrap(), 2);
        assert_eq!(scheduler.active_count(), 2);

        second.finish(RuntimeTerminal::Exited(ChildExit::Exited(Some(0))));
        factory
            .runtime("job-3")
            .finish(RuntimeTerminal::Exited(ChildExit::Exited(Some(0))));
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
            assert_eq!(worker.join().unwrap().unwrap(), JobState::Closed);
        }
        assert!(runtime.stop_calls() >= 1);
        assert_eq!(scheduler.reap_job("job-close").unwrap(), JobState::Closed);
        assert_eq!(scheduler.reap_job("job-close").unwrap(), JobState::Closed);
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
            JobState::Closed
        );
        assert_eq!(scheduler.active_count(), 0);
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
            wait_for_job_state(&store, &format!("concurrent-{index}"), JobState::Closed);
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
        assert_eq!(scheduler.reconcile_startup().unwrap().len(), 2);
        assert_eq!(factory.runtimes.lock().unwrap().len(), 0);
        assert_eq!(
            reopened.get_job("queued").unwrap().unwrap().state,
            JobState::FailedRuntimeLost
        );
        assert_eq!(
            reopened.get_job("starting").unwrap().unwrap().state,
            JobState::Orphaned
        );
    }
}
