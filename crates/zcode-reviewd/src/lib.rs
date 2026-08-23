use std::{
    io,
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
            }),
            changed: Condvar::new(),
        }
    }

    fn emit_driver(&self, event: Inbound, exit_terminal: Option<RuntimeTerminal>) {
        let mut state = self.state.lock().unwrap();
        if matches!(state.owner, OwnerState::Terminal(_)) {
            return;
        }
        self.emit_locked(&mut state, RuntimeEvent::Driver(event));
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
            Ok(outcome) => RuntimeTerminal::Stopped(outcome),
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
