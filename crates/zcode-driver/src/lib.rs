#[cfg(target_os = "linux")]
use std::fs;
#[cfg(unix)]
use std::os::fd::{AsRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::{
    collections::HashMap,
    fmt,
    io::{self, BufReader, Read, Write},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc, Condvar, Mutex, TryLockError,
    },
    thread,
    time::{Duration, Instant},
};
use zcode_protocol::{
    classify_lifecycle, encode, event_type, parse_line, LifecycleOrder, RequestEnvelope,
    ResponseEnvelope, WireId, WireMessage,
};

pub const MAX_NDJSON_LINE_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChildExit {
    Exited(Option<i32>),
    Signaled(i32),
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub pgid: i32,
    pub uid: u32,
    pub start_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inbound {
    Message(WireMessage),
    Lifecycle {
        sequence: u64,
        method: String,
        order: LifecycleOrder,
    },
    Malformed(String),
    OversizedLine {
        bytes: usize,
    },
    ChildExited(ChildExit),
    UnmatchedResponse {
        id: WireId,
        outcome: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    Timeout,
    Cancelled,
    ChildExited(ChildExit),
    StreamClosed,
    WriteFailed(String),
    Remote(serde_json::Value),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "request deadline elapsed"),
            Self::Cancelled => write!(f, "request was cancelled"),
            Self::ChildExited(exit) => {
                write!(f, "runtime exited while request was pending: {exit:?}")
            }
            Self::StreamClosed => write!(f, "runtime response stream closed"),
            Self::WriteFailed(_) => write!(f, "runtime request write failed"),
            Self::Remote(_) => write!(f, "runtime returned an application error"),
        }
    }
}

impl std::error::Error for RequestError {}

type PendingSender = Sender<Result<ResponseEnvelope, RequestError>>;
type PendingMap = HashMap<String, PendingSender>;

pub struct PendingRequest {
    key: String,
    receiver: Receiver<Result<ResponseEnvelope, RequestError>>,
    pending: Arc<Mutex<PendingMap>>,
    finished: bool,
}

impl PendingRequest {
    pub fn wait(mut self, timeout: Duration) -> Result<ResponseEnvelope, RequestError> {
        let result = match self.receiver.recv_timeout(timeout) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => Err(RequestError::Timeout),
            Err(RecvTimeoutError::Disconnected) => Err(RequestError::StreamClosed),
        };
        self.pending.lock().unwrap().remove(&self.key);
        self.finished = true;
        result.and_then(|response| match response.error.clone() {
            Some(error) => Err(RequestError::Remote(error)),
            None => Ok(response),
        })
    }

    pub fn cancel(mut self) {
        self.pending.lock().unwrap().remove(&self.key);
        self.finished = true;
    }
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        if !self.finished {
            self.pending.lock().unwrap().remove(&self.key);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopOutcome {
    AlreadyExited(ChildExit),
    Terminated(ChildExit),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StopFailure {
    kind: io::ErrorKind,
    message: String,
}

impl StopFailure {
    fn from_error(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn to_error(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }
}

#[derive(Debug)]
enum StopState {
    Running {
        generation: u64,
    },
    Stopping {
        generation: u64,
        waiters: usize,
    },
    Stopped(StopOutcome),
    Failed {
        generation: u64,
        failure: StopFailure,
        waiters: usize,
    },
}

enum BeginStop {
    Perform(u64),
    Complete(StopOutcome),
}

pub struct Driver {
    stdin: Arc<Mutex<ChildStdin>>,
    incoming: Mutex<Receiver<Inbound>>,
    child: Arc<Mutex<Option<Child>>>,
    termination: Arc<(Mutex<Option<ChildExit>>, Condvar)>,
    next_id: AtomicU64,
    stop_state: Arc<(Mutex<StopState>, Condvar)>,
    identity: ProcessIdentity,
    pending: Arc<Mutex<PendingMap>>,
    subscribers: Arc<Mutex<Vec<Sender<Inbound>>>>,
}

impl Driver {
    pub fn spawn(mut command: Command) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            unsafe {
                command.pre_exec(|| {
                    // Isolate the runtime and its descendants so stop() can reap the group.
                    if libc::setpgid(0, 0) == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn()?;
        let identity = match observe_process(child.id()) {
            Ok(identity) => identity,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        if let Err(error) = validate_spawn_identity(child.id(), &identity) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        let stdin = Arc::new(Mutex::new(child.stdin.take().expect("piped stdin")));
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let (raw_tx, raw_rx) = mpsc::channel();
        let read_tx = raw_tx.clone();
        let (read_done_tx, read_done_rx) = mpsc::channel();
        thread::spawn(move || read_loop(stdout, read_tx, read_done_tx));
        // Always drain diagnostics independently of the protocol stream. A
        // noisy runtime must not block on its stderr pipe and prevent a
        // response from reaching stdout. Diagnostics are intentionally
        // discarded so they can never contaminate stdout or leak secrets.
        thread::spawn(move || drain_stderr(stderr));
        let child_ref = Arc::new(Mutex::new(Some(child)));
        let monitor_ref = Arc::clone(&child_ref);
        let termination = Arc::new((Mutex::new(None), Condvar::new()));
        let monitor_termination = Arc::clone(&termination);
        thread::spawn(move || {
            monitor_child(monitor_ref, raw_tx, monitor_termination, read_done_rx)
        });
        let pending = Arc::new(Mutex::new(PendingMap::new()));
        let subscribers = Arc::new(Mutex::new(Vec::new()));
        let (event_tx, rx) = mpsc::channel();
        subscribers.lock().unwrap().push(event_tx);
        spawn_dispatcher(raw_rx, Arc::clone(&pending), Arc::clone(&subscribers));
        Ok(Self {
            stdin,
            incoming: Mutex::new(rx),
            child: child_ref,
            termination,
            next_id: AtomicU64::new(1),
            stop_state: Arc::new((
                Mutex::new(StopState::Running { generation: 0 }),
                Condvar::new(),
            )),
            identity,
            pending,
            subscribers,
        })
    }
    #[cfg(test)]
    fn send_request(&self, method: &str, params: serde_json::Value) -> std::io::Result<WireId> {
        let id = i64::try_from(self.next_id.fetch_add(1, Ordering::Relaxed))
            .map_err(|_| io::Error::other("request id space exhausted"))?;
        let id = WireId::Integer(id);
        self.send(&RequestEnvelope::new(id.clone(), method, params))?;
        Ok(id)
    }

    pub fn begin_request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<PendingRequest, RequestError> {
        let id = i64::try_from(self.next_id.fetch_add(1, Ordering::Relaxed))
            .map(WireId::Integer)
            .map_err(|_| RequestError::StreamClosed)?;
        let key = response_key(&id);
        let (sender, receiver) = mpsc::channel();
        {
            let mut pending = self.pending.lock().unwrap();
            if pending.insert(key.clone(), sender).is_some() {
                return Err(RequestError::StreamClosed);
            }
        }
        if let Err(error) = self.send(&RequestEnvelope::new(id, method, params)) {
            self.pending.lock().unwrap().remove(&key);
            return Err(RequestError::WriteFailed(error.to_string()));
        }
        Ok(PendingRequest {
            key,
            receiver,
            pending: Arc::clone(&self.pending),
            finished: false,
        })
    }

    pub fn request(
        &self,
        method: &str,
        params: serde_json::Value,
        timeout: Duration,
    ) -> Result<ResponseEnvelope, RequestError> {
        self.begin_request(method, params)?.wait(timeout)
    }

    pub fn respond(&self, id: WireId, result: serde_json::Value) -> io::Result<()> {
        self.send(&ResponseEnvelope::success(id, result))
    }

    #[cfg(unix)]
    pub fn respond_before(
        &self,
        id: WireId,
        result: serde_json::Value,
        deadline: Instant,
    ) -> Result<(), RequestError> {
        let encoded = encode(&ResponseEnvelope::success(id, result))
            .map_err(|error| RequestError::WriteFailed(error.to_string()))?;
        let mut frame = encoded.into_bytes();
        frame.push(b'\n');
        self.write_frame_before(&frame, deadline)
    }

    #[cfg(unix)]
    fn write_frame_before(&self, frame: &[u8], deadline: Instant) -> Result<(), RequestError> {
        let mut input = loop {
            remaining_before(deadline)?;
            match self.stdin.try_lock() {
                Ok(input) => break input,
                Err(TryLockError::Poisoned(_)) => {
                    return Err(RequestError::WriteFailed(
                        "runtime stdin lock is poisoned".into(),
                    ));
                }
                Err(TryLockError::WouldBlock) => {
                    let remaining = remaining_before(deadline)?;
                    thread::sleep(remaining.min(Duration::from_millis(1)));
                }
            }
        };
        remaining_before(deadline)?;

        let fd = input.as_raw_fd();
        let mut flags = NonblockingFdFlags::install(fd).map_err(request_write_error)?;
        let write_result = write_all_before(&mut input, frame, deadline);
        let restore_result = flags.restore().map_err(request_write_error);
        match (write_result, restore_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }

    pub fn respond_error(&self, id: WireId, error: serde_json::Value) -> io::Result<()> {
        self.send(&ResponseEnvelope::failure(id, error))
    }
    pub fn send<T: serde::Serialize>(&self, value: &T) -> std::io::Result<()> {
        let mut input = self.stdin.lock().unwrap();
        writeln!(input, "{}", encode(value).map_err(std::io::Error::other)?)?;
        input.flush()
    }
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Inbound, RecvTimeoutError> {
        self.incoming.lock().unwrap().recv_timeout(timeout)
    }
    pub fn subscribe(&self) -> Receiver<Inbound> {
        let (sender, receiver) = mpsc::channel();
        self.subscribers.lock().unwrap().push(sender);
        receiver
    }
    pub fn stop(&self) -> std::io::Result<()> {
        self.stop_and_reap(Duration::from_secs(1)).map(|_| ())
    }
    pub fn close(&self) -> std::io::Result<()> {
        self.stop()
    }
    pub fn identity(&self) -> ProcessIdentity {
        self.identity.clone()
    }
    pub fn stop_and_reap(&self, timeout: Duration) -> std::io::Result<StopOutcome> {
        let generation = match self.begin_stop()? {
            BeginStop::Perform(generation) => generation,
            BeginStop::Complete(outcome) => return Ok(outcome),
        };
        let result = self.perform_stop(timeout).map_err(StopFailure::from_error);
        self.finish_stop(generation, result)
    }

    fn begin_stop(&self) -> io::Result<BeginStop> {
        let (state, ready) = &*self.stop_state;
        let mut guard = state.lock().unwrap();
        loop {
            match &*guard {
                StopState::Stopped(outcome) => return Ok(BeginStop::Complete(outcome.clone())),
                StopState::Running { generation } => {
                    let next = generation.saturating_add(1);
                    *guard = StopState::Stopping {
                        generation: next,
                        waiters: 0,
                    };
                    return Ok(BeginStop::Perform(next));
                }
                StopState::Failed {
                    generation,
                    waiters: 0,
                    ..
                } => {
                    let next = generation.saturating_add(1);
                    *guard = StopState::Stopping {
                        generation: next,
                        waiters: 0,
                    };
                    return Ok(BeginStop::Perform(next));
                }
                StopState::Failed { .. } => guard = ready.wait(guard).unwrap(),
                StopState::Stopping {
                    generation,
                    waiters,
                } => {
                    let waiting_for = *generation;
                    let registered = waiters.saturating_add(1);
                    *guard = StopState::Stopping {
                        generation: waiting_for,
                        waiters: registered,
                    };
                    loop {
                        guard = ready.wait(guard).unwrap();
                        match &mut *guard {
                            StopState::Stopped(outcome) => {
                                return Ok(BeginStop::Complete(outcome.clone()));
                            }
                            StopState::Failed {
                                generation,
                                failure,
                                waiters,
                            } if *generation == waiting_for => {
                                let error = failure.to_error();
                                *waiters = waiters.saturating_sub(1);
                                if *waiters == 0 {
                                    ready.notify_all();
                                }
                                return Err(error);
                            }
                            StopState::Stopping { generation, .. }
                                if *generation == waiting_for => {}
                            _ => break,
                        }
                    }
                }
            }
        }
    }

    fn finish_stop(
        &self,
        generation: u64,
        result: Result<StopOutcome, StopFailure>,
    ) -> io::Result<StopOutcome> {
        let (state, ready) = &*self.stop_state;
        let mut guard = state.lock().unwrap();
        let waiters = match &*guard {
            StopState::Stopping {
                generation: active,
                waiters,
            } if *active == generation => *waiters,
            _ => 0,
        };
        match &result {
            Ok(outcome) => *guard = StopState::Stopped(outcome.clone()),
            Err(failure) => {
                *guard = StopState::Failed {
                    generation,
                    failure: failure.clone(),
                    waiters,
                }
            }
        }
        ready.notify_all();
        result.map_err(|failure| failure.to_error())
    }

    fn perform_stop(&self, timeout: Duration) -> io::Result<StopOutcome> {
        let mut child = self.child.lock().unwrap();
        let process = child
            .as_mut()
            .ok_or_else(|| io::Error::other("Driver lost its owned Child handle"))?;

        if let Some(status) = process.try_wait()? {
            ensure_group_empty(self.identity.pgid)?;
            return Ok(StopOutcome::AlreadyExited(exit_class(status)));
        }

        validate_spawn_identity(process.id(), &self.identity)?;
        let observed = match observe_process(process.id()) {
            Ok(identity) => identity,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if let Some(status) = process.try_wait()? {
                    ensure_group_empty(self.identity.pgid)?;
                    return Ok(StopOutcome::AlreadyExited(exit_class(status)));
                }
                if let Some(exit) = wait_for_group_death(process, self.identity.pgid, timeout)? {
                    return Ok(StopOutcome::AlreadyExited(exit));
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        validate_same_identity(&self.identity, &observed)?;
        validate_owned_group(&self.identity, &observe_process_group(self.identity.pgid)?)?;

        signal_group(self.identity.pgid, TERM_SIGNAL)?;
        if let Some(exit) = wait_for_group_death(process, self.identity.pgid, timeout)? {
            return Ok(StopOutcome::Terminated(exit));
        }

        validate_live_group_after_term(
            &self.identity,
            &observe_process_group(self.identity.pgid)?,
        )?;
        signal_group(self.identity.pgid, KILL_SIGNAL)?;
        let exit =
            wait_for_group_death(process, self.identity.pgid, timeout)?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "process group survived SIGKILL")
            })?;
        Ok(StopOutcome::Terminated(exit))
    }

    pub fn wait(&self) -> std::io::Result<Option<i32>> {
        let (result, cvar) = &*self.termination;
        let mut guard = result.lock().unwrap();
        while guard.is_none() {
            guard = cvar.wait(guard).unwrap();
        }
        Ok(
            match guard.as_ref().expect("child monitor publishes before wake") {
                ChildExit::Exited(code) => *code,
                _ => None,
            },
        )
    }
}

#[cfg(unix)]
fn remaining_before(deadline: Instant) -> Result<Duration, RequestError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(RequestError::Timeout)
}

#[cfg(unix)]
fn request_write_error(error: io::Error) -> RequestError {
    if error.kind() == io::ErrorKind::TimedOut {
        RequestError::Timeout
    } else {
        RequestError::WriteFailed(error.to_string())
    }
}

#[cfg(unix)]
fn get_fd_flags(fd: RawFd) -> io::Result<libc::c_int> {
    loop {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags >= 0 {
            return Ok(flags);
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn set_fd_flags(fd: RawFd, flags: libc::c_int) -> io::Result<()> {
    loop {
        if unsafe { libc::fcntl(fd, libc::F_SETFL, flags) } >= 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
struct NonblockingFdFlags {
    fd: RawFd,
    original: libc::c_int,
    restored: bool,
}

#[cfg(unix)]
impl NonblockingFdFlags {
    fn install(fd: RawFd) -> io::Result<Self> {
        let original = get_fd_flags(fd)?;
        set_fd_flags(fd, original | libc::O_NONBLOCK)?;
        Ok(Self {
            fd,
            original,
            restored: false,
        })
    }

    fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        set_fd_flags(self.fd, self.original)?;
        self.restored = true;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for NonblockingFdFlags {
    fn drop(&mut self) {
        if !self.restored {
            let _ = set_fd_flags(self.fd, self.original);
        }
    }
}

#[cfg(all(unix, test))]
fn settable_fd_flags(flags: libc::c_int) -> libc::c_int {
    flags & (libc::O_APPEND | libc::O_ASYNC | libc::O_NONBLOCK)
}

#[cfg(unix)]
fn write_all_before(
    input: &mut ChildStdin,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), RequestError> {
    let fd = input.as_raw_fd();
    let mut offset = 0;
    while offset < frame.len() {
        remaining_before(deadline)?;
        match input.write(&frame[offset..]) {
            Ok(0) => {
                return Err(RequestError::WriteFailed(
                    "runtime stdin accepted a zero-length write".into(),
                ));
            }
            Ok(written) => offset += written,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_writable_before(fd, deadline)?;
            }
            Err(error) => return Err(request_write_error(error)),
        }
    }

    loop {
        remaining_before(deadline)?;
        match input.flush() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_writable_before(fd, deadline)?;
            }
            Err(error) => return Err(request_write_error(error)),
        }
    }
}

#[cfg(unix)]
fn wait_writable_before(fd: RawFd, deadline: Instant) -> Result<(), RequestError> {
    loop {
        let remaining = remaining_before(deadline)?;
        let timeout_millis = remaining
            .as_millis()
            .saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0))
            .clamp(1, libc::c_int::MAX as u128) as libc::c_int;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_millis) };
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(RequestError::WriteFailed(
                    "runtime stdin descriptor is invalid".into(),
                ));
            }
            if descriptor.revents & (libc::POLLOUT | libc::POLLERR | libc::POLLHUP) != 0 {
                return Ok(());
            }
            continue;
        }
        if result == 0 {
            remaining_before(deadline)?;
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(request_write_error(error));
        }
    }
}

const MEMBER_OBSERVATION_RETRIES: usize = 4;
#[cfg(unix)]
const TERM_SIGNAL: i32 = libc::SIGTERM;
#[cfg(unix)]
const KILL_SIGNAL: i32 = libc::SIGKILL;
#[cfg(not(unix))]
const TERM_SIGNAL: i32 = 15;
#[cfg(not(unix))]
const KILL_SIGNAL: i32 = 9;

pub fn observe_process(pid: u32) -> io::Result<ProcessIdentity> {
    if pid <= 1 || pid > i32::MAX as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process id is not signal-safe",
        ));
    }
    platform_observe_process(pid)
}

pub fn observe_process_group(pgid: i32) -> io::Result<Vec<ProcessIdentity>> {
    validate_group_target(pgid)?;
    let mut last_error = None;
    for _ in 0..MEMBER_OBSERVATION_RETRIES {
        match platform_observe_process_group(pgid) {
            Ok(members) => return Ok(members),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => last_error = Some(error),
            Err(error) => return Err(error),
        }
        thread::yield_now();
    }
    Err(last_error.unwrap_or_else(|| io::Error::other("process-group observation failed")))
}

pub fn stop_and_reap_persisted_process_group(
    identity: &ProcessIdentity,
    timeout: Duration,
) -> io::Result<()> {
    validate_spawn_identity(identity.pid, identity)?;
    match observe_process(identity.pid) {
        Ok(observed) => {
            validate_same_identity(identity, &observed)?;
            validate_owned_group(identity, &observe_process_group(identity.pgid)?)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let members = observe_process_group(identity.pgid)?;
            if members.is_empty() {
                return Ok(());
            }
            validate_live_group_after_term(identity, &members)?;
        }
        Err(error) => return Err(error),
    }

    signal_group(identity.pgid, TERM_SIGNAL)?;
    if wait_for_persisted_group_death(identity.pgid, timeout)? {
        return Ok(());
    }

    validate_live_group_after_term(identity, &observe_process_group(identity.pgid)?)?;
    signal_group(identity.pgid, KILL_SIGNAL)?;
    if wait_for_persisted_group_death(identity.pgid, timeout)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "persisted process group survived SIGKILL",
        ))
    }
}

fn validate_spawn_identity(child_pid: u32, identity: &ProcessIdentity) -> io::Result<()> {
    if identity.pid != child_pid
        || identity.pid <= 1
        || identity.pgid <= 1
        || identity.pgid != child_pid as i32
        || identity.start_token.is_empty()
    {
        return Err(io::Error::other(
            "spawned child identity is incomplete or not group-isolated",
        ));
    }
    Ok(())
}

fn validate_same_identity(
    expected: &ProcessIdentity,
    observed: &ProcessIdentity,
) -> io::Result<()> {
    if expected != observed {
        return Err(io::Error::other(
            "process identity changed; refusing to signal",
        ));
    }
    validate_group_target(expected.pgid).map(|_| ())
}

fn validate_owned_group(leader: &ProcessIdentity, members: &[ProcessIdentity]) -> io::Result<()> {
    if members.is_empty() || !members.iter().any(|member| member == leader) {
        return Err(io::Error::other(
            "owned process-group membership does not contain the leader",
        ));
    }
    validate_live_group_after_term(leader, members)
}

fn validate_live_group_after_term(
    leader: &ProcessIdentity,
    members: &[ProcessIdentity],
) -> io::Result<()> {
    validate_group_target(leader.pgid)?;
    for member in members {
        if member.pid <= 1
            || member.pgid != leader.pgid
            || member.uid != leader.uid
            || member.start_token.is_empty()
        {
            return Err(io::Error::other(
                "process-group membership is ambiguous; refusing to signal",
            ));
        }
    }
    Ok(())
}

fn validate_group_target(pgid: i32) -> io::Result<i32> {
    if pgid <= 1 || pgid == i32::MIN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "process-group id is not signal-safe",
        ));
    }
    Ok(-pgid)
}

fn signal_group(pgid: i32, signal: i32) -> io::Result<()> {
    let target = validate_group_target(pgid)?;
    #[cfg(unix)]
    {
        let result = unsafe { libc::kill(target, signal) };
        if result == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        Err(error)
    }
    #[cfg(not(unix))]
    {
        let _ = (target, signal);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process-group signalling is unsupported on this platform",
        ))
    }
}

fn wait_for_group_death(
    process: &mut Child,
    pgid: i32,
    timeout: Duration,
) -> io::Result<Option<ChildExit>> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let mut leader_exit = None;
    loop {
        if leader_exit.is_none() {
            leader_exit = process.try_wait()?.map(exit_class);
        }
        match observe_process_group(pgid) {
            Ok(members) if members.is_empty() => {
                if let Some(exit) = leader_exit {
                    return Ok(Some(exit));
                }
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_persisted_group_death(pgid: i32, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    loop {
        match observe_process_group(pgid) {
            Ok(members) if members.is_empty() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn ensure_group_empty(pgid: i32) -> io::Result<()> {
    if observe_process_group(pgid)?.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(
            "process leader exited while descendants remain; refusing unproven cleanup",
        ))
    }
}

#[cfg(target_os = "macos")]
fn platform_observe_process(pid: u32) -> io::Result<ProcessIdentity> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let expected = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    let written = unsafe {
        libc::proc_pidinfo(
            pid as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            expected,
        )
    };
    if written != expected {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("unable to observe Darwin process {pid}"),
        ));
    }
    if info.pbi_pid != pid || info.pbi_start_tvsec == 0 {
        return Err(io::Error::other("incomplete Darwin process identity"));
    }
    Ok(ProcessIdentity {
        pid: info.pbi_pid,
        pgid: i32::try_from(info.pbi_pgid)
            .map_err(|_| io::Error::other("Darwin process group does not fit i32"))?,
        uid: info.pbi_uid,
        start_token: format!("darwin:{}:{}", info.pbi_start_tvsec, info.pbi_start_tvusec),
    })
}

#[cfg(target_os = "macos")]
fn platform_observe_process_group(pgid: i32) -> io::Result<Vec<ProcessIdentity>> {
    let pids = darwin_process_group_pids(pgid)?;
    let mut members = Vec::with_capacity(pids.len());
    for pid in pids {
        match platform_observe_process(pid as u32) {
            Ok(member) if member.pgid == pgid => members.push(member),
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Darwin process-group membership changed during observation",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    let confirmed = darwin_process_group_pids(pgid)?;
    if confirmed
        .iter()
        .any(|pid| !members.iter().any(|member| member.pid == *pid as u32))
    {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "Darwin process-group membership changed during observation",
        ));
    }
    members.sort_by_key(|member| member.pid);
    Ok(members)
}

#[cfg(target_os = "macos")]
fn darwin_process_group_pids(pgid: i32) -> io::Result<Vec<i32>> {
    let mut capacity = 32usize;
    loop {
        let mut pids = vec![0i32; capacity];
        let bytes = unsafe {
            libc::proc_listpgrppids(
                pgid,
                pids.as_mut_ptr().cast(),
                (pids.len() * std::mem::size_of::<i32>()) as i32,
            )
        };
        if bytes < 0 {
            return Err(io::Error::last_os_error());
        }
        let count = bytes as usize;
        if count >= capacity {
            capacity = capacity
                .checked_mul(2)
                .ok_or_else(|| io::Error::other("Darwin process-group membership is too large"))?;
            if capacity > 65_536 {
                return Err(io::Error::other(
                    "Darwin process-group membership exceeds observation bound",
                ));
            }
            continue;
        }
        pids.truncate(count);
        pids.retain(|pid| *pid > 1);
        pids.sort_unstable();
        pids.dedup();
        return Ok(pids);
    }
}

#[cfg(target_os = "linux")]
fn platform_observe_process(pid: u32) -> io::Result<ProcessIdentity> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let close = stat
        .rfind(')')
        .ok_or_else(|| io::Error::other("malformed Linux process stat"))?;
    let fields: Vec<_> = stat[close + 1..].split_whitespace().collect();
    if fields.len() <= 19 {
        return Err(io::Error::other("incomplete Linux process stat"));
    }
    let pgid = fields[2].parse().map_err(io::Error::other)?;
    let start = fields[19].parse::<u64>().map_err(io::Error::other)?;
    let status = fs::read_to_string(format!("/proc/{pid}/status"))?;
    let uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| io::Error::other("missing Linux process uid"))?
        .parse()
        .map_err(io::Error::other)?;
    Ok(ProcessIdentity {
        pid,
        pgid,
        uid,
        start_token: format!("linux:{start}"),
    })
}

#[cfg(target_os = "linux")]
fn platform_observe_process_group(pgid: i32) -> io::Result<Vec<ProcessIdentity>> {
    let mut members = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        match platform_observe_process(pid) {
            Ok(identity) if identity.pgid == pgid => members.push(identity),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    members.sort_by_key(|member| member.pid);
    Ok(members)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_observe_process(_pid: u32) -> io::Result<ProcessIdentity> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native process identity observation is unsupported on this platform",
    ))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn platform_observe_process_group(_pgid: i32) -> io::Result<Vec<ProcessIdentity>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native process-group observation is unsupported on this platform",
    ))
}

fn drain_stderr(mut stderr: impl Read + Send + 'static) {
    let _ = io::copy(&mut stderr, &mut io::sink());
}
impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn response_key(id: &WireId) -> String {
    serde_json::to_string(id).expect("WireId serialization cannot fail")
}

fn spawn_dispatcher(
    incoming: Receiver<Inbound>,
    pending: Arc<Mutex<PendingMap>>,
    subscribers: Arc<Mutex<Vec<Sender<Inbound>>>>,
) {
    thread::spawn(move || {
        while let Ok(inbound) = incoming.recv() {
            match inbound {
                Inbound::Message(WireMessage::Response(response)) => {
                    let matched = pending.lock().unwrap().remove(&response_key(&response.id));
                    if let Some(waiter) = matched {
                        let _ = waiter.send(Ok(response));
                    } else {
                        broadcast(
                            &subscribers,
                            Inbound::UnmatchedResponse {
                                id: response.id,
                                outcome: if response.error.is_some() {
                                    "error"
                                } else {
                                    "result"
                                }
                                .into(),
                            },
                        );
                    }
                }
                Inbound::ChildExited(exit) => {
                    let waiters = {
                        let mut pending = pending.lock().unwrap();
                        pending
                            .drain()
                            .map(|(_, sender)| sender)
                            .collect::<Vec<_>>()
                    };
                    for waiter in waiters {
                        let _ = waiter.send(Err(RequestError::ChildExited(exit.clone())));
                    }
                    broadcast(&subscribers, Inbound::ChildExited(exit));
                }
                inbound => broadcast(&subscribers, inbound),
            }
        }
        let waiters = {
            let mut pending = pending.lock().unwrap();
            pending
                .drain()
                .map(|(_, sender)| sender)
                .collect::<Vec<_>>()
        };
        for waiter in waiters {
            let _ = waiter.send(Err(RequestError::StreamClosed));
        }
        subscribers.lock().unwrap().clear();
    });
}

fn broadcast(subscribers: &Mutex<Vec<Sender<Inbound>>>, inbound: Inbound) {
    subscribers
        .lock()
        .unwrap()
        .retain(|subscriber| subscriber.send(inbound.clone()).is_ok());
}

fn read_loop(stdout: impl std::io::Read + Send + 'static, tx: Sender<Inbound>, done: Sender<()>) {
    let _done = ReadDone(done);
    let mut reader = BufReader::new(stdout);
    let mut sequence = 0;
    let mut turn_active = false;
    loop {
        match read_bounded_line(&mut reader) {
            Ok(Some((line, bytes))) if bytes <= MAX_NDJSON_LINE_BYTES => {
                sequence += 1;
                let line = String::from_utf8_lossy(&line).to_string();
                match parse_line(&line) {
                    Ok(msg) => {
                        if let WireMessage::Event(event) = &msg {
                            if let Some(kind) = event_type(event) {
                                let order = classify_lifecycle(kind, turn_active);
                                if kind == "turn.started"
                                    && matches!(order, LifecycleOrder::InOrder)
                                {
                                    turn_active = true;
                                }
                                if matches!(kind, "turn.completed" | "turn.failed")
                                    && matches!(order, LifecycleOrder::InOrder)
                                {
                                    turn_active = false;
                                }
                                if tx
                                    .send(Inbound::Lifecycle {
                                        sequence,
                                        method: kind.into(),
                                        order,
                                    })
                                    .is_err()
                                {
                                    return;
                                }
                            }
                        }
                        if tx.send(Inbound::Message(msg)).is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        if tx.send(Inbound::Malformed(format!("{e:?}"))).is_err() {
                            return;
                        }
                    }
                }
            }
            Ok(Some((_, bytes))) => {
                let _ = tx.send(Inbound::OversizedLine { bytes });
                return;
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
}

struct ReadDone(Sender<()>);
impl Drop for ReadDone {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

fn read_bounded_line(reader: &mut impl Read) -> std::io::Result<Option<(Vec<u8>, usize)>> {
    let mut line = Vec::with_capacity(MAX_NDJSON_LINE_BYTES.min(8192));
    let mut byte = [0u8; 1];
    let mut total = 0usize;
    loop {
        match reader.read(&mut byte)? {
            0 => {
                return if total == 0 {
                    Ok(None)
                } else {
                    Ok(Some((line, total)))
                }
            }
            _ => {
                total += 1;
                if byte[0] == b'\n' {
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    return Ok(Some((line, total)));
                }
                if line.len() < MAX_NDJSON_LINE_BYTES {
                    line.push(byte[0]);
                } else {
                    return Ok(Some((Vec::new(), MAX_NDJSON_LINE_BYTES + 1)));
                }
            }
        }
    }
}

fn monitor_child(
    child_ref: Arc<Mutex<Option<Child>>>,
    tx: Sender<Inbound>,
    termination: Arc<(Mutex<Option<ChildExit>>, Condvar)>,
    read_done: Receiver<()>,
) {
    const READ_EXIT_BOUNDARY_TIMEOUT: Duration = Duration::from_secs(1);

    loop {
        let status = {
            let mut guard = child_ref.lock().unwrap();
            match guard.as_mut() {
                Some(child) => match child.try_wait() {
                    Ok(status) => status,
                    Err(_) => {
                        let _ = read_done.recv_timeout(READ_EXIT_BOUNDARY_TIMEOUT);
                        publish_child_exit(ChildExit::Unknown, &tx, &termination);
                        return;
                    }
                },
                None => None,
            }
        };
        if let Some(status) = status {
            // A descendant may retain the stdout descriptor after the leader
            // exits. Preserve the reader ordering barrier when it completes,
            // but publish a bounded boundary so RuntimeOwner can classify a
            // still-live or ambiguous group without signalling it.
            let _ = read_done.recv_timeout(READ_EXIT_BOUNDARY_TIMEOUT);
            let exit = exit_class(status);
            let (result, cvar) = &*termination;
            let mut guard = result.lock().unwrap();
            if guard.is_none() {
                *guard = Some(exit.clone());
            }
            cvar.notify_all();
            let _ = tx.send(Inbound::ChildExited(exit));
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn publish_child_exit(
    exit: ChildExit,
    tx: &Sender<Inbound>,
    termination: &Arc<(Mutex<Option<ChildExit>>, Condvar)>,
) {
    let (result, cvar) = &**termination;
    let mut guard = result.lock().unwrap();
    if guard.is_none() {
        *guard = Some(exit.clone());
    }
    cvar.notify_all();
    let _ = tx.send(Inbound::ChildExited(exit));
}

#[cfg(unix)]
fn exit_class(status: ExitStatus) -> ChildExit {
    use std::os::unix::process::ExitStatusExt;
    if let Some(signal) = status.signal() {
        ChildExit::Signaled(signal)
    } else {
        ChildExit::Exited(status.code())
    }
}

#[cfg(not(unix))]
fn exit_class(status: ExitStatus) -> ChildExit {
    ChildExit::Exited(status.code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[cfg(unix)]
    fn stdin_settable_flags(driver: &Driver) -> i32 {
        let input = driver.stdin.lock().unwrap();
        settable_fd_flags(get_fd_flags(input.as_raw_fd()).unwrap())
    }

    #[cfg(unix)]
    fn fill_stdin_pipe(driver: &Driver) {
        let mut input = driver.stdin.lock().unwrap();
        let fd = input.as_raw_fd();
        let mut flags = NonblockingFdFlags::install(fd).unwrap();
        let chunk = [b'x'; 4096];
        loop {
            match input.write(&chunk) {
                Ok(0) => panic!("stdin pipe unexpectedly accepted a zero-length write"),
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => panic!("failed to fill stdin pipe: {error}"),
            }
        }
        flags.restore().unwrap();
    }

    fn capture_path(label: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "zcode-driver-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn wait_for_file(path: &std::path::Path) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(contents) = std::fs::read(path) {
                return contents;
            }
            assert!(Instant::now() < deadline, "response capture timed out");
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(unix)]
    #[test]
    fn response_deadline_bounds_stdin_mutex_acquisition_without_leaking_writer() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 10"]);
        let driver = Arc::new(Driver::spawn(command).unwrap());
        let guard = driver.stdin.lock().unwrap();
        let responder = Arc::clone(&driver);
        let (finished_tx, finished_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let started = Instant::now();
            let result = responder.respond_before(
                WireId::String("mutex-deadline".into()),
                serde_json::json!({"decision": "deny"}),
                Instant::now() + Duration::from_millis(60),
            );
            finished_tx.send((started.elapsed(), result)).unwrap();
        });

        let (elapsed, result) = finished_rx
            .recv_timeout(Duration::from_millis(300))
            .expect("bounded response writer did not return");
        assert_eq!(result.unwrap_err(), RequestError::Timeout);
        assert!(elapsed >= Duration::from_millis(40));
        assert!(elapsed < Duration::from_millis(250));
        drop(guard);
        worker.join().unwrap();

        driver.stop_and_reap(Duration::from_millis(100)).unwrap();
        assert!(observe_process_group(driver.identity().pgid)
            .unwrap()
            .is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn response_deadline_bounds_pipe_backpressure_and_restores_fd_flags() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 10"]);
        let driver = Driver::spawn(command).unwrap();
        let original_flags = stdin_settable_flags(&driver);
        fill_stdin_pipe(&driver);
        assert_eq!(stdin_settable_flags(&driver), original_flags);

        let started = Instant::now();
        let result = driver.respond_before(
            WireId::String("backpressure-deadline".into()),
            serde_json::json!({"decision": "allow"}),
            Instant::now() + Duration::from_millis(60),
        );
        assert_eq!(result.unwrap_err(), RequestError::Timeout);
        assert!(started.elapsed() >= Duration::from_millis(40));
        assert!(started.elapsed() < Duration::from_millis(250));
        assert_eq!(stdin_settable_flags(&driver), original_flags);

        driver.stop_and_reap(Duration::from_millis(100)).unwrap();
        assert!(observe_process_group(driver.identity().pgid)
            .unwrap()
            .is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn response_before_writes_one_complete_line_and_restores_fd_flags() {
        let path = capture_path("response-line");
        let mut command = Command::new("sh");
        command.env("RESPONSE_PATH", &path).args([
            "-c",
            "IFS= read -r line; printf '%s\\n' \"$line\" > \"$RESPONSE_PATH\"; sleep 10",
        ]);
        let driver = Driver::spawn(command).unwrap();
        let original_flags = stdin_settable_flags(&driver);
        let id = WireId::String("complete-line".into());
        let result = serde_json::json!({"decision": "deny"});
        driver
            .respond_before(
                id.clone(),
                result.clone(),
                Instant::now() + Duration::from_secs(1),
            )
            .unwrap();

        let expected = format!(
            "{}\n",
            encode(&ResponseEnvelope::success(id, result)).unwrap()
        );
        assert_eq!(wait_for_file(&path), expected.as_bytes());
        assert_eq!(stdin_settable_flags(&driver), original_flags);
        driver.stop_and_reap(Duration::from_millis(100)).unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn dispatch_interleaved() {
        let mut c = Command::new("sh");
        c.args(["-c", "read line; printf '%s\\n' '{\"method\":\"session/event\",\"params\":{\"type\":\"turn.started\"}}' '{\"id\":\"server-1\",\"method\":\"interaction/requestPermission\",\"params\":{}}' '{\"id\":1,\"result\":{\"ok\":true}}' '{\"method\":\"session/event\",\"params\":{\"type\":\"turn.completed\"}}'"]);
        let d = Driver::spawn(c).unwrap();
        let _ = d.send_request("turn/start", serde_json::json!({})).unwrap();
        let mut seen = 0;
        for _ in 0..8 {
            if let Ok(Inbound::Message(_)) = d.recv_timeout(Duration::from_secs(2)) {
                seen += 1;
            }
        }
        assert!(seen >= 3);
        d.stop().unwrap();
    }

    #[test]
    fn malformed_and_child_exit_are_visible() {
        let mut c = Command::new("sh");
        c.args([
            "-c",
            "read line; printf '%s\\n' '{' '{\"method\":\"future/event\",\"params\":{}}'",
        ]);
        let d = Driver::spawn(c).unwrap();
        let _ = d.send_request("x", serde_json::json!({}));
        assert!(matches!(
            d.recv_timeout(Duration::from_secs(1)),
            Ok(Inbound::Malformed(_))
        ));
        assert!(matches!(
            d.recv_timeout(Duration::from_secs(1)),
            Ok(Inbound::Message(WireMessage::UnknownEvent { .. }))
        ));
        assert!(matches!(
            d.recv_timeout(Duration::from_secs(1)),
            Ok(Inbound::ChildExited(_))
        ));
    }

    #[test]
    fn stop_is_idempotent_during_turn() {
        let mut c = Command::new("sh");
        c.args(["-c", "read line; sleep 10"]);
        let d = Driver::spawn(c).unwrap();
        let _ = d.send_request("turn/start", serde_json::json!({}));
        d.stop().unwrap();
        d.stop().unwrap();
    }

    #[test]
    fn oversized_line_is_classified_and_discarded() {
        let mut c = Command::new("sh");
        c.args(["-c", "printf '%1048577s\\n' x"]);
        let d = Driver::spawn(c).unwrap();
        assert!(matches!(
            d.recv_timeout(Duration::from_secs(2)),
            Ok(Inbound::OversizedLine { bytes }) if bytes > MAX_NDJSON_LINE_BYTES
        ));
        d.stop().unwrap();
    }

    #[test]
    fn unterminated_oversized_line_is_bounded_and_closes_reader() {
        let mut c = Command::new("sh");
        c.args(["-c", "head -c 1048577 /dev/zero"]);
        let d = Driver::spawn(c).unwrap();
        assert!(matches!(
            d.recv_timeout(Duration::from_secs(2)),
            Ok(Inbound::OversizedLine { bytes }) if bytes == MAX_NDJSON_LINE_BYTES + 1
        ));
    }

    #[test]
    fn child_exit_status_is_published_once() {
        let mut c = Command::new("sh");
        c.args(["-c", "exit 7"]);
        let d = Driver::spawn(c).unwrap();
        assert!(matches!(
            d.recv_timeout(Duration::from_secs(2)),
            Ok(Inbound::ChildExited(ChildExit::Exited(Some(7))))
        ));
        assert!(matches!(
            d.recv_timeout(Duration::from_millis(50)),
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected)
        ));
    }

    #[test]
    fn wait_race_does_not_lose_child_exit_wakeup() {
        // Exercise the boundary where the monitor publishes just as a caller
        // begins waiting. The timeout keeps a lost wakeup from hanging tests.
        for _ in 0..64 {
            let mut c = Command::new("sh");
            c.args(["-c", "exit 0"]);
            let driver = Arc::new(Driver::spawn(c).unwrap());
            let waiter = Arc::clone(&driver);
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let _ = tx.send(waiter.wait());
            });
            let result = rx
                .recv_timeout(Duration::from_secs(1))
                .expect("wait must not lose monitor notification")
                .unwrap();
            assert_eq!(result, Some(0));
        }
    }

    #[test]
    fn out_of_order_lifecycle_keeps_transport_sequence() {
        let mut c = Command::new("sh");
        c.args([
            "-c",
            "printf '%s\\n' '{\"method\":\"session/event\",\"params\":{\"type\":\"turn.completed\"}}' '{\"method\":\"session/event\",\"params\":{\"type\":\"turn.started\"}}'",
        ]);
        let d = Driver::spawn(c).unwrap();
        let first = d.recv_timeout(Duration::from_secs(2)).unwrap();
        let second = d.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            first,
            Inbound::Lifecycle {
                sequence: 1,
                order: LifecycleOrder::OutOfOrder { .. },
                ..
            }
        ));
        assert!(matches!(second, Inbound::Message(WireMessage::Event(_))));
    }

    #[test]
    fn noisy_stderr_does_not_block_stdout_response() {
        let mut c = Command::new("sh");
        c.args([
            "-c",
            "read line; head -c 262144 /dev/zero >&2; printf '%s\\n' '{\"id\":1,\"result\":{\"ok\":true}}'",
        ]);
        let d = Driver::spawn(c).unwrap();
        let response = d
            .request("probe", serde_json::json!({}), Duration::from_secs(3))
            .unwrap();
        assert_eq!(response.id, WireId::Integer(1));
        d.stop().unwrap();
    }

    #[test]
    fn concurrent_waiters_are_correlated_while_events_are_broadcast() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "read first; read second; printf '%s\n' '{\"method\":\"session/event\",\"params\":{\"type\":\"turn.started\"}}' '{\"id\":2,\"result\":{\"value\":\"second\"}}' '{\"id\":\"server-1\",\"method\":\"interaction/requestPermission\",\"params\":{}}' '{\"id\":1,\"result\":{\"value\":\"first\"}}' '{\"method\":\"session/event\",\"params\":{\"type\":\"turn.completed\"}}'; sleep 1",
        ]);
        let driver = Arc::new(Driver::spawn(command).unwrap());
        let events = driver.subscribe();
        let first = driver
            .begin_request("first", serde_json::json!({}))
            .unwrap();
        let second = driver
            .begin_request("second", serde_json::json!({}))
            .unwrap();
        assert_eq!(
            second.wait(Duration::from_secs(2)).unwrap().result.unwrap()["value"],
            "second"
        );
        assert_eq!(
            first.wait(Duration::from_secs(2)).unwrap().result.unwrap()["value"],
            "first"
        );
        let mut methods = Vec::new();
        for _ in 0..8 {
            if let Ok(Inbound::Message(message)) = events.recv_timeout(Duration::from_millis(250)) {
                match message {
                    WireMessage::Event(event) => methods.push(event.method),
                    WireMessage::Request(request) => methods.push(request.method),
                    _ => {}
                }
                if methods.len() == 3 {
                    break;
                }
            }
        }
        assert_eq!(
            methods,
            vec![
                "session/event",
                "interaction/requestPermission",
                "session/event"
            ]
        );
        driver.stop().unwrap();
    }

    #[test]
    fn timeout_cancel_duplicate_and_unknown_ids_cannot_complete_another_waiter() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "read first; read second; read third; printf '%s\n' '{\"id\":99,\"result\":{}}' '{\"id\":2,\"result\":{\"cancelled\":true}}' '{\"id\":3,\"result\":{\"ok\":true}}' '{\"id\":3,\"result\":{\"duplicate\":true}}'; sleep 1",
        ]);
        let driver = Driver::spawn(command).unwrap();
        let events = driver.subscribe();
        let timed_out = driver.begin_request("slow", serde_json::json!({})).unwrap();
        assert_eq!(
            timed_out.wait(Duration::from_millis(20)).unwrap_err(),
            RequestError::Timeout
        );
        let cancelled = driver
            .begin_request("cancel", serde_json::json!({}))
            .unwrap();
        cancelled.cancel();
        let live = driver.begin_request("live", serde_json::json!({})).unwrap();
        assert_eq!(
            live.wait(Duration::from_secs(2)).unwrap().result.unwrap()["ok"],
            true
        );
        let mut unmatched = Vec::new();
        for _ in 0..4 {
            if let Ok(Inbound::UnmatchedResponse { id, .. }) =
                events.recv_timeout(Duration::from_millis(250))
            {
                unmatched.push(id);
            }
        }
        assert!(unmatched.contains(&WireId::Integer(99)));
        assert!(unmatched.contains(&WireId::Integer(2)));
        assert!(unmatched.contains(&WireId::Integer(3)));
        driver.stop().unwrap();
    }

    #[test]
    fn malformed_ids_and_null_outcomes_cannot_complete_a_waiter() {
        let mut command = Command::new("sh");
        command.args([
            "-c",
            "read request; printf '%s\n' '{\"id\":1,\"result\":null}' '{\"id\":1,\"error\":null}' '{\"id\":1}' '{\"id\":1,\"result\":{},\"error\":{}}' '{\"id\":true,\"result\":{\"invalid\":true}}' '{\"id\":{},\"result\":{\"invalid\":true}}' '{\"id\":[],\"result\":{\"invalid\":true}}' '{\"id\":null,\"result\":{\"invalid\":true}}' '{\"id\":1,\"result\":{\"accepted\":true}}'; sleep 1",
        ]);
        let driver = Driver::spawn(command).unwrap();
        let events = driver.subscribe();
        let response = driver
            .begin_request("strict", serde_json::json!({}))
            .unwrap()
            .wait(Duration::from_secs(2))
            .unwrap();
        assert_eq!(response.id, WireId::Integer(1));
        assert_eq!(response.result, Some(serde_json::json!({"accepted": true})));

        let mut malformed = 0;
        while malformed < 8 {
            match events.recv_timeout(Duration::from_secs(1)) {
                Ok(Inbound::Malformed(_)) => malformed += 1,
                Ok(_) => {}
                Err(error) => panic!("missing malformed frame {malformed}: {error}"),
            }
        }
        driver.stop().unwrap();
    }

    #[test]
    fn child_exit_fails_all_pending_waiters() {
        let mut command = Command::new("sh");
        command.args(["-c", "read first; read second; exit 7"]);
        let driver = Driver::spawn(command).unwrap();
        let first = driver.begin_request("one", serde_json::json!({})).unwrap();
        let second = driver.begin_request("two", serde_json::json!({})).unwrap();
        assert!(matches!(
            first.wait(Duration::from_secs(2)),
            Err(RequestError::ChildExited(ChildExit::Exited(Some(7))))
        ));
        assert!(matches!(
            second.wait(Duration::from_secs(2)),
            Err(RequestError::ChildExited(ChildExit::Exited(Some(7))))
        ));
    }

    #[test]
    fn native_identity_is_complete_and_group_isolated() {
        let mut command = Command::new("sh");
        command.args(["-c", "read line; sleep 10"]);
        let driver = Driver::spawn(command).unwrap();
        let identity = driver.identity();
        assert!(identity.pid > 1);
        assert_eq!(identity.pgid, identity.pid as i32);
        assert!(!identity.start_token.is_empty());
        assert_eq!(observe_process(identity.pid).unwrap(), identity);
        assert!(observe_process_group(identity.pgid)
            .unwrap()
            .contains(&identity));
        driver.stop().unwrap();
    }

    #[test]
    fn malformed_or_reused_identity_is_rejected_before_signal_and_can_retry() {
        let malformed = ProcessIdentity {
            pid: 42,
            pgid: 0,
            uid: 1,
            start_token: String::new(),
        };
        assert!(validate_spawn_identity(42, &malformed).is_err());
        assert!(validate_group_target(0).is_err());
        assert!(validate_group_target(1).is_err());
        assert!(observe_process(u32::MAX).is_err());

        let mut command = Command::new("sh");
        command.args(["-c", "read line; sleep 10"]);
        let mut driver = Driver::spawn(command).unwrap();
        let actual = driver.identity();
        driver.identity.start_token.push_str(":reused");
        let error = driver.stop_and_reap(Duration::from_millis(50)).unwrap_err();
        assert!(error.to_string().contains("identity changed"));
        assert!(observe_process(actual.pid).is_ok());

        driver.identity = actual;
        driver.stop_and_reap(Duration::from_millis(100)).unwrap();
    }

    #[test]
    fn persisted_identity_reaper_rejects_reuse_and_reaps_the_owned_group() {
        let mut command = Command::new("sh");
        command.args(["-c", "trap '' TERM; exec tail -f /dev/null"]);
        let driver = Driver::spawn(command).unwrap();
        let identity = driver.identity();
        let mut reused = identity.clone();
        reused.start_token.push_str(":reused");

        let error =
            stop_and_reap_persisted_process_group(&reused, Duration::from_millis(50)).unwrap_err();
        assert!(error.to_string().contains("identity changed"));
        assert_eq!(observe_process(identity.pid).unwrap(), identity);

        stop_and_reap_persisted_process_group(&identity, Duration::from_millis(100)).unwrap();
        assert!(observe_process_group(identity.pgid).unwrap().is_empty());
    }

    #[test]
    fn persisted_identity_reaper_recovers_group_after_leader_exit() {
        let path = capture_path("persisted-orphan");
        let mut command = Command::new("sh");
        command.env("DESCENDANT_PID_FILE", &path).args([
            "-c",
            "sleep 10 </dev/null >/dev/null 2>&1 & child=$!; printf '%s' \"$child\" > \"$DESCENDANT_PID_FILE\"; exit 7",
        ]);
        let driver = Driver::spawn(command).unwrap();
        let identity = driver.identity();
        let descendant = wait_for_pid_file(&path);
        assert_eq!(driver.wait().unwrap(), Some(7));
        assert!(observe_process(identity.pid).is_err());
        assert!(observe_process(descendant).is_ok());

        stop_and_reap_persisted_process_group(&identity, Duration::from_millis(100)).unwrap();

        assert!(observe_process(descendant).is_err());
        assert!(observe_process_group(identity.pgid).unwrap().is_empty());
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn concurrent_stop_callers_share_one_terminal_outcome() {
        let mut command = Command::new("sh");
        command.args(["-c", "trap '' TERM; exec tail -f /dev/null"]);
        let driver = Arc::new(Driver::spawn(command).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let driver = Arc::clone(&driver);
            let barrier = Arc::clone(&barrier);
            workers.push(thread::spawn(move || {
                barrier.wait();
                driver.stop_and_reap(Duration::from_millis(100))
            }));
        }
        barrier.wait();
        let first = workers.remove(0).join().unwrap().unwrap();
        let second = workers.remove(0).join().unwrap().unwrap();
        assert_eq!(first, second);
        assert!(matches!(first, StopOutcome::Terminated(_)));
        assert!(observe_process_group(driver.identity().pgid)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn term_resistant_descendant_is_killed_with_owned_group() {
        let path = std::env::temp_dir().join(format!(
            "zcode-driver-descendant-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        let mut command = Command::new("sh");
        command.env("DESCENDANT_PID_FILE", &path).args([
            "-c",
            "trap '' TERM; sh -c 'trap \"\" TERM; exec tail -f /dev/null' & child=$!; printf '%s' \"$child\" > \"$DESCENDANT_PID_FILE\"; wait",
        ]);
        let driver = Driver::spawn(command).unwrap();
        let descendant = wait_for_pid_file(&path);
        let outcome = driver.stop_and_reap(Duration::from_millis(100)).unwrap();
        assert_eq!(
            outcome,
            StopOutcome::Terminated(ChildExit::Signaled(KILL_SIGNAL))
        );
        assert!(observe_process(descendant).is_err());
        assert!(observe_process_group(driver.identity().pgid)
            .unwrap()
            .is_empty());
        std::fs::remove_file(path).unwrap();
    }

    fn wait_for_pid_file(path: &std::path::Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Ok(contents) = std::fs::read_to_string(path) {
                return contents.parse().unwrap();
            }
            assert!(
                Instant::now() < deadline,
                "descendant pid fixture timed out"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
