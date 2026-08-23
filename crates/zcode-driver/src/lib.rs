#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::{
    io::{self, BufReader, Read, Write},
    process::{Child, ChildStdin, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc, Condvar, Mutex,
    },
    thread,
    time::Duration,
};
use zcode_protocol::{
    classify_lifecycle, encode, parse_line, LifecycleOrder, RequestEnvelope, WireMessage,
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

#[derive(Debug)]
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
}

pub struct Driver {
    stdin: Arc<Mutex<ChildStdin>>,
    incoming: Mutex<Receiver<Inbound>>,
    child: Arc<Mutex<Option<Child>>>,
    termination: Arc<(Mutex<Option<ChildExit>>, Condvar)>,
    next_id: AtomicU64,
    stopped: AtomicBool,
    identity: ProcessIdentity,
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
        let identity = observe_identity(child.id()).unwrap_or_else(|_| ProcessIdentity {
            pid: child.id(),
            pgid: unsafe { libc::getpgid(child.id() as i32) },
            uid: unsafe { libc::geteuid() },
            start_token: String::new(),
        });
        let stdin = Arc::new(Mutex::new(child.stdin.take().expect("piped stdin")));
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let (tx, rx) = mpsc::channel();
        let read_tx = tx.clone();
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
        thread::spawn(move || monitor_child(monitor_ref, tx, monitor_termination, read_done_rx));
        Ok(Self {
            stdin,
            incoming: Mutex::new(rx),
            child: child_ref,
            termination,
            next_id: AtomicU64::new(1),
            stopped: AtomicBool::new(false),
            identity,
        })
    }
    pub fn send_request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> std::io::Result<serde_json::Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.send(&RequestEnvelope {
            id: id.into(),
            method: method.into(),
            params,
        })?;
        Ok(id.into())
    }
    pub fn send<T: serde::Serialize>(&self, value: &T) -> std::io::Result<()> {
        let mut input = self.stdin.lock().unwrap();
        writeln!(input, "{}", encode(value).map_err(std::io::Error::other)?)?;
        input.flush()
    }
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Inbound, RecvTimeoutError> {
        self.incoming.lock().unwrap().recv_timeout(timeout)
    }
    pub fn stop(&self) -> std::io::Result<()> {
        self.stop_and_reap(Duration::from_secs(1))
    }
    pub fn identity(&self) -> ProcessIdentity {
        self.identity.clone()
    }
    pub fn stop_and_reap(&self, timeout: Duration) -> std::io::Result<()> {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let mut child = self.child.lock().unwrap();
        let Some(process) = child.as_mut() else {
            return Ok(());
        };
        if process.try_wait()?.is_some() {
            return Ok(());
        }
        let observed = observe_identity(process.id());
        if !self.identity.start_token.is_empty() && observed.as_ref().ok() != Some(&self.identity) {
            return Err(io::Error::other(
                "process identity changed; refusing signal",
            ));
        }
        #[cfg(unix)]
        unsafe {
            if libc::kill(-(self.identity.pgid), libc::SIGTERM) != 0 {
                // The Driver still owns the live Child handle. If the group
                // probe is unavailable, terminate only that known leader;
                // restart cleanup remains fail-closed on the missing proof.
                process.kill()?;
            }
        }
        #[cfg(unix)]
        if self.identity.pgid <= 1 {
            process.kill()?;
        }
        #[cfg(not(unix))]
        process.kill()?;
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if process.try_wait()?.is_some() {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        #[cfg(unix)]
        unsafe {
            if libc::kill(-(self.identity.pgid), libc::SIGKILL) != 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err(io::Error::last_os_error());
            }
        }
        process.wait().map(|_| ())
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

fn observe_identity(pid: u32) -> io::Result<ProcessIdentity> {
    #[cfg(unix)]
    {
        let output = Command::new("ps")
            .args(["-o", "pid=,pgid=,uid=,lstart=", "-p"])
            .arg(pid.to_string())
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other("unable to observe process identity"));
        }
        let line = String::from_utf8_lossy(&output.stdout);
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 4 {
            return Err(io::Error::other("incomplete process identity"));
        }
        let parsed_pid = fields[0].parse().map_err(io::Error::other)?;
        let pgid = fields[1].parse().map_err(io::Error::other)?;
        let uid = fields[2].parse().map_err(io::Error::other)?;
        Ok(ProcessIdentity {
            pid: parsed_pid,
            pgid,
            uid,
            start_token: fields[3..].join(" "),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(ProcessIdentity {
            pid,
            pgid: pid as i32,
            uid: 0,
            start_token: pid.to_string(),
        })
    }
}

fn drain_stderr(mut stderr: impl Read + Send + 'static) {
    let _ = io::copy(&mut stderr, &mut io::sink());
}
impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.stop();
    }
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
                            let order = classify_lifecycle(&event.method, turn_active);
                            if event.method == "turn/started"
                                && matches!(order, LifecycleOrder::InOrder)
                            {
                                turn_active = true;
                            }
                            if matches!(event.method.as_str(), "turn/completed" | "turn/failed")
                                && matches!(order, LifecycleOrder::InOrder)
                            {
                                turn_active = false;
                            }
                            if tx
                                .send(Inbound::Lifecycle {
                                    sequence,
                                    method: event.method.clone(),
                                    order,
                                })
                                .is_err()
                            {
                                return;
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
    loop {
        let status = {
            let mut guard = child_ref.lock().unwrap();
            match guard.as_mut() {
                Some(child) => match child.try_wait() {
                    Ok(status) => status,
                    Err(_) => {
                        let _ = read_done.recv_timeout(Duration::from_secs(1));
                        publish_child_exit(ChildExit::Unknown, &tx, &termination);
                        return;
                    }
                },
                None => None,
            }
        };
        if let Some(status) = status {
            let _ = read_done.recv_timeout(Duration::from_secs(1));
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
    #[test]
    fn dispatch_interleaved() {
        let mut c = Command::new("sh");
        c.args(["-c", "read line; printf '%s\\n' '{\"method\":\"turn/started\",\"params\":{}}' '{\"method\":\"permission/request\",\"params\":{}}' '{\"id\":1,\"result\":{\"ok\":true}}' '{\"method\":\"turn/completed\",\"params\":{}}'"]);
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
            "printf '%s\\n' '{\"method\":\"turn/completed\",\"params\":{}}' '{\"method\":\"turn/started\",\"params\":{}}'",
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
        d.send_request("probe", serde_json::json!({})).unwrap();
        assert!(matches!(
            d.recv_timeout(Duration::from_secs(3)),
            Ok(Inbound::Message(WireMessage::Response(response)))
                if response.id == serde_json::json!(1)
        ));
        d.stop().unwrap();
    }
}
