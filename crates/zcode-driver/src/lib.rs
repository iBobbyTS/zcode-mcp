#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, Receiver, RecvTimeoutError, Sender},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use zcode_protocol::{encode, parse_line, RequestEnvelope, WireMessage};

#[derive(Debug)]
pub enum Inbound {
    Message(WireMessage),
    Malformed(String),
    ChildExited(Option<i32>),
}

pub struct Driver {
    stdin: Arc<Mutex<ChildStdin>>,
    incoming: Mutex<Receiver<Inbound>>,
    child: Mutex<Option<Child>>,
    next_id: AtomicU64,
    stopped: AtomicBool,
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
        let stdin = Arc::new(Mutex::new(child.stdin.take().expect("piped stdin")));
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || read_loop(stdout, tx));
        Ok(Self {
            stdin,
            incoming: Mutex::new(rx),
            child: Mutex::new(Some(child)),
            next_id: AtomicU64::new(1),
            stopped: AtomicBool::new(false),
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
        if self.stopped.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        if let Some(child) = self.child.lock().unwrap().as_mut() {
            #[cfg(unix)]
            unsafe {
                let _ = libc::kill(-(child.id() as i32), libc::SIGTERM);
            }
            #[cfg(not(unix))]
            let _ = child.kill();
            #[cfg(unix)]
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }
    pub fn wait(&self) -> std::io::Result<Option<i32>> {
        if let Some(child) = self.child.lock().unwrap().as_mut() {
            return Ok(child.wait()?.code());
        }
        Ok(None)
    }
}
impl Drop for Driver {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn read_loop(stdout: impl std::io::Read + Send + 'static, tx: Sender<Inbound>) {
    for line in BufReader::new(stdout).lines() {
        match line {
            Ok(line) => match parse_line(&line) {
                Ok(msg) => {
                    if tx.send(Inbound::Message(msg)).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    if tx.send(Inbound::Malformed(format!("{e:?}"))).is_err() {
                        return;
                    }
                }
            },
            Err(_) => break,
        }
    }
    let _ = tx.send(Inbound::ChildExited(None));
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
        for _ in 0..4 {
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
}
