use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Proof {
    pub pid: u32,
    pub pgid: i32,
    pub start_token: String,
    pub endpoint_nonce: String,
    pub euid: u32,
    pub fingerprint: String,
    pub live: bool,
    pub descendants: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CleanupResult {
    Recovered(Proof),
    Orphaned(String),
    Failed(String),
    Dead(Proof),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityRecord {
    pub capability: String,
    pub proof: Proof,
    pub created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalRecord {
    pub sequence: u64,
    pub event: String,
    pub result: Option<CleanupResult>,
}

pub fn mutate_proof(proof: &Proof, live: bool, descendants: u32) -> CleanupResult {
    let mut next = proof.clone();
    next.live = live;
    next.descendants = descendants;
    if live && descendants == 0 {
        CleanupResult::Recovered(next)
    } else {
        CleanupResult::Orphaned("live attestation and final Dead proof required".into())
    }
}

pub fn write_durable(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let path = dir.join(name);
    if path.exists() && fs::symlink_metadata(&path)?.file_type().is_symlink() {
        return Err(io::Error::other("refusing symlink"));
    }
    let tmp = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    use std::io::Write;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, &path)?;
    let d = fs::File::open(dir)?;
    d.sync_all()?;
    Ok(())
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Replay append-only state after restart; gaps are fail-closed.
pub fn replay_journal(path: &Path) -> io::Result<Vec<JournalRecord>> {
    let text = fs::read_to_string(path)?;
    let mut records = Vec::new();
    for (index, line) in text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .enumerate()
    {
        let expected = index as u64 + 1;
        let record: JournalRecord = serde_json::from_str(line).map_err(io::Error::other)?;
        if record.sequence != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal sequence gap",
            ));
        }
        records.push(record);
    }
    Ok(records)
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct ShimClient {
    pub control: std::path::PathBuf,
    pub capability: String,
    pub proof: Proof,
}

#[cfg(unix)]
impl ShimClient {
    pub fn connect(
        control: impl Into<std::path::PathBuf>,
        capability: impl Into<String>,
        proof: Proof,
    ) -> Self {
        Self {
            control: control.into(),
            capability: capability.into(),
            proof,
        }
    }
    pub fn request(&self, op: &str) -> io::Result<CleanupResult> {
        use std::io::{BufRead, Write};
        let mut stream = std::os::unix::net::UnixStream::connect(&self.control)?;
        writeln!(
            stream,
            "{}",
            serde_json::json!({"op":op,"capability":self.capability})
        )?;
        stream.flush()?;
        let mut line = String::new();
        std::io::BufReader::new(stream).read_line(&mut line)?;
        let response: serde_json::Value = serde_json::from_str(&line).map_err(io::Error::other)?;
        if response.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                response
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("rejected"),
            ));
        }
        serde_json::from_value(response.get("result").cloned().unwrap_or_default())
            .map_err(io::Error::other)
    }
}

#[cfg(unix)]
pub mod shim {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Write},
        os::unix::{
            io::{FromRawFd, RawFd},
            net::{UnixListener, UnixStream},
        },
        process::{Child, Command, Stdio},
        sync::{Arc, Mutex},
        thread,
    };
    #[derive(Debug, Serialize, Deserialize)]
    struct Request {
        op: String,
        capability: String,
    }
    #[derive(Debug, Serialize, Deserialize)]
    struct Response {
        ok: bool,
        proof: Option<Proof>,
        result: Option<CleanupResult>,
        error: Option<String>,
    }

    pub fn run(
        handshake_fd: RawFd,
        control: &Path,
        state: &Path,
        program: &str,
        args: &[String],
    ) -> io::Result<()> {
        let mut hs = unsafe { std::os::unix::net::UnixStream::from_raw_fd(handshake_fd) };
        let mut token = String::new();
        BufReader::new(hs.try_clone()?).read_line(&mut token)?;
        let token = token.trim().to_string();
        let nonce = format!("{}-{}", std::process::id(), now());
        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
                if libc::setpgid(0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let pgid = child.id() as i32;
        let fingerprint = format!("{}:{}:{}", child.id(), pgid, nonce);
        let proof = Proof {
            pid: child.id(),
            pgid,
            start_token: format!("{}", child.id()),
            endpoint_nonce: nonce,
            euid: unsafe { libc::geteuid() },
            fingerprint,
            live: true,
            descendants: 0,
        };
        let authority = AuthorityRecord {
            capability: token.clone(),
            proof: proof.clone(),
            created_at: now(),
        };
        write_durable(
            state,
            "authority.json",
            serde_json::to_vec(&authority).unwrap().as_slice(),
        )?;
        writeln!(hs, "{}", serde_json::to_string(&proof).unwrap())?;
        hs.flush()?;
        if control.exists() {
            if fs::symlink_metadata(control)?.file_type().is_symlink() {
                return Err(io::Error::other("refusing symlink control socket"));
            }
            let _ = fs::remove_file(control);
        }
        let listener = UnixListener::bind(control)?;
        fs::set_permissions(control, fs::Permissions::from_mode(0o600))?;
        let child = Arc::new(Mutex::new(Some(child)));
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let child = Arc::clone(&child);
            let cap = token.clone();
            let proof = proof.clone();
            let state = state.to_path_buf();
            thread::spawn(move || {
                let _ = handle(stream, &cap, proof, child, &state);
            });
        }
        Ok(())
    }
    fn handle(
        mut stream: UnixStream,
        cap: &str,
        proof: Proof,
        child: Arc<Mutex<Option<Child>>>,
        state: &Path,
    ) -> io::Result<()> {
        let mut line = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut line)?;
        let req: Request = serde_json::from_str(&line).map_err(io::Error::other)?;
        if req.capability != cap {
            writeln!(stream, "{{\"ok\":false,\"error\":\"unauthorized\"}}")?;
            return Ok(());
        }
        let mut observed = proof.clone();
        if let Some(c) = child.lock().unwrap().as_mut() {
            if c.try_wait()?.is_some() {
                observed.live = false;
            }
        } else {
            observed.live = false;
        }
        let result = match req.op.as_str() {
            "attest" => Some(if observed.live {
                CleanupResult::Recovered(observed.clone())
            } else {
                CleanupResult::Orphaned("leader is dead; cleanup requires explicit recovery".into())
            }),
            "cleanup" => {
                let mut g = child.lock().unwrap();
                if let Some(c) = g.as_mut() {
                    unsafe {
                        libc::kill(-(c.id() as i32), libc::SIGTERM);
                    }
                    let _ = c.wait();
                    *g = None;
                }
                let mut p = proof.clone();
                p.live = false;
                p.descendants = 0;
                Some(CleanupResult::Dead(p))
            }
            "shutdown" => return Ok(()),
            _ => Some(CleanupResult::Failed("unknown operation".into())),
        };
        let seq_path = state.join("journal.jsonl");
        let seq = fs::read_to_string(&seq_path)
            .map(|s| s.lines().count() as u64 + 1)
            .unwrap_or(1);
        let record = JournalRecord {
            sequence: seq,
            event: req.op,
            result: result.clone(),
        };
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&seq_path)?;
        fs::set_permissions(&seq_path, fs::Permissions::from_mode(0o600))?;
        f.write_all(format!("{}\n", serde_json::to_string(&record).unwrap()).as_bytes())?;
        f.sync_all()?;
        writeln!(
            stream,
            "{}",
            serde_json::to_string(&Response {
                ok: true,
                proof: Some(observed),
                result,
                error: None
            })
            .unwrap()
        )?;
        stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn descendants_never_recovered() {
        let p = Proof {
            pid: 1,
            pgid: 1,
            start_token: "s".into(),
            endpoint_nonce: "n".into(),
            euid: 1,
            fingerprint: "f".into(),
            live: true,
            descendants: 1,
        };
        assert!(matches!(
            mutate_proof(&p, true, 1),
            CleanupResult::Orphaned(_)
        ));
        assert!(matches!(
            mutate_proof(&p, true, 0),
            CleanupResult::Recovered(_)
        ));
    }

    #[test]
    fn journal_replay_rejects_gaps_and_symlink_authority() {
        let root = std::env::temp_dir().join(format!("zcode-journal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let journal = root.join("journal.jsonl");
        let first = JournalRecord {
            sequence: 1,
            event: "attest".into(),
            result: None,
        };
        fs::write(
            &journal,
            format!("{}\n", serde_json::to_string(&first).unwrap()),
        )
        .unwrap();
        assert_eq!(replay_journal(&journal).unwrap().len(), 1);
        let gap = JournalRecord {
            sequence: 3,
            event: "cleanup".into(),
            result: None,
        };
        fs::write(
            &journal,
            format!(
                "{}\n{}\n",
                serde_json::to_string(&first).unwrap(),
                serde_json::to_string(&gap).unwrap()
            ),
        )
        .unwrap();
        assert!(replay_journal(&journal).is_err());
        let link = root.join("link");
        symlink(&journal, &link).unwrap();
        assert!(write_durable(&root, "link", b"x").is_err());
        let _ = fs::remove_dir_all(root);
    }
}
