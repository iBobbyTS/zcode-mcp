use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Handshake {
    pub capability: String,
    pub nonce: String,
}

/// Called by the daemon (never by the shim) to create a one-use inherited grant.
pub fn issue_handshake() -> io::Result<Handshake> {
    let mut bytes = [0u8; 32];
    let mut random = fs::File::open("/dev/urandom")?;
    std::io::Read::read_exact(&mut random, &mut bytes)?;
    let hex = |b: &[u8]| b.iter().map(|v| format!("{v:02x}")).collect::<String>();
    Ok(Handshake {
        capability: hex(&bytes),
        nonce: hex(&bytes[..16]),
    })
}

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

pub fn cleanup_group(
    proof: &Proof,
    child: &mut std::process::Child,
    timeout: std::time::Duration,
) -> io::Result<CleanupResult> {
    unsafe {
        libc::kill(-(proof.pgid), libc::SIGTERM);
    }
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let leader_dead = child.try_wait()?.is_some();
        let group_live = unsafe { libc::kill(-(proof.pgid), 0) == 0 };
        if leader_dead && !group_live {
            let mut p = proof.clone();
            p.live = false;
            p.descendants = 0;
            return Ok(CleanupResult::Dead(p));
        }
        if std::time::Instant::now() >= deadline {
            return Ok(CleanupResult::Orphaned(
                "cleanup deadline exceeded; process group remains live".into(),
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

pub fn write_durable(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
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
        .custom_flags(libc::O_NOFOLLOW)
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

fn append_journal(state: &Path, event: &str, result: Option<CleanupResult>) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let seq_path = state.join("journal.jsonl");
    let seq = if seq_path.exists() {
        replay_journal(&seq_path)?.len() as u64 + 1
    } else {
        1
    };
    let record = JournalRecord {
        sequence: seq,
        event: event.to_string(),
        result,
    };
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&seq_path)?;
    fs::set_permissions(&seq_path, fs::Permissions::from_mode(0o600))?;
    f.write_all(format!("{}\n", serde_json::to_string(&record).unwrap()).as_bytes())?;
    f.sync_all()?;
    fs::File::open(state)?.sync_all()
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
            serde_json::json!({"op":op,"capability":self.capability,"pid":self.proof.pid,"pgid":self.proof.pgid,"fingerprint":self.proof.fingerprint,"endpoint_nonce":self.proof.endpoint_nonce})
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
        pid: u32,
        pgid: i32,
        fingerprint: String,
        endpoint_nonce: String,
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
        let mut line = String::new();
        BufReader::new(hs.try_clone()?).read_line(&mut line)?;
        let handshake: Handshake = serde_json::from_str(line.trim()).map_err(io::Error::other)?;
        if handshake.capability.len() < 32 || handshake.nonce.len() < 16 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid daemon handshake",
            ));
        }
        fs::create_dir_all(state)?;
        let consumed = state.join("handshake.used");
        if consumed.exists() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "replayed handshake",
            ));
        }
        write_durable(state, "handshake.used", handshake.nonce.as_bytes())?;
        let token = handshake.capability;
        let nonce = handshake.nonce;
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
        let journal_lock = Arc::new(Mutex::new(()));
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let child = Arc::clone(&child);
            let cap = token.clone();
            let proof = proof.clone();
            let state = state.to_path_buf();
            let journal_lock = Arc::clone(&journal_lock);
            thread::spawn(move || {
                let _ = handle(stream, &cap, proof, child, &state, journal_lock);
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
        journal_lock: Arc<Mutex<()>>,
    ) -> io::Result<()> {
        let mut line = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut line)?;
        let req: Request = serde_json::from_str(&line).map_err(io::Error::other)?;
        if req.capability != cap
            || req.pid != proof.pid
            || req.pgid != proof.pgid
            || req.fingerprint != proof.fingerprint
            || req.endpoint_nonce != proof.endpoint_nonce
        {
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
                let _journal_guard = journal_lock.lock().unwrap();
                append_journal(state, "cleanup_requested", None)?;
                drop(_journal_guard);
                let mut g = child.lock().unwrap();
                if let Some(c) = g.as_mut() {
                    let result = cleanup_group(&proof, c, std::time::Duration::from_secs(3))?;
                    if matches!(result, CleanupResult::Dead(_)) {
                        *g = None;
                    }
                    Some(result)
                } else {
                    Some(CleanupResult::Dead({
                        let mut p = proof.clone();
                        p.live = false;
                        p.descendants = 0;
                        p
                    }))
                }
            }
            "shutdown" => return Ok(()),
            _ => Some(CleanupResult::Failed("unknown operation".into())),
        };
        let _journal_guard = journal_lock.lock().unwrap();
        append_journal(state, &req.op, result.clone())?;
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
