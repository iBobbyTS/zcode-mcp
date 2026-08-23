use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

fn digest(parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update([0]);
    }
    format!("{:x}", h.finalize())
}
fn random_hex(n: usize) -> io::Result<String> {
    let mut b = vec![0; n];
    std::io::Read::read_exact(&mut fs::File::open("/dev/urandom")?, &mut b)?;
    Ok(b.iter().map(|v| format!("{v:02x}")).collect())
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Handshake {
    pub capability: String,
    pub nonce: String,
    pub job_id: String,
    pub target_digest: String,
    pub issuer: String,
}
#[derive(Debug, Clone)]
pub struct DaemonAuthority {
    handshake: Handshake,
    target: String,
}
impl DaemonAuthority {
    pub fn for_target(job: impl Into<String>, target: impl Into<String>) -> io::Result<Self> {
        let job = job.into();
        let target = target.into();
        let c = random_hex(32)?;
        let n = random_hex(16)?;
        let t = digest(&[&target]);
        let i = digest(&[&c, &n, &job, &t]);
        Ok(Self {
            handshake: Handshake {
                capability: c,
                nonce: n,
                job_id: job,
                target_digest: t,
                issuer: i,
            },
            target,
        })
    }
    pub fn handshake(&self) -> Handshake {
        self.handshake.clone()
    }
    pub fn target(&self) -> &str {
        &self.target
    }
}
pub fn issue_handshake() -> io::Result<Handshake> {
    Ok(Handshake {
        capability: random_hex(32)?,
        nonce: random_hex(16)?,
        job_id: String::new(),
        target_digest: String::new(),
        issuer: String::new(),
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
    pub job_id: String,
    pub target_digest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalRecord {
    pub sequence: u64,
    pub event: String,
    pub result: Option<CleanupResult>,
}
pub fn transition(proof: &Proof, live: bool, desc: u32, terminal: bool) -> CleanupResult {
    let mut p = proof.clone();
    p.live = live;
    p.descendants = desc;
    if terminal && !live && desc == 0 {
        CleanupResult::Dead(p)
    } else if live && desc == 0 {
        CleanupResult::Recovered(p)
    } else {
        CleanupResult::Orphaned("independent whole-group attestation required".into())
    }
}
pub fn mutate_proof(p: &Proof, live: bool, desc: u32) -> CleanupResult {
    transition(p, live, desc, false)
}
fn group_state(p: &Proof) -> io::Result<(bool, u32)> {
    let x = unsafe { libc::kill(p.pid as i32, 0) };
    if x < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ESRCH) {
            return Err(e);
        }
    }
    let x = unsafe { libc::kill(-p.pgid, 0) };
    let live = if x == 0 {
        true
    } else {
        let e = io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ESRCH) {
            false
        } else {
            return Err(e);
        }
    };
    #[cfg(target_os = "linux")]
    {
        let mut d = 0;
        if let Ok(es) = fs::read_dir("/proc") {
            for e in es.flatten() {
                if let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() {
                    if let Ok(s) = fs::read_to_string(format!("/proc/{pid}/stat")) {
                        if let Some((_, r)) = s.rsplit_once(") ") {
                            let f: Vec<_> = r.split_whitespace().collect();
                            if f.len() > 3
                                && f[2].parse::<i32>().ok() == Some(p.pgid)
                                && pid as u32 != p.pid
                            {
                                d += 1
                            }
                        }
                    }
                }
            }
        }
        return Ok((live, d));
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok((live, 0))
    }
}
pub fn cleanup_group(
    p: &Proof,
    c: &mut std::process::Child,
    t: Duration,
) -> io::Result<CleanupResult> {
    let (live, d) = group_state(p)?;
    if !live {
        return Ok(transition(p, false, d, true));
    }
    unsafe { libc::kill(-p.pgid, libc::SIGTERM) };
    let end = std::time::Instant::now() + t;
    while std::time::Instant::now() < end {
        let _ = c.try_wait()?;
        let (l, d) = group_state(p)?;
        if !l {
            let mut q = p.clone();
            q.live = false;
            q.descendants = d;
            return Ok(transition(&q, false, d, true));
        }
        std::thread::sleep(Duration::from_millis(10))
    }
    unsafe { libc::kill(-p.pgid, libc::SIGKILL) };
    let end = std::time::Instant::now() + t;
    while std::time::Instant::now() < end {
        let _ = c.try_wait()?;
        let (l, d) = group_state(p)?;
        if !l {
            let mut q = p.clone();
            q.live = false;
            q.descendants = d;
            return Ok(transition(&q, false, d, true));
        }
        std::thread::sleep(Duration::from_millis(10))
    }
    Ok(CleanupResult::Orphaned(
        "post-kill Dead proof unavailable".into(),
    ))
}
fn check_path(d: &Path) -> io::Result<()> {
    fs::create_dir_all(d)?;
    let mut p = PathBuf::new();
    for c in d.components() {
        p.push(c);
        if let Ok(m) = fs::symlink_metadata(&p) {
            if m.file_type().is_symlink() && p == d {
                return Err(io::Error::other("symlink path component"));
            }
        }
    }
    Ok(())
}
pub fn write_durable(d: &Path, n: &str, b: &[u8]) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    check_path(d)?;
    let p = d.join(n);
    if p.exists() && fs::symlink_metadata(&p)?.file_type().is_symlink() {
        return Err(io::Error::other("refusing symlink"));
    }
    let tmp = d.join(format!(".{n}.tmp-{}-{}", std::process::id(), now()));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    f.write_all(b)?;
    f.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, &p)?;
    fs::File::open(d)?.sync_all()?;
    Ok(())
}
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn replay_journal(p: &Path) -> io::Result<Vec<JournalRecord>> {
    let s = fs::read_to_string(p)?;
    let mut v = Vec::new();
    for (i, l) in s.lines().filter(|x| !x.trim().is_empty()).enumerate() {
        let r: JournalRecord = serde_json::from_str(l).map_err(io::Error::other)?;
        if r.sequence != i as u64 + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal sequence gap",
            ));
        }
        v.push(r)
    }
    Ok(v)
}

fn append_journal(state: &Path, event: &str, result: Option<CleanupResult>) -> io::Result<()> {
    use std::io::Write;
    let path = state.join("journal.jsonl");
    let seq = if path.exists() {
        replay_journal(&path)?.len() as u64 + 1
    } else {
        1
    };
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    let record = JournalRecord {
        sequence: seq,
        event: event.into(),
        result,
    };
    f.write_all(format!("{}\n", serde_json::to_string(&record).unwrap()).as_bytes())?;
    f.sync_all()?;
    fs::File::open(state)?.sync_all()
}
#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct ShimClient {
    pub control: PathBuf,
    pub capability: String,
    pub proof: Proof,
}
#[cfg(unix)]
impl ShimClient {
    pub fn connect(c: impl Into<PathBuf>, cap: impl Into<String>, p: Proof) -> Self {
        Self {
            control: c.into(),
            capability: cap.into(),
            proof: p,
        }
    }
    pub fn request(&self, op: &str) -> io::Result<CleanupResult> {
        use std::io::{BufRead, Write};
        let mut s = std::os::unix::net::UnixStream::connect(&self.control)?;
        writeln!(
            s,
            "{}",
            serde_json::json!({"op":op,"capability":self.capability,"pid":self.proof.pid,"pgid":self.proof.pgid,"fingerprint":self.proof.fingerprint,"endpoint_nonce":self.proof.endpoint_nonce})
        )?;
        s.flush()?;
        let mut l = String::new();
        std::io::BufReader::new(s).read_line(&mut l)?;
        let v: serde_json::Value = serde_json::from_str(&l).map_err(io::Error::other)?;
        if v.get("ok").and_then(|x| x.as_bool()) != Some(true) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "rejected"));
        }
        serde_json::from_value(v["result"].clone()).map_err(io::Error::other)
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
    #[derive(Serialize, Deserialize)]
    struct R {
        op: String,
        capability: String,
        pid: u32,
        pgid: i32,
        fingerprint: String,
        endpoint_nonce: String,
    }
    #[derive(Serialize)]
    struct O {
        ok: bool,
        result: Option<CleanupResult>,
    }
    pub fn run(
        fd: RawFd,
        control: &Path,
        state: &Path,
        program: &str,
        args: &[String],
    ) -> io::Result<()> {
        let mut hs = unsafe { UnixStream::from_raw_fd(fd) };
        let mut l = String::new();
        BufReader::new(hs.try_clone()?).read_line(&mut l)?;
        let g: Handshake = serde_json::from_str(l.trim()).map_err(io::Error::other)?;
        if g.job_id.is_empty()
            || g.target_digest != digest(&[program])
            || g.issuer != digest(&[&g.capability, &g.nonce, &g.job_id, &g.target_digest])
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "daemon-owned target handshake required",
            ));
        }
        check_path(state)?;
        let ap = state.join("authority.json");
        let mut co = None;
        let proof;
        if ap.exists() {
            let a: AuthorityRecord =
                serde_json::from_slice(&fs::read(&ap)?).map_err(io::Error::other)?;
            if a.capability != g.capability || a.job_id != g.job_id {
                return Err(io::Error::other("authority conflict"));
            }
            proof = a.proof
        } else {
            let mut c = Command::new(program);
            c.args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            let ch = c.spawn()?;
            let pg = ch.id() as i32;
            proof = Proof {
                pid: ch.id(),
                pgid: pg,
                start_token: ch.id().to_string(),
                endpoint_nonce: g.nonce.clone(),
                euid: unsafe { libc::geteuid() },
                fingerprint: digest(&[&ch.id().to_string(), &pg.to_string(), &g.nonce]),
                live: true,
                descendants: 0,
            };
            write_durable(
                state,
                "authority.json",
                &serde_json::to_vec(&AuthorityRecord {
                    capability: g.capability.clone(),
                    proof: proof.clone(),
                    created_at: now(),
                    job_id: g.job_id.clone(),
                    target_digest: g.target_digest.clone(),
                })
                .unwrap(),
            )?;
            co = Some(ch)
        }
        writeln!(hs, "{}", serde_json::to_string(&proof).unwrap())?;
        hs.flush()?;
        let _ = fs::remove_file(control);
        let li = UnixListener::bind(control)?;
        let child = Arc::new(Mutex::new(co));
        let lock = Arc::new(Mutex::new(()));
        for st in li.incoming() {
            let Ok(st) = st else { continue };
            let c = Arc::clone(&child);
            let k = Arc::clone(&lock);
            let p = proof.clone();
            let cap = g.capability.clone();
            let state_path = state.to_path_buf();
            thread::spawn(move || {
                let _ = handle(st, &cap, p, c, k, &state_path);
            });
        }
        Ok(())
    }
    fn handle(
        mut s: UnixStream,
        cap: &str,
        p: Proof,
        c: Arc<Mutex<Option<Child>>>,
        k: Arc<Mutex<()>>,
        state: &Path,
    ) -> io::Result<()> {
        let mut l = String::new();
        BufReader::new(s.try_clone()?).read_line(&mut l)?;
        let r: R = serde_json::from_str(&l).map_err(io::Error::other)?;
        if r.capability != cap
            || r.pid != p.pid
            || r.pgid != p.pgid
            || r.fingerprint != p.fingerprint
            || r.endpoint_nonce != p.endpoint_nonce
        {
            writeln!(s, "{{\"ok\":false,\"error\":\"unauthorized\"}}")?;
            return Ok(());
        }
        let (live, d) = group_state(&p)?;
        let x = match r.op.as_str() {
            "attest" => transition(&p, live, d, false),
            "cleanup" => {
                let _g = k.lock().unwrap();
                if let Some(ch) = c.lock().unwrap().as_mut() {
                    cleanup_group(&p, ch, Duration::from_millis(100))?
                } else {
                    CleanupResult::Orphaned("restart requires live shim attestation".into())
                }
            }
            _ => CleanupResult::Failed("unknown operation".into()),
        };
        append_journal(state, &r.op, Some(x.clone()))?;
        writeln!(
            s,
            "{}",
            serde_json::to_string(&O {
                ok: true,
                result: Some(x)
            })
            .unwrap()
        )?;
        s.flush()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn symmetry() {
        let p = Proof {
            pid: 1,
            pgid: 1,
            start_token: "s".into(),
            endpoint_nonce: "n".into(),
            euid: 1,
            fingerprint: "f".into(),
            live: true,
            descendants: 0,
        };
        assert!(matches!(
            transition(&p, true, 1, false),
            CleanupResult::Orphaned(_)
        ));
        assert!(matches!(
            transition(&p, false, 0, true),
            CleanupResult::Dead(_)
        ));
    }
}
