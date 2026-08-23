//! Fail-closed supervisor authority and process-group attestation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
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

#[allow(dead_code)]
fn random_hex(n: usize) -> io::Result<String> {
    let mut b = vec![0; n];
    fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
    Ok(b.iter().map(|v| format!("{v:02x}")).collect())
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Handshake {
    pub capability: String,
    pub nonce: String,
    pub job_id: String,
    pub target_digest: String,
    /// Opaque daemon-issued value. It is deliberately not derivable from the
    /// public handshake fields; the shim accepts it only when the exact grant
    /// has already been installed in the daemon-owned state directory.
    pub issuer: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DaemonAuthority {
    handshake: Handshake,
    target: String,
}

#[allow(dead_code)]
impl DaemonAuthority {
    /// Build an opaque grant. This does not authorize a shim by itself;
    /// `persist_grant` is the daemon-owned publication seam and the shim
    /// requires that exact record before accepting the inherited handshake.
    pub(crate) fn for_target(
        job: impl Into<String>,
        target: impl Into<String>,
    ) -> io::Result<Self> {
        let job = job.into();
        let target = target.into();
        if job.is_empty() || target.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty grant field",
            ));
        }
        Ok(Self {
            handshake: Handshake {
                capability: random_hex(32)?,
                nonce: random_hex(16)?,
                job_id: job,
                target_digest: digest(&[&target]),
                issuer: random_hex(32)?,
            },
            target,
        })
    }

    pub(crate) fn handshake(&self) -> Handshake {
        self.handshake.clone()
    }

    pub(crate) fn target(&self) -> &str {
        &self.target
    }

    /// Publish the exact grant before starting the shim. Publication is
    /// exclusive and durable; a second grant cannot replace an existing one.
    pub(crate) fn persist_grant(&self, state: &Path) -> io::Result<()> {
        check_path(state)?;
        write_durable(
            state,
            "grant.json",
            &serde_json::to_vec(&self.handshake).map_err(io::Error::other)?,
        )
    }
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

/// Unknown observations are represented separately from a measured zero.
/// Callers cannot accidentally turn an unsupported platform result into a
/// successful recovery or terminal proof.
pub fn transition_observed(
    proof: &Proof,
    live: Option<bool>,
    descendants: Option<u32>,
    terminal: bool,
) -> CleanupResult {
    let (Some(live), Some(desc)) = (live, descendants) else {
        return CleanupResult::Orphaned("independent whole-group observation unknown".into());
    };
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

pub fn transition(proof: &Proof, live: bool, desc: u32, terminal: bool) -> CleanupResult {
    transition_observed(proof, Some(live), Some(desc), terminal)
}

pub fn mutate_proof(p: &Proof, live: bool, desc: u32) -> CleanupResult {
    transition(p, live, desc, false)
}

pub fn mutate_terminal(p: &Proof, live: bool, desc: u32) -> CleanupResult {
    transition(p, live, desc, true)
}

#[derive(Debug, Clone)]
struct Observation {
    proof: Proof,
    descendants: Option<u32>,
}

fn process_start_token(p: &Proof) -> io::Result<String> {
    #[cfg(target_os = "linux")]
    {
        let text = fs::read_to_string(format!("/proc/{}/stat", p.pid))?;
        let rest = text
            .rsplit_once(") ")
            .ok_or_else(|| io::Error::other("invalid process stat"))?
            .1;
        let token = rest
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| io::Error::other("missing process start identity"))?;
        return Ok(token.to_owned());
    }
    #[cfg(target_os = "macos")]
    {
        // Darwin's process start-time API is not exposed consistently by libc
        // across SDKs. The shim's independent pid/pgid/euid observation is
        // folded into a stable token and checked on every reconnect.
        return Ok(digest(&[
            &p.pid.to_string(),
            &p.pgid.to_string(),
            &p.euid.to_string(),
        ]));
    }
    #[allow(unreachable_code)]
    Err(io::Error::other("unsupported process identity adapter"))
}

fn descendants_for_group(p: &Proof) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        let entries = fs::read_dir("/proc").ok()?;
        let mut count = 0;
        for entry in entries.flatten() {
            let pid = entry.file_name().to_string_lossy().parse::<i32>().ok()?;
            let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let rest = stat.rsplit_once(") ")?.1;
            let fields: Vec<_> = rest.split_whitespace().collect();
            if fields.get(2)?.parse::<i32>().ok() == Some(p.pgid) && pid as u32 != p.pid {
                count += 1;
            }
        }
        return Some(count);
    }
    #[cfg(target_os = "macos")]
    {
        let output = std::process::Command::new("/bin/ps")
            .args(["-axo", "pid=,pgid="])
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let mut count = 0;
        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let mut fields = line.split_whitespace();
            let pid = fields.next()?.parse::<u32>().ok()?;
            let pgid = fields.next()?.parse::<i32>().ok()?;
            if pgid == p.pgid && pid != p.pid {
                count += 1;
            }
        }
        return Some(count);
    }
    #[allow(unreachable_code)]
    None
}

fn observe_group(p: &Proof) -> io::Result<Observation> {
    if p.pid == 0 || p.pgid <= 0 || p.endpoint_nonce.is_empty() || p.fingerprint.is_empty() {
        return Err(io::Error::other("incomplete persisted proof"));
    }
    let expected_fingerprint = digest(&[
        &p.pid.to_string(),
        &p.pgid.to_string(),
        &p.start_token,
        &p.endpoint_nonce,
        &p.euid.to_string(),
    ]);
    if p.fingerprint != expected_fingerprint {
        return Err(io::Error::other("persisted fingerprint mismatch"));
    }
    let mut leader_alive = match unsafe { libc::kill(p.pid as i32, 0) } {
        0 => true,
        -1 => match io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => false,
            Some(libc::EPERM) => return Err(io::Error::other("leader liveness ambiguous (EPERM)")),
            _ => return Err(io::Error::last_os_error()),
        },
        _ => true,
    };
    let group_alive = match unsafe { libc::kill(-p.pgid, 0) } {
        0 => true,
        -1 => match io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => false,
            Some(libc::EPERM) if !leader_alive => {
                // On Darwin a reaped leader can leave a transient EPERM for
                // the group probe. Independent membership enumeration
                // disambiguates only the proven-empty case.
                match descendants_for_group(p) {
                    Some(0) => false,
                    Some(_) => true,
                    None => return Err(io::Error::other("group liveness ambiguous (EPERM)")),
                }
            }
            // A live, identity-checked leader proves the group is live even
            // when the group-wide probe itself is permission-limited.
            Some(libc::EPERM) => true,
            _ => return Err(io::Error::last_os_error()),
        },
        _ => true,
    };
    let euid = unsafe { libc::geteuid() };
    if euid != p.euid {
        return Err(io::Error::other("effective uid changed"));
    }
    if leader_alive {
        let current_pgid = unsafe { libc::getpgid(p.pid as i32) };
        if current_pgid < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                leader_alive = false;
            } else {
                return Err(io::Error::last_os_error());
            }
        } else if current_pgid != p.pgid {
            return Err(io::Error::other("leader process group changed"));
        }
    }
    if leader_alive {
        let current = process_start_token(p)?;
        if current != p.start_token {
            return Err(io::Error::other("process start identity changed"));
        }
    }
    let descendants = if group_alive {
        descendants_for_group(p)
    } else {
        Some(0)
    };
    let mut proof = p.clone();
    proof.live = group_alive;
    proof.descendants = descendants.unwrap_or(u32::MAX);
    Ok(Observation { proof, descendants })
}

fn bind_session_nonce(mut proof: Proof, nonce: &str) -> Proof {
    proof.endpoint_nonce = nonce.to_owned();
    proof.fingerprint = digest(&[
        &proof.pid.to_string(),
        &proof.pgid.to_string(),
        &proof.start_token,
        &proof.endpoint_nonce,
        &proof.euid.to_string(),
    ]);
    proof
}

pub fn cleanup_group(p: &Proof, c: &mut Child, t: Duration) -> io::Result<CleanupResult> {
    cleanup_group_with_child(p, Some(c), t)
}

fn cleanup_group_with_child(
    p: &Proof,
    mut child: Option<&mut Child>,
    t: Duration,
) -> io::Result<CleanupResult> {
    let initial = observe_group(p)?;
    if !initial.proof.live {
        return Ok(transition_observed(
            &initial.proof,
            Some(false),
            initial.descendants,
            true,
        ));
    }
    if initial.descendants.is_none() {
        return Ok(CleanupResult::Orphaned(
            "descendant observation unknown".into(),
        ));
    }
    if unsafe { libc::kill(-p.pgid, libc::SIGTERM) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut end = std::time::Instant::now() + t;
    while std::time::Instant::now() < end {
        if let Some(child) = child.as_deref_mut() {
            let _ = child.try_wait()?;
        }
        let current = observe_group(p)?;
        if !current.proof.live {
            return Ok(transition_observed(
                &current.proof,
                Some(false),
                current.descendants,
                true,
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if unsafe { libc::kill(-p.pgid, libc::SIGKILL) } != 0 {
        return Err(io::Error::last_os_error());
    }
    end = std::time::Instant::now() + t;
    while std::time::Instant::now() < end {
        if let Some(child) = child.as_deref_mut() {
            let _ = child.try_wait()?;
        }
        let current = observe_group(p)?;
        if !current.proof.live {
            return Ok(transition_observed(
                &current.proof,
                Some(false),
                current.descendants,
                true,
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Ok(CleanupResult::Orphaned(
        "post-kill Dead proof unavailable".into(),
    ))
}

fn check_path(d: &Path) -> io::Result<()> {
    if d.as_os_str().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty state path",
        ));
    }
    let mut current = PathBuf::new();
    for component in d.components() {
        match component {
            Component::RootDir => current.push("/"),
            Component::CurDir => continue,
            Component::ParentDir => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "parent component is not allowed",
                ))
            }
            Component::Normal(name) => current.push(name),
            Component::Prefix(_) => current.push(component.as_os_str()),
        }
        match fs::symlink_metadata(&current) {
            Ok(meta) => {
                if meta.file_type().is_symlink() {
                    return Err(io::Error::other("symlink path component"));
                }
                if !meta.is_dir() {
                    return Err(io::Error::other("state component is not a directory"));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                fs::set_permissions(&current, fs::Permissions::from_mode(0o700))?;
            }
            Err(error) => return Err(error),
        }
    }
    fs::set_permissions(d, fs::Permissions::from_mode(0o700))
}

fn ensure_name(name: &str) -> io::Result<()> {
    if name.is_empty() || name.contains('/') || name == "." || name == ".." {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid durable name",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurableFault {
    None,
    Read,
    Write,
}

static DURABLE_FAULT: OnceLock<Mutex<DurableFault>> = OnceLock::new();

pub fn set_durable_fault(fault: DurableFault) {
    *DURABLE_FAULT
        .get_or_init(|| Mutex::new(DurableFault::None))
        .lock()
        .unwrap() = fault;
}

fn fault(kind: DurableFault) -> io::Result<()> {
    if *DURABLE_FAULT
        .get_or_init(|| Mutex::new(DurableFault::None))
        .lock()
        .unwrap()
        == kind
    {
        return Err(io::Error::other("injected durable I/O failure"));
    }
    Ok(())
}

fn open_read_nofollow(path: &Path) -> io::Result<fs::File> {
    fault(DurableFault::Read)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if meta.permissions().mode() & 0o777 != 0o600 || meta.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::other("durable file ownership or mode"));
    }
    Ok(file)
}

/// Publish a mode-0600 record with no replacement semantics. A hard-link from
/// the synced temporary inode gives an atomic create-only commit; the parent
/// directory is then synced before returning.
pub fn write_durable(d: &Path, n: &str, b: &[u8]) -> io::Result<()> {
    ensure_name(n)?;
    check_path(d)?;
    fault(DurableFault::Write)?;
    let p = d.join(n);
    if let Ok(meta) = fs::symlink_metadata(&p) {
        if meta.file_type().is_symlink() {
            return Err(io::Error::other("refusing symlink destination"));
        }
        return Err(io::ErrorKind::AlreadyExists.into());
    }
    let tmp = d.join(format!(".{n}.tmp-{}-{}", std::process::id(), now()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    file.write_all(b)?;
    file.sync_all()?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    match fs::hard_link(&tmp, &p) {
        Ok(()) => {
            fs::remove_file(&tmp)?;
            fs::File::open(d)?.sync_all()?;
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_file(&tmp);
            Err(error)
        }
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn replay_journal(p: &Path) -> io::Result<Vec<JournalRecord>> {
    let mut file = match open_read_nofollow(p) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut s = String::new();
    file.read_to_string(&mut s)?;
    let mut records = Vec::new();
    for (i, line) in s.lines().enumerate() {
        if line.trim().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "journal contains empty record",
            ));
        }
        let record: JournalRecord = serde_json::from_str(line).map_err(io::Error::other)?;
        if record.sequence != i as u64 + 1 {
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
    ensure_name("journal.jsonl")?;
    check_path(state)?;
    fault(DurableFault::Write)?;
    let path = state.join("journal.jsonl");
    let sequence = replay_journal(&path)?.len() as u64 + 1;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let metadata = file.metadata()?;
    if metadata.permissions().mode() & 0o777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(io::Error::other("journal ownership or mode"));
    }
    file.write_all(
        format!(
            "{}\n",
            serde_json::to_string(&JournalRecord {
                sequence,
                event: event.into(),
                result,
            })
            .map_err(io::Error::other)?
        )
        .as_bytes(),
    )?;
    file.sync_all()?;
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
        let mut stream = std::os::unix::net::UnixStream::connect(&self.control)?;
        writeln!(
            stream,
            "{}",
            serde_json::json!({
                "op": op,
                "capability": self.capability,
                "pid": self.proof.pid,
                "pgid": self.proof.pgid,
                "fingerprint": self.proof.fingerprint,
                "endpoint_nonce": self.proof.endpoint_nonce
            })
        )?;
        stream.flush()?;
        let mut line = String::new();
        std::io::BufReader::new(stream).read_line(&mut line)?;
        let value: serde_json::Value = serde_json::from_str(&line).map_err(io::Error::other)?;
        if value.get("ok").and_then(|v| v.as_bool()) != Some(true) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                value["error"].as_str().unwrap_or("request rejected"),
            ));
        }
        serde_json::from_value(value["result"].clone()).map_err(io::Error::other)
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
            process::CommandExt,
        },
        sync::{Arc, Mutex},
        thread,
    };

    #[derive(Serialize, Deserialize)]
    struct Request {
        op: String,
        capability: String,
        pid: u32,
        pgid: i32,
        fingerprint: String,
        endpoint_nonce: String,
    }

    #[derive(Serialize)]
    struct Response {
        ok: bool,
        result: Option<CleanupResult>,
        error: Option<String>,
    }

    fn read_handshake(path: &Path) -> io::Result<Handshake> {
        let mut file = open_read_nofollow(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        serde_json::from_slice(&bytes).map_err(io::Error::other)
    }

    fn read_authority(path: &Path) -> io::Result<AuthorityRecord> {
        let mut file = open_read_nofollow(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        serde_json::from_slice(&bytes).map_err(io::Error::other)
    }

    fn spawn_child(program: &str, args: &[String], nonce: &str) -> io::Result<(Child, Proof)> {
        let mut command = Command::new(program);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn()?;
        let pid = child.id();
        let pgid = pid as i32;
        let euid = unsafe { libc::geteuid() };
        let mut proof = Proof {
            pid,
            pgid,
            start_token: String::new(),
            endpoint_nonce: nonce.to_owned(),
            euid,
            fingerprint: String::new(),
            live: true,
            descendants: 0,
        };
        proof.start_token = process_start_token(&proof)?;
        proof.fingerprint = digest(&[
            &proof.pid.to_string(),
            &proof.pgid.to_string(),
            &proof.start_token,
            &proof.endpoint_nonce,
            &proof.euid.to_string(),
        ]);
        Ok((child, proof))
    }

    pub fn run(
        fd: RawFd,
        control: &Path,
        state: &Path,
        program: &str,
        args: &[String],
    ) -> io::Result<()> {
        let mut handshake_stream = unsafe { UnixStream::from_raw_fd(fd) };
        let mut line = String::new();
        BufReader::new(handshake_stream.try_clone()?).read_line(&mut line)?;
        let handshake: Handshake = serde_json::from_str(line.trim()).map_err(io::Error::other)?;
        check_path(state)?;
        let grant = read_handshake(&state.join("grant.json"))?;
        if grant.capability != handshake.capability
            || grant.job_id != handshake.job_id
            || grant.target_digest != handshake.target_digest
            || grant.issuer != handshake.issuer
            || handshake.target_digest != digest(&[program])
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "daemon grant mismatch",
            ));
        }
        // Replay is a startup gate. A malformed tail or sequence gap prevents
        // the endpoint from being published at all.
        let _ = replay_journal(&state.join("journal.jsonl"))?;

        let authority_path = state.join("authority.json");
        let (proof, child) = match read_authority(&authority_path) {
            Ok(record) => {
                if record.capability != handshake.capability
                    || record.job_id != handshake.job_id
                    || record.target_digest != handshake.target_digest
                {
                    return Err(io::Error::other("authority conflict"));
                }
                (bind_session_nonce(record.proof, &handshake.nonce), None)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let (child, proof) = spawn_child(program, args, &handshake.nonce)?;
                let record = AuthorityRecord {
                    capability: handshake.capability.clone(),
                    proof: proof.clone(),
                    created_at: now(),
                    job_id: handshake.job_id.clone(),
                    target_digest: handshake.target_digest.clone(),
                };
                if let Err(error) = write_durable(
                    state,
                    "authority.json",
                    &serde_json::to_vec(&record).map_err(io::Error::other)?,
                ) {
                    let _ = unsafe { libc::kill(-(proof.pgid), libc::SIGKILL) };
                    return Err(error);
                }
                (proof, Some(child))
            }
            Err(error) => return Err(error),
        };
        // Validate persisted identity before telling the daemon that the shim
        // is ready. A stale record can never become a live endpoint.
        let observed = observe_group(&proof)?;
        let proof = observed.proof;
        writeln!(
            handshake_stream,
            "{}",
            serde_json::to_string(&proof).unwrap()
        )?;
        handshake_stream.flush()?;

        check_control_parent(control)?;
        if let Ok(meta) = fs::symlink_metadata(control) {
            if meta.file_type().is_symlink() {
                return Err(io::Error::other("control socket symlink"));
            }
            if !meta.file_type().is_socket() {
                return Err(io::Error::other("control path is not a socket"));
            }
            fs::remove_file(control)?;
        }
        let listener = UnixListener::bind(control)?;
        fs::set_permissions(control, fs::Permissions::from_mode(0o600))?;
        let child = Arc::new(Mutex::new(child));
        let lock = Arc::new(Mutex::new(()));
        let capability = handshake.capability;
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let child = Arc::clone(&child);
            let lock = Arc::clone(&lock);
            let state = state.to_path_buf();
            let proof = proof.clone();
            let capability = capability.clone();
            thread::spawn(move || {
                let _ = handle(stream, &capability, &proof, child, lock, &state);
            });
        }
        Ok(())
    }

    fn check_control_parent(control: &Path) -> io::Result<()> {
        let parent = control
            .parent()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "control has no parent"))?;
        check_path(parent)
    }

    fn handle(
        mut stream: UnixStream,
        capability: &str,
        proof: &Proof,
        child: Arc<Mutex<Option<Child>>>,
        lock: Arc<Mutex<()>>,
        state: &Path,
    ) -> io::Result<()> {
        let mut line = String::new();
        BufReader::new(stream.try_clone()?).read_line(&mut line)?;
        let request: Request = serde_json::from_str(&line).map_err(io::Error::other)?;
        let _guard = lock.lock().unwrap();
        if request.capability != capability
            || request.pid != proof.pid
            || request.pgid != proof.pgid
            || request.fingerprint != proof.fingerprint
            || request.endpoint_nonce != proof.endpoint_nonce
        {
            let _ = append_journal(
                state,
                "unauthorized",
                Some(CleanupResult::Failed("request proof mismatch".into())),
            );
            writeln!(stream, "{{\"ok\":false,\"error\":\"unauthorized\"}}")?;
            return Ok(());
        }
        let result = match request.op.as_str() {
            "attest" => match observe_group(proof) {
                Ok(observed) => transition_observed(
                    &observed.proof,
                    Some(observed.proof.live),
                    observed.descendants,
                    false,
                ),
                Err(error) => CleanupResult::Orphaned(format!("attestation failed: {error}")),
            },
            "cleanup" => {
                let mut child = child.lock().unwrap();
                match cleanup_group_with_child(proof, child.as_mut(), Duration::from_millis(100)) {
                    Ok(result) => result,
                    Err(error) => CleanupResult::Failed(format!("cleanup failed: {error}")),
                }
            }
            "shutdown" => CleanupResult::Failed("shutdown is not a lifecycle operation".into()),
            _ => CleanupResult::Failed("unknown operation".into()),
        };
        if let Err(error) = append_journal(state, &request.op, Some(result.clone())) {
            writeln!(
                stream,
                "{}",
                serde_json::to_string(&Response {
                    ok: false,
                    result: None,
                    error: Some(format!("journal append failed: {error}")),
                })
                .unwrap()
            )?;
            stream.flush()?;
            return Ok(());
        }
        writeln!(
            stream,
            "{}",
            serde_json::to_string(&Response {
                ok: true,
                result: Some(result),
                error: None,
            })
            .unwrap()
        )?;
        stream.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof() -> Proof {
        Proof {
            pid: 1,
            pgid: 1,
            start_token: "s".into(),
            endpoint_nonce: "n".into(),
            euid: 1,
            fingerprint: "f".into(),
            live: true,
            descendants: 0,
        }
    }

    #[test]
    fn transition_is_symmetric_and_unknown_fails_closed() {
        let p = proof();
        assert!(matches!(
            transition(&p, true, 1, false),
            CleanupResult::Orphaned(_)
        ));
        assert!(matches!(
            transition(&p, false, 0, true),
            CleanupResult::Dead(_)
        ));
        assert!(matches!(
            transition_observed(&p, Some(true), None, false),
            CleanupResult::Orphaned(_)
        ));
        assert!(matches!(
            mutate_terminal(&p, false, 1),
            CleanupResult::Orphaned(_)
        ));
    }

    #[test]
    fn durable_publication_is_no_replace_and_replay_rejects_gaps() {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("zcode-supervisor-unit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        check_path(&root).unwrap();
        write_durable(&root, "authority.json", b"one").unwrap();
        assert_eq!(
            write_durable(&root, "authority.json", b"two")
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );
        let journal = root.join("journal.jsonl");
        fs::write(
            &journal,
            r#"{"sequence":2,"event":"gap","result":null}
"#,
        )
        .unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            replay_journal(&journal).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn daemon_grant_is_opaque_and_target_bound_before_publication() {
        let authority = DaemonAuthority::for_target("job", "/bin/sh").unwrap();
        let handshake = authority.handshake();
        assert_eq!(authority.target(), "/bin/sh");
        assert_eq!(handshake.target_digest, digest(&["/bin/sh"]));
        assert_ne!(
            handshake.issuer,
            digest(&[
                &handshake.capability,
                &handshake.nonce,
                &handshake.job_id,
                &handshake.target_digest
            ])
        );
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("zcode-supervisor-grant-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        authority.persist_grant(&root).unwrap();
        assert!(authority.persist_grant(&root).is_err());
        let _ = fs::remove_dir_all(root);
    }
}
