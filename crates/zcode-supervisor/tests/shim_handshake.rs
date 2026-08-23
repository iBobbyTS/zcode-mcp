#![cfg(unix)]

use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::{fs::PermissionsExt, io::IntoRawFd},
    path::Path,
    process::Command,
    time::Duration,
};
use zcode_supervisor::{CleanupResult, Handshake, Proof, ShimClient};

fn grant() -> Handshake {
    Handshake {
        capability: "capability-from-daemon".into(),
        nonce: "endpoint-nonce-from-daemon".into(),
        job_id: "job-from-daemon".into(),
        target_digest: sha2_digest("/bin/sh"),
        issuer: "opaque-daemon-issuer".into(),
    }
}

fn sha2_digest(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(value.as_bytes());
    h.update([0]);
    format!("{:x}", h.finalize())
}

fn prepare_state(root: &Path, grant: &Handshake) -> std::path::PathBuf {
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(state.join("grant.json"), serde_json::to_vec(grant).unwrap()).unwrap();
    fs::set_permissions(state.join("grant.json"), fs::Permissions::from_mode(0o600)).unwrap();
    state
}

fn launch(
    root: &Path,
    control: &Path,
    state: &Path,
    command: &str,
) -> (Command, std::os::unix::net::UnixStream, std::process::Child) {
    let (parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd = child.into_raw_fd();
    unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    let bin = std::env::var("CARGO_BIN_EXE_zcode-supervisor-shim").unwrap();
    let mut cmd = Command::new(bin);
    let process = cmd
        .arg("--shim")
        .arg(control)
        .arg(state)
        .arg("/bin/sh")
        .arg("-c")
        .arg(command)
        .env("ZCODE_SHIM_HANDSHAKE_FD", fd.to_string())
        .spawn()
        .unwrap();
    let _ = root;
    (cmd, parent, process)
}

fn read_proof(mut parent: std::os::unix::net::UnixStream, grant: &Handshake) -> Proof {
    parent
        .write_all(format!("{}\n", serde_json::to_string(grant).unwrap()).as_bytes())
        .unwrap();
    parent.flush().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut line = String::new();
    BufReader::new(parent).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn wait_socket(path: &Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("shim control socket did not appear: {}", path.display());
}

#[test]
fn real_shim_process_attests_and_reaches_dead() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("zcode-shim-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let grant2 = grant();
    let state = prepare_state(&root, &grant2);
    let control = root.join("control.sock");
    let (_command, parent, mut process) = launch(&root, &control, &state, "sleep 30");
    let proof = read_proof(parent, &grant2);
    wait_socket(&control);
    let client = ShimClient::connect(&control, grant2.capability.clone(), proof.clone());
    assert!(matches!(
        client.request("attest").unwrap(),
        CleanupResult::Recovered(_)
    ));
    let mut forged = std::os::unix::net::UnixStream::connect(&control).unwrap();
    writeln!(
        forged,
        "{}",
        serde_json::json!({
            "op": "attest",
            "capability": grant2.capability,
            "pid": proof.pid + 1,
            "pgid": proof.pgid,
            "fingerprint": proof.fingerprint,
            "endpoint_nonce": proof.endpoint_nonce
        })
    )
    .unwrap();
    let mut forged_response = String::new();
    BufReader::new(forged)
        .read_line(&mut forged_response)
        .unwrap();
    assert!(forged_response.contains("unauthorized"));
    let cleanup = client.request("cleanup").unwrap();
    assert!(matches!(cleanup, CleanupResult::Dead(dead) if !dead.live && dead.descendants == 0));
    process.kill().ok();
    let _ = process.wait();
    let authority = fs::metadata(state.join("authority.json")).unwrap();
    assert_eq!(authority.permissions().mode() & 0o777, 0o600);
    let journal = zcode_supervisor::replay_journal(&state.join("journal.jsonl")).unwrap();
    assert_eq!(journal.len(), 3);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn restart_replays_live_authority_and_cleanup_reconnects_without_child_handle() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("zcode-shim-restart-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let grant2 = grant();
    let state = prepare_state(&root, &grant2);
    let control = root.join("control.sock");
    let (_command, parent, mut first) = launch(&root, &control, &state, "sleep 30");
    let proof = read_proof(parent, &grant2);
    wait_socket(&control);
    let client = ShimClient::connect(&control, grant2.capability.clone(), proof.clone());
    assert!(matches!(
        client.request("attest").unwrap(),
        CleanupResult::Recovered(_)
    ));
    first.kill().unwrap();
    let _ = first.wait();

    let replay_control = root.join("replay.sock");
    let replay_grant = Handshake {
        nonce: "fresh-reconnect-challenge".into(),
        ..grant2.clone()
    };
    let (_command, replay_parent, mut replay) = launch(&root, &replay_control, &state, "true");
    let restarted = read_proof(replay_parent, &replay_grant);
    assert_eq!(restarted.pid, proof.pid);
    wait_socket(&replay_control);
    assert_ne!(restarted.endpoint_nonce, proof.endpoint_nonce);
    assert_ne!(restarted.fingerprint, proof.fingerprint);
    let reconnect =
        ShimClient::connect(&replay_control, replay_grant.capability.clone(), restarted);
    assert!(matches!(
        reconnect.request("attest").unwrap(),
        CleanupResult::Recovered(_)
    ));
    let cleanup = reconnect.request("cleanup").unwrap();
    assert!(matches!(cleanup, CleanupResult::Dead(dead) if !dead.live && dead.descendants == 0));
    replay.kill().ok();
    let _ = replay.wait();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn descendants_and_term_ignoring_are_never_recovered_without_escalation() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("zcode-shim-descendants-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let desc_grant = grant();
    let state = prepare_state(&root, &desc_grant);
    let control = root.join("control.sock");
    let (_command, parent, mut process) = launch(&root, &control, &state, "sleep 30 & wait");
    let proof = read_proof(parent, &desc_grant);
    wait_socket(&control);
    let client = ShimClient::connect(&control, desc_grant.capability.clone(), proof);
    let attest = client.request("attest").unwrap();
    assert!(matches!(attest, CleanupResult::Orphaned(_)));
    assert!(
        matches!(client.request("cleanup").unwrap(), CleanupResult::Dead(dead) if !dead.live && dead.descendants == 0)
    );
    process.kill().ok();
    let _ = process.wait();

    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("zcode-shim-term-ignore-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let term_grant = grant();
    let state = prepare_state(&root, &term_grant);
    let control = root.join("control.sock");
    let (_command, parent, mut process) = launch(&root, &control, &state, "trap '' TERM; sleep 30");
    let proof = read_proof(parent, &term_grant);
    wait_socket(&control);
    let client = ShimClient::connect(&control, term_grant.capability, proof);
    assert!(
        matches!(client.request("cleanup").unwrap(), CleanupResult::Dead(dead) if !dead.live && dead.descendants == 0)
    );
    process.kill().ok();
    let _ = process.wait();
    let _ = fs::remove_dir_all(root);
}

#[test]
fn forged_grant_without_daemon_state_and_forged_proof_are_rejected() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("zcode-shim-forge-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let state = root.join("state");
    fs::create_dir(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    let control = root.join("control.sock");
    let forged = Handshake {
        target_digest: sha2_digest("/bin/sh"),
        ..grant()
    };
    let (_command, parent, mut process) = launch(&root, &control, &state, "true");
    parent
        .try_clone()
        .unwrap()
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut parent = parent;
    parent
        .write_all(format!("{}\n", serde_json::to_string(&forged).unwrap()).as_bytes())
        .unwrap();
    process.wait().unwrap();
    assert!(!control.exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn durable_parent_symlink_and_io_failures_fail_closed() {
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("zcode-shim-durable-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let real = root.join("real");
    fs::create_dir(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
    let link = root.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(zcode_supervisor::write_durable(&link, "x", b"x").is_err());
    zcode_supervisor::set_durable_fault(zcode_supervisor::DurableFault::Write);
    assert!(zcode_supervisor::write_durable(&real, "x", b"x").is_err());
    zcode_supervisor::set_durable_fault(zcode_supervisor::DurableFault::None);
    zcode_supervisor::write_durable(&real, "x", b"x").unwrap();
    zcode_supervisor::set_durable_fault(zcode_supervisor::DurableFault::Read);
    assert!(zcode_supervisor::replay_journal(&real.join("journal.jsonl")).is_err());
    zcode_supervisor::set_durable_fault(zcode_supervisor::DurableFault::None);
    let _ = fs::remove_dir_all(root);
}
