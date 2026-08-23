#![cfg(unix)]
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::io::IntoRawFd,
    process::Command,
    time::Duration,
};
use zcode_supervisor::{issue_handshake, CleanupResult, Proof, ShimClient};

#[test]
fn real_shim_process_attests_and_reaches_dead() {
    let root = std::env::temp_dir().join(format!("zcode-shim-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let control = root.join("control.sock");
    let state = root.join("state");
    let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd = child.into_raw_fd();
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, 0);
    }
    let bin =
        std::env::var("CARGO_BIN_EXE_zcode-supervisor-shim").expect("cargo exposes shim binary");
    let mut process = Command::new(bin)
        .arg("--shim")
        .arg(&control)
        .arg(&state)
        .arg("/bin/sh")
        .arg("-c")
        .arg("sleep 30")
        .env("ZCODE_SHIM_HANDSHAKE_FD", fd.to_string())
        .spawn()
        .unwrap();
    let _ = fd;
    let grant = issue_handshake().unwrap();
    parent
        .write_all(format!("{}\n", serde_json::to_string(&grant).unwrap()).as_bytes())
        .unwrap();
    parent.flush().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut line = String::new();
    BufReader::new(parent.try_clone().unwrap())
        .read_line(&mut line)
        .unwrap();
    let proof: Proof = serde_json::from_str(&line).unwrap();
    for _ in 0..30 {
        if control.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let client = ShimClient::connect(&control, grant.capability.clone(), proof.clone());
    for _ in 0..50 {
        if client.request("attest").is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(
        client.request("attest").unwrap(),
        CleanupResult::Recovered(_)
    ));
    assert!(matches!(
        client.request("cleanup").unwrap(),
        CleanupResult::Dead(_)
    ));
    process.kill().unwrap();
    process.wait().unwrap();
    assert!(state.join("authority.json").exists());
    assert!(state.join("journal.jsonl").exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn handshake_is_one_time_and_capability_is_bound_to_proof() {
    let root = std::env::temp_dir().join(format!("zcode-shim-replay-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let grant = issue_handshake().unwrap();
    let control = root.join("control.sock");
    let state = root.join("state");
    let (mut parent, child) = std::os::unix::net::UnixStream::pair().unwrap();
    let fd = child.into_raw_fd();
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, 0);
    }
    let bin = std::env::var("CARGO_BIN_EXE_zcode-supervisor-shim").unwrap();
    let mut first = Command::new(&bin)
        .arg("--shim")
        .arg(&control)
        .arg(&state)
        .arg("/bin/sh")
        .arg("-c")
        .arg("sleep 5")
        .env("ZCODE_SHIM_HANDSHAKE_FD", fd.to_string())
        .spawn()
        .unwrap();
    parent
        .write_all(format!("{}\n", serde_json::to_string(&grant).unwrap()).as_bytes())
        .unwrap();
    parent.flush().unwrap();
    parent
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut line = String::new();
    BufReader::new(parent.try_clone().unwrap())
        .read_line(&mut line)
        .unwrap();
    let proof: Proof = serde_json::from_str(&line).unwrap();
    let mut forged = None;
    for _ in 0..100 {
        if let Ok(stream) = std::os::unix::net::UnixStream::connect(&control) {
            forged = Some(stream);
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let mut forged = forged.expect("shim control socket did not accept connections");
    writeln!(forged, "{}", serde_json::json!({"op":"attest","capability":grant.capability,"pid":proof.pid + 1,"pgid":proof.pgid,"fingerprint":proof.fingerprint,"endpoint_nonce":proof.endpoint_nonce})).unwrap();
    let mut response = String::new();
    BufReader::new(forged).read_line(&mut response).unwrap();
    assert!(response.contains("unauthorized"));
    first.kill().unwrap();
    first.wait().unwrap();

    let (mut replay_parent, replay_child) = std::os::unix::net::UnixStream::pair().unwrap();
    let replay_fd = replay_child.into_raw_fd();
    unsafe {
        libc::fcntl(replay_fd, libc::F_SETFD, 0);
    }
    let mut replay = Command::new(&bin)
        .arg("--shim")
        .arg(root.join("replay.sock"))
        .arg(&state)
        .arg("/bin/sh")
        .arg("-c")
        .arg("true")
        .env("ZCODE_SHIM_HANDSHAKE_FD", replay_fd.to_string())
        .spawn()
        .unwrap();
    replay_parent
        .write_all(format!("{}\n", serde_json::to_string(&grant).unwrap()).as_bytes())
        .unwrap();
    replay_parent.flush().unwrap();
    assert!(replay.wait().unwrap().code().is_some_and(|code| code != 0));
    let _ = fs::remove_dir_all(root);
}
