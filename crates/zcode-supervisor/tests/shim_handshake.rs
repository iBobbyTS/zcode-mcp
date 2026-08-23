#![cfg(unix)]
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    os::unix::io::IntoRawFd,
    process::Command,
    time::Duration,
};
use zcode_supervisor::{CleanupResult, Proof, ShimClient};

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
    parent.write_all(b"capability-test\n").unwrap();
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
    let client = ShimClient::connect(&control, "capability-test", proof.clone());
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
