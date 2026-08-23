use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::File,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, Serialize, PartialEq)]
pub struct Preflight {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_version: Option<String>,
    pub compatibility_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_methods: Option<Vec<String>>,
}

pub fn identity(path: Option<&Path>) -> io::Result<Preflight> {
    let Some(path) = path else {
        return Ok(untested("ZCODE_RUNTIME_PATH is unset"));
    };
    if !path.is_file() {
        return Ok(untested("runtime path is not a regular file"));
    }
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    let node_version = Command::new("node")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
    Ok(Preflight {
        runtime_path: Some("<redacted>".into()),
        runtime_size: Some(size),
        runtime_sha256: Some(format!("{:x}", hasher.finalize())),
        runtime_version: Some("unknown".into()),
        node_version,
        compatibility_status: "untested".into(),
        reason: None,
        observed_methods: None,
    })
}

pub fn probe(path: Option<&Path>, timeout: Duration) -> Preflight {
    probe_with_node(path, Path::new("node"), timeout)
}

pub fn probe_with_node(path: Option<&Path>, node: &Path, timeout: Duration) -> Preflight {
    let Some(path) = path else {
        return untested("runtime unavailable");
    };
    if !path.is_file() {
        return untested("runtime unavailable");
    }
    let mut child = match Command::new(node)
        .arg(path)
        .arg("app-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return failed("unable to start node"),
    };
    let request = r#"{"jsonrpc":"2.0","id":"preflight-1","method":"workspace/readState","params":{}}
"#;
    if child
        .stdin
        .as_mut()
        .and_then(|stdin| stdin.write_all(request.as_bytes()).ok())
        .is_none()
    {
        return failed("unable to write probe");
    }
    drop(child.stdin.take());
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let (tx, rx) = mpsc::channel();
    let tx_out = tx.clone();
    thread::spawn(move || {
        let _ = tx_out.send(("stdout", read_bounded(stdout, 64 * 1024)));
    });
    thread::spawn(move || {
        let _ = tx.send(("stderr", read_bounded(stderr, 64 * 1024)));
    });
    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if child.try_wait().ok().flatten().is_none() {
        timed_out = true;
        let _ = child.kill();
    }
    let status = child.wait().ok();
    let mut out = Vec::new();
    for _ in 0..2 {
        if let Ok((stream, bytes)) = rx.recv_timeout(Duration::from_millis(250)) {
            if stream == "stdout" {
                out = bytes;
            }
        }
    }
    if timed_out {
        return failed("probe timed out");
    }
    let Some(status) = status else {
        return failed("unable to read probe");
    };
    if !status.success() {
        return failed("app-server exited non-zero");
    }
    let Some(value) = parse_response(&out) else {
        return failed(if out.contains(&b'{') {
            "malformed JSON-RPC response"
        } else {
            "non-JSON app-server output"
        });
    };
    if value.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return failed("invalid JSON-RPC version");
    }
    if value.get("id") != Some(&serde_json::Value::String("preflight-1".into())) {
        return failed("JSON-RPC id mismatch");
    }
    if value.get("result").is_none() {
        return failed("JSON-RPC result missing");
    }
    let mut methods = Vec::new();
    if let Some(method) = value.get("method").and_then(|v| v.as_str()) {
        methods.push(method.to_string());
    }
    let status = "tested";
    Preflight {
        runtime_path: None,
        runtime_size: None,
        runtime_sha256: None,
        runtime_version: None,
        node_version: None,
        compatibility_status: status.into(),
        reason: None,
        observed_methods: Some(methods),
    }
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut buf = [0u8; 4096];
    while bytes.len() < limit {
        let chunk = (limit - bytes.len()).min(buf.len());
        match reader.read(&mut buf[..chunk]) {
            Ok(0) | Err(_) => break,
            Ok(n) => bytes.extend_from_slice(&buf[..n]),
        }
    }
    bytes
}

fn parse_response(output: &[u8]) -> Option<serde_json::Value> {
    for line in String::from_utf8_lossy(output)
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(line) {
            if value.is_object() {
                return Some(value);
            }
        }
    }
    None
}

fn untested(reason: &str) -> Preflight {
    Preflight {
        runtime_path: None,
        runtime_size: None,
        runtime_sha256: None,
        runtime_version: None,
        node_version: None,
        compatibility_status: "untested".into(),
        reason: Some(reason.into()),
        observed_methods: None,
    }
}
fn failed(reason: &str) -> Preflight {
    Preflight {
        compatibility_status: "failed".into(),
        reason: Some(reason.into()),
        runtime_path: None,
        runtime_size: None,
        runtime_sha256: None,
        runtime_version: None,
        node_version: None,
        observed_methods: None,
    }
}

pub fn run_from_env(timeout: Duration) -> io::Result<Preflight> {
    let path = env::var_os("ZCODE_RUNTIME_PATH").map(PathBuf::from);
    let mut result = identity(path.as_deref())?;
    if path.is_some() {
        let smoke = probe(path.as_deref(), timeout);
        result.compatibility_status = smoke.compatibility_status;
        result.reason = smoke.reason;
        result.observed_methods = smoke.observed_methods;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn missing_is_untested() {
        assert_eq!(identity(None).unwrap().compatibility_status, "untested");
    }
    #[test]
    fn identity_hashes_without_secrets() {
        let path = std::env::temp_dir().join(format!("runtime-preflight-{}", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(b"runtime-fixture").unwrap();
        drop(f);
        let r = identity(Some(&path)).unwrap();
        assert_eq!(
            r.runtime_sha256.as_ref().unwrap().as_str(),
            format!("{:x}", Sha256::digest(b"runtime-fixture"))
        );
        let json = serde_json::to_string(&r).unwrap();
        assert!(!json.contains("token"));
        assert!(!json.contains("secret"));
        let _ = std::fs::remove_file(path);
    }

    fn fixture(contents: &str) -> (PathBuf, PathBuf) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "runtime-preflight-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let node = dir.join("node-fixture");
        let runtime = dir.join("runtime.js");
        std::fs::write(&node, contents).unwrap();
        std::fs::write(&runtime, b"runtime").unwrap();
        (node, runtime)
    }

    fn cleanup(paths: (PathBuf, PathBuf)) {
        let _ = std::fs::remove_dir_all(paths.0.parent().unwrap());
    }

    #[test]
    fn probe_accepts_noise_and_valid_response() {
        let paths = fixture("#!/bin/sh\nprintf 'noise\\n{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"id\\\":\\\"preflight-1\\\",\\\"result\\\":{}}\\n'");
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&paths.0)
            .status()
            .unwrap();
        assert_eq!(
            probe_with_node(Some(&paths.1), &paths.0, Duration::from_secs(1)).compatibility_status,
            "tested"
        );
        cleanup(paths);
    }

    #[test]
    fn probe_rejects_bad_id_and_nonzero() {
        let paths = fixture("#!/bin/sh\nprintf '{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"id\\\":\\\"wrong\\\",\\\"result\\\":{}}\\n'; exit 3");
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&paths.0)
            .status()
            .unwrap();
        let result = probe_with_node(Some(&paths.1), &paths.0, Duration::from_secs(1));
        assert_eq!(result.compatibility_status, "failed");
        assert!(result.reason.unwrap().contains("non-zero"));
        cleanup(paths);
    }

    #[test]
    fn probe_rejects_malformed_json_rpc() {
        let paths = fixture("#!/bin/sh\nprintf '{not-json}\\n'");
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&paths.0)
            .status()
            .unwrap();
        let result = probe_with_node(Some(&paths.1), &paths.0, Duration::from_secs(1));
        assert_eq!(result.compatibility_status, "failed");
        assert!(result.reason.unwrap().contains("malformed"));
        cleanup(paths);
    }

    #[test]
    fn probe_times_out_and_redacts_identity() {
        let paths = fixture("#!/bin/sh\nsleep 2");
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&paths.0)
            .status()
            .unwrap();
        let result = probe_with_node(Some(&paths.1), &paths.0, Duration::from_millis(20));
        assert_eq!(result.compatibility_status, "failed");
        assert!(result.reason.unwrap().contains("timed out"));
        assert_eq!(
            identity(Some(&paths.1)).unwrap().runtime_path.as_deref(),
            Some("<redacted>")
        );
        cleanup(paths);
    }
}
