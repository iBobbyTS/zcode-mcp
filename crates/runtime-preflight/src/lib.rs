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

#[cfg(unix)]
use std::os::unix::process::CommandExt;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_models: Option<Vec<String>>,
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
        current_model: None,
        available_models: None,
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
    let mut command = Command::new(node);
    command
        .arg(path)
        .arg("app-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    unsafe {
        command.pre_exec(|| {
            if setsid() == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(_) => return failed("unable to start node"),
    };
    let workspace = std::env::current_dir()
        .ok()
        .and_then(|path| std::fs::canonicalize(path).ok())
        .unwrap_or_else(|| PathBuf::from("/"));
    let request = serde_json::json!({
        "id":"preflight-1",
        "method":"workspace/readState",
        "params":{"workspace":{
            "workspaceKey":workspace,
            "workspacePath":workspace
        }}
    });
    let request = format!("{request}\n");
    let write_result = child
        .stdin
        .as_mut()
        .ok_or(())
        .and_then(|stdin| stdin.write_all(request.as_bytes()).map_err(|_| ()));
    if write_result.is_err() {
        terminate_process_group(&mut child);
        let _ = child.wait();
        return failed("unable to write probe");
    }
    drop(child.stdin.take());
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");
    let (stdout_tx, stdout_rx) = mpsc::channel();
    let (stderr_tx, stderr_rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = stdout_tx.send(read_bounded(stdout, 64 * 1024));
    });
    thread::spawn(move || {
        let _ = stderr_tx.send(read_bounded(stderr, 64 * 1024));
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
        terminate_process_group(&mut child);
    }
    let status = child.wait().ok();
    // Descendants can inherit the pipes after the leader exits. Never join a
    // reader indefinitely; process-group termination normally closes them.
    let out = stdout_rx
        .recv_timeout(Duration::from_millis(100))
        .unwrap_or_default();
    let _stderr = stderr_rx
        .recv_timeout(Duration::from_millis(100))
        .unwrap_or_default();
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
            "malformed NDJSON response"
        } else {
            "non-JSON app-server output"
        });
    };
    if value.get("jsonrpc").is_some() {
        return failed("unexpected jsonrpc member");
    }
    if value.get("id") != Some(&serde_json::Value::String("preflight-1".into())) {
        return failed("NDJSON id mismatch");
    }
    if value.get("result").is_none() {
        return failed("NDJSON result missing");
    }
    let methods = vec!["workspace/readState".to_owned()];
    let result = value.get("result").expect("checked above");
    let current_model = result
        .pointer("/settings/model/current/modelId")
        .or_else(|| result.pointer("/settings/model/current/id"))
        .or_else(|| result.pointer("/settings/model/current"))
        .or_else(|| result.pointer("/settings/model/value/modelId"))
        .or_else(|| result.pointer("/settings/model/value"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let mut available_models = Vec::new();
    collect_model_ids(result.get("modelCatalog"), &mut available_models);
    available_models.sort();
    available_models.dedup();
    Preflight {
        runtime_path: None,
        runtime_size: None,
        runtime_sha256: None,
        runtime_version: None,
        node_version: None,
        compatibility_status: "tested".into(),
        reason: None,
        observed_methods: Some(methods),
        current_model,
        available_models: Some(available_models),
    }
}

fn collect_model_ids(value: Option<&serde_json::Value>, output: &mut Vec<String>) {
    let Some(value) = value else { return };
    match value {
        serde_json::Value::Object(object) => {
            if let Some(model) = object.get("modelId").and_then(serde_json::Value::as_str) {
                if model.len() <= 128 && !model.contains('\0') {
                    output.push(model.to_owned());
                }
            }
            for value in object.values() {
                collect_model_ids(Some(value), output);
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                collect_model_ids(Some(value), output);
            }
        }
        _ => {}
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn setsid() -> i32;
    fn killpg(pgrp: i32, sig: i32) -> i32;
}

fn terminate_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    unsafe {
        let _ = killpg(child.id() as i32, 9);
    }
    let _ = child.kill();
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
        current_model: None,
        available_models: None,
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
        current_model: None,
        available_models: None,
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
        result.current_model = smoke.current_model;
        result.available_models = smoke.available_models;
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
        let paths = fixture("#!/bin/sh\nprintf 'noise\\n{\\\"id\\\":\\\"preflight-1\\\",\\\"result\\\":{\\\"settings\\\":{\\\"model\\\":{\\\"current\\\":{\\\"modelId\\\":\\\"glm-current\\\"}}},\\\"modelCatalog\\\":{\\\"items\\\":[{\\\"modelId\\\":\\\"glm-current\\\"},{\\\"modelId\\\":\\\"glm-other\\\"}]}}}\\n'");
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&paths.0)
            .status()
            .unwrap();
        let result = probe_with_node(Some(&paths.1), &paths.0, Duration::from_secs(1));
        assert_eq!(result.compatibility_status, "tested");
        assert_eq!(result.current_model.as_deref(), Some("glm-current"));
        assert_eq!(
            result.available_models.unwrap(),
            vec!["glm-current", "glm-other"]
        );
        cleanup(paths);
    }

    #[test]
    fn preflight_catalog_does_not_collect_current_or_session_models() {
        let paths = fixture("#!/bin/sh\nprintf '{\\\"id\\\":\\\"preflight-1\\\",\\\"result\\\":{\\\"settings\\\":{\\\"model\\\":{\\\"current\\\":{\\\"modelId\\\":\\\"glm-current\\\"}}},\\\"session\\\":{\\\"modelId\\\":\\\"glm-session\\\"},\\\"modelCatalog\\\":{\\\"items\\\":[{\\\"modelId\\\":\\\"glm-catalog\\\"}]}}}\\n'");
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&paths.0)
            .status()
            .unwrap();
        let result = probe_with_node(Some(&paths.1), &paths.0, Duration::from_secs(1));
        assert_eq!(result.current_model.as_deref(), Some("glm-current"));
        assert_eq!(result.available_models.unwrap(), vec!["glm-catalog"]);
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
        let paths = fixture("#!/bin/sh\nsleep 2 & wait");
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&paths.0)
            .status()
            .unwrap();
        let started = Instant::now();
        let result = probe_with_node(Some(&paths.1), &paths.0, Duration::from_millis(20));
        assert_eq!(result.compatibility_status, "failed");
        assert!(result.reason.unwrap().contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            identity(Some(&paths.1)).unwrap().runtime_path.as_deref(),
            Some("<redacted>")
        );
        cleanup(paths);
    }

    #[test]
    fn probe_reports_write_failure_without_leaking_child() {
        let paths = fixture("#!/bin/sh\nexit 0");
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&paths.0)
            .status()
            .unwrap();
        let result = probe_with_node(Some(&paths.1), &paths.0, Duration::from_secs(1));
        assert!(matches!(
            result.compatibility_status.as_str(),
            "failed" | "incompatible"
        ));
        cleanup(paths);
    }
}
