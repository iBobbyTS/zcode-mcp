use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};
use zcode_driver::{Driver, Inbound, RequestError};
use zcode_protocol::{
    RuntimePreferences, WireMessage, WorkspaceDiagnosticProjection, WorkspaceParams, WorkspaceRef,
    SESSION_REQUEST_RUNTIME_PREFERENCES, WORKSPACE_READ_STATE,
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
    command.arg(path).arg("app-server");
    let driver = match Driver::spawn(command) {
        Ok(driver) => Arc::new(driver),
        Err(_) => return failed("unable to start node"),
    };
    let workspace = std::env::current_dir()
        .ok()
        .and_then(|path| std::fs::canonicalize(path).ok())
        .unwrap_or_else(|| PathBuf::from("/"));
    let workspace = workspace.to_string_lossy();
    let params = match serde_json::to_value(WorkspaceParams {
        workspace: WorkspaceRef {
            workspace_key: &workspace,
            workspace_path: &workspace,
        },
    }) {
        Ok(params) => params,
        Err(_) => return failed("unable to serialize workspace probe"),
    };
    let response = request_with_runtime_preferences(&driver, params, timeout);
    let cleanup_grace = timeout.min(Duration::from_millis(250));
    if driver.stop_and_reap(cleanup_grace).is_err() {
        return failed("unable to reap app-server process group");
    }
    let response = match response {
        Ok(response) => response,
        Err(reason) => return failed(reason),
    };
    let Some(result) = response.result.as_ref() else {
        return failed("workspace/readState result missing");
    };
    let projection = match WorkspaceDiagnosticProjection::from_result(result) {
        Ok(projection) => projection,
        Err(error) => {
            return failed(&format!(
                "workspace/readState result shape is incompatible: {error}"
            ));
        }
    };
    Preflight {
        runtime_path: None,
        runtime_size: None,
        runtime_sha256: None,
        runtime_version: None,
        node_version: None,
        compatibility_status: "tested".into(),
        reason: None,
        observed_methods: Some(vec![WORKSPACE_READ_STATE.to_owned()]),
        current_model: projection.current_model,
        available_models: Some(projection.available_models),
    }
}

fn request_with_runtime_preferences(
    driver: &Arc<Driver>,
    params: serde_json::Value,
    timeout: Duration,
) -> Result<zcode_protocol::ResponseEnvelope, &'static str> {
    let events = driver.subscribe();
    let done = Arc::new(AtomicBool::new(false));
    let handler_error = Arc::new(Mutex::new(None));
    let request = thread::scope(|scope| {
        let handler_done = Arc::clone(&done);
        let handler_error = Arc::clone(&handler_error);
        scope.spawn(move || {
            while !handler_done.load(Ordering::Acquire) {
                match events.recv_timeout(Duration::from_millis(10)) {
                    Ok(Inbound::Message(WireMessage::Request(request)))
                        if request.method == SESSION_REQUEST_RUNTIME_PREFERENCES =>
                    {
                        let preferences = serde_json::to_value(RuntimePreferences::default())
                            .expect("runtime preferences serialization cannot fail");
                        if driver.respond(request.id, preferences).is_err() {
                            *handler_error.lock().unwrap() =
                                Some("unable to answer runtime preferences request");
                            return;
                        }
                    }
                    Ok(Inbound::Message(WireMessage::Request(request))) => {
                        let _ = driver.respond_error(
                            request.id,
                            serde_json::json!({
                                "code": -32601,
                                "message": "unsupported preflight server request"
                            }),
                        );
                        *handler_error.lock().unwrap() =
                            Some("unsupported app-server request during preflight");
                        return;
                    }
                    Ok(Inbound::Malformed(_)) => {
                        *handler_error.lock().unwrap() = Some("malformed NDJSON response");
                        return;
                    }
                    Ok(Inbound::OversizedLine { .. }) => {
                        *handler_error.lock().unwrap() = Some("oversized NDJSON response");
                        return;
                    }
                    Ok(_) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
            }
        });
        let response = driver.request(WORKSPACE_READ_STATE, params, timeout);
        done.store(true, Ordering::Release);
        response
    });
    if let Some(error) = *handler_error.lock().unwrap() {
        return Err(error);
    }
    request.map_err(|error| match error {
        RequestError::Timeout => "probe timed out",
        RequestError::Remote(_) => "workspace/readState returned an error",
        RequestError::ChildExited(_) => "app-server exited before probe response",
        RequestError::WriteFailed(_) => "unable to write probe",
        RequestError::Cancelled | RequestError::StreamClosed => "unable to read probe response",
    })
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
    use std::time::Instant;
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
    fn probe_uses_driver_correlation_and_handles_runtime_preferences() {
        let paths = fixture(
            r#"#!/bin/sh
read request
printf '%s\n' '{"id":"server-1","method":"session/requestRuntimePreferences","params":{}}'
read preferences
printf '%s\n' '{"id":1,"result":{"settings":{"model":{"current":{"modelId":"glm-current"}}},"modelCatalog":{"available":[{"ref":{"modelId":"glm-current"}},{"ref":{"modelId":"glm-other"}}]}}}'
sleep 10"#,
        );
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&paths.0)
            .status()
            .unwrap();
        let result = probe_with_node(Some(&paths.1), &paths.0, Duration::from_secs(1));
        assert_eq!(result.compatibility_status, "tested", "{result:?}");
        assert_eq!(
            result.current_model.as_deref(),
            Some("glm-current"),
            "{result:?}"
        );
        assert_eq!(
            result.available_models.unwrap(),
            vec!["glm-current", "glm-other"]
        );
        cleanup(paths);
    }

    #[test]
    fn preflight_catalog_does_not_collect_current_or_session_models() {
        let paths = fixture(
            r#"#!/bin/sh
read request
printf '%s\n' '{"id":1,"result":{"settings":{"model":{"current":{"modelId":"glm-current"}}},"session":{"modelId":"glm-session"},"modelCatalog":{"available":[{"ref":{"modelId":"glm-catalog"}}]}}}'"#,
        );
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
        let paths = fixture(
            r#"#!/bin/sh
read request
printf '%s\n' '{"id":99,"result":{}}'
exit 3"#,
        );
        std::process::Command::new("chmod")
            .arg("+x")
            .arg(&paths.0)
            .status()
            .unwrap();
        let result = probe_with_node(Some(&paths.1), &paths.0, Duration::from_secs(1));
        assert_eq!(result.compatibility_status, "failed");
        assert!(
            result
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("exited")),
            "{result:?}"
        );
        cleanup(paths);
    }

    #[test]
    fn probe_rejects_malformed_json_rpc() {
        let paths = fixture("#!/bin/sh\nread request\nprintf '{not-json}\\n'");
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
        let paths = fixture("#!/bin/sh\nread request\nsleep 2 & wait");
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
