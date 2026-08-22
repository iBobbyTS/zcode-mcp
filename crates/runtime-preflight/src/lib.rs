use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    env,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
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
        runtime_path: Some(path.canonicalize()?.display().to_string()),
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
    let Some(path) = path else {
        return untested("runtime unavailable");
    };
    if !path.is_file() {
        return untested("runtime unavailable");
    }
    let mut child = match Command::new("node")
        .arg(path)
        .arg("app-server")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
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
        .and_then(|stdin| std::io::Write::write_all(stdin, request.as_bytes()).ok())
        .is_none()
    {
        return failed("unable to write probe");
    }
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if child.try_wait().ok().flatten().is_none() {
        let _ = child.kill();
    }
    let output = child.wait_with_output();
    let Ok(output) = output else {
        return failed("unable to read probe");
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().unwrap_or("");
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return failed("non-JSON app-server output");
    };
    let mut methods = Vec::new();
    if let Some(method) = value.get("method").and_then(|v| v.as_str()) {
        methods.push(method.to_string());
    }
    let status = if value.get("result").is_some() {
        "tested"
    } else {
        "incompatible"
    };
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
        ..untested("")
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
}
