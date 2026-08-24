use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn discover(protocol_version: &str) -> Vec<Value> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zcode-review-mcp"))
        .env(
            "ZCODE_REVIEWD_SOCKET",
            "/tmp/zcode-review-mcp-test-unused.sock",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for request in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":protocol_version,"capabilities":{},"clientInfo":{"name":"fixture","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    ] {
        writeln!(stdin, "{request}").unwrap();
    }
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let frames = stdout
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        frames.len(),
        2,
        "stdout must contain only MCP response frames: {stdout}"
    );
    frames
}

#[test]
fn stdio_is_clean_and_modern_and_legacy_clients_discover_exact_tools() {
    for version in ["2025-11-25", "2024-11-05"] {
        let frames = discover(version);
        assert_eq!(frames[0]["result"]["protocolVersion"], version);
        let tools = frames[1]["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), zcode_review_mcp::PUBLIC_TOOLS.len());
        assert!(tools.iter().all(|tool| tool.get("outputSchema").is_some()));
    }
}
