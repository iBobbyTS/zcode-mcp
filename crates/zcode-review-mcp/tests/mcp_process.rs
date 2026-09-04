use serde_json::{json, Value};
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn discover() -> Vec<Value> {
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
    let frames = [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
    ];
    {
        let stdin = child.stdin.as_mut().unwrap();
        for frame in frames {
            writeln!(stdin, "{frame}").unwrap();
        }
    }
    drop(child.stdin.take());
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

#[test]
fn stdio_catalog_is_exactly_the_generic_nine_tools() {
    let frames = discover();
    let tools = frames.iter().find(|frame| frame["id"] == 2).unwrap()["result"]["tools"]
        .as_array()
        .unwrap();
    let names = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(names, zcode_review_mcp::V2_PUBLIC_TOOLS);
    let schema = serde_json::to_string(tools).unwrap();
    for forbidden in [
        concat!("zcode_", "review_"),
        "zcode_system_ensure_ready",
        "zcode_agent_get",
        "zcode_agent_events",
        "zcode_agent_wait",
        concat!("review", "_id"),
        concat!("report_", "markdown"),
        concat!("check_", "report"),
        concat!("artifact", "_intents"),
        "interrupt_and_continue",
        "semantic_soft_timeout_ms",
        "semantic_hard_timeout_ms",
    ] {
        assert!(!schema.contains(forbidden), "catalog leaked {forbidden}");
    }
}
