use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn write_value(out: &mut impl Write, value: Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, &value)?;
    out.write_all(b"\n")?;
    out.flush()
}

fn response(id: Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn event(method: &str, params: Value) -> Value {
    json!({"jsonrpc": "2.0", "method": method, "params": params})
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "session".into());
    let stdin = io::stdin();
    let mut out = io::stdout();
    let mut active_turn: Option<String> = None;
    let mut next_turn = 1u64;
    let session_id = "fake-session-7f3a";

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if mode == "malformed" {
            let _ = out.write_all(b"{\n");
            let _ = write_value(&mut out, event("future/event", json!({"raw": "sensitive"})));
            break;
        }
        if mode == "out-of-order" {
            let _ = write_value(&mut out, event("turn/completed", json!({})));
            let _ = write_value(&mut out, event("turn/started", json!({})));
            break;
        }

        let Some(id) = value.get("id").cloned() else {
            continue;
        };
        let Some(method) = value.get("method").and_then(Value::as_str) else {
            let _ = write_value(
                &mut out,
                event(
                    "session/updated",
                    json!({"response_received": id, "response": value.get("result")}),
                ),
            );
            continue;
        };
        let params = value.get("params").cloned().unwrap_or(Value::Null);
        match method {
            "workspace/readState" => {
                let _ = write_value(&mut out, response(id, json!({"ready": true})));
            }
            "session/create" => {
                let _ = write_value(
                    &mut out,
                    response(id, json!({"session": {"id": session_id}})),
                );
            }
            "session/subscribe" => {
                let _ = write_value(&mut out, response(id, json!({"subscribed": true})));
            }
            "session/send" => {
                if active_turn.is_some() {
                    let _ = write_value(
                        &mut out,
                        json!({
                            "jsonrpc": "2.0",
                            "id": id,
                            "error": {"code": "PROMPT_ALREADY_RUNNING"}
                        }),
                    );
                    continue;
                }
                let turn_id = format!("fake-turn-{next_turn}");
                next_turn += 1;
                active_turn = Some(turn_id.clone());
                let _ = write_value(&mut out, response(id, json!({"turn": {"id": turn_id}})));
                let _ = write_value(&mut out, event("turn/started", json!({"turn_id": turn_id})));
                let content = params
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if content.contains("permission") {
                    let _ = write_value(
                        &mut out,
                        json!({
                            "jsonrpc": "2.0",
                            "id": "permission-1",
                            "method": "permission/request",
                            "params": {"tool": "read", "path": "fixture.txt"}
                        }),
                    );
                }
                if content.contains("input") {
                    let _ = write_value(
                        &mut out,
                        json!({
                            "jsonrpc": "2.0",
                            "id": "input-1",
                            "method": "input/request",
                            "params": {"question": "fixture question"}
                        }),
                    );
                }
                if content.contains("unknown_event") {
                    let _ = write_value(
                        &mut out,
                        event("future/event", json!({"secret": "redacted"})),
                    );
                }
                if content.contains("auto_complete") {
                    let _ = write_value(
                        &mut out,
                        event("turn/completed", json!({"turn_id": turn_id})),
                    );
                    active_turn = None;
                }
            }
            "session/stop" => {
                let _ = write_value(&mut out, response(id, json!({"stopped": true})));
                if let Some(turn_id) = active_turn.take() {
                    let _ = write_value(
                        &mut out,
                        event(
                            "turn/completed",
                            json!({"turn_id": turn_id, "stopped": true}),
                        ),
                    );
                }
            }
            "session/close" => {
                let _ = write_value(&mut out, response(id, json!({"closed": true})));
                break;
            }
            _ => {
                let _ = write_value(
                    &mut out,
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": {"code": "METHOD_NOT_FOUND"}
                    }),
                );
            }
        }
    }
}
