use serde_json::{json, Map, Value};
use std::io::{self, BufRead, Write};

fn write_value(out: &mut impl Write, value: Value) -> io::Result<()> {
    serde_json::to_writer(&mut *out, &value)?;
    out.write_all(b"\n")?;
    out.flush()
}

fn response(id: Value, result: Value) -> Value {
    json!({"id": id, "result": result})
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({"id": id, "error": {"code": code, "message": message}})
}

fn event(sequence: &mut u64, session_id: &str, kind: &str, payload: Value) -> Value {
    *sequence = sequence.saturating_add(1);
    json!({
        "method": "session/event",
        "params": {
            "eventId": format!("fake-event-{sequence}"),
            "sessionId": session_id,
            "seq": sequence,
            "timestamp": sequence,
            "type": kind,
            "payload": payload,
        }
    })
}

fn exact_keys(object: &Map<String, Value>, required: &[&str], optional: &[&str]) -> bool {
    required.iter().all(|key| object.contains_key(*key))
        && object
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
}

fn valid_wire_id(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.as_i64().is_some() || value.is_string())
}

fn valid_request_envelope(value: &Value) -> bool {
    value.get("jsonrpc").is_none()
        && value.as_object().is_some_and(|object| {
            exact_keys(object, &["id", "method", "params"], &[]) && valid_wire_id(object.get("id"))
        })
}

fn valid_response_envelope(value: &Value) -> bool {
    value.get("jsonrpc").is_none()
        && value.as_object().is_some_and(|object| {
            exact_keys(object, &["id", "result"], &[])
                && valid_wire_id(object.get("id"))
                && object.get("result").is_some_and(|result| !result.is_null())
        })
}

fn valid_params(method: &str, params: &Value, session_id: &str) -> bool {
    let Some(params) = params.as_object() else {
        return false;
    };
    match method {
        "workspace/readState" => params.is_empty(),
        "session/create" => {
            if !exact_keys(params, &["workspace"], &["mcpServers"]) {
                return false;
            }
            let Some(workspace) = params.get("workspace").and_then(Value::as_object) else {
                return false;
            };
            let workspace_valid = exact_keys(workspace, &["workspaceKey", "workspacePath"], &[])
                && workspace.get("workspaceKey").is_some_and(Value::is_string)
                && workspace.get("workspacePath").is_some_and(Value::is_string);
            let mcp_valid = params.get("mcpServers").is_none_or(|servers| {
                servers.as_array().is_some_and(|servers| {
                    !servers.is_empty()
                        && servers.iter().all(|server| {
                            server.as_object().is_some_and(|server| {
                                exact_keys(server, &["name", "command", "args", "env"], &[])
                                    && server.get("name").is_some_and(Value::is_string)
                                    && server.get("command").is_some_and(Value::is_string)
                                    && server.get("args").is_some_and(Value::is_array)
                                    && server.get("env").is_some_and(Value::is_array)
                            })
                        })
                })
            });
            workspace_valid && mcp_valid
        }
        "session/subscribe" => {
            exact_keys(
                params,
                &["sessionId", "deliveryKind", "includeSnapshot"],
                &["afterSeq"],
            ) && params.get("sessionId").and_then(Value::as_str) == Some(session_id)
                && params.get("deliveryKind").is_some_and(Value::is_string)
                && params.get("includeSnapshot").is_some_and(Value::is_boolean)
        }
        "session/send" => {
            exact_keys(params, &["sessionId", "content"], &["inputId", "queryId"])
                && params.get("sessionId").and_then(Value::as_str) == Some(session_id)
                && params.get("content").is_some_and(Value::is_string)
        }
        "session/stop" | "session/close" => {
            exact_keys(params, &["sessionId"], &[])
                && params.get("sessionId").and_then(Value::as_str) == Some(session_id)
        }
        _ => false,
    }
}

fn valid_permission_response(result: &Value) -> bool {
    let Some(result) = result.as_object() else {
        return false;
    };
    exact_keys(
        result,
        &["decision"],
        &["reason", "modifiedInput", "permissionUpdates"],
    ) && matches!(
        result.get("decision").and_then(Value::as_str),
        Some("allow" | "deny")
    )
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "session".into());
    let stdin = io::stdin();
    let mut out = io::stdout();
    let mut active_turn = false;
    let mut next_turn = 1u64;
    let mut sequence = 0u64;
    let session_id = "fake-session-7f3a";
    let mut pending_permission: Option<Value> = None;

    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        if mode == "malformed" {
            let _ = out.write_all(b"{\n");
            let _ = write_value(
                &mut out,
                event(
                    &mut sequence,
                    session_id,
                    "future.event",
                    json!({"raw": "sensitive"}),
                ),
            );
            break;
        }
        if mode == "out-of-order" {
            let _ = write_value(
                &mut out,
                event(&mut sequence, session_id, "turn.completed", json!({})),
            );
            let _ = write_value(
                &mut out,
                event(&mut sequence, session_id, "turn.started", json!({})),
            );
            break;
        }

        let id = value
            .get("id")
            .filter(|_| valid_wire_id(value.get("id")))
            .cloned()
            .unwrap_or_else(|| Value::String("invalid-id".into()));
        if value.get("jsonrpc").is_some() {
            let _ = write_value(&mut out, error(id, -32600, "jsonrpc is not accepted"));
            continue;
        }
        let Some(object) = value.as_object() else {
            continue;
        };
        if object.get("method").is_none() {
            if valid_response_envelope(&value)
                && pending_permission.as_ref() == Some(&id)
                && object.get("error").is_none()
                && object.get("result").is_some_and(valid_permission_response)
            {
                pending_permission = None;
                let _ = write_value(
                    &mut out,
                    event(
                        &mut sequence,
                        session_id,
                        "permission.responded",
                        json!({"accepted": true}),
                    ),
                );
            }
            continue;
        }
        if !valid_request_envelope(&value) {
            let _ = write_value(&mut out, error(id, -32600, "invalid strict envelope"));
            continue;
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            let _ = write_value(&mut out, error(id, -32600, "method must be a string"));
            continue;
        };
        let params = object.get("params").unwrap_or(&Value::Null);
        if !valid_params(method, params, session_id) {
            let _ = write_value(&mut out, error(id, -32602, "invalid method parameters"));
            continue;
        }
        match method {
            "workspace/readState" => {
                let _ = write_value(&mut out, response(id, json!({"ready": true})));
            }
            "session/create" => {
                let _ = write_value(
                    &mut out,
                    response(id, json!({"session": {"sessionId": session_id}})),
                );
            }
            "session/subscribe" => {
                let _ = write_value(
                    &mut out,
                    response(
                        id,
                        json!({"sessionId": session_id, "eventSeq": sequence, "events": []}),
                    ),
                );
            }
            "session/send" => {
                if active_turn {
                    let _ = write_value(&mut out, error(id, -32010, "PROMPT_ALREADY_RUNNING"));
                    continue;
                }
                let turn_id = format!("fake-turn-{next_turn}");
                next_turn += 1;
                active_turn = true;
                let _ = write_value(
                    &mut out,
                    response(id, json!({"sessionId": session_id, "accepted": true})),
                );
                let _ = write_value(
                    &mut out,
                    event(
                        &mut sequence,
                        session_id,
                        "turn.started",
                        json!({"turnId": turn_id, "turnNumber": next_turn - 1}),
                    ),
                );
                let content = params
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if content.contains("permission") {
                    let request_id = Value::String("server-1".into());
                    pending_permission = Some(request_id.clone());
                    let _ = write_value(
                        &mut out,
                        json!({
                            "id": request_id,
                            "method": "interaction/requestPermission",
                            "params": {
                                "toolCallId": "tool-1",
                                "toolName": "read",
                                "riskLevel": "low",
                                "reason": "fixture permission",
                                "input": {"path": "fixture.txt"},
                                "options": [
                                    {"optionId": "allow-once", "kind": "allow", "name": "Allow once", "response": {"decision": "allow"}},
                                    {"optionId": "deny-once", "kind": "deny", "name": "Deny", "response": {"decision": "deny"}}
                                ]
                            }
                        }),
                    );
                }
                if content.contains("input") {
                    let _ = write_value(
                        &mut out,
                        json!({
                            "id": "server-input-1",
                            "method": "interaction/requestUserInput",
                            "params": {"question": "unsupported fixture input"}
                        }),
                    );
                }
                if content.contains("unknown_event") {
                    let _ = write_value(
                        &mut out,
                        event(
                            &mut sequence,
                            session_id,
                            "future.event",
                            json!({"secret": "redacted"}),
                        ),
                    );
                }
                if content.contains("auto_complete") {
                    let _ = write_value(
                        &mut out,
                        event(
                            &mut sequence,
                            session_id,
                            "turn.completed",
                            json!({"response": "fixture complete"}),
                        ),
                    );
                    active_turn = false;
                }
            }
            "session/stop" => {
                let _ = write_value(&mut out, response(id, json!({"stopped": true})));
                if active_turn {
                    active_turn = false;
                    let _ = write_value(
                        &mut out,
                        event(
                            &mut sequence,
                            session_id,
                            "turn.completed",
                            json!({"stopped": true}),
                        ),
                    );
                }
            }
            "session/close" => {
                let _ = write_value(&mut out, response(id, json!({"closed": true})));
                break;
            }
            _ => unreachable!("valid_params rejects unsupported methods"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_params_reject_legacy_session_and_message_fields() {
        assert!(!valid_params(
            "session/send",
            &json!({"session_id":"fake-session-7f3a","message":"review"}),
            "fake-session-7f3a",
        ));
        assert!(valid_params(
            "session/send",
            &json!({"sessionId":"fake-session-7f3a","content":"review"}),
            "fake-session-7f3a",
        ));
    }

    #[test]
    fn strict_envelope_rejects_jsonrpc_and_extra_fields() {
        assert!(!valid_request_envelope(
            &json!({"jsonrpc":"2.0","id":1,"method":"session/stop","params":{}})
        ));
        assert!(!valid_request_envelope(
            &json!({"id":1,"method":"session/stop","params":{},"legacy":true})
        ));
        assert!(valid_request_envelope(
            &json!({"id":1,"method":"session/stop","params":{"sessionId":"s1"}})
        ));
    }

    #[test]
    fn strict_envelope_rejects_non_wire_ids_and_null_response_outcomes() {
        for id in [json!(true), json!(null), json!({}), json!([]), json!(1.5)] {
            assert!(!valid_request_envelope(
                &json!({"id":id,"method":"session/stop","params":{}})
            ));
            assert!(!valid_response_envelope(&json!({"id":id,"result":{}})));
        }
        assert!(!valid_response_envelope(
            &json!({"id":"server-1","result":null})
        ));
        assert!(valid_response_envelope(
            &json!({"id":"server-1","result":{"decision":"allow"}})
        ));
    }

    #[test]
    fn permission_response_rejects_invented_content_field() {
        assert!(valid_permission_response(&json!({"decision":"allow"})));
        assert!(!valid_permission_response(
            &json!({"decision":"answer","content":"guessed"})
        ));
    }
}
