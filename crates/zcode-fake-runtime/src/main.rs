use serde_json::{json, Map, Value};
use std::{
    io::{self, BufRead, BufReader, Read, Write},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const LEDGER_TOOLS: [&str; 5] = [
    "review_checkpoint",
    "review_finding_upsert",
    "review_validation_record",
    "review_finalize",
    "review_progress",
];

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
        "workspace/readState" => {
            exact_keys(params, &["workspace"], &[])
                && params
                    .get("workspace")
                    .and_then(Value::as_object)
                    .is_some_and(|workspace| {
                        exact_keys(workspace, &["workspaceKey", "workspacePath"], &[])
                            && workspace.get("workspaceKey").is_some_and(Value::is_string)
                            && workspace.get("workspacePath").is_some_and(Value::is_string)
                    })
        }
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
                &[],
            ) && params.get("sessionId").and_then(Value::as_str) == Some(session_id)
                && params.get("deliveryKind").and_then(Value::as_str) == Some("desktop-continuous")
                && params.get("includeSnapshot") == Some(&Value::Bool(true))
        }
        "session/send" => {
            exact_keys(params, &["sessionId", "content"], &[])
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

fn is_review_flow(mode: &str) -> bool {
    mode.starts_with("review-flow")
}

fn mcp_request(
    input: &mut impl Write,
    output: &mut impl BufRead,
    id: u64,
    method: &str,
    params: Value,
) -> io::Result<Value> {
    write_value(
        input,
        json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}),
    )?;
    let mut line = String::new();
    if output.read_line(&mut line)? == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "ledger MCP closed without a response",
        ));
    }
    let response: Value = serde_json::from_str(&line).map_err(io::Error::other)?;
    if response.get("id") != Some(&json!(id)) || response.get("error").is_some() {
        return Err(io::Error::other("ledger MCP returned an invalid response"));
    }
    Ok(response)
}

fn ledger_tool_call(
    input: &mut impl Write,
    output: &mut impl BufRead,
    id: u64,
    name: &str,
    arguments: Value,
) -> io::Result<()> {
    let response = mcp_request(
        input,
        output,
        id,
        "tools/call",
        json!({"name":name,"arguments":arguments}),
    )?;
    let result = response
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| io::Error::other("ledger tool response has no result"))?;
    if result.get("isError") != Some(&Value::Bool(false))
        || result.get("structuredContent").is_none()
    {
        return Err(io::Error::other("ledger tool call was not successful"));
    }
    Ok(())
}

fn wait_ledger_child(child: &mut Child) -> io::Result<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| io::Error::other(format!("stage=child-wait: {error}")))?
        {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return child.wait().map_err(|error| {
                io::Error::other(format!(
                    "stage=child-wait: timeout; kill wait failed: {error}"
                ))
            });
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn run_ledger_flow(server: &Value, finalize: bool) -> io::Result<()> {
    let mode = std::env::var("ZCODE_FAKE_MODE").unwrap_or_default();
    let server = server
        .as_object()
        .ok_or_else(|| io::Error::other("ledger MCP descriptor is not an object"))?;
    if server.get("name").and_then(Value::as_str) != Some("review-ledger") {
        return Err(io::Error::other("ledger MCP descriptor has the wrong name"));
    }
    let command = server
        .get("command")
        .and_then(Value::as_str)
        .ok_or_else(|| io::Error::other("ledger MCP command is missing"))?;
    let args = server
        .get("args")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other("ledger MCP args are missing"))?;
    let task_scoped = args
        .iter()
        .any(|value| value.as_str() == Some("--task-ledger-mcp"));
    let env = server
        .get("env")
        .and_then(Value::as_array)
        .ok_or_else(|| io::Error::other("ledger MCP env is missing"))?;
    let mut process = Command::new(command);
    for argument in args {
        process.arg(
            argument
                .as_str()
                .ok_or_else(|| io::Error::other("ledger MCP arg is not text"))?,
        );
    }
    for variable in env {
        let variable = variable
            .as_object()
            .ok_or_else(|| io::Error::other("ledger MCP env entry is not an object"))?;
        let name = variable
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("ledger MCP env name is missing"))?;
        let value = variable
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(|| io::Error::other("ledger MCP env value is missing"))?;
        process.env(name, value);
    }
    let mut child = process
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| io::Error::other(format!("stage=spawn: {error}")))?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("ledger MCP stdin is missing"))?;
    let mut output = BufReader::new(
        child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("ledger MCP stdout is missing"))?,
    );
    let stderr = child.stderr.take().unwrap();
    let stderr_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stderr.take(8193).read_to_end(&mut bytes);
        let truncated = bytes.len() > 8192;
        bytes.truncate(8192);
        (String::from_utf8_lossy(&bytes).into_owned(), truncated)
    });

    let flow = (|| -> io::Result<()> {
        let initialized = mcp_request(&mut input, &mut output, 1, "initialize", json!({}))
            .map_err(|error| io::Error::other(format!("stage=initialize: {error}")))?;
        if initialized["result"]["serverInfo"]["name"] != "zcode-review-ledger" {
            return Err(io::Error::other(
                "stage=initialize: ledger MCP response is invalid",
            ));
        }
        let listed = mcp_request(&mut input, &mut output, 2, "tools/list", json!({}))
            .map_err(|error| io::Error::other(format!("stage=tools-list: {error}")))?;
        let names = listed["result"]["tools"]
            .as_array()
            .ok_or_else(|| io::Error::other("stage=tools-list: tool list is missing"))?
            .iter()
            .filter_map(|tool| tool.get("name").and_then(Value::as_str))
            .collect::<Vec<_>>();
        let expected_tools = if task_scoped {
            LEDGER_TOOLS.as_slice()
        } else {
            &LEDGER_TOOLS[..4]
        };
        if names != expected_tools {
            return Err(io::Error::other(
                "stage=tools-list: ledger MCP tool list is not exact",
            ));
        }

        let mut next_id = 3;
        if task_scoped && mode != "review-flow-ledger-without-progress" {
            ledger_tool_call(
                &mut input,
                &mut output,
                next_id,
                LEDGER_TOOLS[4],
                json!({
                    "stage":"inspection",
                    "summary":"fake runtime started semantic review",
                    "counters":{"files":0}
                }),
            )
            .map_err(|error| io::Error::other(format!("stage=progress: {error}")))?;
            next_id += 1;
        }
        if mode == "review-flow-progress-only" {
            return Ok(());
        }
        ledger_tool_call(
        &mut input,
        &mut output,
        next_id,
        LEDGER_TOOLS[0],
        json!({
            "checkpoint_id":"scope-1","stage":"inspection","summary":"bounded evidence observed",
            "inspected":[{"path":"src/approval.rs","line_ranges":["1"]}],
            "commands":[],"open_questions":[],"remaining_scope":[]
        }),
    )
        .map_err(|error| io::Error::other(format!("stage=checkpoint: {error}")))?;
        ledger_tool_call(
        &mut input,
        &mut output,
        next_id + 1,
        LEDGER_TOOLS[1],
        json!({
            "finding_id":"S06-F1","severity":"P2","confidence":"medium",
            "title":"candidate","locations":[{"path":"src/approval.rs","start_line":1,"end_line":1}],
            "evidence":["observable fixture"],"impact":"bounded","suggested_remediation":"none",
            "status":"open"
        }),
    )
        .map_err(|error| io::Error::other(format!("stage=finding-open: {error}")))?;
        ledger_tool_call(
        &mut input,
        &mut output,
        next_id + 2,
        LEDGER_TOOLS[1],
        json!({
            "finding_id":"S06-F1","severity":"P2","confidence":"high",
            "title":"candidate disproved","locations":[{"path":"src/approval.rs","start_line":1,"end_line":1}],
            "evidence":["later observable fixture"],"impact":"none","suggested_remediation":"none",
            "status":"withdrawn"
        }),
    )
        .map_err(|error| io::Error::other(format!("stage=finding-withdraw: {error}")))?;
        ledger_tool_call(
            &mut input,
            &mut output,
            next_id + 3,
            LEDGER_TOOLS[2],
            json!({
                "validation_id":"validation-1","command":"cargo test -p fixture","cwd":".",
                "exit_code":0,"duration_ms":1,"stdout_summary":"passed","stderr_summary":"",
                "related_findings":[]
            }),
        )
        .map_err(|error| io::Error::other(format!("stage=validation: {error}")))?;
        if finalize {
            ledger_tool_call(
                &mut input,
                &mut output,
                next_id + 4,
                LEDGER_TOOLS[3],
                json!({
                    "signal":"no_findings_observed","summary":"bounded review complete",
                    "coverage":{"covered":["src"],"not_covered":[]},
                    "uncertainties":[],"recommended_next_actions":[]
                }),
            )
            .map_err(|error| io::Error::other(format!("stage=finalize: {error}")))?;
        }
        Ok(())
    })();
    drop(input);
    let status = wait_ledger_child(&mut child);
    let (stderr_text, stderr_truncated) = stderr_reader.join().unwrap_or_default();
    let status = status?;
    if let Err(error) = flow {
        return Err(io::Error::other(format!(
            "{error}; child_status={status}; stderr={stderr_text:?}; stderr_truncated={stderr_truncated}"
        )));
    }
    if !status.success() {
        return Err(io::Error::other(format!(
            "stage=child-wait: ledger MCP process exited with {status}; stderr={stderr_text:?}; stderr_truncated={stderr_truncated}"
        )));
    }
    Ok(())
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "session".into());
    let stdin = io::stdin();
    let mut out = io::stdout();
    let mut active_turn = false;
    let mut next_turn = 1u64;
    let mut sequence = 0u64;
    let mut ledger_server: Option<Value> = None;
    let mut ledger_completed = false;
    let session_id =
        std::env::var("ZCODE_FAKE_SESSION_ID").unwrap_or_else(|_| "fake-session-7f3a".into());
    let mut pending_permission: Option<Value> = None;
    let _descendant: Option<Child> = if is_review_flow(&mode) {
        Command::new("sh")
            .args(["-c", "trap '' TERM; sleep 30"])
            .spawn()
            .ok()
    } else {
        None
    };

    let mut lines = stdin.lock().lines();
    while let Some(line) = lines.next() {
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
                    &session_id,
                    "future.event",
                    json!({"raw": "sensitive"}),
                ),
            );
            break;
        }
        if mode == "out-of-order" {
            let _ = write_value(
                &mut out,
                event(&mut sequence, &session_id, "turn.completed", json!({})),
            );
            let _ = write_value(
                &mut out,
                event(&mut sequence, &session_id, "turn.started", json!({})),
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
                let expected_response = if is_review_flow(&mode) {
                    json!({"decision": "deny", "reason": "denied"})
                } else {
                    json!({"decision": "allow", "reason": "allowed once"})
                };
                if object.get("result") != Some(&expected_response) {
                    continue;
                }
                if is_review_flow(&mode)
                    && mode != "review-flow-no-ledger"
                    && mode != "review-flow-no-progress"
                    && !ledger_completed
                {
                    let Some(server) = ledger_server.as_ref() else {
                        std::process::exit(23);
                    };
                    if let Err(error) = run_ledger_flow(server, mode != "review-flow-no-finalize") {
                        eprintln!("fake-runtime ledger failure: {error}");
                        std::process::exit(23);
                    }
                    ledger_completed = true;
                }
                pending_permission = None;
                if is_review_flow(&mode) && active_turn {
                    active_turn = false;
                    let _ = write_value(
                        &mut out,
                        event(
                            &mut sequence,
                            &session_id,
                            "turn.completed",
                            json!({"response": "permission settled"}),
                        ),
                    );
                }
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
        if !valid_params(method, params, &session_id) {
            let _ = write_value(&mut out, error(id, -32602, "invalid method parameters"));
            continue;
        }
        match method {
            "workspace/readState" => {
                let _ = write_value(&mut out, response(id, json!({"ready": true})));
            }
            "session/create" => {
                ledger_server = params
                    .get("mcpServers")
                    .and_then(Value::as_array)
                    .and_then(|servers| {
                        servers.iter().find(|server| {
                            server.get("name").and_then(Value::as_str) == Some("review-ledger")
                        })
                    })
                    .cloned();
                let preference_id = Value::String("runtime-preferences-1".into());
                let _ = write_value(
                    &mut out,
                    json!({
                        "id": preference_id,
                        "method": "session/requestRuntimePreferences",
                        "params": {"scope":"session","sessionId":&session_id}
                    }),
                );
                let preference_response = lines
                    .next()
                    .and_then(Result::ok)
                    .and_then(|line| serde_json::from_str::<Value>(&line).ok());
                if preference_response.as_ref().is_none_or(|response| {
                    response.get("id") != Some(&preference_id)
                        || response.get("result")
                            != Some(&json!({
                                "nativeSearchEnhancementsEnabled":false,
                                "memoryEnabled":false,
                                "askUserQuestionAutoResolutionEnabled":false
                            }))
                }) {
                    std::process::exit(24);
                }
                let _ = write_value(
                    &mut out,
                    response(
                        id,
                        json!({
                            "session": {"sessionId": &session_id},
                            "settings":{"model":{"current":{"modelId":"fixture-model"}}}
                        }),
                    ),
                );
            }
            "session/subscribe" => {
                let _ = write_value(
                    &mut out,
                    response(
                        id,
                        json!({"sessionId": &session_id, "eventSeq": sequence, "events": []}),
                    ),
                );
            }
            "session/send" => {
                let content = params
                    .get("content")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if mode == "review-flow-nudge-send-failure"
                    && content.contains("Provide one bounded semantic progress update")
                {
                    let _ = write_value(&mut out, error(id, -32012, "SCRIPTED_NUDGE_FAILURE"));
                    continue;
                }
                if mode == "review-flow-send-failure" && next_turn > 1 {
                    let _ = write_value(&mut out, error(id, -32011, "SCRIPTED_SEND_FAILURE"));
                    continue;
                }
                if active_turn {
                    let _ = write_value(&mut out, error(id, -32010, "PROMPT_ALREADY_RUNNING"));
                    continue;
                }
                let turn_id = format!("fake-turn-{next_turn}");
                next_turn += 1;
                active_turn = true;
                let _ = write_value(
                    &mut out,
                    response(id, json!({"sessionId": &session_id, "accepted": true})),
                );
                let _ = write_value(
                    &mut out,
                    event(
                        &mut sequence,
                        &session_id,
                        "turn.started",
                        json!({"turnId": turn_id, "turnNumber": next_turn - 1}),
                    ),
                );
                let review_flow_initial = is_review_flow(&mode) && next_turn == 2;
                if content.contains("permission") || review_flow_initial {
                    let request_id = Value::String("server-1".into());
                    pending_permission = Some(request_id.clone());
                    let hard_deny = review_flow_initial;
                    let _ = write_value(
                        &mut out,
                        json!({
                            "id": request_id,
                            "method": "interaction/requestPermission",
                            "params": {
                                "toolCallId": "tool-1",
                                "toolName": if hard_deny { "git_ref_mutation" } else { "read" },
                                "riskLevel": "low",
                                "reason": "fixture permission",
                                "input": if hard_deny { json!({}) } else { json!({"path": "fixture.txt"}) },
                                "options": [
                                    {"id": "allow_once", "kind": "allow_once", "label": "Allow once", "response": {"decision": "allow", "reason": "allowed once"}},
                                    {"id": "deny", "kind": "deny", "label": "Deny", "response": {"decision": "deny", "reason": "denied"}}
                                ]
                            }
                        }),
                    );
                }
                if content.contains("input") || review_flow_initial {
                    let _ = write_value(
                        &mut out,
                        json!({
                            "id": "server-input-1",
                            "method": "interaction/requestUserInput",
                            "params": {"question": "unsupported fixture input"}
                        }),
                    );
                }
                if content.contains("unknown_event") || review_flow_initial {
                    let _ = write_value(
                        &mut out,
                        event(
                            &mut sequence,
                            &session_id,
                            "future.event",
                            json!({"secret": "redacted"}),
                        ),
                    );
                }
                if content.contains("auto_complete") {
                    if is_review_flow(&mode)
                        && mode != "review-flow-no-ledger"
                        && mode != "review-flow-no-progress"
                        && !ledger_completed
                    {
                        let Some(server) = ledger_server.as_ref() else {
                            std::process::exit(23);
                        };
                        if let Err(error) =
                            run_ledger_flow(server, mode != "review-flow-no-finalize")
                        {
                            eprintln!("fake-runtime ledger failure: {error}");
                            std::process::exit(23);
                        }
                        ledger_completed = true;
                    }
                    let _ = write_value(
                        &mut out,
                        event(
                            &mut sequence,
                            &session_id,
                            "turn.completed",
                            json!({"response": "fixture complete"}),
                        ),
                    );
                    active_turn = false;
                }
                if mode == "crash" {
                    std::process::exit(17);
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
                            &session_id,
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
    fn pinned_request_keys_accept_observed_and_reject_unobserved_fields() {
        assert!(valid_params(
            "workspace/readState",
            &json!({
                "workspace": {
                    "workspaceKey": "workspace-key",
                    "workspacePath": "/workspace"
                }
            }),
            "fake-session-7f3a",
        ));
        assert!(!valid_params(
            "workspace/readState",
            &json!({
                "workspace": {
                    "workspaceKey": "workspace-key",
                    "workspacePath": "/workspace"
                },
                "invented": true
            }),
            "fake-session-7f3a",
        ));
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
        assert!(valid_params(
            "session/subscribe",
            &json!({
                "sessionId":"fake-session-7f3a",
                "deliveryKind":"desktop-continuous",
                "includeSnapshot":true
            }),
            "fake-session-7f3a",
        ));
        assert!(!valid_params(
            "session/subscribe",
            &json!({
                "sessionId":"fake-session-7f3a",
                "deliveryKind":"desktop-continuous",
                "includeSnapshot":true,
                "afterSeq":0
            }),
            "fake-session-7f3a",
        ));
        for key in ["inputId", "queryId"] {
            let mut params = json!({
                "sessionId":"fake-session-7f3a",
                "content":"review"
            });
            params
                .as_object_mut()
                .unwrap()
                .insert(key.into(), json!("invented"));
            assert!(!valid_params("session/send", &params, "fake-session-7f3a",));
        }
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
