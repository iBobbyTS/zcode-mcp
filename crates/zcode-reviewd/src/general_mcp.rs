use crate::rpc::{
    GeneralCompleteInput, GeneralRunCheckInput, RpcClient, RpcMethod, RpcOutcome, RpcRequest,
    RpcSuccess, RPC_VERSION,
};
use review_preparation::GeneralCompletionSubmission;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Write},
    path::Path,
    time::Duration,
};

pub const GENERAL_COMPLETE_TOOL: &str = "zcode_general_complete";
pub const GENERAL_RUN_CHECK_TOOL: &str = "zcode_general_run_check";
const MAX_MCP_FRAME_BYTES: usize = 64 * 1024;

pub fn serve<R: BufRead, W: Write>(
    socket: &Path,
    agent_id: &str,
    mut reader: R,
    mut writer: W,
) -> io::Result<()> {
    let client = RpcClient::new(socket, Duration::from_secs(3_605));
    let mut sequence = 0u64;
    loop {
        let line = match read_frame(&mut reader, MAX_MCP_FRAME_BYTES)? {
            FrameRead::Eof => return Ok(()),
            FrameRead::Oversized => {
                write_response(
                    &mut writer,
                    &json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"request exceeds cap"}}),
                )?;
                continue;
            }
            FrameRead::Frame(line) => line,
        };
        let value: Value = match serde_json::from_slice(&line) {
            Ok(value) => value,
            Err(_) => {
                write_response(
                    &mut writer,
                    &json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"invalid JSON"}}),
                )?;
                continue;
            }
        };
        let id = value.get("id").cloned();
        if id.is_none() {
            continue;
        }
        let id = id.unwrap_or(Value::Null);
        let response = match value.get("method").and_then(Value::as_str) {
            Some("initialize") => json!({
                "jsonrpc":"2.0","id":id,"result":{
                    "protocolVersion":"2025-06-18",
                    "capabilities":{"tools":{"listChanged":false}},
                    "serverInfo":{"name":"zcode-general-completion","version":env!("CARGO_PKG_VERSION")}
                }
            }),
            Some("ping") => json!({"jsonrpc":"2.0","id":id,"result":{}}),
            Some("tools/list") => json!({
                "jsonrpc":"2.0","id":id,"result":{"tools":[completion_tool_definition(), run_check_tool_definition()]}
            }),
            Some("tools/call") => {
                sequence = sequence.saturating_add(1);
                call_tool(&client, agent_id, sequence, &value, id)
            }
            Some(_) => json!({
                "jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"method not found"}
            }),
            None => json!({
                "jsonrpc":"2.0","id":id,"error":{"code":-32600,"message":"invalid request"}
            }),
        };
        write_response(&mut writer, &response)?;
    }
}

fn call_tool(
    client: &RpcClient,
    agent_id: &str,
    sequence: u64,
    request: &Value,
    id: Value,
) -> Value {
    let Some(params) = request.get("params").and_then(Value::as_object) else {
        return invalid_params(id);
    };
    let (request_id, method) =
        match params.get("name").and_then(Value::as_str) {
            Some(GENERAL_COMPLETE_TOOL) => {
                let Some(submission) = params.get("arguments").cloned().and_then(|arguments| {
                    serde_json::from_value::<GeneralCompletionSubmission>(arguments).ok()
                }) else {
                    return invalid_params(id);
                };
                (
                    format!("general-completion-{sequence}"),
                    RpcMethod::GeneralComplete(GeneralCompleteInput {
                        agent_id: agent_id.to_owned(),
                        submission,
                    }),
                )
            }
            Some(GENERAL_RUN_CHECK_TOOL) => {
                let Some(arguments) = params.get("arguments").cloned().and_then(|arguments| {
                    serde_json::from_value::<RunCheckArguments>(arguments).ok()
                }) else {
                    return invalid_params(id);
                };
                (
                    format!("general-check-{sequence}"),
                    RpcMethod::GeneralRunCheck(GeneralRunCheckInput {
                        agent_id: agent_id.to_owned(),
                        command_id: arguments.command_id,
                    }),
                )
            }
            _ => return invalid_params(id),
        };
    let request = RpcRequest {
        version: RPC_VERSION,
        request_id,
        method,
    };
    match client.call(&request) {
        Ok(response) => match response.outcome {
            RpcOutcome::Success { result } => match *result {
                RpcSuccess::GeneralCompletionAccepted { accepted } => json!({
                    "jsonrpc":"2.0","id":id,"result":{
                        "content":[{"type":"text","text":"general completion accepted"}],
                        "structuredContent":{"accepted":accepted},"isError":false
                    }
                }),
                RpcSuccess::GeneralCheckCompleted { result } => json!({
                    "jsonrpc":"2.0","id":id,"result":{
                        "content":[{"type":"text","text":if result.succeeded {"named check passed"} else {"named check failed"}}],
                        "structuredContent":result,
                        "isError":!result.succeeded
                    }
                }),
                _ => tool_error(id, "daemon returned an unexpected result"),
            },
            RpcOutcome::Error { error } => tool_error(id, &error.message),
        },
        Err(_) => tool_error(id, "review daemon is unavailable"),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunCheckArguments {
    command_id: String,
}

fn completion_tool_definition() -> Value {
    json!({
        "name":GENERAL_COMPLETE_TOOL,
        "description":"Submit the final bounded result for this general task.",
        "inputSchema":{
            "type":"object","additionalProperties":false,
            "required":["requested_outcome","summary"],
            "properties":{
                "requested_outcome":{"enum":["SUCCEEDED","BLOCKED"]},
                "summary":{"type":"string","minLength":1,"maxLength":262144,"pattern":"^[^\\u0000]+$"},
                "checks":{"type":"array","maxItems":128,"items":{"type":"string","maxLength":16384,"pattern":"^[^\\u0000]*$"}},
                "residual_gaps":{"type":"array","maxItems":128,"items":{"type":"string","maxLength":16384,"pattern":"^[^\\u0000]*$"}},
                "artifact_intents":{"type":"array","maxItems":3,"items":{
                    "type":"object","additionalProperties":false,"required":["kind"],
                    "properties":{
                        "kind":{"enum":["report_markdown","changes_patch","check_report"]},
                        "sha256":{"type":"string","pattern":"^[A-Fa-f0-9]{64}$"},
                        "size_bytes":{"type":"integer","minimum":1}
                    }
                }}
            }
        }
    })
}

fn run_check_tool_definition() -> Value {
    json!({
        "name":GENERAL_RUN_CHECK_TOOL,
        "description":"Run one daemon-published validation command selected for this task.",
        "inputSchema":{
            "type":"object","additionalProperties":false,
            "required":["command_id"],
            "properties":{
                "command_id":{"type":"string","minLength":1,"maxLength":256,"pattern":"^[A-Za-z0-9_.:-]+$"}
            }
        }
    })
}

enum FrameRead {
    Eof,
    Frame(Vec<u8>),
    Oversized,
}

fn read_frame(reader: &mut impl BufRead, cap: usize) -> io::Result<FrameRead> {
    let mut frame = Vec::with_capacity(cap.min(8 * 1024));
    let mut oversized = false;
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if oversized {
                Ok(FrameRead::Oversized)
            } else if frame.is_empty() {
                Ok(FrameRead::Eof)
            } else {
                Ok(FrameRead::Frame(frame))
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.unwrap_or(available.len());
        if !oversized {
            if frame.len().saturating_add(take) > cap {
                frame.clear();
                oversized = true;
            } else {
                frame.extend_from_slice(&available[..take]);
            }
        }
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            if oversized {
                return Ok(FrameRead::Oversized);
            }
            if frame.last() == Some(&b'\r') {
                frame.pop();
            }
            return Ok(FrameRead::Frame(frame));
        }
    }
}

fn invalid_params(id: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":-32602,"message":"invalid tool call"}})
}

fn tool_error(id: Value, message: &str) -> Value {
    let mut bounded = message.to_owned();
    bounded.truncate(512);
    json!({
        "jsonrpc":"2.0","id":id,"result":{
            "content":[{"type":"text","text":bounded}],"isError":true
        }
    })
}

fn write_response(writer: &mut impl Write, response: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, response).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_tool_schema_is_closed_and_bounded() {
        let schema = &completion_tool_definition()["inputSchema"];
        jsonschema::draft202012::meta::validate(schema).unwrap();
        let validator = jsonschema::draft202012::options().build(schema).unwrap();
        assert!(validator.is_valid(&json!({
            "requested_outcome":"SUCCEEDED","summary":"done","checks":[],
            "residual_gaps":[],"artifact_intents":[]
        })));
        assert!(!validator.is_valid(&json!({
            "requested_outcome":"SUCCEEDED","summary":"done","unexpected":true
        })));
    }

    #[test]
    fn run_check_tool_schema_accepts_only_exact_command_id() {
        let schema = &run_check_tool_definition()["inputSchema"];
        jsonschema::draft202012::meta::validate(schema).unwrap();
        let validator = jsonschema::draft202012::options().build(schema).unwrap();
        assert!(validator.is_valid(&json!({"command_id":"cargo-test"})));
        for invalid in [
            json!({"command_id":"cargo-test","args":["--all"]}),
            json!({"command_id":"cargo test"}),
            json!({"program":"cargo"}),
        ] {
            assert!(!validator.is_valid(&invalid), "accepted {invalid}");
        }
        assert!(serde_json::from_value::<RunCheckArguments>(json!({
            "command_id":"cargo-test","cwd":"."
        }))
        .is_err());
    }
}
