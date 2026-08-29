use crate::rpc::{
    ReviewToolInput, RpcClient, RpcMethod, RpcOutcome, RpcRequest, RpcSuccess, RPC_VERSION,
};
use review_ledger::{
    MAX_TOOL_ID_BYTES, MAX_TOOL_ITEMS, MAX_TOOL_TEXT_CHARS, REVIEW_CHECKPOINT, REVIEW_FINALIZE,
    REVIEW_FINDING_UPSERT, REVIEW_PROGRESS, REVIEW_VALIDATION_RECORD,
};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Write},
    path::Path,
    time::Duration,
};

const MAX_MCP_FRAME_BYTES: usize = 64 * 1024;

pub fn serve<R: BufRead, W: Write>(
    socket: &Path,
    agent_id: &str,
    reader: R,
    writer: W,
) -> io::Result<()> {
    serve_routed(socket, agent_id, false, reader, writer)
}

pub fn serve_task<R: BufRead, W: Write>(
    socket: &Path,
    agent_id: &str,
    reader: R,
    writer: W,
) -> io::Result<()> {
    serve_routed(socket, agent_id, true, reader, writer)
}

fn serve_routed<R: BufRead, W: Write>(
    socket: &Path,
    agent_id: &str,
    task_scoped: bool,
    mut reader: R,
    mut writer: W,
) -> io::Result<()> {
    let client = RpcClient::new(socket, Duration::from_secs(5));
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
        let Some(method) = value.get("method").and_then(Value::as_str) else {
            write_response(
                &mut writer,
                &json!({"jsonrpc":"2.0","id":value.get("id").cloned().unwrap_or(Value::Null),"error":{"code":-32600,"message":"invalid request"}}),
            )?;
            continue;
        };
        let id = value.get("id").cloned();
        if id.is_none() {
            continue;
        }
        let id = id.unwrap_or(Value::Null);
        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "zcode-review-ledger", "version": env!("CARGO_PKG_VERSION")}
                }
            }),
            "ping" => json!({"jsonrpc":"2.0","id":id,"result":{}}),
            "tools/list" => json!({
                "jsonrpc":"2.0",
                "id":id,
                "result":{"tools": tool_definitions()}
            }),
            "tools/call" => {
                sequence = sequence.saturating_add(1);
                call_tool(&client, agent_id, task_scoped, sequence, &value, id)
            }
            _ => json!({
                "jsonrpc":"2.0",
                "id":id,
                "error":{"code":-32601,"message":"method not found"}
            }),
        };
        write_response(&mut writer, &response)?;
    }
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

fn call_tool(
    client: &RpcClient,
    agent_id: &str,
    task_scoped: bool,
    sequence: u64,
    request: &Value,
    id: Value,
) -> Value {
    let Some(params) = request.get("params").and_then(Value::as_object) else {
        return invalid_params(id);
    };
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return invalid_params(id);
    };
    if !matches!(
        name,
        REVIEW_CHECKPOINT
            | REVIEW_FINDING_UPSERT
            | REVIEW_VALIDATION_RECORD
            | REVIEW_FINALIZE
            | REVIEW_PROGRESS
    ) {
        return invalid_params(id);
    }
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let input = ReviewToolInput {
        agent_id: agent_id.to_owned(),
        tool: name.to_owned(),
        arguments,
    };
    let rpc = RpcRequest {
        version: RPC_VERSION,
        request_id: format!("ledger-{sequence}"),
        method: if task_scoped {
            RpcMethod::TaskReviewTool(input)
        } else {
            RpcMethod::ReviewTool(input)
        },
    };
    match client.call(&rpc) {
        Ok(response) => match response.outcome {
            RpcOutcome::Success { result } => match *result {
                RpcSuccess::ReviewTool { result } => json!({
                    "jsonrpc":"2.0",
                    "id":id,
                    "result":{
                        "content":[{"type":"text","text":serde_json::to_string(&result).unwrap_or_else(|_| "{}".into())}],
                        "structuredContent":result,
                        "isError":false
                    }
                }),
                _ => tool_error(id, "daemon returned an unexpected result"),
            },
            RpcOutcome::Error { error } => tool_error(id, &error.message),
        },
        Err(_) => tool_error(id, "review daemon is unavailable"),
    }
}

fn tool_error(id: Value, message: &str) -> Value {
    let mut bounded = message.to_owned();
    bounded.truncate(512);
    json!({
        "jsonrpc":"2.0",
        "id":id,
        "result":{
            "content":[{"type":"text","text":bounded}],
            "isError":true
        }
    })
}

fn invalid_params(id: Value) -> Value {
    json!({
        "jsonrpc":"2.0",
        "id":id,
        "error":{"code":-32602,"message":"invalid tool call"}
    })
}

fn write_response(writer: &mut impl Write, response: &Value) -> io::Result<()> {
    serde_json::to_writer(&mut *writer, response).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn tool_definitions() -> Value {
    let id = || {
        json!({
            "type":"string",
            "minLength":1,
            "maxLength":MAX_TOOL_ID_BYTES,
            "pattern":"^[A-Za-z0-9._:-]+$"
        })
    };
    let text = || {
        json!({
            "type":"string",
            "minLength":1,
            "maxLength":MAX_TOOL_TEXT_CHARS,
            "pattern":"^[^\\u0000]+$"
        })
    };
    let optional_text = || {
        json!({
            "type":"string",
            "maxLength":MAX_TOOL_TEXT_CHARS,
            "pattern":"^[^\\u0000]*$"
        })
    };
    let text_array = || json!({"type":"array","maxItems":MAX_TOOL_ITEMS,"items":text()});
    json!([
        {
            "name": REVIEW_CHECKPOINT,
            "description": "Record one observable evidence checkpoint.",
            "inputSchema": {
                "type":"object","additionalProperties":false,
                "required":["checkpoint_id","stage","summary"],
                "properties":{
                    "checkpoint_id":id(),
                    "stage":{"enum":["scope","inspection","validation","synthesis"]},
                    "summary":text(),
                    "inspected":{"type":"array","maxItems":MAX_TOOL_ITEMS,"items":{
                        "type":"object","additionalProperties":false,"required":["path"],
                        "properties":{"path":text(),"line_ranges":text_array()}
                    }},
                    "commands":{"type":"array","maxItems":MAX_TOOL_ITEMS,"items":{
                        "type":"object","additionalProperties":false,"required":["command","result_summary"],
                        "properties":{"command":text(),"result_summary":text()}
                    }},
                    "open_questions":text_array(),
                    "remaining_scope":text_array()
                }
            }
        },
        {
            "name": REVIEW_FINDING_UPSERT,
            "description": "Create, update, or withdraw one evidence-backed finding.",
            "inputSchema": {
                "type":"object","additionalProperties":false,
                "required":["finding_id","severity","confidence","title","impact","suggested_remediation","status"],
                "properties":{
                    "finding_id":id(),"severity":{"enum":["P0","P1","P2","P3"]},
                    "confidence":{"enum":["high","medium","low"]},"title":text(),
                    "locations":{"type":"array","maxItems":MAX_TOOL_ITEMS,"items":{
                        "type":"object","additionalProperties":false,"required":["path","start_line","end_line"],
                        "properties":{
                            "path":text(),
                            "start_line":{"type":"integer","minimum":1,"maximum":18446744073709551615u64},
                            "end_line":{"type":"integer","minimum":1,"maximum":18446744073709551615u64}
                        }
                    }},"evidence":text_array(),
                    "impact":text(),"suggested_remediation":text(),
                    "status":{"enum":["open","withdrawn"]}
                }
            }
        },
        {
            "name": REVIEW_VALIDATION_RECORD,
            "description": "Record one bounded validation outcome.",
            "inputSchema": {
                "type":"object","additionalProperties":false,
                "required":["validation_id","command","cwd","exit_code","duration_ms","stdout_summary","stderr_summary"],
                "properties":{
                    "validation_id":id(),"command":text(),"cwd":text(),
                    "exit_code":{"type":"integer","minimum":-2147483648,"maximum":2147483647},
                    "duration_ms":{"type":"integer","minimum":0,"maximum":18446744073709551615u64},
                    "stdout_summary":optional_text(),"stderr_summary":optional_text(),
                    "related_findings":{"type":"array","maxItems":MAX_TOOL_ITEMS,"items":id()}
                }
            }
        },
        {
            "name": REVIEW_FINALIZE,
            "description": "Finalize the evidence ledger exactly once.",
            "inputSchema": {
                "type":"object","additionalProperties":false,
                "required":["signal","summary","coverage"],
                "properties":{
                    "signal":{"enum":["findings_present","no_findings_observed","incomplete_evidence","unable_to_review"]},
                    "summary":text(),"coverage":{
                        "type":"object","additionalProperties":false,"required":["covered","not_covered"],
                        "properties":{
                            "covered":text_array(),
                            "not_covered":text_array()
                        }
                    },
                    "uncertainties":text_array(),
                    "recommended_next_actions":text_array()
                }
            }
        },
        {
            "name": REVIEW_PROGRESS,
            "description": "Record bounded semantic progress for the current review attempt.",
            "inputSchema": {
                "type":"object","additionalProperties":false,
                "required":["attempt_sequence","run_idempotency_key","stage","summary"],
                "properties":{
                    "attempt_sequence":{"type":"integer","minimum":1,"maximum":18446744073709551615u64},
                    "run_idempotency_key":id(),
                    "stage":{"enum":["scope","inspection","validation","synthesis"]},
                    "summary":text(),
                    "counters":{"type":"object","maxProperties":16,"additionalProperties":{"type":"integer","minimum":0,"maximum":1000000000}}
                }
            }
        }
    ])
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::{
        rpc::{RpcServer, RpcService, ServerOptions},
        LifecycleSink, ManagedRuntime, RuntimeFactory, Scheduler, SchedulerConfig,
    };
    use review_ledger::{validate_tool_arguments, LedgerManager};
    use review_store::{NewJob, ReviewInitialization, Store};
    use std::{io::Cursor, sync::Arc};

    struct UnusedFactory;

    impl RuntimeFactory for UnusedFactory {
        fn spawn(
            &self,
            _job: &review_store::Job,
            _sink: Arc<dyn LifecycleSink>,
        ) -> io::Result<Arc<dyn ManagedRuntime>> {
            Err(io::Error::other("runtime is unused"))
        }
    }

    #[test]
    fn oversized_frame_is_drained_without_retention_and_next_frame_is_processed() {
        let mut input = vec![b'x'; MAX_MCP_FRAME_BYTES * 8];
        input.push(b'\n');
        input.extend_from_slice(
            serde_json::to_string(&json!({"jsonrpc":"2.0","id":7,"method":"ping"}))
                .unwrap()
                .as_bytes(),
        );
        input.push(b'\n');
        let mut output = Vec::new();
        serve(
            Path::new("/unused/socket"),
            "bound-job",
            Cursor::new(input),
            &mut output,
        )
        .unwrap();
        let responses: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 2);
        assert_eq!(responses[0]["error"]["message"], "request exceeds cap");
        assert_eq!(responses[1]["id"], 7);
        assert_eq!(responses[1]["result"], json!({}));

        let mut output = Vec::new();
        serve(
            Path::new("/unused/socket"),
            "bound-job",
            Cursor::new(vec![b'x'; MAX_MCP_FRAME_BYTES * 8]),
            &mut output,
        )
        .unwrap();
        let response: Value = serde_json::from_slice(
            output
                .strip_suffix(b"\n")
                .expect("one newline-terminated response"),
        )
        .unwrap();
        assert_eq!(response["error"]["message"], "request exceeds cap");
    }

    #[test]
    fn advertised_tool_schemas_match_rust_shape_constraints() {
        let definitions = tool_definitions();
        let definitions = definitions.as_array().unwrap();
        let cases = [
            (
                REVIEW_CHECKPOINT,
                json!({
                    "checkpoint_id":"cp-1","stage":"inspection","summary":"observed",
                    "inspected":[],"commands":[],"open_questions":[],"remaining_scope":[]
                }),
                true,
            ),
            (
                REVIEW_CHECKPOINT,
                json!({"checkpoint_id":"bad/id","stage":"inspection","summary":"observed"}),
                false,
            ),
            (
                REVIEW_FINDING_UPSERT,
                json!({
                    "finding_id":"F-1","severity":"P2","confidence":"high","title":"issue",
                    "locations":[{"path":"src/lib.rs","start_line":1,"end_line":2}],
                    "evidence":[],"impact":"impact","suggested_remediation":"repair","status":"open"
                }),
                true,
            ),
            (
                REVIEW_FINDING_UPSERT,
                json!({
                    "finding_id":"F-2","severity":"P2","confidence":"high","title":"issue",
                    "locations":[{"path":"src/lib.rs","start_line":0,"end_line":2}],
                    "impact":"impact","suggested_remediation":"repair","status":"open"
                }),
                false,
            ),
            (
                REVIEW_VALIDATION_RECORD,
                json!({
                    "validation_id":"val-1","command":"cargo test","cwd":"/workspace",
                    "exit_code":0,"duration_ms":1,"stdout_summary":"","stderr_summary":"",
                    "related_findings":["F-1"]
                }),
                true,
            ),
            (
                REVIEW_VALIDATION_RECORD,
                json!({
                    "validation_id":"val-2","command":"","cwd":"/workspace",
                    "exit_code":0,"duration_ms":1,"stdout_summary":"","stderr_summary":""
                }),
                false,
            ),
            (
                REVIEW_FINALIZE,
                json!({
                    "signal":"incomplete_evidence","summary":"bounded",
                    "coverage":{"covered":[],"not_covered":[]},
                    "uncertainties":[],"recommended_next_actions":[]
                }),
                true,
            ),
            (
                REVIEW_FINALIZE,
                json!({
                    "signal":"incomplete_evidence","summary":"",
                    "coverage":{"covered":[],"not_covered":[]}
                }),
                false,
            ),
        ];

        for (tool, arguments, expected) in cases {
            let schema = &definitions
                .iter()
                .find(|definition| definition["name"] == tool)
                .unwrap()["inputSchema"];
            jsonschema::draft202012::meta::validate(schema).unwrap();
            let validator = jsonschema::draft202012::options().build(schema).unwrap();
            assert_eq!(
                validator.is_valid(&arguments),
                expected,
                "schema parity for {tool}: {arguments}"
            );
            assert_eq!(
                validate_tool_arguments(tool, &arguments).is_ok(),
                expected,
                "Rust parity for {tool}: {arguments}"
            );
        }

        let mut too_many = json!({
            "checkpoint_id":"cp-many","stage":"inspection","summary":"observed",
            "inspected":[],"commands":[],"open_questions":[],"remaining_scope":[]
        });
        too_many["remaining_scope"] = Value::Array(
            (0..=MAX_TOOL_ITEMS)
                .map(|index| json!(format!("item-{index}")))
                .collect(),
        );
        let schema = &definitions[0]["inputSchema"];
        let validator = jsonschema::draft202012::options().build(schema).unwrap();
        assert!(!validator.is_valid(&too_many));
        assert!(validate_tool_arguments(REVIEW_CHECKPOINT, &too_many).is_err());

        for (characters, expected) in [
            ("é".repeat(MAX_TOOL_TEXT_CHARS), true),
            ("é".repeat(MAX_TOOL_TEXT_CHARS + 1), false),
        ] {
            let arguments = json!({
                "checkpoint_id":"cp-unicode","stage":"inspection","summary":characters
            });
            assert_eq!(validator.is_valid(&arguments), expected);
            assert_eq!(
                validate_tool_arguments(REVIEW_CHECKPOINT, &arguments).is_ok(),
                expected
            );
        }

        let finding_schema = &definitions[1]["inputSchema"];
        let finding_validator = jsonschema::draft202012::options()
            .build(finding_schema)
            .unwrap();
        let reversed = json!({
            "finding_id":"F-reversed","severity":"P2","confidence":"high","title":"issue",
            "locations":[{"path":"src/lib.rs","start_line":9,"end_line":2}],
            "evidence":[],"impact":"impact","suggested_remediation":"repair","status":"open"
        });
        assert!(finding_validator.is_valid(&reversed));
        assert!(validate_tool_arguments(REVIEW_FINDING_UPSERT, &reversed).is_err());

        let at_u64_max = json!({
            "finding_id":"F-max","severity":"P2","confidence":"high","title":"issue",
            "locations":[{"path":"src/lib.rs","start_line":u64::MAX,"end_line":u64::MAX}],
            "evidence":[],"impact":"impact","suggested_remediation":"repair","status":"open"
        });
        assert!(finding_validator.is_valid(&at_u64_max));
        assert!(validate_tool_arguments(REVIEW_FINDING_UPSERT, &at_u64_max).is_ok());
        let over_u64_max: Value = serde_json::from_str(
            r#"{
                "finding_id":"F-over","severity":"P2","confidence":"high","title":"issue",
                "locations":[{"path":"src/lib.rs","start_line":18446744073709551616,"end_line":18446744073709551616}],
                "evidence":[],"impact":"impact","suggested_remediation":"repair","status":"open"
            }"#,
        )
        .unwrap();
        assert!(!finding_validator.is_valid(&over_u64_max));
        assert!(validate_tool_arguments(REVIEW_FINDING_UPSERT, &over_u64_max).is_err());

        let validation_schema = &definitions[2]["inputSchema"];
        let validation_validator = jsonschema::draft202012::options()
            .build(validation_schema)
            .unwrap();
        let at_duration_max = json!({
            "validation_id":"val-max","command":"cargo test","cwd":"/workspace",
            "exit_code":0,"duration_ms":u64::MAX,"stdout_summary":"","stderr_summary":""
        });
        assert!(validation_validator.is_valid(&at_duration_max));
        assert!(validate_tool_arguments(REVIEW_VALIDATION_RECORD, &at_duration_max).is_ok());
        let over_duration_max: Value = serde_json::from_str(
            r#"{
                "validation_id":"val-over","command":"cargo test","cwd":"/workspace",
                "exit_code":0,"duration_ms":18446744073709551616,
                "stdout_summary":"","stderr_summary":""
            }"#,
        )
        .unwrap();
        assert!(!validation_validator.is_valid(&over_duration_max));
        assert!(validate_tool_arguments(REVIEW_VALIDATION_RECORD, &over_duration_max).is_err());
    }

    #[test]
    fn stdio_endpoint_lists_exact_tools_and_binds_calls_to_its_job() {
        let directory = tempfile::tempdir().unwrap();
        let report_root = directory.path().join("reports");
        std::fs::create_dir(&report_root).unwrap();
        let report_root = std::fs::canonicalize(report_root).unwrap();
        let report = report_root.join("GLM-RAW.md");
        let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
        let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
        store
            .enqueue_job(&NewJob::new(
                "bound-job",
                directory.path().to_string_lossy(),
            ))
            .unwrap();
        store
            .initialize_review(&ReviewInitialization {
                agent_id: "bound-job".into(),
                expected_path: report.to_string_lossy().into_owned(),
                report_root: report_root.to_string_lossy().into_owned(),
                manifest_sha256: "a".repeat(64),
                prepared_sha256: "b".repeat(64),
                base_sha: "c".repeat(40),
                head_sha: "d".repeat(40),
                runtime_sha256: None,
                requested_model: None,
            })
            .unwrap();
        ledger.recover("bound-job").unwrap();
        let socket_root = directory.path().join("socket");
        std::fs::create_dir(&socket_root).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = socket_root.join("reviewd.sock");
        let scheduler = Scheduler::new(
            "ledger-mcp-test",
            Arc::clone(&store),
            Arc::new(UnusedFactory),
            SchedulerConfig::default(),
        )
        .unwrap()
        .with_ledger(
            ledger,
            crate::InternalLedgerMcpConfig {
                command: Path::new("/usr/bin/false").to_path_buf(),
                socket: socket.clone(),
                runtime_sha256: None,
            },
        )
        .unwrap();
        let service = Arc::new(RpcService::new(scheduler, Arc::clone(&store)).unwrap());
        let server = RpcServer::bind(&socket, service, ServerOptions::default()).unwrap();
        let input = format!(
            "{}\n{}\n{}\n{}\n",
            json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
            json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}),
            json!({
                "jsonrpc":"2.0","id":3,"method":"tools/call",
                "params":{"name":REVIEW_CHECKPOINT,"arguments":{
                    "checkpoint_id":"cp-1","stage":"inspection","summary":"bound evidence",
                    "inspected":[],"commands":[],"open_questions":[],"remaining_scope":[]
                }}
            }),
            json!({
                "jsonrpc":"2.0","id":4,"method":"tools/call",
                "params":{"name":REVIEW_CHECKPOINT,"arguments":{
                    "agent_id":"other-job","checkpoint_id":"cp-2","stage":"inspection",
                    "summary":"attempted rebind"
                }}
            })
        );
        let mut output = Vec::new();
        serve(
            &socket,
            "bound-job",
            Cursor::new(input.into_bytes()),
            &mut output,
        )
        .unwrap();
        server.shutdown();
        let responses: Vec<Value> = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(responses.len(), 4);
        let names: Vec<_> = responses[1]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|tool| tool["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            vec![
                REVIEW_CHECKPOINT,
                REVIEW_FINDING_UPSERT,
                REVIEW_VALIDATION_RECORD,
                REVIEW_FINALIZE,
                REVIEW_PROGRESS
            ]
        );
        assert_eq!(responses[2]["result"]["isError"], false);
        assert_eq!(responses[3]["result"]["isError"], true);
        let snapshot = store.review_snapshot("bound-job").unwrap().unwrap();
        assert_eq!(snapshot.checkpoints.len(), 1);
        assert_eq!(snapshot.checkpoints[0].stable_id, "cp-1");
    }
}
