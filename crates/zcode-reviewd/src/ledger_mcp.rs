use crate::rpc::{
    ReviewToolInput, RpcClient, RpcMethod, RpcOutcome, RpcRequest, RpcSuccess, RPC_VERSION,
};
use review_ledger::{
    REVIEW_CHECKPOINT, REVIEW_FINALIZE, REVIEW_FINDING_UPSERT, REVIEW_VALIDATION_RECORD,
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
    mut reader: R,
    mut writer: W,
) -> io::Result<()> {
    let client = RpcClient::new(socket, Duration::from_secs(5));
    let mut line = Vec::new();
    let mut sequence = 0u64;
    loop {
        line.clear();
        let bytes = reader.read_until(b'\n', &mut line)?;
        if bytes == 0 {
            return Ok(());
        }
        if line.len() > MAX_MCP_FRAME_BYTES {
            write_response(
                &mut writer,
                &json!({"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"request exceeds cap"}}),
            )?;
            continue;
        }
        while matches!(line.last(), Some(b'\n' | b'\r')) {
            line.pop();
        }
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
                call_tool(&client, agent_id, sequence, &value, id)
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
    let Some(name) = params.get("name").and_then(Value::as_str) else {
        return invalid_params(id);
    };
    if !matches!(
        name,
        REVIEW_CHECKPOINT | REVIEW_FINDING_UPSERT | REVIEW_VALIDATION_RECORD | REVIEW_FINALIZE
    ) {
        return invalid_params(id);
    }
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let rpc = RpcRequest {
        version: RPC_VERSION,
        request_id: format!("ledger-{sequence}"),
        method: RpcMethod::ReviewTool(ReviewToolInput {
            agent_id: agent_id.to_owned(),
            tool: name.to_owned(),
            arguments,
        }),
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
    json!([
        {
            "name": REVIEW_CHECKPOINT,
            "description": "Record one observable evidence checkpoint.",
            "inputSchema": {
                "type":"object","additionalProperties":false,
                "required":["checkpoint_id","stage","summary"],
                "properties":{
                    "checkpoint_id":{"type":"string"},
                    "stage":{"enum":["scope","inspection","validation","synthesis"]},
                    "summary":{"type":"string"},
                    "inspected":{"type":"array","items":{
                        "type":"object","additionalProperties":false,"required":["path"],
                        "properties":{"path":{"type":"string"},"line_ranges":{"type":"array","items":{"type":"string"}}}
                    }},
                    "commands":{"type":"array","items":{
                        "type":"object","additionalProperties":false,"required":["command","result_summary"],
                        "properties":{"command":{"type":"string"},"result_summary":{"type":"string"}}
                    }},
                    "open_questions":{"type":"array","items":{"type":"string"}},
                    "remaining_scope":{"type":"array","items":{"type":"string"}}
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
                    "finding_id":{"type":"string"},"severity":{"enum":["P0","P1","P2","P3"]},
                    "confidence":{"enum":["high","medium","low"]},"title":{"type":"string"},
                    "locations":{"type":"array","items":{
                        "type":"object","additionalProperties":false,"required":["path","start_line","end_line"],
                        "properties":{
                            "path":{"type":"string"},"start_line":{"type":"integer","minimum":1},
                            "end_line":{"type":"integer","minimum":1}
                        }
                    }},"evidence":{"type":"array","items":{"type":"string"}},
                    "impact":{"type":"string"},"suggested_remediation":{"type":"string"},
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
                    "validation_id":{"type":"string"},"command":{"type":"string"},"cwd":{"type":"string"},
                    "exit_code":{"type":"integer"},"duration_ms":{"type":"integer","minimum":0},
                    "stdout_summary":{"type":"string"},"stderr_summary":{"type":"string"},
                    "related_findings":{"type":"array","items":{"type":"string"}}
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
                    "summary":{"type":"string"},"coverage":{
                        "type":"object","additionalProperties":false,"required":["covered","not_covered"],
                        "properties":{
                            "covered":{"type":"array","items":{"type":"string"}},
                            "not_covered":{"type":"array","items":{"type":"string"}}
                        }
                    },
                    "uncertainties":{"type":"array","items":{"type":"string"}},
                    "recommended_next_actions":{"type":"array","items":{"type":"string"}}
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
    use review_ledger::LedgerManager;
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
    fn stdio_endpoint_lists_exact_tools_and_binds_calls_to_its_job() {
        let directory = tempfile::tempdir().unwrap();
        let report_root = directory.path().join("reports");
        std::fs::create_dir(&report_root).unwrap();
        let report_root = std::fs::canonicalize(report_root).unwrap();
        let report = report_root.join("GLM-RAW.md");
        let store = Arc::new(Store::open(directory.path().join("review.sqlite3")).unwrap());
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
        let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
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
                REVIEW_FINALIZE
            ]
        );
        assert_eq!(responses[2]["result"]["isError"], false);
        assert_eq!(responses[3]["result"]["isError"], true);
        let snapshot = store.review_snapshot("bound-job").unwrap().unwrap();
        assert_eq!(snapshot.checkpoints.len(), 1);
        assert_eq!(snapshot.checkpoints[0].stable_id, "cp-1");
    }
}
