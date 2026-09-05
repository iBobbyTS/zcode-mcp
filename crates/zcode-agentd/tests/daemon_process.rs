#![cfg(unix)]

use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zcode_agent_preparation::{
    general_launch_prompt, AccessMode, GeneralTaskManifest, GeneralTaskPreparer,
    GENERAL_TASK_SCHEMA,
};
use zcode_agent_store::{BudgetRequest, EffectiveBudget, NewTask, Store, TaskPhase};
use zcode_agentd::rpc::{
    RespondInput, ResponseDecision, RpcClient, RpcMethod, RpcOutcome, RpcRequest, RpcSuccess,
    TaskPollQuery, RPC_VERSION,
};
use zcode_driver::{observe_process, observe_process_group};

fn fake_runtime() -> PathBuf {
    let executable = std::env::current_exe().unwrap();
    executable
        .parent()
        .and_then(Path::parent)
        .unwrap()
        .join(format!(
            "zcode-fake-runtime{}",
            std::env::consts::EXE_SUFFIX
        ))
}

fn hook_provenance(root: &Path) -> (PathBuf, String) {
    let plugin_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../plugins/zcode-subagent-mcp")
        .canonicalize()
        .unwrap();
    let config = root.join("hook-config.json");
    let provenance = root.join("hook-provenance.json");
    let guard = plugin_root.join("hooks/check-bash-readonly.mjs");
    let file = plugin_root.join("hooks/check-agent-files.mjs");
    let audit = plugin_root.join("hooks/audit-bash-result.mjs");
    let process_hook = |matcher: &str, path: &Path| {
        serde_json::json!({
            "matcher": matcher,
            "hooks": [{
                "type": "process",
                "command": "node",
                "args": [path],
                "timeoutMs": 5000
            }]
        })
    };
    let value = serde_json::json!({
        "hooks": {
            "events": {
                "PreToolUse": [process_hook("Bash", &guard), process_hook("^(Read|Grep|Glob|Write|Edit|Delete|Move)$", &file)],
                "PostToolUse": [process_hook("Bash", &audit)],
                "PostToolUseFailure": [process_hook("Bash", &audit)]
            }
        }
    });
    std::fs::write(&config, serde_json::to_vec(&value).unwrap()).unwrap();
    let installer = plugin_root.join("scripts/install-agent-hooks.mjs");
    let preflight = plugin_root.join("scripts/preflight-agent-hooks.mjs");
    for script in [&installer, &preflight] {
        let output = Command::new("node")
            .arg(script)
            .args([
                "--config",
                config.to_str().unwrap(),
                "--provenance",
                provenance.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{} failed: {}",
            script.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&provenance).unwrap()).unwrap();
    let generation = record["service_generation"].as_str().unwrap().to_owned();
    (provenance, generation)
}

fn request(request_id: &str, method: RpcMethod) -> RpcRequest {
    RpcRequest {
        version: RPC_VERSION,
        request_id: request_id.into(),
        method,
    }
}

fn success(response: zcode_agentd::rpc::RpcResponse) -> RpcSuccess {
    match response.outcome {
        RpcOutcome::Success { result } => *result,
        RpcOutcome::Error { error } => panic!("unexpected daemon RPC error: {error:?}"),
    }
}

#[test]
fn daemon_rejects_missing_hook_provenance_before_socket_publication() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("missing-provenance.sqlite3");
    let socket = directory.path().join("private").join("missing.sock");
    let daemon_executable = env!("CARGO_BIN_EXE_zcode-agentd");
    let mut daemon = Command::new(daemon_executable)
        .env("ZCODE_AGENTD_STORE", &database)
        .env("ZCODE_AGENTD_SOCKET", &socket)
        .env("ZCODE_AGENT_SERVICE_GENERATION", "daemon-test")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = daemon.wait().unwrap();
    assert!(!status.success());
    assert!(!socket.exists());
    let mut stderr = String::new();
    daemon
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.contains("provenance"), "{stderr}");
}

#[test]
fn daemon_rejects_hook_provenance_from_another_service_generation() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("mismatched-provenance.sqlite3");
    let socket = directory.path().join("private").join("mismatched.sock");
    let (provenance, _) = hook_provenance(directory.path());
    let daemon_executable = env!("CARGO_BIN_EXE_zcode-agentd");
    let mut daemon = Command::new(daemon_executable)
        .env("ZCODE_AGENTD_STORE", &database)
        .env("ZCODE_AGENTD_SOCKET", &socket)
        .env("ZCODE_AGENT_HOOK_PROVENANCE", &provenance)
        .env("ZCODE_AGENT_SERVICE_GENERATION", "different-daemon")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let status = daemon.wait().unwrap();
    assert!(!status.success());
    assert!(!socket.exists());
}

#[test]
fn daemon_auto_claims_is_single_instance_reconnects_and_handles_sigterm() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("zcode-agent.sqlite3");
    let socket = directory.path().join("private").join("zcode-agent.sock");
    let runtime = fake_runtime();
    assert!(
        runtime.is_file(),
        "workspace fake runtime binary is required"
    );
    let daemon_executable = env!("CARGO_BIN_EXE_zcode-agentd");
    let (hook_file, service_generation) = hook_provenance(directory.path());
    let repository = create_repository(directory.path());
    let head = git_text(&repository, &["rev-parse", "HEAD"]);
    let manifest = GeneralTaskManifest {
        schema: GENERAL_TASK_SCHEMA.into(),
        agent_id: "daemon-job".into(),
        repository,
        base_ref: head,
        access_mode: AccessMode::ReadOnly,
        permission_mode: zcode_agent_preparation::PermissionMode::Plan,
        prompt: "permission input".into(),
        repo_context: vec!["src/lib.rs".into()],
        attachments: Vec::new(),
        write_manifest: Vec::new(),
        scratch_root: ".agent-work/scratch/daemon-job".into(),
        artifact_root: ".agent-work/artifacts/daemon-job".into(),
        budget: None,
        validation_commands: Default::default(),
        retain_partial: false,
        idempotency_key: "daemon-key".into(),
    };
    let prepared = GeneralTaskPreparer::new(Vec::new())
        .unwrap()
        .prepare_submission(&manifest)
        .unwrap();
    let agent_id = prepared.agent_id.clone();
    let budget = EffectiveBudget {
        absolute_wall_time_ms: prepared.effective_budget.absolute_wall_time_ms,
        runtime_activity_idle_timeout_ms: prepared
            .effective_budget
            .runtime_activity_idle_timeout_ms,
        model_stream_idle_timeout_ms: prepared.effective_budget.model_stream_idle_timeout_ms,
        tool_call_timeout_ms: prepared.effective_budget.tool_call_timeout_ms,
        input_wait_timeout_ms: prepared.effective_budget.input_wait_timeout_ms,
        max_turns: prepared.effective_budget.max_turns,
        max_tool_calls: prepared.effective_budget.max_tool_calls,
        max_context_bytes: prepared.effective_budget.max_context_bytes,
        max_result_bytes: prepared.effective_budget.max_result_bytes,
        max_artifact_bytes: prepared.effective_budget.max_artifact_bytes,
    };
    Store::open(&database)
        .unwrap()
        .enqueue_task_authoritative(&NewTask {
            agent_id: agent_id.clone(),
            idempotency_key: prepared.idempotency_key.clone(),
            repository: prepared.repository.to_string_lossy().into_owned(),
            group_id: Some("daemon-process-test".into()),
            workspace_path: prepared.worktree.path.to_string_lossy().into_owned(),
            runtime_hash: None,
            prepared_launch_json: serde_json::to_string(&prepared).unwrap(),
            prepared_launch_sha256: prepared.prepared_sha256.clone(),
            initial_prompt: general_launch_prompt(&prepared, &manifest.prompt).unwrap(),
            budget: BudgetRequest::Limits(budget),
            retain_partial: false,
        })
        .unwrap();
    let mut daemon = Command::new(daemon_executable)
        .env("ZCODE_AGENTD_STORE", &database)
        .env("ZCODE_AGENTD_SOCKET", &socket)
        .env("ZCODE_RUNTIME_PATH", &runtime)
        .env("ZCODE_AGENT_HOOK_PROVENANCE", &hook_file)
        .env("ZCODE_AGENT_SERVICE_GENERATION", &service_generation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon socket was not created");
        thread::sleep(Duration::from_millis(10));
    }
    let client = RpcClient::new(&socket, Duration::from_secs(2));
    match success(
        client
            .call(&request("system-status", RpcMethod::SystemStatus))
            .unwrap(),
    ) {
        RpcSuccess::SystemStatus { status } => {
            assert_eq!(status.service_generation, service_generation)
        }
        other => panic!("unexpected status response: {other:?}"),
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let status = success(
            client
                .call(&request(
                    "status",
                    RpcMethod::TaskPoll(TaskPollQuery {
                        agent_id: agent_id.clone(),
                        after_revision: 0,
                        timeout_ms: 0,
                    }),
                ))
                .unwrap(),
        );
        if matches!(
            status,
            RpcSuccess::TaskPoll { ref task, .. }
                if matches!(task.phase.as_str(), "RUNNING" | "WAITING_INPUT")
        ) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "automatic claim did not become ready"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let store = Store::open(&database).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let permission = loop {
        if let Some(request) = store
            .pending_requests(&agent_id)
            .unwrap()
            .into_iter()
            .find(|request| request.request_type == "permission")
        {
            break request;
        }
        assert!(
            Instant::now() < deadline,
            "permission request was not persisted"
        );
        thread::sleep(Duration::from_millis(10));
    };
    success(
        client
            .call(&request(
                "respond-local-policy",
                RpcMethod::TaskRespond(RespondInput {
                    agent_id: agent_id.clone(),
                    request_id: permission.request_id.clone(),
                    decision: ResponseDecision::Allow,
                    content: None,
                }),
            ))
            .unwrap(),
    );
    let persisted = store
        .pending_request(&agent_id, &permission.request_id)
        .unwrap()
        .unwrap();
    assert_eq!(persisted.response_decision.as_deref(), Some("deny"));
    assert_eq!(
        persisted.response_content.as_deref(),
        Some("read_path_unverifiable")
    );

    let second_socket = directory.path().join("private").join("second.sock");
    let mut second = Command::new(daemon_executable)
        .env("ZCODE_AGENTD_STORE", &database)
        .env("ZCODE_AGENTD_SOCKET", &second_socket)
        .env("ZCODE_RUNTIME_PATH", &runtime)
        .env("ZCODE_AGENT_HOOK_PROVENANCE", &hook_file)
        .env("ZCODE_AGENT_SERVICE_GENERATION", &service_generation)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let second_status = loop {
        if let Some(status) = second.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = second.kill();
            let _ = second.wait();
            panic!("same database with a different socket acquired a second owner");
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert!(!second_status.success());
    let mut second_stdout = Vec::new();
    second
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut second_stdout)
        .unwrap();
    assert!(second_stdout.is_empty());
    assert!(!second_socket.exists());

    let reconnected = RpcClient::new(&socket, Duration::from_secs(2));
    assert!(matches!(
        success(
            reconnected
                .call(&request(
                    "status-again",
                    RpcMethod::TaskPoll(TaskPollQuery {
                        agent_id: agent_id.clone(),
                        after_revision: 0,
                        timeout_ms: 0,
                    }),
                ))
                .unwrap()
        ),
        RpcSuccess::TaskPoll { ref task, .. }
            if matches!(task.phase.as_str(), "RUNNING" | "WAITING_INPUT")
    ));
    let identity = Store::open(&database)
        .unwrap()
        .get_task(&agent_id)
        .unwrap()
        .unwrap()
        .process_identity
        .unwrap();

    unsafe {
        assert_eq!(libc::kill(daemon.id() as i32, libc::SIGTERM), 0);
    }
    let deadline = Instant::now() + Duration::from_secs(4);
    let status = loop {
        if let Some(status) = daemon.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = daemon.kill();
            panic!("daemon did not stop after SIGTERM");
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success());
    let mut stdout = Vec::new();
    daemon
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    assert!(
        stdout.is_empty(),
        "daemon stdout must remain protocol-clean"
    );
    assert!(!socket.exists());
    assert!(observe_process_group(identity.process_group_id)
        .unwrap()
        .is_empty());
    let job = Store::open(&database)
        .unwrap()
        .get_task(&agent_id)
        .unwrap()
        .unwrap();
    assert_eq!(job.phase, TaskPhase::Terminal);
    assert!(job.closed_at.is_some());
}

fn create_repository(root: &Path) -> PathBuf {
    let repository = root.join("repository");
    std::fs::create_dir_all(repository.join("src")).unwrap();
    std::fs::write(repository.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    git_text(&repository, &["init"]);
    git_text(&repository, &["config", "user.name", "S04 Test"]);
    git_text(
        &repository,
        &["config", "user.email", "s04@example.invalid"],
    );
    git_text(&repository, &["add", "src/lib.rs"]);
    git_text(&repository, &["commit", "-m", "fixture"]);
    std::fs::create_dir_all(repository.join(".agent-work")).unwrap();
    std::fs::write(repository.join(".agent-work/PLAN.md"), "# plan\n").unwrap();
    std::fs::canonicalize(repository).unwrap()
}

fn git_text(repository: &Path, arguments: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().into()
}

#[test]
fn signal_before_daemon_start_exits_without_socket_runtime_or_durable_activation() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("startup.sqlite3");
    let socket = directory.path().join("private").join("startup.sock");
    let gate_path = directory.path().join("startup-gate.sock");
    let gate_listener = UnixListener::bind(&gate_path).unwrap();
    gate_listener.set_nonblocking(true).unwrap();
    let store = Store::open(&database).unwrap();
    store
        .enqueue_task_authoritative(&NewTask {
            agent_id: "startup-job".into(),
            idempotency_key: "startup-job".into(),
            repository: "/workspace".into(),
            group_id: None,
            workspace_path: "/workspace".into(),
            runtime_hash: None,
            prepared_launch_json: "{}".into(),
            prepared_launch_sha256: "prepared".into(),
            initial_prompt: "test".into(),
            budget: BudgetRequest::Omitted,
            retain_partial: false,
        })
        .unwrap();
    drop(store);

    let daemon_executable = env!("CARGO_BIN_EXE_zcode-agentd");
    let runtime = fake_runtime();
    let (hook_file, service_generation) = hook_provenance(directory.path());
    let mut daemon = Command::new(daemon_executable)
        .env("ZCODE_AGENTD_STORE", &database)
        .env("ZCODE_AGENTD_SOCKET", &socket)
        .env("ZCODE_RUNTIME_PATH", &runtime)
        .env("ZCODE_AGENT_HOOK_PROVENANCE", &hook_file)
        .env("ZCODE_AGENT_SERVICE_GENERATION", &service_generation)
        .env("ZCODE_AGENTD_TEST_STARTUP_GATE", &gate_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let daemon_pid = daemon.id();

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut gate = loop {
        match gate_listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "daemon did not reach the post-signal-registration gate"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("startup gate accept failed: {error}"),
        }
    };
    let mut ready = [0u8; 1];
    gate.read_exact(&mut ready).unwrap();
    assert_eq!(ready, [1]);
    assert!(
        !socket.exists(),
        "daemon published its socket before the gate"
    );

    unsafe {
        assert_eq!(libc::kill(daemon_pid as i32, libc::SIGTERM), 0);
    }
    gate.write_all(&[1]).unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = daemon.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = daemon.kill();
            let _ = daemon.wait();
            panic!("daemon did not honor the startup-window signal");
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert!(status.success());
    let mut stdout = Vec::new();
    daemon
        .stdout
        .take()
        .unwrap()
        .read_to_end(&mut stdout)
        .unwrap();
    assert!(stdout.is_empty(), "startup shutdown polluted stdout");
    assert!(!socket.exists());
    assert!(matches!(
        observe_process(daemon_pid),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ));

    let store = Store::open(&database).unwrap();
    let job = store.get_task("startup-job").unwrap().unwrap();
    assert_eq!(job.phase, TaskPhase::Queued);
    assert!(
        job.process_identity.is_none(),
        "a runtime process group started"
    );
    assert!(job.runtime_agent_id.is_none());
    assert!(job.zcode_session_id.is_none());
    assert_eq!(store.active_count().unwrap(), 0);
}
