#![cfg(unix)]

use review_preparation::{
    general_launch_prompt, GeneralProfile, GeneralTaskManifest, GeneralTaskPreparer,
    GENERAL_TASK_SCHEMA,
};
use review_store::{BudgetRequest, EffectiveBudget, JobState, NewJob, NewTask, Store, TaskKind};
use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zcode_driver::{observe_process, observe_process_group};
use zcode_reviewd::rpc::{
    ReadinessResultView, RespondInput, ResponseDecision, RpcClient, RpcMethod, RpcOutcome,
    RpcRequest, RpcSuccess, RPC_VERSION,
};

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

fn request(request_id: &str, method: RpcMethod) -> RpcRequest {
    RpcRequest {
        version: RPC_VERSION,
        request_id: request_id.into(),
        method,
    }
}

fn success(response: zcode_reviewd::rpc::RpcResponse) -> RpcSuccess {
    match response.outcome {
        RpcOutcome::Success { result } => *result,
        RpcOutcome::Error { error } => panic!("unexpected daemon RPC error: {error:?}"),
    }
}

#[test]
fn production_daemon_readiness_distinguishes_missing_config_from_spawn_failure() {
    for configured in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("review.sqlite3");
        let socket = directory.path().join("private/review.sock");
        let runtime = directory
            .path()
            .join("configured-but-not-executable-runtime");
        if configured {
            std::fs::write(&runtime, b"not executable").unwrap();
        }

        let mut command = Command::new(env!("CARGO_BIN_EXE_zcode-reviewd"));
        command
            .env("ZCODE_REVIEWD_DATABASE", &database)
            .env("ZCODE_REVIEWD_SOCKET", &socket)
            .env_remove("ZCODE_RUNTIME_PATH")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if configured {
            command.env("ZCODE_RUNTIME_PATH", &runtime);
        }
        let mut daemon = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !socket.exists() {
            assert!(
                daemon.try_wait().unwrap().is_none(),
                "daemon exited before readiness RPC"
            );
            assert!(Instant::now() < deadline, "daemon socket was not created");
            thread::sleep(Duration::from_millis(10));
        }

        let result = success(
            RpcClient::new(&socket, Duration::from_secs(2))
                .call(&request(
                    "production-readiness-classification",
                    RpcMethod::SystemEnsureReady { timeout_ms: 100 },
                ))
                .unwrap(),
        );
        let (expected, expected_reason) = if configured {
            (ReadinessResultView::ZcodeStartFailed, "ZCODE_START_FAILED")
        } else {
            (ReadinessResultView::ConfigInvalid, "CONFIG_INVALID")
        };
        match result {
            RpcSuccess::SystemReadiness {
                ready,
                probe_result,
                reason_code,
                ..
            } => {
                assert!(!ready);
                assert_eq!(probe_result, expected);
                assert_eq!(reason_code.as_deref(), Some(expected_reason));
            }
            other => panic!("unexpected readiness response: {other:?}"),
        }

        unsafe {
            assert_eq!(libc::kill(daemon.id() as i32, libc::SIGTERM), 0);
        }
        assert!(daemon.wait().unwrap().success());
    }
}

#[test]
fn daemon_auto_claims_is_single_instance_reconnects_and_handles_sigterm() {
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("review.sqlite3");
    let socket = directory.path().join("private").join("review.sock");
    let runtime = fake_runtime();
    assert!(
        runtime.is_file(),
        "workspace fake runtime binary is required"
    );
    let daemon_executable = env!("CARGO_BIN_EXE_zcode-reviewd");
    let repository = create_repository(directory.path());
    let head = git_text(&repository, &["rev-parse", "HEAD"]);
    let manifest = GeneralTaskManifest {
        schema: GENERAL_TASK_SCHEMA.into(),
        task_id: "daemon-job".into(),
        repository,
        base_ref: head,
        profile: GeneralProfile::AnalysisReadonly,
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
    let agent_id = prepared.task_id.clone();
    let mut queued = NewJob::new(&agent_id, prepared.worktree.path.to_string_lossy());
    queued.idempotency_key = Some(prepared.idempotency_key.clone());
    queued.feature_id = Some("feature".into());
    queued.initial_prompt = general_launch_prompt(&prepared, &manifest.prompt).unwrap();
    queued.prepared_launch_json = Some(serde_json::to_string(&prepared).unwrap());
    queued.prepared_launch_sha256 = Some(prepared.prepared_sha256.clone());
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
        .enqueue_task(&NewTask {
            job: queued,
            public_agent_id: agent_id.clone(),
            task_kind: TaskKind::General,
            repository: prepared.repository.to_string_lossy().into_owned(),
            feature_id: "feature".into(),
            ownership_token: "daemon-process-test".into(),
            budget: BudgetRequest::Limits(budget),
            retain_partial: false,
        })
        .unwrap();
    let mut daemon = Command::new(daemon_executable)
        .env("ZCODE_REVIEWD_DATABASE", &database)
        .env("ZCODE_REVIEWD_SOCKET", &socket)
        .env("ZCODE_RUNTIME_PATH", &runtime)
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
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let status = success(
            client
                .call(&request(
                    "status",
                    RpcMethod::TaskStatus {
                        agent_id: agent_id.clone(),
                    },
                ))
                .unwrap(),
        );
        if matches!(
            status,
            RpcSuccess::TaskStatus { ref task } if task.phase == "RUNNING"
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
        .env("ZCODE_REVIEWD_DATABASE", &database)
        .env("ZCODE_REVIEWD_SOCKET", &second_socket)
        .env("ZCODE_RUNTIME_PATH", &runtime)
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
                    RpcMethod::TaskStatus {
                        agent_id: agent_id.clone(),
                    },
                ))
                .unwrap()
        ),
        RpcSuccess::TaskStatus { ref task } if task.phase == "RUNNING"
    ));
    let identity = Store::open(&database)
        .unwrap()
        .get_job(&agent_id)
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
        .get_job(&agent_id)
        .unwrap()
        .unwrap();
    assert_eq!(job.state, JobState::Cancelled);
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
        .enqueue_job(&NewJob::new("startup-job", "/workspace"))
        .unwrap();
    drop(store);

    let daemon_executable = env!("CARGO_BIN_EXE_zcode-reviewd");
    let runtime = fake_runtime();
    let mut daemon = Command::new(daemon_executable)
        .env("ZCODE_REVIEWD_DATABASE", &database)
        .env("ZCODE_REVIEWD_SOCKET", &socket)
        .env("ZCODE_RUNTIME_PATH", &runtime)
        .env("ZCODE_REVIEWD_TEST_STARTUP_GATE", &gate_path)
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
    let job = store.get_job("startup-job").unwrap().unwrap();
    assert_eq!(job.state, JobState::Queued);
    assert!(
        job.process_identity.is_none(),
        "a runtime process group started"
    );
    assert!(job.runtime_agent_id.is_none());
    assert!(job.zcode_session_id.is_none());
    assert_eq!(store.active_count().unwrap(), 0);
}
