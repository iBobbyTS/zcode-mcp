#![cfg(unix)]

use review_preparation::{
    NetworkPolicy, ReviewKind, ReviewManifest, ReviewPreparer, RoundKind, ScratchPolicy,
};
use review_store::{JobState, NewJob, Store};
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
    JobStateView, RespondInput, ResponseDecision, RpcClient, RpcMethod, RpcOutcome, RpcRequest,
    RpcSuccess, RPC_VERSION,
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
    let prepared = ReviewPreparer
        .prepare(&ReviewManifest {
            schema: "sectioned-zcode-review/v1".into(),
            review_kind: ReviewKind::Code,
            feature_id: "feature".into(),
            section_id: "S04".into(),
            round_kind: RoundKind::InitialBounded,
            repository,
            base_ref: head.clone(),
            head_ref: head,
            plan_path: ".agent-work/PLAN.md".into(),
            context_paths: Vec::new(),
            scope_paths: vec!["src".into()],
            forbidden_input_globs: Vec::new(),
            validation_commands: Vec::new(),
            report_target: ".agent-work/reviews/daemon/report.md".into(),
            scratch_root: ".agent-work/scratch/jobs".into(),
            model: None,
            fresh_session: true,
            network_policy: NetworkPolicy::Deny,
            scratch_policy: ScratchPolicy::Isolated,
            idempotency_key: "daemon-key".into(),
        })
        .unwrap();
    let mut queued = NewJob::new("daemon-job", prepared.worktree.path.to_string_lossy());
    queued.idempotency_key = Some(prepared.idempotency_key.clone());
    queued.review_kind = Some("code".into());
    queued.feature_id = Some("feature".into());
    queued.section_id = Some("S04".into());
    queued.round_kind = Some("INITIAL_BOUNDED".into());
    queued.report_path = Some(prepared.report_target.to_string_lossy().into_owned());
    queued.runtime_hash = Some("fake".into());
    queued.initial_prompt = "permission input".into();
    queued.prepared_launch_json = Some(prepared.canonical_json().unwrap());
    queued.prepared_launch_sha256 = Some(prepared.prepared_sha256);
    Store::open(&database)
        .unwrap()
        .enqueue_job(&queued)
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
                    RpcMethod::Status {
                        agent_id: "daemon-job".into(),
                    },
                ))
                .unwrap(),
        );
        if matches!(
            status,
            RpcSuccess::Status { ref job }
                if job.state == JobStateView::Running
                    && job.zcode_session_id.as_deref() == Some("fake-session-7f3a")
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
            .pending_requests("daemon-job")
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
                RpcMethod::Respond(RespondInput {
                    agent_id: "daemon-job".into(),
                    request_id: permission.request_id.clone(),
                    decision: ResponseDecision::Allow,
                    content: None,
                }),
            ))
            .unwrap(),
    );
    let persisted = store
        .pending_request("daemon-job", &permission.request_id)
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
                    RpcMethod::Status {
                        agent_id: "daemon-job".into(),
                    },
                ))
                .unwrap()
        ),
        RpcSuccess::Status { ref job } if job.state == JobStateView::Running
    ));
    let identity = Store::open(&database)
        .unwrap()
        .get_job("daemon-job")
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
        .get_job("daemon-job")
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
