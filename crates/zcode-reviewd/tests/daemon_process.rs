#![cfg(unix)]

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
    JobStateView, NewJobInput, RpcClient, RpcMethod, RpcOutcome, RpcRequest, RpcSuccess,
    RPC_VERSION,
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
    success(
        client
            .call(&request(
                "enqueue",
                RpcMethod::Enqueue {
                    job: NewJobInput {
                        agent_id: "daemon-job".into(),
                        workspace_path: "/workspace".into(),
                        idempotency_key: Some("daemon-key".into()),
                        parent_agent_id: None,
                        review_kind: Some("code".into()),
                        feature_id: Some("feature".into()),
                        section_id: Some("S03".into()),
                        round_kind: Some("fixture".into()),
                        report_path: None,
                        runtime_hash: Some("fake".into()),
                        initial_prompt: "permission input".into(),
                    },
                },
            ))
            .unwrap(),
    );
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
