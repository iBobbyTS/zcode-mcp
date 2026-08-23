#![cfg(unix)]

use review_store::{JobState, Store};
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use zcode_driver::observe_process_group;
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
