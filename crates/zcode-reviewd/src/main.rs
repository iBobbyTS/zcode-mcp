use review_ledger::LedgerManager;
use review_store::Store;
use sha2::{Digest, Sha256};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use std::{
    env, fs,
    io::{self, BufReader, Read},
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicBool, Arc},
    thread,
    time::Duration,
};
#[cfg(debug_assertions)]
use std::{io::Write, os::unix::net::UnixStream};
use zcode_reviewd::{
    general_mcp, ledger_mcp, rpc::ServerOptions, CommandRuntimeFactory, Daemon,
    InternalLedgerMcpConfig, RuntimeFactory, Scheduler, SchedulerConfig,
};

struct Config {
    database: PathBuf,
    socket: PathBuf,
    runtime: Option<PathBuf>,
}

const PRODUCTION_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(90);
const PRODUCTION_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--ledger-mcp")) {
        return run_ledger_mcp(false).map_err(Into::into);
    }
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--task-ledger-mcp")) {
        return run_ledger_mcp(true).map_err(Into::into);
    }
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--general-mcp")) {
        return run_general_mcp().map_err(Into::into);
    }
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&shutdown_requested))?;
    signal_hook::flag::register(SIGTERM, Arc::clone(&shutdown_requested))?;
    let config = parse_config()?;
    wait_for_startup_test_gate(&shutdown_requested)?;
    if shutdown_requested.load(std::sync::atomic::Ordering::Acquire) {
        return Ok(());
    }
    let store = Arc::new(Store::open(&config.database)?);
    let ledger = Arc::new(LedgerManager::new(Arc::clone(&store)));
    let runtime = config.runtime.clone();
    let runtime_sha256 = runtime.as_deref().map(file_sha256).transpose()?;
    let factory = Arc::new(CommandRuntimeFactory::new_prepared(
        move |_job: &review_store::Job| runtime_command(runtime.as_deref()),
    ));
    let runtime_factory: Arc<dyn RuntimeFactory> = factory;
    let scheduler = Scheduler::new(
        format!("reviewd-{}", std::process::id()),
        store,
        runtime_factory,
        production_scheduler_config(),
    )?
    .with_ledger(
        ledger,
        InternalLedgerMcpConfig {
            command: fs::canonicalize(env::current_exe()?)?,
            socket: config.socket.clone(),
            runtime_sha256,
        },
    )?;
    let daemon = match Daemon::start_with_shutdown(
        &config.socket,
        scheduler,
        ServerOptions::default(),
        Duration::from_millis(20),
        Arc::clone(&shutdown_requested),
    ) {
        Ok(daemon) => daemon,
        Err(error)
            if error.kind() == io::ErrorKind::Interrupted
                && shutdown_requested.load(std::sync::atomic::Ordering::Acquire) =>
        {
            return Ok(())
        }
        Err(error) => return Err(error.into()),
    };
    while !shutdown_requested.load(std::sync::atomic::Ordering::Acquire) {
        thread::sleep(Duration::from_millis(20));
    }
    daemon.shutdown();
    Ok(())
}

fn production_scheduler_config() -> SchedulerConfig {
    SchedulerConfig {
        bootstrap_timeout: PRODUCTION_BOOTSTRAP_TIMEOUT,
        control_timeout: PRODUCTION_CONTROL_TIMEOUT,
        ..SchedulerConfig::default()
    }
}

#[cfg(debug_assertions)]
fn wait_for_startup_test_gate(shutdown_requested: &AtomicBool) -> io::Result<()> {
    let Some(path) = env::var_os("ZCODE_REVIEWD_TEST_STARTUP_GATE") else {
        return Ok(());
    };
    let mut gate = UnixStream::connect(path)?;
    gate.write_all(&[1])?;
    let mut release = [0u8; 1];
    gate.read_exact(&mut release)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while !shutdown_requested.load(std::sync::atomic::Ordering::Acquire) {
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "startup test gate did not observe a shutdown signal",
            ));
        }
        thread::yield_now();
    }
    Ok(())
}

#[cfg(not(debug_assertions))]
fn wait_for_startup_test_gate(_shutdown_requested: &AtomicBool) -> io::Result<()> {
    Ok(())
}

fn parse_config() -> io::Result<Config> {
    let mut database = env::var_os("ZCODE_REVIEWD_DATABASE").map(PathBuf::from);
    let mut socket = env::var_os("ZCODE_REVIEWD_SOCKET").map(PathBuf::from);
    let mut runtime = env::var_os("ZCODE_RUNTIME_PATH").map(PathBuf::from);
    let mut arguments = env::args_os().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "daemon option is missing a value",
            )
        })?;
        match argument.to_string_lossy().as_ref() {
            "--database" => database = Some(PathBuf::from(value)),
            "--socket" => socket = Some(PathBuf::from(value)),
            "--runtime" => runtime = Some(PathBuf::from(value)),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown daemon option",
                ))
            }
        }
    }
    let database = absolute_path(database.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ZCODE_REVIEWD_DATABASE or --database is required",
        )
    })?)?;
    let socket = absolute_path(socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ZCODE_REVIEWD_SOCKET or --socket is required",
        )
    })?)?;
    let runtime = runtime.map(fs::canonicalize).transpose()?;
    if runtime.as_ref().is_some_and(|path| !path.is_file()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime path is not a regular file",
        ));
    }
    Ok(Config {
        database,
        socket,
        runtime,
    })
}

fn absolute_path(path: PathBuf) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

fn file_sha256(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn run_ledger_mcp(task_scoped: bool) -> io::Result<()> {
    let mut socket = None;
    let mut agent_id = None;
    let mut arguments = env::args_os().skip(2);
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "ledger MCP option is missing a value",
            )
        })?;
        match argument.to_string_lossy().as_ref() {
            "--socket" => socket = Some(PathBuf::from(value)),
            "--agent-id" => agent_id = Some(value.to_string_lossy().into_owned()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown ledger MCP option",
                ))
            }
        }
    }
    let socket = socket
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--socket is required"))?;
    let agent_id = agent_id
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--agent-id is required"))?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    if task_scoped {
        ledger_mcp::serve_task(
            &socket,
            &agent_id,
            BufReader::new(stdin.lock()),
            stdout.lock(),
        )
    } else {
        ledger_mcp::serve(
            &socket,
            &agent_id,
            BufReader::new(stdin.lock()),
            stdout.lock(),
        )
    }
}

fn run_general_mcp() -> io::Result<()> {
    let mut socket = None;
    let mut agent_id = None;
    let mut arguments = env::args_os().skip(2);
    while let Some(argument) = arguments.next() {
        let value = arguments.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "general MCP option is missing a value",
            )
        })?;
        match argument.to_string_lossy().as_ref() {
            "--socket" => socket = Some(PathBuf::from(value)),
            "--agent-id" => agent_id = Some(value.to_string_lossy().into_owned()),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unknown general MCP option",
                ))
            }
        }
    }
    let socket = socket
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--socket is required"))?;
    let agent_id = agent_id
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "--agent-id is required"))?;
    let stdin = io::stdin();
    let stdout = io::stdout();
    general_mcp::serve(
        &socket,
        &agent_id,
        BufReader::new(stdin.lock()),
        stdout.lock(),
    )
}

fn runtime_command(runtime: Option<&Path>) -> io::Result<Command> {
    let runtime = runtime.ok_or_else(|| {
        io::Error::new(io::ErrorKind::NotFound, "ZCODE_RUNTIME_PATH is unavailable")
    })?;
    if matches!(
        runtime.extension().and_then(|value| value.to_str()),
        Some("js" | "cjs" | "mjs")
    ) {
        let mut command = Command::new("node");
        command.arg(runtime).arg("app-server");
        Ok(command)
    } else {
        Ok(Command::new(runtime))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_scheduler_allows_the_verified_official_runtime_bootstrap_window() {
        let defaults = SchedulerConfig::default();
        let production = production_scheduler_config();

        assert_eq!(production.bootstrap_timeout, Duration::from_secs(90));
        assert_eq!(production.control_timeout, Duration::from_secs(5));
        assert_eq!(production.global_max_agents, defaults.global_max_agents);
        assert_eq!(
            production.per_workspace_max_agents,
            defaults.per_workspace_max_agents
        );
        assert_eq!(production.stop_grace, defaults.stop_grace);
    }
}
