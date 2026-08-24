use review_store::Store;
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use std::{
    env, fs,
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicBool, Arc},
    thread,
    time::Duration,
};
use zcode_reviewd::{
    rpc::ServerOptions, CommandRuntimeFactory, Daemon, RuntimeFactory, Scheduler, SchedulerConfig,
};

struct Config {
    database: PathBuf,
    socket: PathBuf,
    runtime: Option<PathBuf>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&shutdown_requested))?;
    signal_hook::flag::register(SIGTERM, Arc::clone(&shutdown_requested))?;
    let config = parse_config()?;
    wait_for_startup_test_gate(&shutdown_requested)?;
    if shutdown_requested.load(std::sync::atomic::Ordering::Acquire) {
        return Ok(());
    }
    let store = Arc::new(Store::open(&config.database)?);
    let runtime = config.runtime.clone();
    let factory = Arc::new(CommandRuntimeFactory::new_prepared(
        move |_job: &review_store::Job| runtime_command(runtime.as_deref()),
    ));
    let runtime_factory: Arc<dyn RuntimeFactory> = factory;
    let scheduler = Scheduler::new(
        format!("reviewd-{}", std::process::id()),
        store,
        runtime_factory,
        SchedulerConfig::default(),
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
    let database = database.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ZCODE_REVIEWD_DATABASE or --database is required",
        )
    })?;
    let socket = socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ZCODE_REVIEWD_SOCKET or --socket is required",
        )
    })?;
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
