use signal_hook::consts::signal::{SIGINT, SIGTERM};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicBool, Arc},
    thread,
    time::Duration,
};
#[cfg(debug_assertions)]
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
};
use zcode_agent_store::Store;
use zcode_agentd::{
    rpc::ServerOptions, CommandRuntimeFactory, Daemon, GeneralCommandCatalog, RuntimeFactory,
    Scheduler, SchedulerConfig,
};

struct Config {
    database: PathBuf,
    socket: PathBuf,
    runtime: Option<PathBuf>,
    command_catalog: Option<PathBuf>,
    service_generation: String,
}

const PRODUCTION_BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(90);
const PRODUCTION_CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let shutdown_requested = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(SIGINT, Arc::clone(&shutdown_requested))?;
    signal_hook::flag::register(SIGTERM, Arc::clone(&shutdown_requested))?;
    let config = parse_config()?;
    let provenance = zcode_agent_preparation::agent_bash_hook_provenance_for_service_generation(
        Some(&config.service_generation),
    );
    if !provenance.hook_activation_verified {
        return Err("agent hook provenance is missing, stale, or mismatched".into());
    }
    wait_for_startup_test_gate(&shutdown_requested)?;
    if shutdown_requested.load(std::sync::atomic::Ordering::Acquire) {
        return Ok(());
    }
    let store = Arc::new(Store::open(&config.database)?);
    let runtime = config.runtime.clone();
    let factory = Arc::new(CommandRuntimeFactory::new_prepared(
        move |_task: &zcode_agent_store::TaskRecord| runtime_command(runtime.as_deref()),
    ));
    let runtime_factory: Arc<dyn RuntimeFactory> = factory;
    let command_catalog = config
        .command_catalog
        .as_deref()
        .map(GeneralCommandCatalog::load)
        .transpose()?
        .unwrap_or_default();
    let scheduler = Scheduler::new(
        format!("agentd-{}", std::process::id()),
        store,
        runtime_factory,
        production_scheduler_config(),
    )?
    .with_general_command_catalog(command_catalog)?;
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
    let Some(path) = env::var_os("ZCODE_AGENTD_TEST_STARTUP_GATE") else {
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
    let mut database = env::var_os("ZCODE_AGENTD_STORE").map(PathBuf::from);
    let mut socket = env::var_os("ZCODE_AGENTD_SOCKET").map(PathBuf::from);
    let mut runtime = env::var_os("ZCODE_RUNTIME_PATH").map(PathBuf::from);
    let mut command_catalog = env::var_os("ZCODE_AGENTD_COMMAND_CATALOG").map(PathBuf::from);
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
            "--command-catalog" => command_catalog = Some(PathBuf::from(value)),
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
            "ZCODE_AGENTD_STORE or --database is required",
        )
    })?)?;
    let service_generation = env::var("ZCODE_AGENT_SERVICE_GENERATION").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ZCODE_AGENT_SERVICE_GENERATION is required",
        )
    })?;
    if service_generation.is_empty() || service_generation.len() > 128 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ZCODE_AGENT_SERVICE_GENERATION is invalid",
        ));
    }
    let socket = absolute_path(socket.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ZCODE_AGENTD_SOCKET or --socket is required",
        )
    })?)?;
    let runtime = runtime.map(fs::canonicalize).transpose()?;
    if runtime.as_ref().is_some_and(|path| !path.is_file()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime path is not a regular file",
        ));
    }
    let command_catalog = command_catalog
        .map(absolute_path)
        .transpose()?
        .map(|path| {
            let canonical = fs::canonicalize(&path)?;
            if canonical != path {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "command catalog path must already be canonical",
                ));
            }
            Ok(canonical)
        })
        .transpose()?;
    Ok(Config {
        database,
        socket,
        runtime,
        command_catalog,
        service_generation,
    })
}

fn absolute_path(path: PathBuf) -> io::Result<PathBuf> {
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(env::current_dir()?.join(path))
    }
}

fn runtime_command(runtime: Option<&Path>) -> io::Result<Command> {
    let runtime = runtime.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "ZCODE_RUNTIME_PATH is unavailable",
        )
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
