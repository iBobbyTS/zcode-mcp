use super::{
    RpcError, RpcErrorCode, RpcOutcome, RpcRequest, RpcResponse, RpcService, MAX_FRAME_BYTES,
    RPC_VERSION,
};
use std::{
    fs,
    io::{self, BufRead, BufReader, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

#[derive(Debug, Clone, Copy)]
pub struct ServerOptions {
    pub max_connections: usize,
    pub connection_timeout: Duration,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            max_connections: 16,
            connection_timeout: Duration::from_secs(1),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

pub struct RpcServer {
    path: PathBuf,
    socket_identity: SocketIdentity,
    shutdown: Arc<AtomicBool>,
    accept_thread: Mutex<Option<JoinHandle<()>>>,
}

impl RpcServer {
    pub fn bind(
        path: impl AsRef<Path>,
        service: Arc<RpcService>,
        options: ServerOptions,
    ) -> io::Result<Self> {
        if options.max_connections == 0 || options.connection_timeout.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "server bounds must be positive",
            ));
        }
        let path = path.as_ref().to_path_buf();
        prepare_parent(&path)?;
        remove_stale_socket(&path)?;
        let listener = UnixListener::bind(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;
        let metadata = fs::symlink_metadata(&path)?;
        let socket_identity = SocketIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let accept_shutdown = Arc::clone(&shutdown);
        let accept_path = path.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let accept_thread = thread::spawn(move || {
            let mut workers = Vec::new();
            while !accept_shutdown.load(Ordering::Acquire) {
                reap_finished_workers(&mut workers);
                match listener.accept() {
                    Ok((stream, _)) => {
                        if active.load(Ordering::Acquire) >= options.max_connections {
                            write_busy(stream, options.connection_timeout);
                            continue;
                        }
                        active.fetch_add(1, Ordering::AcqRel);
                        let service = Arc::clone(&service);
                        let worker_active = Arc::clone(&active);
                        workers.push(thread::spawn(move || {
                            handle_connection(stream, &service, options.connection_timeout);
                            worker_active.fetch_sub(1, Ordering::AcqRel);
                        }));
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                        ) =>
                    {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            for worker in workers {
                let _ = worker.join();
            }
            let _ = remove_matching_socket(&accept_path, socket_identity);
        });
        Ok(Self {
            path,
            socket_identity,
            shutdown,
            accept_thread: Mutex::new(Some(accept_thread)),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn shutdown(&self) {
        if self.shutdown.swap(true, Ordering::AcqRel) {
            return;
        }
        let _ = UnixStream::connect(&self.path);
        if let Some(thread) = self.accept_thread.lock().unwrap().take() {
            let _ = thread.join();
        }
        let _ = remove_matching_socket(&self.path, self.socket_identity);
    }
}

impl Drop for RpcServer {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Debug, Clone)]
pub struct RpcClient {
    path: PathBuf,
    timeout: Duration,
}

impl RpcClient {
    pub fn new(path: impl AsRef<Path>, timeout: Duration) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            timeout,
        }
    }

    pub fn call(&self, request: &RpcRequest) -> io::Result<RpcResponse> {
        let mut stream = UnixStream::connect(&self.path)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        let mut frame = serde_json::to_vec(request)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if frame.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "request frame exceeds cap",
            ));
        }
        frame.push(b'\n');
        stream.write_all(&frame)?;
        let mut reader = BufReader::new(stream);
        let response = read_limited_frame(&mut reader, MAX_FRAME_BYTES)?;
        serde_json::from_slice(&response)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

fn prepare_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket path has no parent"))?;
    let created = match fs::symlink_metadata(parent) {
        Ok(metadata)
            if metadata.file_type().is_dir() && metadata.permissions().mode() & 0o077 == 0 =>
        {
            false
        }
        Ok(metadata) if metadata.file_type().is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "socket parent directory is not private",
            ))
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "socket parent is not a directory",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            fs::create_dir_all(parent)?;
            true
        }
        Err(error) => return Err(error),
    };
    if created {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn reap_finished_workers(workers: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            let _ = worker.join();
        } else {
            index += 1;
        }
    }
}

fn remove_stale_socket(path: &Path) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "socket path exists and is not a socket",
        ));
    }
    if UnixStream::connect(path).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "socket already has a listener",
        ));
    }
    fs::remove_file(path)
}

fn remove_matching_socket(path: &Path, expected: SocketIdentity) -> io::Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket()
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
    {
        return Ok(());
    }
    fs::remove_file(path)
}

fn handle_connection(mut stream: UnixStream, service: &RpcService, timeout: Duration) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    let response = {
        let mut reader = BufReader::new(&mut stream);
        match read_limited_frame(&mut reader, MAX_FRAME_BYTES) {
            Ok(frame) => service.handle_bytes(&frame),
            Err(error) if error.kind() == io::ErrorKind::InvalidData => RpcResponse::error(
                None,
                RpcError::new(RpcErrorCode::Oversized, "request frame exceeds cap"),
            ),
            Err(_) => return,
        }
    };
    let _ = write_response(&mut stream, response);
}

fn write_busy(mut stream: UnixStream, timeout: Duration) {
    let _ = stream.set_write_timeout(Some(timeout));
    let response = RpcResponse::error(
        None,
        RpcError::new(RpcErrorCode::Conflict, "server connection limit reached"),
    );
    let _ = write_response(&mut stream, response);
}

fn write_response(stream: &mut UnixStream, mut response: RpcResponse) -> io::Result<()> {
    let mut frame = serde_json::to_vec(&response)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    if frame.len() > MAX_FRAME_BYTES {
        response = RpcResponse {
            version: RPC_VERSION,
            request_id: response.request_id,
            outcome: RpcOutcome::Error {
                error: RpcError::new(RpcErrorCode::Oversized, "response frame exceeds cap"),
            },
        };
        frame = serde_json::to_vec(&response)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    }
    frame.push(b'\n');
    stream.write_all(&frame)
}

fn read_limited_frame<R: BufRead>(reader: &mut R, cap: usize) -> io::Result<Vec<u8>> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return if frame.is_empty() {
                Err(io::Error::new(io::ErrorKind::UnexpectedEof, "empty frame"))
            } else {
                Ok(frame)
            };
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.unwrap_or(available.len());
        if frame.len().saturating_add(take) > cap {
            reader.consume(take + usize::from(newline.is_some()));
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame exceeds cap",
            ));
        }
        frame.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(frame);
        }
    }
}
