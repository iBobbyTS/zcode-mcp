use std::{env, path::PathBuf, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = env::var_os("ZCODE_REVIEWD_SOCKET")
        .map(PathBuf::from)
        .ok_or("ZCODE_REVIEWD_SOCKET is required")?;
    if !socket.is_absolute() {
        return Err("ZCODE_REVIEWD_SOCKET must be absolute".into());
    }
    let mode =
        zcode_review_mcp::PublicApiMode::parse(env::var_os("ZCODE_PUBLIC_API_MODE").as_deref())?;
    zcode_review_mcp::serve_stdio_mode(socket, Duration::from_secs(6), mode).await
}
