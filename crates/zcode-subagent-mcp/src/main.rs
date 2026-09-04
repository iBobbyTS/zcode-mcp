use std::{env, path::PathBuf, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let socket = env::var_os("ZCODE_AGENTD_SOCKET")
        .map(PathBuf::from)
        .ok_or("ZCODE_AGENTD_SOCKET is required")?;
    if !socket.is_absolute() {
        return Err("ZCODE_AGENTD_SOCKET must be absolute".into());
    }
    zcode_subagent_mcp::serve_stdio_v2(socket, Duration::from_secs(6)).await
}
