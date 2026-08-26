use sectioned_shadow::{run_shadow_v2, RmcpFacadeClient, ShadowConfig};
use std::{env, fs, path::PathBuf};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config_path = env::args_os()
        .nth(1)
        .ok_or("usage: sectioned-shadow CONFIG.json")?;
    let config: ShadowConfig = serde_json::from_slice(&fs::read(config_path)?)?;
    let facade = env::var_os("ZCODE_REVIEW_MCP_PATH")
        .map(PathBuf::from)
        .ok_or("ZCODE_REVIEW_MCP_PATH is required")?;
    let socket = env::var_os("ZCODE_REVIEWD_SOCKET")
        .map(PathBuf::from)
        .ok_or("ZCODE_REVIEWD_SOCKET is required")?;
    let client = RmcpFacadeClient::spawn(&facade, &socket).await?;
    let run = run_shadow_v2(&client, &config).await?;
    println!("{}", serde_json::to_string(&run.provenance)?);
    client.shutdown().await?;
    Ok(())
}
