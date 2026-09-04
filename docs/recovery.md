# Recovery

## Facade restart

The MCP facade is stateless. Restart it with the same `ZCODE_AGENTD_SOCKET`, then use `zcode_agent_poll` or `zcode_agent_result` with the durable `agent_id`. The configured `service_generation` is bound to the installed Hook provenance and is reused across daemon restarts; reinstalling or regenerating that provenance changes it. Do not confuse this configured binding with a facade restart or a task identity.

## Daemon restart

Stop the daemon with SIGTERM or SIGINT and wait for its exact socket to disappear. Restart with the same canonical database and socket paths. Startup reconciliation runs before publication. Live runtime reconnect is unsupported; interrupted work becomes runtime-lost or orphaned without signaling an unverified PID or process group.

After restart, call `zcode_agent_list` with explicit repository, feature, or ownership scope. Inspect tasks with `poll` and `result`, then close them after verifying durable state. Start a new Agent for further work.

## Data and artifacts

For a consistent SQLite backup, stop the sole daemon and preserve the database with any WAL/SHM companions. Read artifact chunks through `zcode_agent_result`; verify repeated size/SHA-256 metadata and the final digest. Never read a private stored locator directly.

This unreleased architecture intentionally has no compatibility framework for removed dedicated-task records. Discovery of real user data requiring migration is a Human Gate.
