# Setup

## Build

Requirements are Rust 1.97 or compatible, Cargo, Git, and macOS or a compatible Unix host.

```text
cargo build --release -p zcode-agentd -p zcode-subagent-mcp
```

## Daemon

Use private absolute database and socket paths outside the target repository:

```text
export ZCODE_AGENTD_STORE=/absolute/private/zcode-agent.sqlite3
export ZCODE_AGENTD_SOCKET=/absolute/private/zcode-agent.sock
export ZCODE_RUNTIME_PATH=/absolute/official/zcode-runtime
./target/release/zcode-agentd
```

The daemon and Store are the sole durable lifecycle owner. The runtime owner keeps child process, stdio, session, turn, stop, and reap authority. `--database`, `--socket`, `--runtime`, and `--command-catalog` are equivalent CLI options.

## Codex MCP

Merge values from `config/codex-zcode-subagent-mcp.toml` into Codex configuration only when explicitly requested. The binary has one startup-static catalog:

```text
zcode_system_status
zcode_agent_spawn
zcode_agent_poll
zcode_agent_list
zcode_agent_send
zcode_agent_respond
zcode_agent_cancel
zcode_agent_result
zcode_agent_close
```

Review is a normal read-only Agent invocation. Put review instructions in `prompt`; no review task type or continuation identity exists.

```json
{
  "repository": "/absolute/repository",
  "base_ref": "0123456789abcdef0123456789abcdef01234567",
  "prompt": "Review base..HEAD and report concrete findings.",
  "access_mode": "read_only",
  "group_id": "feature",
  "idempotency_key": "fresh-agent-key",
  "allowed_command_ids": [],
  "required_command_ids": []
}
```

`allowed_command_ids` controls which daemon-owned named checks may run. `required_command_ids` separately binds mandatory checks to the finalized tree. Callers cannot submit programs, arguments, cwd, shell, or environment.
