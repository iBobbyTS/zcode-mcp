# zcode-as-subagent setup

## Build

Source builds require Rust 1.97 or compatible and Cargo. The distributed product requires Node.js 20 and macOS.

```text
cargo build --release -p zcode-agentd -p zcode-subagent-mcp
```

## Daemon

Use private absolute database and socket paths outside the target repository:

```text
export ZCODE_AGENTD_STORE=/absolute/private/zcode-agent.sqlite3
export ZCODE_AGENTD_SOCKET=/absolute/private/zcode-agent.sock
export ZCODE_AGENT_HOOK_PROVENANCE=/absolute/private/zcode-agent-hook-provenance.json
export ZCODE_AGENT_SERVICE_GENERATION=<service_generation emitted by the hook installer>
./target/release/zcode-agentd
```

The daemon and Store are the sole durable lifecycle owner. The runtime owner keeps child process, stdio, session, turn, stop, and reap authority. `--database`, `--socket`, `--runtime`, and `--command-catalog` are equivalent CLI options.
Daemon startup verifies the installed Hook record, including its exact
`service_generation`, before opening the Store or publishing the private
socket. Missing, stale, tampered, or mismatched provenance fails closed.
The npm product always uses `/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs`; it does not search PATH or expose a runtime override.

## Codex MCP

Merge values from `config/codex-zcode-subagent-mcp.toml` into Codex configuration only when explicitly requested. The binary has one startup-static catalog:

```text
zcode_subagent_status
zcode_subagent_spawn
zcode_subagent_poll
zcode_subagent_list
zcode_subagent_send
zcode_subagent_respond
zcode_subagent_cancel
zcode_subagent_result
zcode_subagent_close
```

Review is a normal read-only Agent invocation. Put review instructions in `prompt`; no review task type or continuation identity exists.

```json
{
  "repository": "/absolute/repository",
  "prompt": "Review base..HEAD and report concrete findings.",
  "permission_mode": "build",
  "group_id": "feature",
  "idempotency_key": "fresh-agent-key",
  "allowed_command_ids": [],
  "required_command_ids": []
}
```

`allowed_command_ids` controls which daemon-owned named checks may run. `required_command_ids` separately binds mandatory checks to the finalized tree. Callers cannot submit programs, arguments, cwd, shell, or environment.
