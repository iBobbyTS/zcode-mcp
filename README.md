# zcode-subagent-mcp

ZCode Subagent MCP exposes one generic local Agent control plane to Codex.
Review, analysis, and implementation are caller prompts over the same
`read_only` or `workspace_write` Agent; the daemon and Store own lifecycle and
durable state.

The workspace contains seven crates:

```text
zcode-protocol
zcode-driver
zcode-fake-runtime
zcode-agent-store
zcode-agent-preparation
zcode-agentd
zcode-subagent-mcp
```

The public MCP catalog is exactly nine tools:

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

Runtime activity is passive liveness evidence. Poll exposes bounded text tails,
reasoning/tool counters, pending requests, and terminal result availability;
semantic review progress and finding admission remain caller concerns.

Security remains deny-first: disposable worktrees, frozen write manifests,
daemon-owned named checks, typed permission requests, path/secret/symlink/Git
ref confinement, late-event fencing, immutable result/artifact hashes, and
process-group cleanup are enforced by the existing owners.

Build and run the local daemon/facade with the generic names in
[`docs/setup.md`](/Users/ibobby/Projects/zcode-mcp/docs/setup.md). The plugin
and isolated Hook tests live in
[`plugins/zcode-subagent-mcp`](/Users/ibobby/Projects/zcode-mcp/plugins/zcode-subagent-mcp).
