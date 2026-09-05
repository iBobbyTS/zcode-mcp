# zcode-as-subagent

`zcode-as-subagent` is a local npm-distributed CLI and MCP facade for running
one durable Agent in a caller-selected workspace. The package exposes the same
Agent lifecycle through `zcode-as-subagent` and the `zcode_subagent_*` MCP
tools; there is no compatibility alias or migration layer.

## Install and use

```bash
npm install -g zcode-as-subagent
zcode-as-subagent help
zcode-as-subagent init --dry-run
zcode-as-subagent status
```

The macOS runtime is probed only at the fixed bundle location
`/Applications/ZCode.app/Contents/Resources/glm/zcode.cjs`. Windows supports
only `help` and `version`; business commands return structured
`UNSUPPORTED_PLATFORM` without touching HOME. The npm package never downloads,
upgrades, or manages providers, credentials, GUI clients, remote daemons,
multi-tenant services, Windows daemons, Rosetta, Git, worktrees, or a second
supervisor.

## Public MCP catalog

The nine tools are `zcode_subagent_status`, `zcode_subagent_spawn`,
`zcode_subagent_poll`, `zcode_subagent_list`, `zcode_subagent_send`,
`zcode_subagent_respond`, `zcode_subagent_cancel`, `zcode_subagent_result`,
and `zcode_subagent_close`. Spawn accepts only `build`, `edit`, `plan`, or
`yolo` permission modes (default `build`). A canonical workspace has one
active Agent; a collision is reported as `WORKSPACE_BUSY` with the active id.

## Data, cleanup, and safety

`uninstall` removes service registration but retains data. `purge --yes` is the
only destructive data operation. `cleanup-legacy --yes` removes an old,
unpublished installation without importing or aliasing its data. Hook
PreToolUse remains an independent deny-first boundary in every permission
mode, including `yolo`; PostToolUse records metadata-only hashes.

See [docs/setup.md](docs/setup.md), [docs/operations.md](docs/operations.md),
[docs/recovery.md](docs/recovery.md), and the
[plugin validation guide](plugins/zcode-subagent-mcp/docs/VALIDATION.md).
