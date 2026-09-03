# Sectioned shadow integration

`sectioned-shadow` is an optional generic read-only Agent consumer. It calls `zcode_agent_spawn`, advances `zcode_agent_poll` using `next_revision`, reads `zcode_agent_result`, and always calls `zcode_agent_close`.

Review scope, finding admission, Clean decisions, repair limits, reviewer alternation, and merge readiness remain owned by the calling Codex workflow. Every terminal recheck creates a fresh Agent and idempotency key.

The adapter writes bounded `*-ZCODE-RAW.md` final text and `*-ZCODE-PROVENANCE.json`. It never receives reasoning content, tool arguments/output, cwd, or private filesystem handles.

```text
ZCODE_REVIEW_MCP_PATH=/absolute/path/zcode-review-mcp \
ZCODE_REVIEWD_SOCKET=/absolute/private/zcode-agent.sock \
sectioned-shadow /absolute/path/shadow-config.json
```
