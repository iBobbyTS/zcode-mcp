# Project Development Workflow

## Single-Threaded Development

- Develop this repository only in the primary checkout at `/Users/ibobby/Projects/zcode-mcp`.
- Do not create additional Git worktrees for this project. In particular, do not run `git worktree add` for feature, review, repair, or audit work.
- Keep code-writing work sequential. Do not run multiple implementation or repair writers concurrently against this repository.
- When a branch is needed, create or switch branches in the primary checkout and preserve any existing user changes before switching.
- Keep general local workflow, review, and audit evidence under the primary checkout's `.agent-work/` directory. Do not maintain a second `.agent-work` tree in another checkout.
- Live-agent source scenarios and executions follow `tests/live-agent/README.md`: committed small tests live in `non-git-based/`, local complex Git scenarios live in ignored `git-based/`, and every execution copy and result lives in ignored `workspace/`.
- Test harnesses may create bounded temporary fixture repositories or runtime workspaces when the test contract requires isolation. These are runtime artifacts, not development worktrees, and must be reaped or retained under `tests/live-agent/workspace/` when the run finishes.

## Decision Ownership And Failure Investigation

- The external Advisor owns software architecture decisions, public-contract changes, security/trust-boundary changes, and other decisions explicitly reserved for the Advisor.
- Codex acts as the Orchestrator and executor for this repository. Codex must investigate and, where in scope, repair failures reported by ZCode, agents, or test harnesses before declaring that Advisor or Human intervention is required.
- A `FAILED` result from another agent or harness is evidence to investigate, not a final escalation decision. Inspect the raw error, logs, process state, artifacts, and local runtime configuration, then classify the cause as an environment blocker, test/harness defect, fixture defect, product defect, or an actual Advisor-owned decision.
- Do not escalate to the Advisor or Human solely because ZCode has an environment, login, socket, daemon, or other operational problem. If the evidence confirms a local environment blocker that Codex cannot safely resolve, stop and ask the Human to address that environment condition.
- When the Advisor's contract or expected behavior differs from the behavior of the actually installed and authenticated ZCode client, treat the observed ZCode behavior as the operational source of truth for test-only adaptation. This does not override an Advisor software-architecture, public-contract, or security/trust-boundary decision; Codex must continue to obey that decision and escalate the conflict rather than silently bypassing it. Record the discrepancy, evidence, and resulting limitation in the final report; do not silently weaken product security or public contracts.

## Git Integration

- Integrate completed local branches into `main` only from the primary checkout and only with explicit user authorization.
- Do not push, rewrite history, or delete user work without explicit user authorization.
