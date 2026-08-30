# Project Development Workflow

## Single-Threaded Development

- Develop this repository only in the primary checkout at `/Users/ibobby/Projects/zcode-mcp`.
- Do not create additional Git worktrees for this project. In particular, do not run `git worktree add` for feature, review, repair, or audit work.
- Keep code-writing work sequential. Do not run multiple implementation or repair writers concurrently against this repository.
- When a branch is needed, create or switch branches in the primary checkout and preserve any existing user changes before switching.
- Keep all local workflow, review, and audit evidence under the primary checkout's `.agent-work/` directory. Do not maintain a second `.agent-work` tree in another checkout.
- Test harnesses may create bounded temporary fixture repositories or runtime workspaces when the test contract requires isolation. These are runtime artifacts, not development worktrees, and must be reaped or archived under the primary `.agent-work/` tree when the run finishes.

## Git Integration

- Integrate completed local branches into `main` only from the primary checkout and only with explicit user authorization.
- Do not push, rewrite history, or delete user work without explicit user authorization.
