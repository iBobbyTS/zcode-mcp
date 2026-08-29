# Validation Record

## Build under test

- Package: `zcode-readonly-bash-guard`
- Version: `1.0.0`
- Policy version: `zcode-readonly-bash/v1.0.0`
- Policy descriptor SHA-256: `aa8fb18884f3b6b597a8dfeec5ccde85a8c7461a4bd2975aaaa18fc4d5c01aa0`
- Node.js: `v22.16.0`
- Git: `2.47.3`
- Validation date: `2026-08-28`

## Commands executed

```bash
npm run verify
```

This command performs, in order:

1. deterministic regeneration of the single-file hook;
2. Node.js syntax checks for the modular hook, audit hook, and policy module;
3. all Node.js test files under `test/`.

## Results

```text
21 tests
21 passed
0 failed
0 skipped
```

Covered behavior includes:

- limited shell tokenization and quoted literal handling;
- denial of shell composition, expansion, redirection, and background execution;
- command-specific allow/deny corpora;
- path confinement, symlink escape, secret path, and special-file rejection;
- trusted executable resolution independent of caller `PATH`;
- exact ZCode `PreToolUse` JSON input/output and `updatedInput` rewrite behavior;
- modular/single-file behavioral parity;
- 2,000 deterministic dangerous command mutations;
- execution of representative accepted commands in a temporary Git repository while proving tracked/staged state remains unchanged.

## Representative adversarial decisions

| Input | Result |
|---|---|
| `find . -delete` | `deny / find_action_denied` |
| `find . -exec rm -rf '{}' +` | `deny / find_action_denied` |
| `git branch -D victim` | `deny / git_branch_mutation_or_unknown_option` |
| `git diff --output=/tmp/leak.patch` | `deny / git_execution_or_output_option_denied` |
| `git log & touch /tmp/pwn` | `deny / shell_background_or_and` |
| `cat ~/.ssh/id_rsa` | `deny / tilde_path` |
| `rg -n 'TODO|FIXME' .` | `allow / readonly_rg` |
| `sed -n '1,20p' README.md` | `allow / readonly_sed_print` |

## Package hygiene

Verified absent:

- `node_modules/`
- `.DS_Store`
- `__MACOSX/`
- `__pycache__/`
- generated build/cache directories

The package contains no third-party npm dependencies.

## Security boundary

Passing this suite does not turn the hook into an operating-system sandbox. The supported deployment still requires a disposable review worktree, daemon/MCP write confinement, bounded output and process cleanup, and daemon-owned named commands for tests/builds or other repository code execution. Unsupported or ambiguous Bash commands fail closed by default.
