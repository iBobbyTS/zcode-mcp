# Testing

## Full validation

```bash
npm run verify
```

This performs:

1. standalone-file regeneration;
2. Node syntax checks;
3. tokenizer tests;
4. allow/deny policy corpus;
5. path and symlink confinement tests;
6. hook protocol tests;
7. 2,000 deterministic dangerous-command mutations;
8. actual execution of representative allowed commands in a temporary Git repository;
9. proof that tracked/staged state remains unchanged;
10. Rust/JavaScript corpus parity.

## Direct hook smoke

```bash
printf '%s\n' '{
  "cwd":"/absolute/path/to/repository",
  "hook_event_name":"PreToolUse",
  "tool_name":"Bash",
  "tool_input":{"command":"git status --short"}
}' | node hooks/check-bash-readonly.mjs | jq
```

Expected result:

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "permissionDecisionReason": "...",
    "updatedInput": {
      "command": "GIT_OPTIONAL_LOCKS=0 ... git ... status --short"
    }
  }
}
```

Dangerous smoke:

```bash
printf '%s\n' '{
  "cwd":"/absolute/path/to/repository",
  "hook_event_name":"PreToolUse",
  "tool_name":"Bash",
  "tool_input":{"command":"find . -delete"}
}' | node hooks/check-bash-readonly.mjs | jq
```

Expected decision: `deny`.

## Adding command support

Do not add an executable to a generic regex.

1. Add or extend one command-specific validator in `lib/bash-policy.mjs`.
2. Enumerate every allowed option role.
3. Identify options that execute programs, write output, follow symlinks, access network, or escape the root.
4. Add positive corpus cases.
5. Add direct adversarial cases and mutation families.
6. Confirm canonical command execution does not alter Git status.
7. Run `npm run check` to verify every shipped wrapper.
8. Run `npm run verify`.

## Platform coverage

The policy targets POSIX shell semantics on macOS and Linux. The delivered validation was run with Node 22 and Git 2.47 on Linux. The code uses Node/POSIX APIs available on current macOS, but the package does not claim Windows shell compatibility.
