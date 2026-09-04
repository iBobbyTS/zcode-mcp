# Design Rationale

## Why not use a whole-command regex

A whole-string regex confuses executable identity, option roles, shell syntax, and path scope. It tends to produce both:

- dangerous false allows, such as `find -delete` or output redirection hidden behind an allowed prefix;
- high-friction false denials, such as a quoted `rg` regular expression.

The policy instead classifies a limited shell grammar and then validates each command's argv shape.

## Why reject composition instead of parsing all shell syntax

Safely evaluating `&&`, pipelines, redirections, subshells, variables, globbing, and wrapper shells requires a complete shell parser plus composition rules. That adds a large security surface for little agent value. ZCode can issue multiple tool calls for multiple inspections.

## Why rewrite accepted commands

The hook's parser should not merely guess how the shell will execute the original input. Re-rendering the accepted argv as a canonical command:

- eliminates original quoting ambiguity;
- prevents unvalidated expansion from surviving;
- injects fixed Git hardening flags;
- makes audit evidence stable.

## Why Bash is not used for tests

A command can be read-only with respect to tracked files and still execute arbitrary repository code, start child processes, access network, or write caches. Tests/builds therefore belong to a task-scoped named-command service controlled by the daemon, not the autonomous inspection hook.

## Influences

The design follows the same broad principles used by contemporary agent permission systems:

- parse commands into argv-like structure instead of matching unsafe substrings;
- use command-specific option policy;
- deny or ask when classification is ambiguous;
- keep policy enforcement separate from filesystem/process isolation;
- prefer false denials over silent false allows for destructive actions.

See official ZCode hook documentation, OpenAI Codex execution-policy documentation, and the Tact/OpenHands permission designs referenced in `SOURCES.md`.
