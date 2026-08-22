# Reference and License Matrix

These repositories are research references only. This project does not clone,
vendor, extract, decompile, patch, or redistribute the official ZCode runtime
(`zcode.cjs`) or third-party source. The commits below were resolved with
`git ls-remote <url> HEAD` on 2026-08-22 and are recorded in `REFERENCES.lock`.

| Repo | Commit | License file | Design reference | Code copy | Files copied |
|---|---|---|---|---|---|
| zcode-acp | `42fe149d` | `LICENSE` (repository path; not fetched) | Yes | No | None |
| zcode-cli | `e6e110cb` | `LICENSE` (repository path; not fetched) | Yes | No | None |
| zcode-tui | `8ba8f688` | `LICENSE` (repository path; not fetched) | Yes | No | None |
| omg.dev | `0e574c42` | `LICENSE` (repository path; not fetched) | Yes | No | None |
| pi-subagents | `3f9d35cd` | `LICENSE` (repository path; not fetched) | Yes | No | None |
| sailing | `b1ec38ec` | `LICENSE` (repository path; not fetched) | Yes | No | None |
| mcp-supersubagents | `c30fd7c1` | `LICENSE` (repository path; not fetched) | Yes | No | None |

Before reusing any implementation, a maintainer must inspect the exact license
at the pinned commit and record an explicit decision here. S00 intentionally
contains no copied third-party code.
