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
| omg.dev | `c75b3181` | `LICENSE` (repository path; not fetched) | Yes | No | None |
| pi-subagents | `3f9d35cd` | `LICENSE` (repository path; not fetched) | Yes | No | None |
| sailing | `b1ec38ec` | `LICENSE` (repository path; not fetched) | Yes | No | None |
| mcp-supersubagents | `c30fd7c1` | `LICENSE` (repository path; not fetched) | Yes | No | None |

Before reusing any implementation, a maintainer must inspect the exact license
at the pinned commit and record an explicit decision here. S00 intentionally
contains no copied third-party code.

## Cargo dependency inventory

The [exact Cargo dependency license inventory](dependency-licenses.md) covers
all 189 resolved third-party packages in the locked workspace graph.

- `Cargo.lock` SHA-256:
  `ec2471b508ef12cee914fbd1554e3cef2d4be9a9127d9253db887d3797149a7e`
- Canonical inventory SHA-256:
  `a9067c2f48aed8560f62c5a5a3d2a3a2d7e255a8021efdc7bf514a32df17541f`
- `docs/dependency-licenses.md` SHA-256:
  `d76211a16d8be9a9a19cb2a7f3e31e9674c70472133b56126d8c1c763085515f`

The locally installed official ZCode runtime is not a Cargo dependency and is
not vendored or redistributed by this project, so it is outside that Cargo
inventory.
