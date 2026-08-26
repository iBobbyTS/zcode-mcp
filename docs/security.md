# Security boundary

`zcode-reviewd` owns durable task identity, scope, budgets, pending requests,
runtime processes, cleanup, and artifact locators. `zcode-review-mcp` is a
stateless local projection: it validates bounded public inputs, calls the
private Unix RPC, and returns only approved fields. Do not expose the private
socket to untrusted local users; keep its directory and the SQLite database
outside reviewed repositories with owner-only permissions.

The V2 facade never publishes prompts, context contents, host/workspace/artifact
paths, raw pending payloads, private correlation/runtime/process identities,
environment, credentials, or reasoning. Event payloads are reduced to stable
event categories plus a public pending-request ID. Permission responses are
accepted only for typed daemon-published pending requests, and local policy may
override an external allow to deny.

Task listing is never daemon-wide: callers must provide at least one explicit
repository, feature, or ownership-token scope, which the Store applies before
the bound. Stable public IDs are not authentication tokens; this is a local,
single-user transport without remote or multi-tenant authorization.

Artifact metadata contains only ID, approved kind, SHA-256, and size. Chunk
retrieval verifies the stored row, expected task result, regular non-symlink
file type, complete SHA-256, size, offset, and per-call cap before returning
base64 bytes. Any replacement, truncation, symlink, or malformed metadata fails
closed as `result_invalid` or not found.

The repo-local V2 plugin and sample config set only the public catalog selector
and forward the already configured socket. They do not copy credentials,
download runtimes, edit provider/account configuration, or start a second
daemon/service.
