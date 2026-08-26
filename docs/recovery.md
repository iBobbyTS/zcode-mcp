# Recovery

## Facade restart

The MCP facade is stateless. Stop or replace it, retain the daemon/database, and
start a new facade with the same `ZCODE_REVIEWD_SOCKET`. The same `agent_id`
continues to address the durable job. No facade journal or restore step exists.
Restart with the same catalog selector. A V2 replacement can use
`zcode_agent_get` immediately; compare `zcode_system_status.service_generation`
when deciding whether the daemon also changed. A differently configured legacy
facade may share the daemon, but legacy by-ID/list operations intentionally
cannot observe V2 task rows.

## Daemon restart

Stop the daemon with SIGTERM/SIGINT and wait for it to remove its exact socket.
Restart it with the same canonical database and socket paths. Before accepting
connections it acquires the database singleton, opens/migrates the Store, and
reconciles durable jobs.

Live ZCode session reconnect is not supported. A daemon crash may leave active
jobs as `FAILED_RUNTIME_LOST` or `ORPHANED`; partial events and reports remain
available. Restart recovery does not signal an old process group unless leader
PID, PGID, UID, Darwin start time, and membership are independently re-observed
and match. Missing or ambiguous identity fails closed.

After restart:

1. Call `zcode_review_list` with `scope=active` and inspect affected jobs.
2. Read each job's events and partial result.
3. Close jobs only after verifying their durable state; close preserves history.
4. Submit a new manifest/idempotency key for genuinely new independent evidence.
   A compatible replay is not a fresh review.

In V2, list only with an explicit repository/feature/ownership-token scope.
Continue a completed structured review with its stable public identities; the
daemon reconstructs immutable parent context and assigns the next attempt.
Retrying the same continuation idempotency key returns the same attempt.

## Database backup and migration

The database uses SQLite WAL. For a consistent file-level backup, stop the sole
daemon first and preserve the database together with any `-wal` and `-shm`
companions that still exist. Do not copy only the main file while the daemon is
writing. Preserve report artifacts referenced by durable rows.

Opening the database migrates supported old versions transactionally to schema
v4. Accepted v1/v3 migration fixtures preserve prior rows. Take a recoverable
backup before upgrading. A schema version newer than v4 fails closed; use the
matching newer binary or restore the complete pre-upgrade backup rather than
editing `user_version` manually.

## Runtime loss and stuck work

Use `stop` first for normal cancellation. It records cancellation and performs
bounded session/process stop without erasing evidence. Use `close` to converge
stop if necessary and reap owned runtime resources. Repeating either operation
is idempotent for the same durable Agent.

Never manually signal a PID copied from logs or a database. PID reuse and
unknown process-group membership are explicit fail-closed cases. If identity
cannot be proven, retain the job as orphaned/runtime-lost and resolve the host
process outside this application's authority.

Unsupported `interaction/requestUserInput` cannot be answered through this
seam. It appears as non-respondable and makes shadow evidence incomplete; stop
the job if it cannot proceed.

If artifact retrieval returns `result_invalid`, stop trusting all previously
read chunks for that artifact. Do not read the stored locator directly. Retain
the durable task for diagnosis, repair or restore the confined artifact through
its owning workflow, and retry metadata plus chunks from offset zero.

## Consumer rollback

The installed sectioned consumer is not Git-managed. Restore the exact backup
from `.agent-work/consumer-backups/sectioned-feature-development-pre-S08/SKILL.md`
only when intentionally rolling back the optional shadow paragraph. Verify the
pre-change SHA-256 is
`d0a8d11d7daa4a1d5a65322a5371a47739aec765e59a906c7b90fbeb62d051f3`.
The checked-in patch deterministically reproduces the installed
`8c324dd3...0f7f8` bytes from that backup.
