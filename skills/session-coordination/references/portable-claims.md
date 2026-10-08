# Portable workspace claims

Use this optional utility when a repository needs a shared record of which agent
session is working on a path. Claims are advisory coordination data: they do not
enforce edit permissions, authenticate a local process, or authorize a task.
Repository instructions and the user's scope still govern all work.

## Existing ownership takes precedence

Read the repository's instructions before setup. If it already owns a claims or
worktree lifecycle system, continue using that system. The portable writer refuses
setup and every mutation when it detects any of these in the main checkout:

- `.session-state/master-claims.tsv`
- `.session-state/master-freeze`
- `.session-state/worktrees/`
- `scripts/master-claim.sh` or `scripts/worktree-claim.sh`
- A configured `MASTER_CLAIMS_FILE` or `MASTER_FREEZE_FILE` environment variable

This detection covers supported compatibility formats, not every possible local
ownership system. Never bypass it by renaming, moving, or removing existing files.
There is no override or takeover flag. Discovery remains read-only and can still
report the repository's existing records.

## Commands

Run from this collection's root, replacing `/path/to/repository` with the target
checkout. Initializing is a deliberate per-repository setup action:

```sh
node skills/session-coordination/scripts/workspace-claims.mjs init --repo /path/to/repository
node skills/session-coordination/scripts/workspace-claims.mjs list --repo /path/to/repository --json
```

Claim a narrow repository-relative path for the current session:

```sh
node skills/session-coordination/scripts/workspace-claims.mjs claim src/search --repo /path/to/repository --tool codex --note 'Search review'
node skills/session-coordination/scripts/workspace-claims.mjs renew src/search --repo /path/to/repository --tool codex
node skills/session-coordination/scripts/workspace-claims.mjs release src/search --repo /path/to/repository --tool codex
```

Use `--tool claude` for that agent. Identity comes from `CODEX_THREAD_ID` or
`CLAUDE_SESSION_ID` for the selected tool. If the native environment variable is
unavailable, `--session` may supply the verified native ID of the current session.
An explicit ID cannot override a different ID already set for that tool. Never
use a peer's identity to release or renew its claim.

## Ownership and expiry

Claims apply across checkouts sharing the same Git common directory. Parent and
child paths overlap; sibling names such as `src/search` and `src/searching` do not.
Comparison is conservatively case-insensitive even on case-sensitive filesystems.
Root paths, traversal, metadata paths and symlink aliases are rejected. A repeated
claim for the exact same path and owner returns the original claim without renewing
it. Only the same tool and native session can renew or release it.

The default TTL is eight hours. `--ttl-seconds` accepts 1 through 604800 seconds
for acquisition or renewal. Expiry marks an unreleased claim as stale intent; it
continues blocking overlapping claims until its owner releases it. Session idle,
end or missing presence never automatically releases ownership. These rules do
not alter the lifecycle semantics of existing repository-specific claim formats.

`list` shows all unreleased claims, including expired ones. `list --all` also shows
released history. Listing never initializes, prunes, renews or rewrites records.

## Storage and recovery

State lives at `agent-workflow-claims/state.json` beneath the repository's Git
common directory. Linked worktrees share it; ordinary Git commits never include
it. The version 1 JSON contains claim IDs, path prefixes, owning tool/session,
task notes, checkout paths and creation/update/expiry/release timestamps. Files
use mode 0600 and the directory mode 0700 on supported POSIX systems.

Writes acquire an exclusive directory lock before rereading and changing state,
then atomically replace the JSON file. A concurrent writer gets a busy error and
must retry after the other command completes. The utility never removes another
writer's lock automatically. An interrupted writer may leave a lock; verify that
writer has stopped before an authorized manual recovery of that exact lock.

Malformed state and unsafe symlinks fail closed. Preserve the evidence and repair
the data deliberately; do not delete the store to evade an ownership conflict.
There is no automated reassignment of an unavailable owner's claims. Keep all
real runtime data and backups private and outside published source.
