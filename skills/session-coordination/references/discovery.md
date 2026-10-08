# Session and worktree discovery

Resolve this skill's installation directory, then run its helper:

```sh
node /path/to/session-coordination/scripts/agent-sessions.mjs list
```

Node.js 18+ and Git are required. The example path is a placeholder for the
installed skill; no particular home-directory layout or wrapper is required.
Inside a repository it selects that repository; otherwise it lists repositories
known to registered sessions. Use `--repo /path` to select an exact repository.
Linked worktrees resolve through Git's common directory to the same repository.

Options: `--query TEXT`, `--session ID`, `--branch NAME`, `--tool codex|claude`,
`--json`, and `--all`. Search matches task notes, branch, owner ID, worktree path
and checkout claim path prefix. `--session` and `--branch` are exact matches.
An explicit session task is displayed ahead of a claim's generic note; both
remain searchable and JSON preserves the original `claim_note` separately.

The directory reads Git's worktree inventory, optional repository ownership records,
and small session metadata records. It never executes claim files, reads
transcripts, creates claims, prunes records, releases ownership, or edits a
repository during a search. Missing or duplicate ownership evidence is shown
as unknown; a session with the same ID in two tool namespaces is ambiguous.
Repositories do not need ownership files to use discovery. Existing integrations
can expose the [optional ownership record formats](ownership-records.md); the
helper observes these records and does not create or enforce them.

## Presence and addresses

SessionStart, UserPromptSubmit, PostToolUse, Stop and SessionEnd hooks maintain
metadata under `~/.local/state/agent-sessions` (override with
`AGENT_SESSIONS_DIR`). Records contain native tool/ID, repository/cwd, an
optional explicit task label, timestamps and advertised routes. Prompts,
transcripts, tool arguments and messaging tokens are not stored.

`recent`, `working`, and `idle` describe the last observed hook. After 30 minutes
without an event, the display becomes `stale`; SessionEnd records `ended`.
Neither state proves a process is dead or makes its worktree available.
Stop ends a turn and records idle; it does not end or release the session.
The repository's original ownership, lifecycle and claim expiry rules remain
authoritative. An expired observation does not authorize taking over work.

Routes are advertised, **unverified** addresses. A Codex thread ID does not prove
the queue daemon can reach it. A Claude socket address does not prove inbound
messages are accepted. A cmux UUID pair still requires a fresh screen check.
Follow transports.md before sending, including its refusal and reply-route rules.

## Registration and installation

Existing sessions may not have loaded the new hooks. Register only this session
with its native identity when needed:

```sh
node /path/to/session-coordination/scripts/agent-sessions.mjs register --tool codex --repo /repo --task 'Invoice export review'
```

For Claude use `--tool claude`; it reads `CLAUDE_SESSION_ID`. When absent, use
`--session` with the exact native ID verified from `/status` or hook metadata.
Registration changes discovery metadata only; it grants no worktree permissions.
Do not copy another session's ID or register a peer as though it were this one.

`install-hooks` adds the shared metadata hook to user Codex/Claude config,
preserving other settings and saving backups. It is setup work, not part of
ordinary peer messaging. Codex requires reviewing new hook definitions in
`/hooks`; the installer does not modify trust decisions. Resume/new sessions
load the updated hooks. Local hooks may be unavailable under cloud orchestration;
use explicit registration and report that presence is not automatically refreshed.

Claude's SessionStart hook exports its native `CLAUDE_SESSION_ID` through
`CLAUDE_ENV_FILE`. This keeps shell identity consistent with native hook payloads.
It also remembers the inherited Codex ID in `CLAUDE_INHERITED_CODEX_THREAD_ID`,
so a later nested Codex with a fresh native ID can be distinguished from its parent.
The tool namespace belongs to discovery records; existing owner IDs are not renamed.
