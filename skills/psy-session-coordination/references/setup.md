# Coordination setup

The skill instructions work without additional setup when the host already exposes
the needed peer discovery and messaging. The bundled helper adds a shared local
session directory. The claims utility adds optional path ownership records.

## Prerequisites

- Node.js 18+ and Git for the bundled helpers.
- A host that supports the selected hook or messaging integration.
- A stable installation path: hook commands refer to the helper and Node binary
  by absolute path. Moving either requires updating those commands.

Run the helpers from the collection root in these examples. For an individually
installed skill, resolve its `scripts/` folder from the actual installation.

## Read-only discovery

```sh
node skills/psy-session-coordination/scripts/agent-sessions.mjs list --repo /path/to/repository --json
```

A Git checkout may appear before any sessions register. An unknown owner or
missing route is missing evidence; do not infer either from a checkout or branch.

## Optional lifecycle hooks

When the user requests automatic discovery, the existing installer can configure
the local Codex and Claude settings:

```sh
node skills/psy-session-coordination/scripts/agent-sessions.mjs install-hooks
```

This command currently configures both tools. It preserves unrelated settings,
backs up existing configuration under the private session registry, and avoids
adding an identical command twice. It does not install agent software, configure
messaging servers or change hook trust decisions. Review and trust new Codex hook
definitions through the installed host's supported interface. New or resumed
sessions load the hook configuration as supported by that host.

The installer refuses symlinked settings files or tool configuration directories,
including dangling links, before updating either tool. It also refuses nonregular
files and settings larger than 1 MiB. For dotfile-managed settings, integrate the
hook definitions into the canonical configuration through your existing setup;
keep the symlinks intact. Do not edit settings concurrently with installation.

The five events are `SessionStart`, `UserPromptSubmit`, `PostToolUse`, `Stop` and
`SessionEnd`. Each invokes the same helper in `hook --tool ...` mode. It records
native identity, checkout, task label, observed presence and advertised routes.
These session records exclude prompt text, transcripts, tool arguments and
messaging tokens. Configuration backups are separate and contain the complete
original settings, as explained below.

Default state lives at `~/.local/state/agent-sessions`; `AGENT_SESSIONS_DIR` or
`--state-dir` can select another private location. Local hook execution is
host-dependent. Installing skill files alone does not activate these hooks.

To remove the integration, remove only the exact helper commands from each tool's
hook configuration. Preserve unrelated hooks and review changes through the host.
The installer currently has no uninstall or path-migration command. Installing
again from a different path does not remove old entries; inspect those explicitly.

## Local data and retention

Session records contain repository and checkout paths, tool and native session
IDs, explicit task notes, timestamps, observed presence and advertised reply
routes. These can reveal private project names and local activity even without
chat content. Keep task notes free of secrets and unnecessary personal data.

The helper writes registry directories with mode `0700` and record/backup files
with mode `0600` on systems that support POSIX permissions. It sends no network
requests. Peer messages are a separate action through the selected host or
transport and follow that system's privacy settings.

The `config-backups/` directory holds full copies of pre-installation Codex and
Claude settings. Those copies can contain credentials or other sensitive values
already present in the settings. Restrictive file permissions do not redact them.
Keep the registry outside repositories and public/shared or cloud-synced folders.

There is no automatic retention limit or purge command. Ended and stale session
records remain on disk; `--all` includes historical records. Removing the hook
commands stops future hook updates but leaves records and backups in place.
After disabling hooks, review and remove only the records and backups you no
longer need from the configured registry. Active hooks can recreate records.
Deleting discovery metadata does not release repository ownership claims.

## Manual registration

Where hooks are unavailable, register the current session explicitly:

```sh
node skills/psy-session-coordination/scripts/agent-sessions.mjs register --repo /path/to/repository --tool codex --task 'Search review'
```

Use the selected tool's native session environment or a verified `--session` ID.
Register only the current session. Manual registration does not provide ongoing
presence refresh, ownership, or messaging reachability.

## Optional claims and messaging

Keep existing repository ownership tooling. For a repository without it, follow
the [portable claims guide](portable-claims.md) after explicit setup authorization.
Hooks report presence; they do not create or release claims.

Sending messages requires an independently available [delivery route](transports.md):
native messaging, a reachable queue, an existing mailbox integration, or a verified
terminal fallback. None is bundled or enabled by these helpers. An advertised
address is unverified until the relevant transport checks succeed.

## Verification

```sh
node --test skills/psy-session-coordination/scripts/*.test.mjs
```

Tests use disposable Git repositories, session registries and settings files.
They do not install real hooks, contact peers, or modify live repository claims.
They establish local helper behavior, not end-to-end delivery through every host.
