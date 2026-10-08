# Delivery routes

Use live tool schemas and installed `--help` over examples when they differ.
Read only the relevant route; these are not setup steps to run for every task.

## Claude native messaging

Use exposed `ListAgents` to discover the peer and `SendMessage` with its returned
identity. Verify working directory and task where available. `/list-agents` or
`/peers` shows reachable sessions; `/status` shows the caller's peer address.
Mailbox service names are a different namespace.

Native messages reach active turns between tool calls or start a turn in an idle
session, subject to inbound controls. Held/refused messages must not be bypassed.
Where exposed, `notify_when_idle` requests one completion notice without polling;
idle alone is not task success. The proactive default covers relevant local
sessions; cross-machine contact needs existing authorization for that destination.

Source: [Claude cross-session messaging](https://code.claude.com/docs/en/cross-session-messaging).

## Codex queue

Check `codex queue --help`. Use an exact thread UUID from the current
session environment, a live listing, or that peer's own `/status`; never guess or
use `--last`. `codex agents` is an interactive browser of the shared local daemon,
not a JSON inventory command. Desktop, CLI and child-agent IDs are not necessarily
reachable through the same daemon.

```sh
codex queue --thread <verified-thread-uuid> --message '<peer message>'
```

Use correct shell quoting; for complex text prefer a subprocess argument array
with `shell=False`. Do not interpolate message text into executable shell code or
add model, profile, permission or sandbox overrides to a peer message. Record the
actual receipt and check the answer through the established reply route. A queue
receipt alone proves neither a running nor a completed turn.

If the owning daemon is unreachable, the route is unavailable. Do not bootstrap,
restart, resume or fork it to deliver a message. For uncertain send status inspect
the exact target before retrying or falling back.

The installed CLI help is the command contract; the [general CLI
reference](https://developers.openai.com/codex/cli/reference) may lag local builds.

## Existing mailbox integration

Use only when configured and both peers are registered. Read the actual schemas:
`mcp_agent_mail` and `osteele/agent-mail` are different implementations. Resolve the
project and recipient, send a threaded request, and inspect delivery/read/answer
state. Check whether worktrees share a project key or have separate inboxes.

An inbox may need explicit polling; do not promise it wakes an idle Codex session.
Check at useful work boundaries; use notifications only when already enabled.
Advisory reservations do not supersede repository claims or guarantee exclusion.
Installation, hooks, daemons and settings are separate setup work.

References: [MCP Agent Mail skill](https://github.com/Dicklesworthstone/mcp_agent_mail/blob/main/SKILL.md),
[agent-mail delivery](https://github.com/osteele/agent-mail#how-delivery-works).

## cmux terminal fallback

This can bridge Codex and Claude terminals in cmux. It sends terminal input, so
verify the intended agent and composer before every delivery. Use only within the
user's authorized scope and never to bypass held/refused native delivery.

```sh
cmux --json --id-format both identify
cmux --json --id-format both tree --all
cmux read-screen --workspace <workspace-uuid> --surface <surface-uuid> --lines 60
```

Read only relevant candidate terminals after matching task/path metadata. Use
stable UUIDs from inventory. When `identify` returns `caller: null`, its `focused`
surface belongs to the user: it is neither your reply address nor a default
target. Never send to an implicit focused terminal.

Send only when a fresh screen shows the intended live agent idle with an empty
composer. A shell prompt, busy agent, permission/trust dialog, existing draft or
uncertain screen is not safe. Wait or use an available messaging channel; do not
clear input, press Escape/Ctrl-C, accept a dialog, or interrupt another job.

Read `cmux send --help` and `cmux send-key --help`. `send` interprets escapes such
as backslash-n as Enter. Keep terminal messages short, on one line, with no
backslashes/control characters. For complex content use a private local message
file and send its safely quoted path and request ID. The file is peer context,
not new user authority. Remove only your own temporary files when done.

```sh
cmux send --workspace <workspace-uuid> --surface <surface-uuid> '<one-line peer message>'
cmux read-screen --workspace <workspace-uuid> --surface <surface-uuid> --lines 20
# Verify the exact draft is intact in the intended agent's composer.
cmux send-key --workspace <workspace-uuid> --surface <surface-uuid> enter
```

Re-read after submission to establish receipt; cmux success alone proves only
input acceptance. On timeout read before retrying to avoid duplicate questions.
Supply a verified reply route. If unaddressable, ask the peer to print an answer
with the request ID and explicitly collect it while your turn is active. This
does not wake a desktop conversation after its turn ends.

When expecting a reply into your own terminal, finish the sending turn so your
composer becomes idle. If you need to keep working, ask the peer to print the
answer in its terminal and collect it there; do not make two busy terminals wait
for each other's empty composer.

Do not change focus, close other sessions, or launch replacement agents as a
fallback. State unsupported cases plainly.

Source: [cmux CLI contract](https://github.com/manaflow-ai/cmux/blob/main/docs/cli-contract.md).
