# Psy agent workflow skills

Six portable skills for implementation, verification, closeout, continuation and
coordination between existing agent sessions.

**Published as-is. No ongoing maintenance, updates or support are promised.**
You are welcome to fork and adapt this snapshot under the [MIT license](LICENSE).

| Skill                                                                | Use it to                                                                                    |
| -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| [psy-build](skills/psy-build/SKILL.md)                               | Implement and verify an explicitly requested change using the current repository's workflow. |
| [psy-finish](skills/psy-finish/SKILL.md)                             | Complete authorized verification, commit and integration steps.                              |
| [psy-next-step](skills/psy-next-step/SKILL.md)                       | Choose one useful next action, including closing a completed session.                        |
| [psy-next-prompt](skills/psy-next-prompt/SKILL.md)                   | Write a continuation prompt that preserves scope and authority.                              |
| [psy-prove](skills/psy-prove/SKILL.md)                               | Verify changed behavior or substantiate a finding with scoped evidence.                      |
| [psy-session-coordination](skills/psy-session-coordination/SKILL.md) | Exchange scoped questions and findings between existing sessions.                            |

## Installation

Use the [Skills CLI](https://github.com/vercel-labs/skills) to select skills:

```sh
npx skills add psydigital/agent-workflow-skills
```

Install the complete collection:

```sh
npx skills add psydigital/agent-workflow-skills --skill '*'
```

Or install from a local checkout with `npx skills add .`. Installing the files
does not install lifecycle hooks, register slash commands in every host, or replace
a repository's build and finish commands. Invocation syntax depends on the agent.
The `psy-` prefix distinguishes this collection in shared skill directories.

## Repository-aware workflows

Start with `psy-build` when a full development workflow is requested. It discovers
repository instructions, local skills and documented setup/check scripts. Use
`psy-finish` for authorized closeout. Existing project workflows supply their
implementation, including worktree, development-server and cleanup procedures.
Without custom workflows, the skills guide ordinary scoped development and Git
operations within the user's authority. An asset compilation task is not a full
implementation workflow. Worktrees and servers are used only where needed.

The other skills refer to these two entry points when appropriate and installed.
Each skill also works on its own through verified local equivalents or plain
instructions. No third-party skill pack, framework, claims system, database or
agent orchestration package is a mandatory dependency.

Example requests:

- “Use psy-build to implement and verify this change using the repository's workflow.”
- “Use psy-finish to prepare this branch for handback. Do not push or merge.”
- “Use psy-next-step: should we continue, review, finish, hand off, or close?”
- “Use psy-next-prompt to write a short continuation from this session.”
- “Use psy-prove to verify this fix within the authorized scope.”
- “Use psy-session-coordination to ask the existing review session about its findings.”

Implementation, review, integration, publication and deployment remain distinct
operations. A recommendation or drafted prompt does not execute its contents.

## Optional session discovery

The coordination skill includes local session discovery and optional path claims,
requiring Node.js 18+ and Git. It does not read chat transcripts or send messages.
The [setup guide](skills/psy-session-coordination/references/setup.md) covers
optional lifecycle hooks, manual registration and messaging prerequisites.

Use existing repository ownership tooling where present. The optional
[claims utility](skills/psy-session-coordination/references/portable-claims.md)
refuses initialization and writes when it detects supported existing systems.
Hooks report presence; they do not claim paths. Listing is read-only. Installation
and claims initialization are explicit setup actions, not prerequisites for
asking another session a question.

## Verification and provenance

```sh
node --test skills/psy-session-coordination/scripts/*.test.mjs
```

The `evals/evals.json` files describe behavioral scenarios for manual or agent
assessment. They are not an automated evaluation runner or proof of model behavior.
Repository safety CI checks publication hygiene; it does not certify agent decisions.
See [snapshot editing guidance](AGENTS.md) before contributing changes.

This collection contains original workflow instructions and local coordination
helpers. References to external tools describe integrations; those tools and
third-party skill packs are not bundled. The vendored repository safety scanner
supports publication checks and is separate from the installable skills.

## Snapshot status

MIT licensed; no release cadence or support commitment. The publication copy is
independent of existing private agent installations and project workflows. There
is no automatic synchronization into those environments.
