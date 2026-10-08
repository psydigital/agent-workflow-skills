# Psy agent workflow skills

```text
 ____   ____ __   __
|  _ \ / ___|\ \ / /
| |_) |\___ \ \ V /
|  __/  ___) | | |
|_|    |____/  |_|

 A G E N T   W O R K F L O W   S K I L L S
```

**Build with context. Finish with evidence. Know what comes next.**

Seven portable skills to help an AI coding agent implement changes, check its
work, coordinate with existing sessions and leave a useful handoff. They follow
the current repository's conventions and tools, so you can bring them to different
projects without bringing an entire development environment along.

[Explore the skills](#skill-index) · [Install](#installation) ·
[Try a prompt](#example-prompts) · [MIT licensed](LICENSE)

> **An as-is snapshot.** No ongoing maintenance, updates or support are promised.
> Fork it, adapt it and make it your own.

## Contents

- [Start here](#start-here)
- [Skill index](#skill-index)
- [Installation](#installation)
- [How the workflows fit together](#how-the-workflows-fit-together)
- [When features overlap across worktrees](#when-features-overlap-across-worktrees)
- [Example prompts](#example-prompts)
- [Optional coordination tools](#optional-coordination-tools)
- [Inside the repository](#inside-the-repository)
- [Verification](#verification)
- [Maintenance and license](#maintenance-and-license)

## Start here

If you're unsure what to do next, start with **`psy-next-step`**. It can recommend
continuing, reviewing, finishing, handing off or simply closing a completed task.

For a concrete implementation request, use **`psy-build`**. When the work is ready
for closeout, use **`psy-finish`**. Both discover the current repository's workflow
and keep the task within the authority you've given the agent.

For a transition between sessions, use **`psy-handoff`** to save the context that
needs to survive, and **`psy-next-prompt`** for a short instruction to continue.

You can install the whole collection or pick individual skills. Each has a
fallback for optional companion skills that aren't installed.

## Skill index

| You want to…                 | Skill                                                                | What it brings                                                                         |
| ---------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| Implement a change           | [psy-build](skills/psy-build/SKILL.md)                               | Scoped implementation, repository-aware setup and meaningful verification.             |
| Finish the work              | [psy-finish](skills/psy-finish/SKILL.md)                             | Verification, commits and authorized integration through the project's own procedures. |
| Decide what's next           | [psy-next-step](skills/psy-next-step/SKILL.md)                       | One useful recommendation, including stopping when the work is complete.               |
| Save context for later       | [psy-handoff](skills/psy-handoff/SKILL.md)                           | A durable record of the task, decisions, evidence, ownership and remaining work.       |
| Write the next instruction   | [psy-next-prompt](skills/psy-next-prompt/SKILL.md)                   | A concise, copyable prompt for the correct authorized session.                         |
| Establish what is proven     | [psy-prove](skills/psy-prove/SKILL.md)                               | Evidence that matches the claim, with clear limits on what was checked.                |
| Coordinate existing sessions | [psy-session-coordination](skills/psy-session-coordination/SKILL.md) | Scoped peer questions and findings, with verified identity and delivery routes.        |

## Installation

Use the [Skills CLI](https://github.com/vercel-labs/skills) to install into your
agent's skills directory. See the [CLI documentation](https://skills.sh/docs/cli)
for supported installation options.

> **Before publication:** install from the local checkout with `npx skills add .`.
> The GitHub commands below are for the published snapshot.

**Choose interactively:**

```sh
npx skills add psydigital/agent-workflow-skills
```

**Install all seven:**

```sh
npx skills add psydigital/agent-workflow-skills --skill '*'
```

**Pick a pair:**

```sh
npx skills add psydigital/agent-workflow-skills --skill psy-next-step --skill psy-next-prompt
```

The `psy-` prefix distinguishes these skills in shared skill directories.
Invocation syntax depends on your agent: the plain-language prompts below are a
useful starting point. Installing skill files doesn't automatically install
hooks, start servers or replace a repository's existing commands.

The external Skills CLI collects usage telemetry by default. Its
[telemetry documentation](https://github.com/vercel-labs/skills#telemetry) explains
what is sent. To disable its telemetry and security-audit requests for an install:

```sh
DO_NOT_TRACK=1 npx skills add psydigital/agent-workflow-skills
```

This setting applies to the installer; your coding agent and any messaging
transport have their own data handling. Review the selected skill files before
installation, including optional scripts you intend to run.

## How the workflows fit together

**`psy-build` and `psy-finish` are the development entry points.** They read
repository instructions, discover the relevant local skills and scripts, and use
the project's supported setup, checks and closeout procedures. Without a custom
workflow, they guide ordinary scoped development and Git operations.

**`psy-prove` supports either stage.** It helps the agent distinguish a source
inspection from a passing test, and a local result from deployment evidence.
**`psy-next-step`** chooses a useful action. **`psy-session-coordination`** helps
when another existing session has relevant work or evidence.

**`psy-handoff` and `psy-next-prompt` serve different needs:** the handoff is the
saved context, and the prompt is the next instruction. A short task may only need
a prompt. A long investigation may need a handoff with links to its evidence.
Neither transfers another session's ownership or permission to act.

Use only the pieces the task needs. A recommendation or drafted prompt doesn't
execute its contents. Worktrees and review servers are used when required by the
task or project workflow. An asset compilation command isn't treated as an
entire development workflow.

The collection has no mandatory framework or third-party skill-pack dependency.
Implementation, review, integration, publication and deployment remain separate
operations, governed by the user's request and the repository's rules.

## When features overlap across worktrees

**Separate worktrees can still depend on the same decisions.** One session might
be building search filters while another adds CSV exports. Their files can merge
cleanly even if they disagree about filter names, empty values or which records
should be included.

`psy-session-coordination` helps those existing sessions find each other and
exchange a focused question through an available, verified messaging route.
The search session can explain its proposed filter contract; the export session
can identify the case it needs preserved. Each keeps ownership of its own work
and records the relevant agreement and commit in its existing task context.

| Shared dependency                    | A useful exchange                                                                               |
| ------------------------------------ | ----------------------------------------------------------------------------------------------- |
| API and consuming UI                 | Confirm response fields, error behavior and the revision being implemented.                     |
| Different features using one service | Identify who owns the shared change and which callers need to stay compatible.                  |
| Fixtures, tests or a pipeline        | Share the exact failing check and commit so another session can distinguish its own regression. |
| Integration order                    | Confirm which dependency is ready and which action must wait, within existing permissions.      |

This can catch incompatible assumptions before integration, avoid duplicate
investigation and spare you from carrying messages between terminals. Work that
doesn't depend on the answer continues. A queued question stays unresolved until
the peer answers; a test result stays tied to the revision actually checked.

The skill coordinates peers already doing authorized work. It does not create an
agent team, assign new tasks, take over another worktree or grant merge/release
authority. Discovery and messaging depend on the host's available integrations;
when there is no usable route, it prepares a message for you and reports that it
hasn't been delivered.

## Example prompts

Copy a prompt and replace the task details with your own.

<details>
<summary><strong>Build a change</strong></summary>

```text
Use psy-build to add pagination to the search results. Follow this repository's
existing patterns, verify the changed behavior and report the local result.
```

</details>

<details>
<summary><strong>Finish a branch</strong></summary>

```text
Use psy-finish to verify and commit the owned changes on this branch.
Keep the branch available for review; do not merge or push.
```

</details>

<details>
<summary><strong>Choose the next step</strong></summary>

```text
Use psy-next-step: should we continue here, review, finish, hand off,
create a next prompt, or close this session?
```

</details>

<details>
<summary><strong>Save a handoff</strong></summary>

```text
Use psy-handoff to save the context needed to resume this investigation.
Keep the current scope, ownership, findings and unresolved questions explicit.
```

</details>

<details>
<summary><strong>Write a continuation prompt</strong></summary>

```text
Use psy-next-prompt to write a concise continuation from this session.
Preserve the remaining task, verified state and ownership restrictions.
```

</details>

<details>
<summary><strong>Verify a fix</strong></summary>

```text
Use psy-prove to verify this fix with the smallest meaningful checks.
Explain what the evidence establishes and what remains unverified.
```

</details>

<details>
<summary><strong>Ask an existing session for its findings</strong></summary>

```text
Use psy-session-coordination to ask the existing review session which findings
remain open. Verify the peer and reply route; keep each session's ownership intact.
```

</details>

<details>
<summary><strong>Coordinate overlapping features in separate worktrees</strong></summary>

```text
Use psy-session-coordination to contact the session building search filters.
Our CSV export work depends on the same filter contract. Confirm the fields,
empty-value behavior and relevant commit; agree who owns any shared service
changes. Continue independent export work while waiting, and keep each session's
existing scope and worktree ownership intact.
```

</details>

## Optional coordination tools

The coordination skill includes local session discovery and optional path claims.
The helpers require **Node.js 18+ and Git**. They don't read chat transcripts or
send messages themselves; messaging uses a separately available transport.

| Guide                                                                                | Covers                                                                       |
| ------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| [Setup](skills/psy-session-coordination/references/setup.md)                         | Optional lifecycle hooks, manual registration and prerequisites.             |
| [Session discovery](skills/psy-session-coordination/references/discovery.md)         | Finding sessions and interpreting ownership, presence and advertised routes. |
| [Delivery routes](skills/psy-session-coordination/references/transports.md)          | Choosing and verifying an available messaging transport.                     |
| [Ownership records](skills/psy-session-coordination/references/ownership-records.md) | Reading supported repository records without changing their rules.           |
| [Portable claims](skills/psy-session-coordination/references/portable-claims.md)     | Opt-in path ownership for repositories without existing ownership tooling.   |

Keep existing repository ownership tooling where present. The portable writer
refuses setup and writes when it detects supported existing systems. Listing is
read-only; hooks report presence without claiming paths. Installing hooks or
initializing claims is a deliberate setup action.

Optional hooks retain local session metadata, and their installer saves full
backups of existing agent settings. Backups can include credentials already in
those settings. Read [local data and retention](skills/psy-session-coordination/references/setup.md#local-data-and-retention)
before enabling hooks; removing hook commands does not erase those files.

## Inside the repository

```text
skills/
|-- psy-build/
|-- psy-finish/
|-- psy-handoff/
|-- psy-next-step/
|-- psy-next-prompt/
|-- psy-prove/
`-- psy-session-coordination/
    |-- SKILL.md
    |-- agents/       Agent UI metadata
    |-- references/   Setup, discovery, ownership and delivery guides
    `-- scripts/      Local helpers and their tests
```

Every skill has a `SKILL.md` entry point and agent UI metadata. The six skills
outside coordination also include behavioral scenarios in `evals/evals.json`.
The repository's publication checks live separately under `.github/`.

## Verification

Run the coordination helper tests from the repository root:

```sh
node --test skills/psy-session-coordination/scripts/*.test.mjs
```

Tests use disposable repositories, settings files and session registries.
Behavioral scenario files support manual or agent assessment; they aren't an
automated evaluation runner or proof of model behavior. Publication safety checks
inspect repository hygiene and don't certify agent decisions.

For changes to your own copy, follow the [snapshot editing guidance](AGENTS.md).

## Maintenance and license

This is an **as-is, MIT-licensed snapshot**. No ongoing maintenance, release
cadence, compatibility updates or support are promised. You're welcome to fork
and adapt it under the [license terms](LICENSE).

The collection contains original workflow instructions and local coordination
helpers. External tools and third-party skill packs mentioned in the guides
aren't bundled. The vendored safety scanner supports repository publication checks
and is separate from the installable skills.

The publication copy is independent of existing private skill installations and
project workflows. There is no automatic synchronization into those environments.

[Back to top](#psy-agent-workflow-skills)
