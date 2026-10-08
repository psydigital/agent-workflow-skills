# Agent workflow skills

Four focused skills for deciding what comes next, continuing work, coordinating
existing sessions, and supporting claims with evidence.

| Skill                                                        | Use it to                                                                    |
| ------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| [next-step](skills/next-step/SKILL.md)                       | Choose one useful next action, including closing a completed session.        |
| [next-prompt](skills/next-prompt/SKILL.md)                   | Write a concise continuation prompt that preserves scope and authority.      |
| [session-coordination](skills/session-coordination/SKILL.md) | Exchange scoped questions and findings between existing agent sessions.      |
| [prove](skills/prove/SKILL.md)                               | Verify changed behavior or substantiate a finding with appropriate evidence. |

## Installation

From a local checkout, use the [Skills CLI](https://github.com/vercel-labs/skills):

```sh
npx skills add . --skill next-step --skill next-prompt --skill session-coordination --skill prove
```

Alternatively, link individual folders under `skills/` into your agent's skill
directory. Keep these folders as the source for ongoing maintenance. Each skill
is independently usable; the collection does not require a particular application
framework, repository layout, or agent orchestration workflow.

Example requests:

- “Use next-step: should we continue, review, finish, hand off, or close?”
- “Use next-prompt to write a short continuation from this session.”
- “Use session-coordination to ask the existing review session about its findings.”
- “Use prove to verify this fix within the authorized scope.”

Invocation syntax and discovery support depend on the host agent.

## Optional session discovery

The coordination skill includes a local metadata helper requiring Node.js 18+
and Git. It reads registered sessions and Git worktrees without reading chat
transcripts. Supported ownership records are optional; their absence means
ownership is unknown. See its [discovery reference](skills/session-coordination/references/discovery.md).

Listing is read-only. Registration writes private local metadata. Installing hooks
changes agent settings and is a separate setup action, never an automatic part of
asking another session a question. Messaging requires an available, verified
transport; the helper itself does not send messages.

## Verification and maintenance

```sh
node --test skills/session-coordination/scripts/agent-sessions.test.mjs
```

The other skills include behavioral evaluation cases in `evals/evals.json`.
These are scenarios for evaluation, not a claim that an automated agent evaluation
has run. Keep examples synthetic and follow [the maintenance instructions](AGENTS.md).

## Publication status

This collection is prepared locally. A publication license and remote release
have not been selected. Before publishing, complete provenance and license review,
full-history privacy checks, and approval of the exact release candidate. References
to external tools describe integrations and do not bundle those tools or their skills.
