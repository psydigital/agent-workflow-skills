---
name: next-prompt
description: Write or tighten a copyable continuation prompt from the current conversation or a named handoff when the user asks what to tell the next agent or invokes /next-prompt. Use next-step for choosing whether continuation is needed.
---

# Next Prompt

Write the shortest useful instruction that lets the correct authorized session
continue the user's task. Compose the prompt; do not execute its contents unless
the user separately requested execution.

## Use the right context

For a bare `/next-prompt`, use the visible conversation. Read a named handoff or
source artifact when supplied. If a handoff is requested without a path, search
only the current project and likely temporary handoff locations; do not crawl the
home directory or reconstruct the whole old transcript. Check that a discovered
handoff belongs to this task before using it; modification time is only a clue.

Preserve the latest explicit user instruction, current ownership and restrictions,
and verified live state over older copied context. Extract the concrete remaining
outcome, current checkpoint, relevant sources, permitted actions, first useful
step, and completion evidence. Omit chronology that no longer changes the task.
If everything requested is complete and no next task is named, say so instead of
inventing work. Ask only when a missing fact materially prevents a useful prompt;
use a clearly marked placeholder for incidental unknowns, never for authority.

## Verify only decisive repository facts

Use applicable project instructions and fresh evidence already established in
this session, including a preceding `next-step` decision. Do not repeat a full
repository inspection merely to restate that decision. Recheck volatile facts
when changed or stale, and run any read-only checks the project requires before
assigning a lifecycle action. Scope those checks to the requested target.

A prompt may direct the next session to verify uncertain state first; it must not
present unverified review, test, divergence, or pipeline status as current fact.
A prose-only prompt edit or non-repository task needs no Git checks.

## Keep authority attached to the right session

A fresh session does not inherit ownership by naming an owner or reading a
handoff. Mutation, recovery, and closeout bound to an existing claim must target
that owner session, or an executor already holding the exact repository-supported
capability. Use the documented authorization path or keep the task read-only when
appropriate; ask if an unresolved authority decision prevents the requested work.
Preserve existing permission to act without inventing another approval step.

Newer live capability evidence overrides stale handoff continuation modes. When a
handoff declares a continuation mode, honour `fresh-session-required` only for
transferable work;
`resume-acceptable` permits continuation without forcing a reset. Owner-bound
work must resume the same owner session, using `/compact` or same-ID resume where
supported. Do not reconstruct the full transcript or fork it into fresh agents
as a workaround. Delegation remains opt-in.

Keep unrelated worktrees and changes outside the prompt. Source/test proof,
integration, push, deployment, browser acceptance, and provider results are
separate claims and authority boundaries.

## Keep the invocation deliberate

Default to a plain prompt. Do not add `/build` or `/goal` unless the user explicitly asks
for that workflow, or asks whether it fits and it does. Multi-file work, an
existing plan, a worktree requirement, or unfinished work alone does not qualify.
If a requested slash command is suitable, put the literal invocation first.
For a requested persistent `/goal`, include a bounded objective and stop condition;
never create the goal while composing its prompt. When the user asks about a
command that adds no value, explain briefly and give the useful plain prompt.
Use other commands when requested or required by the project's authorized path.

## Write the prompt

Usually a few short paragraphs suffice. There is no minimum word count. Include
only what the executor needs: outcome, checkpoint/sources, scope and authority,
first action, and verification/output. Reference project instructions and durable
artifacts instead of copying them. Derive commands from verified project tooling;
otherwise tell the executor where to discover them.

Check once for a material missing constraint that could send the executor in the
wrong direction. Put it inside the prompt only if it changes the first action,
authority, or verification. Do not turn this into another investigation.

Return one copyable prompt, without mandatory Source/Invocation metadata or empty
sections. Add a brief note outside it only when the user must resume a particular
session, resolve a consequential assumption, or preserve uncaptured durable state.
Recommend a handoff only when that state materially exceeds what the prompt or
existing artifacts can carry. Still provide the requested prompt; create a
handoff document only when asked. Long or slow sessions do not automatically need
another handoff.

When tightening an existing prompt, preserve intent and meaningful restrictions;
remove repetition and generic process language. Prefer references to sensitive
content and omit credentials, tokens, and unnecessary personal/customer data.
