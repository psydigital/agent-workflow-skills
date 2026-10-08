---
name: next-step
description: Choose one next action or confirm closure when the user asks what next, review or finish, continue or hand off, or invokes /next-step. Recommends the action; executes it only when also requested.
---

# Next Step

Choose the next useful action from the current task and evidence. Completion is a
valid outcome; do not manufacture another review, prompt, handoff, or workstream.

## Establish only the state that matters

Use the latest request, work already done, remaining obligations, and applicable
project instructions. Reuse facts already verified in this session while their
source, scope, and environment still match. When chained with `next-prompt`, pass
that evidence forward instead of repeating the same inspection.

For repository decisions, inspect only the target and facts that could change the
answer: owned changes, relevant verification/review, and integration state if
integration remains. Recheck volatile ownership, refs, or dirty state when stale,
changed, or about to support a lifecycle action. Follow the repository's required
read-only ownership/closeout checks; do not invent a claims protocol or sweep
unrelated worktrees. Non-repository questions need no Git inspection.

Unrelated dirty work does not prevent continuing or closing this session. Never
stage, clean, or claim it. Ask only if unresolved ownership or another material
missing decision blocks the actual next action.

## Preserve the authorized executor

Session-bound authority wins over stale handoffs and copied context. A new prompt
or a session named as owner does not transfer ownership. Owner-bound mutation,
recovery, and closeout stay in the same owner session unless the repository's
exact supported capability authorizes another executor. A read-only review does
not grant mutation, merge, cleanup, push, or deployment authority.

If the owner session is struggling, recommend context relief in that session
(`/compact` or same-ID resume where supported). Duration or compaction alone does
not require migration. A fresh read-only session may return evidence to the owner
when permitted; it cannot take over the work.

## Choose one recommendation

- **Continue here:** authorized work, verification, or a scoped commit remains.
  Prioritize a blocking fix before optional process steps.
- **Review:** risk or repository policy requires an outstanding review. Name the
  concrete concern, such as authorization, money, data loss, or broad shared
  behaviour. A small verified cosmetic edit does not automatically need review.
  Reuse completed scoped reviews unless relevant changes invalidate them; remote
  synchronization alone does not create another review requirement.
- **Finish:** the scoped branch is ready and required integration/closeout remains
  executable by the authorized session. Point to the known project workflow.
  A direct main/master commit with no integration left does not need `/finish`.
- **Handoff:** unfinished work needs durable context that would otherwise be lost
  at a requested or useful transition. Existing source artifacts may suffice.
  Keep any owner-bound continuation directed to that owner.
- **Next prompt:** a concrete remaining task needs a concise instruction for an
  authorized later session, and needed state is already captured. Completed
  research alone does not imply a follow-up task.
- **Close:** this session has no unfinished owned work, required review/closeout,
  or necessary uncaptured continuation state. Another authorized session's work
  does not keep this one open.
- **Ask user:** one consequential decision or unavailable fact prevents choosing
  a safe action. Ask that question directly, without a menu of workflows.

Choose closure as soon as its conditions hold. Otherwise resolve actual blockers,
then the necessary verification/review/integration, before optional context work.
Do not introduce `/build`, `/goal`, planning, or delegation without an explicit
request. Recommending an action does not execute it; when the user also authorizes
that action, carry it out without asking them to repeat the instruction.

## Output

Usually three short lines are enough:

```text
Recommendation: [one label]
Why: [the decisive fact]
Action: [one concrete next action, or end this session]
```

Add a short warning only for a material uncertainty that changes the decision.
Do not write a full continuation prompt or handoff unless also requested.
