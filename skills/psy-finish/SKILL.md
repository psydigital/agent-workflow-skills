---
name: psy-finish
description: Finish authorized development work using the current repository's verification, commit and integration procedures. Use when the user requests closeout, finishing a branch, or merging a worktree; report readiness when further integration is not authorized.
---

# Psy Finish

Bring the owned work to the requested stopping point. Finishing may mean a local
commit, an authorized merge, a pull request, or a readiness report. Resolve that
meaning from the user's request and current project rules instead of assuming a
release or presenting an unnecessary menu.

## Establish the target and authority

Identify the exact checkout, branch, intended base, owned changes and requested
operation. Follow applicable agent instructions and ownership checks. A handoff,
branch name or expired presence record does not grant another session's rights.
Preserve unrelated changes and concurrent work.

Read the project's finish command or skill and the scripts it uses. When one
exists, that is the implementation of closeout; use it within current authority
and do not run this skill recursively if the local entry point points back here.
Respect guarded merge, worktree, database and server cleanup procedures. Never
bypass a failed local lifecycle helper with raw Git or filesystem operations.

If a single wrapper combines authorized and unauthorized actions, use a documented
scoped mode when available. Otherwise stop before that wrapper and identify the
missing permission. Permission to finish locally does not include a push, release,
deployment or deletion that the user did not request.

## Establish readiness once

Review the owned diff and completion evidence for the exact target. Reuse checks
and reviews when their source, scope and environment still match. Run only the
affected checks when later changes invalidate evidence. Use `psy-prove` if
available; its absence does not prevent directly performing the relevant checks.

Resolve actual blockers and required review findings before claiming readiness.
Do not add an aggregate review merely because several independently reviewed
commits are being integrated. If verification fails or cannot run, report that
limit and keep the work available; do not clean it away.

Stage only verified owned paths and commit when authorized or required. Existing
unrelated dirty work is not permission to stash, discard or include it. A direct
commit with no further requested integration may already be complete.

## Use the project's integration path

For an authorized merge or pull request, prefer the local workflow. Confirm the
base and target refs immediately before the operation. Follow the repository's
conflict handling; never use reset, force push or deletion to manufacture a clean
result. If approval covers only readiness, report the exact candidate and stop
there without requesting already-granted permissions again.

When no custom finish workflow exists, ordinary Git operations may implement the
specific authorized action. Check destination checkout ownership and cleanliness,
use the established merge strategy, and preserve the source branch until success
is verified. No custom workflow is not permission to guess a base branch, push
remote, delete a worktree or broaden the requested operation. Ask only for a
material missing decision.

Verify the resulting integration or tracking state of the named branch. Run
post-integration checks when required or when the integration changed behavior;
do not repeat every test solely to narrate the finish.

## Close resources and report

Remove a worktree, branch or isolated database only when cleanup is authorized
and the documented prerequisites hold. Use the owning lifecycle helper where
present. Never kill a shared server or every process matching a generic name.
Stop only the session's own processes unless explicitly authorized otherwise;
retain review servers when the user is expected to use them and report their URLs.

Report the commit and exact branch/worktree state, verification, integration and
remote actions actually completed. Distinguish pending approval, unresolved
conflicts and retained resources from success. If all requested work is finished,
close without manufacturing a build, handoff or continuation prompt.
