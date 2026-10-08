---
name: prove
description: Verify changed behaviour with scoped evidence, or substantiate audit and review findings with exact source citations. Use when verification or proof is requested or needed to support a completion claim.
---

# Prove

Match each claim to evidence that actually supports it. Follow the user's scope
and the project's completion rules; this skill supplies no universal test suite
or framework-specific commands.

## Choose useful evidence

Read applicable project instructions and the exact change or audit target. Use
current source, package/composer scripts, tool configuration, and existing tests
to identify available verification. Do not assume a Laravel command, npm script,
test database, or directory layout exists in another project.

Check the changed contract and its consumers when shared behaviour is affected.
Start with the smallest meaningful check. Widen only for changed risk, a failure,
or a repository requirement. Cosmetic edits and documentation/configuration
changes need their relevant checks; they do not automatically require new tests,
a browser, a database, or every available linter.

For behaviour changes, follow the project's focused regression-test requirements,
including relevant failure, permission, retry, or data-integrity cases. A passing
typecheck does not prove an interaction. A syntax check does not prove a skill's
decisions, a hook's side effects, or a deployed service's behaviour.

Use required isolation and cleanup for tests that touch databases or other shared
resources. A verification request does not grant new live/provider, publication,
or destructive authority. Complete authorized independent checks if another
check is blocked, and distinguish that blocker from a product failure.

## Verify changes

Run the selected checks and inspect their result, including exit status and
relevant output. For a bug fix, demonstrate the failing condition and its corrected
behaviour where practical; distinguish a reproduced failure from one inferred
from source. For a refactor, verify preserved behaviour through relevant tests.

Reuse prior passing evidence when the command, result, source checkpoint, scope,
and relevant environment are known and still match. Rerun affected checks after
changes that invalidate them; do not repeat every check at every closeout. A clean
working tree alone is not validation. Review committed changes against their
actual base when necessary; a dirty-only formatter check cannot cover them.

Format exact owned files at the appropriate checkpoint when project policy calls
for it, then inspect the diff. Never rewrite unrelated changes to make checks pass.
Once sufficient checks pass, finish the requested task without inventing another
review, audit, UAT run, or continuation.

## Substantiate source findings

Read the relevant code before reporting a finding. Search results and memory
identify candidates; they are not proof. For each reported issue establish the
trigger, faulty behaviour, expected contract, and concrete impact. Check nearby
and upstream guards that could disprove it. Cite exact file and line locations,
and the authoritative rule when the finding depends on one.

For an omission, name the searched/read scope and cite the boundary where the
missing protection matters. Authorization claims require tracing the applicable
route/request/policy/action; concurrency claims require the actual read/write
window and relevant locking or constraints. Read current baseline entries before
calling an issue known, resolved, or accepted. Mark inconclusive claims as such.

Keep source findings, runtime reproduction, schema evidence, and observed live
state distinct. A migration shows intended schema, not the deployed schema.
Do not run code-change stages for an unchanged read-only audit.

## Report proportionally

Lead with the outcome. Give the meaningful command and result, what it proves,
and any material unverified behaviour. Summarize routine output; keep detailed
logs in tool results or an existing appropriate artifact, with secrets redacted.
Do not create a report or paste full logs unless the task needs them.

For reviews, lead with actionable findings and source links. For changes, explain
the resulting behaviour and verification. Use counts only from actual results.
Say a check failed or was not run when that is what happened; never substitute
"should pass" for evidence. Passing local tests do not establish merge state,
deployment, browser acceptance, or provider proof.
