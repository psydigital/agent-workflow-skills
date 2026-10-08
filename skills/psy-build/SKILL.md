---
name: psy-build
description: Carry out an explicitly requested development workflow from scoped implementation through local verification and handback, using the current repository's conventions. Use when the user asks for psy-build or an end-to-end development workflow; an asset compilation request alone does not select it.
---

# Psy Build

Deliver the requested change using the current project's tools. This skill is a
portable entry point, not a framework installer or a replacement for repository
policy. Creating or editing this skill does not invoke its workflow.

## Resolve the local workflow

Establish the requested outcome, working directory, existing changes and current
session's ownership. Read applicable agent instructions and the relevant local
command or skill definitions. Follow their references to setup and verification
scripts. Inspect package manifests or task files only where the needed command
is not documented; read a candidate script before running it.

If the repository supplies an implementation workflow, use it within the user's
authorized scope. Do not recurse into another reference to this skill. If that
workflow requires an unrequested expansion such as delegation or a persistent
goal, continue only the compatible authorized work and resolve the actual missing
decision before the dependent step. A local rule must not silently enlarge the
user's request.

Distinguish the development workflow from compiling assets, building an image,
or packaging a release. A script named `build` alone proves none of the other
steps. Do not assume a `/build` command, framework, package manager, database or
particular directory layout exists. If there is no local workflow, use the
scoped implementation sequence below directly.

## Prepare only the environment needed

Use an existing authorized checkout when suitable. If project policy requires
isolation, use its documented worktree or environment setup helper. Preserve
claims, session identity, dependencies and data isolation. Do not replace a
guarded setup script with raw Git commands when the helper fails. Follow the
project's recovery path or report the concrete blocker.

Where there is no custom lifecycle, ordinary Git worktrees are available when
isolation is justified and authorized. They are not mandatory for every change.
Before creation, confirm the source ref, destination and branch without switching
or disturbing another checkout. Do not install a claims system as a prerequisite.

A worktree does not imply a running server. Start a development environment only
when the authorized task needs it. Prefer the project's documented server helper;
otherwise identify its existing dev task and prerequisites. Verify the checkout,
ports and data target, preserve peers' processes, and report the actual URL only
after confirming readiness. Never infer safe migrations or seed operations from
permission to start a server. Leave a server running only for an expected review;
otherwise stop only the processes this session started.

## Implement and verify

Make the smallest coherent change that fulfils the request. Use existing design
and code conventions. An implementation workflow does not require a persistent
plan document, subagents or a fixed review ceremony. Use them only when requested
and permitted. Ask about consequential unresolved choices; decide routine
implementation details from the available context.

Select meaningful checks from the changed behavior and repository requirements.
When installed, use `psy-prove` for scoped evidence. Otherwise run the relevant
tests or checks directly and record their results and limitations. Apply the
project's required review without repeating a still-valid review solely because
the work is ending. A failing required check prevents a success claim.

## Hand back or finish

Commit verified owned changes when authorized or required by project policy,
staging exact paths and preserving unrelated work. If `psy-finish` is installed,
use it for requested closeout; otherwise follow the documented local finish path
within the same authority. Build permission alone does not authorize merging,
pushing, publication, deployment, destructive cleanup or live provider writes.

Report what changed, evidence actually obtained, commit/worktree state and any
remaining authorized step or blocker. Keep local completion distinct from release
or deployment. Stop when the requested outcome is complete.
