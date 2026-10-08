# Maintaining these skills

The directories under `skills/` are the maintained source. Installed copies
should link here or be refreshed from here; do not maintain competing copies.

Keep instructions portable. Do not introduce personal names, usernames, email
addresses, home-directory paths, client or private project names, live session
IDs, private hosts, credentials, transcripts, or operational evidence. Use
synthetic examples and reserved example domains. Public tool names may be used
where they explain an actual integration.

Read the relevant skill and its supporting references before editing. Preserve
scope, session ownership, and authorization boundaries. Do not introduce planning,
persistent execution, delegation, installation, or publication as an incidental
step in an ordinary workflow.

Validate changed frontmatter and JSON, check relative links, and run the discovery
helper tests when changing its code or documented contracts:

```sh
node --test skills/session-coordination/scripts/*.test.mjs
```

The `evals/evals.json` files describe behavioral cases. Parsing them does not
prove agent behavior; report separately which cases were actually exercised.

Preserve existing discovery output and hook behavior when adding integrations.
Test ownership changes in disposable repositories and agent settings in temporary
homes. Do not initialize claims, install hooks, or change real ownership records
as part of development verification. Existing repository claims and enforcement
remain authoritative; portable claims must stay opt-in and separately stored.

Review the exact diff before committing. Use a public-safe Git identity and keep
real runtime records outside this repository. Do not import a private Git history.

Publishing requires a separately authorized release: create a private remote
first, review provenance and licensing, scan the complete intended public history
and metadata, install publication enforcement and required remote checks, and
obtain approval for the exact candidate before changing visibility. Local tests
and secret scans alone are not publication approval.

`CLAUDE.md` and `GEMINI.md` are relative symlinks to this file.
