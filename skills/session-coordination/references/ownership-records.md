# Optional ownership records

The discovery helper can read these existing repository-owned formats. They are
optional compatibility inputs, not a locking protocol to install automatically.
If a repository uses another format, inspect its own ownership tooling separately.
Session presence, checkout location, and Git branches never establish ownership.

For a repository without its own ownership tooling, use the separately stored,
opt-in [portable claim format](portable-claims.md). Its writer never updates the
compatibility files below. Their expiry, release and enforcement rules remain
owned by the repository that produces them.

## Worktree records

The helper looks under `.session-state/worktrees/` in the main checkout for
UTF-8 `.env` files containing plain `key=value` lines. It parses text without
executing or sourcing it. Values must not use shell quoting or expansion.

Recognized fields:

| Field                               | Meaning                                 |
| ----------------------------------- | --------------------------------------- |
| `canonical_path` or `worktree_path` | Absolute path of the owned worktree.    |
| `owner_session_id` or `thread_id`   | Native owning session ID.               |
| `worktree_id`                       | Repository-defined worktree identifier. |
| `initial_branch` or `branch`        | Branch label for historical records.    |
| `lifecycle_state` or `status`       | Repository-defined lifecycle label.     |
| `note`                              | Short task description.                 |

Only an exact, unique worktree-path match supplies an owner. Records marked
`retired` or `merged` are excluded from active ownership matching. Unmatched
records are shown only with `--all`. If the same owner ID is registered under
multiple tools, its tool and messaging route remain ambiguous.

## Checkout path claims

The optional file `.session-state/master-claims.tsv` uses this legacy filename
regardless of the main branch name. Each row has seven tab-separated fields:

1. Creation time in Unix seconds.
2. Legacy user field, ignored by discovery.
3. Legacy host field, ignored by discovery.
4. Claimed repository-relative path prefix.
5. Optional task note.
6. Checkout path.
7. Native owning session ID.

Empty columns retain their positions. `MASTER_CLAIMS_TTL_SECONDS` controls display
expiry, defaulting to 28,800 seconds. Expired entries appear only with `--all`.
The helper never prunes or edits claims. JSON uses `kind: "master"` for these
records as a compatibility label, not as a branch-name requirement.

Keep real ownership files, session records and test output outside published
source. Use disposable synthetic fixtures when testing an integration.
