import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const script = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  "agent-sessions.mjs",
);
const env = { ...process.env };
for (const key of [
  "CODEX_THREAD_ID",
  "CODEX_SESSION_ID",
  "CLAUDE_SESSION_ID",
  "CLAUDECODE",
  "CLAUDE_CODE_MESSAGING_SOCKET",
  "CLAUDE_CODE_MESSAGING_TOKEN",
  "CMUX_WORKSPACE_ID",
  "CMUX_SURFACE_ID",
  "CLAUDE_ENV_FILE",
])
  delete env[key];

function fixture(t) {
  const dir = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "agent-directory-test-")),
  );
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function run(dir, args, input = "", extraEnv = {}) {
  return spawnSync(
    process.execPath,
    [script, ...args, "--state-dir", path.join(dir, "registry")],
    {
      cwd: dir,
      env: { ...env, ...extraEnv },
      input,
      encoding: "utf8",
    },
  );
}

function json(dir, args) {
  const result = run(dir, [...args, "--json"]);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function git(dir, ...args) {
  return execFileSync("git", ["-C", dir, ...args], {
    encoding: "utf8",
    env,
  }).trim();
}

function repository(t) {
  const dir = fixture(t);
  git(dir, "init", "-q", "-b", "master");
  git(dir, "config", "user.name", "Directory Test");
  git(dir, "config", "user.email", "directory@example.test");
  fs.writeFileSync(
    path.join(dir, ".gitignore"),
    "registry/\n.session-state/\n.worktrees/\n",
  );
  git(dir, "add", ".gitignore");
  git(dir, "commit", "-qm", "fixture");
  return dir;
}

function hook(
  dir,
  tool,
  id,
  event = "SessionStart",
  extra = {},
  extraEnv = {},
) {
  const result = run(
    dir,
    ["hook", "--tool", tool],
    JSON.stringify({
      session_id: id,
      cwd: dir,
      hook_event_name: event,
      ...extra,
    }),
    extraEnv,
  );
  assert.equal(result.status, 0, result.stderr);
  assert.equal(
    result.stdout,
    "",
    "discovery hooks must not inject chatter or permission decisions",
  );
}

test("empty discovery does not create a registry or claim directories", (t) => {
  const dir = repository(t);
  const result = json(dir, ["list", "--repo", dir]);
  assert.equal(
    result.rows.length,
    1,
    "the main checkout is discoverable even without a session",
  );
  assert.equal(result.rows[0].kind, "worktree");
  assert.equal(result.rows[0].session_id, null);
  assert.equal(fs.existsSync(path.join(dir, "registry")), false);
  assert.equal(fs.existsSync(path.join(dir, ".session-state")), false);
});

test("native hook metadata is namespaced and excludes prompt, transcript and tokens", (t) => {
  const dir = repository(t);
  const envFile = path.join(dir, "claude.env");
  hook(
    dir,
    "claude",
    "same-id",
    "SessionStart",
    {
      prompt: "PRIVATE-PROMPT",
      transcript_path: "PRIVATE-TRANSCRIPT",
      tool_input: { command: "PRIVATE-COMMAND" },
    },
    {
      CLAUDE_ENV_FILE: envFile,
      CLAUDE_CODE_MESSAGING_TOKEN: "PRIVATE-TOKEN",
      CODEX_THREAD_ID: "foreign-parent",
    },
  );
  hook(dir, "codex", "same-id");
  const rows = json(dir, ["list", "--repo", dir, "--session", "same-id"]).rows;
  assert.deepEqual(rows.map((r) => r.tool).sort(), ["claude", "codex"]);
  const contents = fs
    .readdirSync(path.join(dir, "registry"))
    .map((f) => fs.readFileSync(path.join(dir, "registry", f), "utf8"))
    .join("");
  assert.doesNotMatch(contents, /PRIVATE-|foreign-parent/);
  assert.match(
    fs.readFileSync(envFile, "utf8"),
    /export CLAUDE_SESSION_ID='same-id'/,
  );
  assert.match(
    fs.readFileSync(envFile, "utf8"),
    /export CLAUDE_INHERITED_CODEX_THREAD_ID='foreign-parent'/,
  );
  for (const f of fs.readdirSync(path.join(dir, "registry")))
    assert.equal(
      fs.statSync(path.join(dir, "registry", f)).mode & 0o777,
      0o600,
    );
});

test("discovery joins exact owners across a linked worktree and keeps retired history optional", (t) => {
  const dir = repository(t);
  const worktree = path.join(dir, ".worktrees", "feature");
  git(dir, "worktree", "add", "-qb", "feat/search", worktree);
  const claims = path.join(dir, ".session-state/worktrees");
  fs.mkdirSync(claims, { recursive: true });
  const active = `worktree_id=wt-current\ninitial_branch=feat/search\ncanonical_path=${worktree}\nowner_session_id=claude-owner\nlifecycle_state=active\nnote=Invoice search\n`;
  const historical = `worktree_id=wt-retired\ninitial_branch=feat/old\ncanonical_path=${dir}/missing\nowner_session_id=old-owner\nlifecycle_state=retired\nnote=Old search\n`;
  fs.writeFileSync(path.join(claims, "active.env"), active);
  fs.writeFileSync(path.join(claims, "retired.env"), historical);
  hook(dir, "claude", "claude-owner", "SessionStart", { cwd: worktree });
  const result = json(dir, ["list", "--repo", worktree, "--query", "invoice"]);
  assert.equal(result.repository, dir);
  assert.equal(result.rows.length, 1);
  assert.equal(result.rows[0].session_id, "claude-owner");
  assert.equal(result.rows[0].tool, "claude");
  assert.equal(result.rows[0].worktree_id, "wt-current");
  assert.equal(result.rows[0].presence, "recent");
  assert.equal(result.rows[0].head, git(worktree, "rev-parse", "HEAD"));
  assert.equal(
    json(dir, ["list", "--repo", dir, "--branch", "feat/old"]).rows.length,
    0,
  );
  assert.equal(
    json(dir, ["list", "--repo", dir, "--branch", "feat/old", "--all"]).rows
      .length,
    1,
  );
  assert.equal(
    fs.readFileSync(path.join(claims, "active.env"), "utf8"),
    active,
  );
  assert.equal(
    fs.readFileSync(path.join(claims, "retired.env"), "utf8"),
    historical,
  );
  const registration = run(dir, [
    "register",
    "--tool",
    "claude",
    "--session",
    "claude-owner",
    "--repo",
    worktree,
    "--task",
    "Settlement compatibility review",
  ]);
  assert.equal(registration.status, 0, registration.stderr);
  const taskResult = json(dir, [
    "list",
    "--repo",
    dir,
    "--query",
    "compatibility",
  ]).rows;
  assert.equal(
    taskResult.length,
    1,
    "an explicit session task remains searchable when the claim has its own note",
  );
  assert.equal(taskResult[0].task, "Settlement compatibility review");
  assert.equal(taskResult[0].claim_note, "Invoice search");
  assert.equal(
    json(dir, ["list", "--repo", dir, "--query", "invoice"]).rows.length,
    1,
  );
});

test("ending or aging a session never releases its worktree or invents reachability", (t) => {
  const dir = repository(t);
  const claims = path.join(dir, ".session-state/worktrees");
  fs.mkdirSync(claims, { recursive: true });
  const claim = `worktree_id=wt-owned\ninitial_branch=master\ncanonical_path=${dir}\nowner_session_id=codex-owner\nlifecycle_state=active\nnote=Work in progress\n`;
  fs.writeFileSync(path.join(claims, "owner.env"), claim);
  hook(dir, "codex", "codex-owner");
  hook(dir, "codex", "codex-owner", "Stop");
  let row = json(dir, ["list", "--repo", dir, "--session", "codex-owner"])
    .rows[0];
  assert.equal(row.presence, "idle");
  assert.equal(row.routes[0].verification, "unverified");
  const metadataFile = path.join(
    dir,
    "registry",
    fs.readdirSync(path.join(dir, "registry"))[0],
  );
  const metadata = JSON.parse(fs.readFileSync(metadataFile, "utf8"));
  metadata.last_seen = "2000-01-01T00:00:00.000Z";
  fs.writeFileSync(metadataFile, JSON.stringify(metadata));
  row = json(dir, ["list", "--repo", dir, "--session", "codex-owner"]).rows[0];
  assert.equal(row.presence, "stale");
  assert.equal(row.lifecycle, "active");
  hook(dir, "codex", "codex-owner", "SessionEnd");
  row = json(dir, ["list", "--repo", dir, "--session", "codex-owner"]).rows[0];
  assert.equal(row.presence, "ended");
  assert.equal(row.lifecycle, "active");
  assert.equal(fs.readFileSync(path.join(claims, "owner.env"), "utf8"), claim);
});

test("a colliding native ID never attributes a claim to either tool", (t) => {
  const dir = repository(t);
  const claims = path.join(dir, ".session-state/worktrees");
  fs.mkdirSync(claims, { recursive: true });
  fs.writeFileSync(
    path.join(claims, "owner.env"),
    `canonical_path=${dir}\nowner_session_id=same-id\nlifecycle_state=active\n`,
  );
  hook(dir, "claude", "same-id");
  hook(dir, "codex", "same-id");
  const claim = json(dir, ["list", "--repo", dir]).rows.find(
    (row) => row.kind === "worktree",
  );
  assert.equal(claim.tool, null);
  assert.equal(claim.ambiguous_identity, true);
  assert.deepEqual(claim.routes, []);
});

test("master discovery preserves empty TSV columns, TTL and anonymous claims without pruning", (t) => {
  const dir = repository(t);
  fs.mkdirSync(path.join(dir, ".session-state"));
  const file = path.join(dir, ".session-state/master-claims.tsv");
  const now = Math.floor(Date.now() / 1000);
  const claims = `${now}\tuser\thost\tapp/Models\t\t${dir}\tmaster-owner\n1\tuser\thost\tapp/Old\tOld\t${dir}\told-owner\n`;
  fs.writeFileSync(file, claims);
  hook(dir, "claude", "master-owner");
  const rows = json(dir, [
    "list",
    "--repo",
    dir,
    "--session",
    "master-owner",
  ]).rows;
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, "master");
  assert.equal(rows[0].path_prefix, "app/Models");
  assert.equal(rows[0].tool, "claude");
  assert.equal(
    json(dir, ["list", "--repo", dir, "--session", "old-owner"]).rows.length,
    0,
  );
  assert.equal(
    json(dir, ["list", "--repo", dir, "--session", "old-owner", "--all"]).rows
      .length,
    1,
  );
  assert.equal(fs.readFileSync(file, "utf8"), claims);
});

test("hook installation preserves existing settings and is idempotent", (t) => {
  const dir = fixture(t);
  const home = path.join(dir, "home");
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  const original = {
    permissions: { deny: ["Write(secret)"] },
    hooks: {
      PreToolUse: [
        {
          matcher: "Bash",
          hooks: [{ type: "command", command: "existing-hook" }],
        },
      ],
    },
  };
  fs.writeFileSync(
    path.join(home, ".claude/settings.json"),
    JSON.stringify(original),
  );
  let result = run(dir, ["install-hooks", "--home", home]);
  assert.equal(result.status, 0, result.stderr);
  const first = fs.readFileSync(
    path.join(home, ".claude/settings.json"),
    "utf8",
  );
  const settings = JSON.parse(first);
  assert.deepEqual(settings.permissions, original.permissions);
  assert.deepEqual(settings.hooks.PreToolUse[0], original.hooks.PreToolUse[0]);
  assert.equal(settings.hooks.SessionStart.length, 1);
  result = run(dir, ["install-hooks", "--home", home]);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(
    fs.readFileSync(path.join(home, ".claude/settings.json"), "utf8"),
    first,
  );
  assert.equal(
    JSON.parse(fs.readFileSync(path.join(home, ".codex/hooks.json"))).hooks
      .SessionEnd.length,
    1,
  );
});
