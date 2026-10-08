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
      timeout: 5000,
      killSignal: "SIGKILL",
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
  const backups = path.join(dir, "registry/config-backups");
  const backupFiles = fs.readdirSync(backups);
  assert.equal(backupFiles.length, 1);
  assert.equal(fs.statSync(backups).mode & 0o777, 0o700);
  const backup = path.join(backups, backupFiles[0]);
  assert.deepEqual(JSON.parse(fs.readFileSync(backup, "utf8")), original);
  assert.equal(fs.statSync(backup).mode & 0o777, 0o600);
});

for (const target of [".codex/hooks.json", ".claude/settings.json"])
  for (const dangling of [false, true])
    test(`hook installation leaves both configs untouched for a ${dangling ? "dangling" : "valid"} ${target} symlink`, (t) => {
      const dir = fixture(t);
      const home = path.join(dir, "home");
      const original = '{"permissions":{"deny":["Write(secret)"]}}\n';
      for (const name of [".codex/hooks.json", ".claude/settings.json"]) {
        fs.mkdirSync(path.dirname(path.join(home, name)), { recursive: true });
        if (name !== target) fs.writeFileSync(path.join(home, name), original);
      }
      const shared = path.join(dir, "shared-settings.json");
      if (!dangling) fs.writeFileSync(shared, original);
      fs.symlinkSync(shared, path.join(home, target));

      const result = run(dir, ["install-hooks", "--home", home]);
      assert.equal(result.status, 1, result.stderr);
      assert.match(result.stderr, /symlink/i);
      assert.equal(fs.readlinkSync(path.join(home, target)), shared);
      if (dangling) assert.equal(fs.existsSync(shared), false);
      else assert.equal(fs.readFileSync(shared, "utf8"), original);
      const other = target.startsWith(".codex")
        ? ".claude/settings.json"
        : ".codex/hooks.json";
      assert.equal(fs.readFileSync(path.join(home, other), "utf8"), original);
      assert.equal(fs.existsSync(path.join(dir, "registry")), false);
    });

for (const kind of ["worktree", "master", "session"])
  for (const unsafe of ["symlink", "oversized"])
    test(`discovery skips ${unsafe} ${kind} metadata and reports incomplete evidence`, (t) => {
      const dir = repository(t);
      let file;
      let contents;
      if (kind === "worktree") {
        file = path.join(dir, ".session-state/worktrees/unsafe.env");
        contents = `canonical_path=${dir}\nowner_session_id=untrusted-owner\n`;
      } else if (kind === "master") {
        file = path.join(dir, ".session-state/master-claims.tsv");
        contents = `${Math.floor(Date.now() / 1000)}\tu\th\tsrc/shared\tnote\t${dir}\tuntrusted-owner\n`;
      } else {
        hook(dir, "codex", "untrusted-owner");
        file = path.join(
          dir,
          "registry",
          fs.readdirSync(path.join(dir, "registry"))[0],
        );
        contents = fs.readFileSync(file, "utf8");
        fs.unlinkSync(file);
      }
      fs.mkdirSync(path.dirname(file), { recursive: true });
      if (unsafe === "symlink") {
        const external = path.join(dir, "external-metadata");
        fs.writeFileSync(external, contents);
        fs.symlinkSync(external, file);
      } else fs.writeFileSync(file, contents + " ".repeat(2 * 1024 * 1024));

      const result = json(dir, ["list", "--repo", dir]);
      assert.equal(
        result.rows.some((row) => row.session_id === "untrusted-owner"),
        false,
      );
      assert.ok(
        result.warnings.length > 0,
        "unsafe input must not look like a complete inventory",
      );
      assert.ok(
        result.rows.some((row) => row.kind === "worktree" && row.registered),
      );
      if (unsafe === "symlink")
        assert.equal(fs.lstatSync(file).isSymbolicLink(), true);
      else
        assert.equal(
          fs.statSync(file).size,
          Buffer.byteLength(contents) + 2 * 1024 * 1024,
        );
    });

for (const alias of [".session-state", ".session-state/worktrees", "registry"])
  test(`discovery refuses metadata beneath a symlinked ${alias} directory`, (t) => {
    const dir = repository(t);
    let original;
    if (alias === "registry") {
      hook(dir, "codex", "untrusted-owner");
      original = path.join(dir, "registry");
    } else {
      const claims = path.join(dir, ".session-state/worktrees");
      fs.mkdirSync(claims, { recursive: true });
      fs.writeFileSync(
        path.join(claims, "owner.env"),
        `canonical_path=${dir}\nowner_session_id=untrusted-owner\n`,
      );
      original = path.join(dir, alias);
    }
    const external = path.join(dir, "external-directory");
    fs.renameSync(original, external);
    fs.symlinkSync(external, original, "dir");
    const result = json(dir, ["list", "--repo", dir]);
    assert.equal(
      result.rows.some((row) => row.session_id === "untrusted-owner"),
      false,
    );
    assert.ok(result.warnings.length > 0);
    assert.equal(fs.readlinkSync(original), external);
  });

test(
  "discovery rejects a FIFO claim without waiting for a writer",
  { skip: process.platform === "win32" },
  (t) => {
    const dir = repository(t);
    const claims = path.join(dir, ".session-state/worktrees");
    fs.mkdirSync(claims, { recursive: true });
    execFileSync("mkfifo", [path.join(claims, "blocked.env")]);
    const result = json(dir, ["list", "--repo", dir]);
    assert.ok(result.warnings.length > 0);
    assert.equal(result.rows[0].session_id, null);
  },
);

test("discovery refuses an excessive metadata directory rather than reporting a partial owner set", (t) => {
  const dir = repository(t);
  const claims = path.join(dir, ".session-state/worktrees");
  fs.mkdirSync(claims, { recursive: true });
  for (let i = 0; i < 513; i++)
    fs.writeFileSync(path.join(claims, `${i}.env`), "");
  const result = json(dir, ["list", "--repo", dir]);
  assert.match(result.warnings.join("\n"), /limit|too many/i);
  assert.equal(result.rows[0].session_id, null);
  assert.equal(fs.readdirSync(claims).length, 513);
});

test("invalid session JSON never echoes its contents in discovery warnings", (t) => {
  const dir = repository(t);
  hook(dir, "codex", "current-session");
  const file = path.join(
    dir,
    "registry",
    fs.readdirSync(path.join(dir, "registry"))[0],
  );
  fs.writeFileSync(file, "PRIVATE synthetic metadata");
  const result = json(dir, ["list", "--repo", dir]);
  assert.ok(result.warnings.length > 0);
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE/);
});

test("invalid settings JSON is rejected without echoing configuration values or writing either config", (t) => {
  const dir = fixture(t);
  const home = path.join(dir, "home");
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  const file = path.join(home, ".claude/settings.json");
  fs.writeFileSync(file, "PRIVATE synthetic setting");
  const result = run(dir, ["install-hooks", "--home", home]);
  assert.equal(result.status, 1);
  assert.doesNotMatch(result.stdout + result.stderr, /PRIVATE/);
  assert.equal(fs.readFileSync(file, "utf8"), "PRIVATE synthetic setting");
  assert.equal(fs.existsSync(path.join(home, ".codex")), false);
  assert.equal(fs.existsSync(path.join(dir, "registry")), false);
});

test("hook installation preserves a symlinked tool configuration directory", (t) => {
  const dir = fixture(t);
  const home = path.join(dir, "home");
  const shared = path.join(dir, "shared-claude");
  fs.mkdirSync(home);
  fs.mkdirSync(shared);
  fs.writeFileSync(path.join(shared, "settings.json"), "{}");
  fs.symlinkSync(shared, path.join(home, ".claude"), "dir");
  const result = run(dir, ["install-hooks", "--home", home]);
  assert.equal(result.status, 1);
  assert.equal(fs.readlinkSync(path.join(home, ".claude")), shared);
  assert.equal(
    fs.readFileSync(path.join(shared, "settings.json"), "utf8"),
    "{}",
  );
  assert.equal(fs.existsSync(path.join(home, ".codex")), false);
});

test("oversized settings are rejected before either config is written", (t) => {
  const dir = fixture(t);
  const home = path.join(dir, "home");
  fs.mkdirSync(path.join(home, ".claude"), { recursive: true });
  const file = path.join(home, ".claude/settings.json");
  const original = "{}" + " ".repeat(2 * 1024 * 1024);
  fs.writeFileSync(file, original);
  const result = run(dir, ["install-hooks", "--home", home]);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /limit/i);
  assert.equal(fs.readFileSync(file, "utf8"), original);
  assert.equal(fs.existsSync(path.join(home, ".codex")), false);
});

test("hook installation supports a fresh home with no settings", (t) => {
  const dir = fixture(t);
  const home = path.join(dir, "home");
  const result = run(dir, ["install-hooks", "--home", home]);
  assert.equal(result.status, 0, result.stderr);
  for (const target of [".codex/hooks.json", ".claude/settings.json"]) {
    const file = path.join(home, target);
    assert.equal(
      JSON.parse(fs.readFileSync(file, "utf8")).hooks.SessionStart.length,
      1,
    );
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  }
  assert.equal(fs.existsSync(path.join(dir, "registry")), false);
});
