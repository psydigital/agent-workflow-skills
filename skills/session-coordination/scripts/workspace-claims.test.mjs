import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scripts = path.dirname(fileURLToPath(import.meta.url));
const cli = path.join(scripts, "workspace-claims.mjs");
const discovery = path.join(scripts, "agent-sessions.mjs");
const env = { ...process.env };
for (const key of [
  "CODEX_THREAD_ID",
  "CLAUDE_SESSION_ID",
  "CLAUDE_ENV_FILE",
  "CLAUDE_CODE_MESSAGING_SOCKET",
  "CMUX_WORKSPACE_ID",
  "CMUX_SURFACE_ID",
  "MASTER_CLAIMS_FILE",
  "MASTER_FREEZE_FILE",
])
  delete env[key];
const owner = ["--tool", "codex", "--session", "example-owner"];
const peer = ["--tool", "claude", "--session", "example-peer"];

function git(dir, ...args) {
  return execFileSync("git", ["-C", dir, ...args], {
    encoding: "utf8",
    env,
  }).trim();
}

function fixture(t) {
  const root = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), "claims-test-")),
  );
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, "repo");
  fs.mkdirSync(repo);
  git(repo, "init", "-q", "-b", "main");
  git(repo, "config", "user.name", "Fixture Author");
  git(repo, "config", "user.email", "fixture@example.test");
  git(repo, "commit", "--allow-empty", "-qm", "fixture");
  return {
    root,
    repo,
    directory: path.join(repo, ".git/agent-workflow-claims"),
    file: path.join(repo, ".git/agent-workflow-claims/state.json"),
  };
}

function run(repo, args, extraEnv = {}) {
  return spawnSync(process.execPath, [cli, ...args, "--repo", repo], {
    encoding: "utf8",
    env: { ...env, ...extraEnv },
  });
}

function ok(repo, args) {
  const result = run(repo, [...args, "--json"]);
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test("listing an unconfigured repository is read-only and claiming requires explicit setup", (t) => {
  const f = fixture(t);
  assert.deepEqual(ok(f.repo, ["list"]).claims, []);
  assert.equal(ok(f.repo, ["list"]).initialized, false);
  assert.notEqual(run(f.repo, ["claim", "src/search", ...owner]).status, 0);
  assert.equal(fs.existsSync(f.directory), false);
  assert.equal(git(f.repo, "status", "--porcelain"), "");
});

test("claims round-trip without tracking runtime files and repeated setup preserves them", (t) => {
  const f = fixture(t);
  ok(f.repo, ["init"]);
  const result = ok(f.repo, [
    "claim",
    "src/search",
    ...owner,
    "--note",
    "Search review",
  ]);
  assert.equal(result.claim.path_prefix, "src/search");
  assert.equal(result.claim.session_id, "example-owner");
  assert.equal(result.claim.tool, "codex");
  const before = fs.readFileSync(f.file);
  ok(f.repo, ["init"]);
  const listed = ok(f.repo, ["list"]);
  assert.equal(listed.claims.length, 1);
  assert.equal(listed.claims[0].status, "active");
  assert.deepEqual(fs.readFileSync(f.file), before);
  assert.equal(fs.statSync(f.file).mode & 0o777, 0o600);
  assert.equal(fs.statSync(f.directory).mode & 0o777, 0o700);
  assert.equal(git(f.repo, "status", "--porcelain"), "");
});

test("existing ownership files, scripts and freezes prevent setup without touching their data", (t) => {
  for (const relative of [
    ".session-state/master-claims.tsv",
    ".session-state/master-freeze",
    ".session-state/worktrees/owner.env",
    "scripts/master-claim.sh",
    "scripts/worktree-claim.sh",
  ]) {
    const f = fixture(t);
    const existing = path.join(f.repo, relative);
    fs.mkdirSync(path.dirname(existing), { recursive: true });
    fs.writeFileSync(existing, "existing ownership data\n");
    const result = run(f.repo, ["init"]);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /existing ownership/i);
    assert.equal(
      fs.readFileSync(existing, "utf8"),
      "existing ownership data\n",
    );
    assert.equal(fs.existsSync(f.directory), false);
  }
});

test("a repository adopting another ownership system also blocks subsequent portable writes", (t) => {
  const f = fixture(t);
  ok(f.repo, ["init"]);
  ok(f.repo, ["claim", "src/search", ...owner]);
  const before = fs.readFileSync(f.file);
  fs.mkdirSync(path.join(f.repo, ".session-state"));
  fs.writeFileSync(
    path.join(f.repo, ".session-state/master-freeze"),
    "frozen\n",
  );
  for (const args of [
    ["claim", "src/other", ...owner],
    ["renew", "src/search", ...owner],
    ["release", "src/search", ...owner],
  ]) {
    assert.notEqual(run(f.repo, args).status, 0);
    assert.deepEqual(fs.readFileSync(f.file), before);
  }
});

test("overlap checks cover parents, children and case aliases while permitting adjacent names", (t) => {
  const f = fixture(t);
  ok(f.repo, ["init"]);
  const first = ok(f.repo, ["claim", "src/search", ...owner]);
  assert.equal(
    ok(f.repo, ["claim", "./src/search/", ...owner]).claim.id,
    first.claim.id,
  );
  for (const prefix of [
    "src",
    "src/search",
    "src/search/index.js",
    "SRC/SEARCH",
  ]) {
    assert.notEqual(run(f.repo, ["claim", prefix, ...peer]).status, 0, prefix);
  }
  ok(f.repo, ["claim", "src/searching", ...peer]);
  assert.equal(ok(f.repo, ["list"]).claims.length, 2);
});

test("only the exact tool and session can renew or release, including expired claims", (t) => {
  const f = fixture(t);
  ok(f.repo, ["init"]);
  ok(f.repo, ["claim", "src/search", ...owner]);
  const state = JSON.parse(fs.readFileSync(f.file));
  state.claims[0].expires_at = "2000-01-01T00:00:00.000Z";
  fs.writeFileSync(f.file, JSON.stringify(state));
  assert.equal(ok(f.repo, ["list"]).claims[0].status, "expired");
  const expired = fs.readFileSync(f.file);
  for (const action of ["renew", "release"]) {
    assert.notEqual(run(f.repo, [action, "src/search", ...peer]).status, 0);
    assert.notEqual(
      run(f.repo, [
        action,
        "src/search",
        "--tool",
        "claude",
        "--session",
        "example-owner",
      ]).status,
      0,
    );
  }
  assert.notEqual(run(f.repo, ["claim", "src/search", ...peer]).status, 0);
  assert.deepEqual(fs.readFileSync(f.file), expired);
  ok(f.repo, ["renew", "src/search", ...owner]);
  assert.equal(ok(f.repo, ["list"]).claims[0].status, "active");
  ok(f.repo, ["release", "src/search", ...owner]);
  assert.equal(ok(f.repo, ["list"]).claims.length, 0);
  assert.equal(ok(f.repo, ["list", "--all"]).claims[0].status, "released");
  ok(f.repo, ["claim", "src/search", ...peer]);
});

test("native identity cannot be overridden and invalid path aliases cannot evade conflicts", (t) => {
  const f = fixture(t);
  ok(f.repo, ["init"]);
  for (const prefix of [
    ".",
    "../outside",
    "src/../other",
    "/absolute",
    "C:/absolute",
    "src\\alias",
    ".git/config",
    "src\talias",
  ]) {
    assert.notEqual(run(f.repo, ["claim", prefix, ...owner]).status, 0, prefix);
  }
  assert.notEqual(
    run(f.repo, ["claim", "src/search", ...owner], {
      CODEX_THREAD_ID: "different-owner",
    }).status,
    0,
  );
  fs.mkdirSync(path.join(f.repo, "src"));
  fs.symlinkSync("src", path.join(f.repo, "alias"));
  assert.notEqual(run(f.repo, ["claim", "alias/search", ...owner]).status, 0);
  assert.equal(ok(f.repo, ["list"]).claims.length, 0);
});

test("linked worktrees share overlap protection and resolve existing ownership from the main checkout", (t) => {
  const f = fixture(t);
  const worktree = path.join(f.root, "feature");
  git(f.repo, "worktree", "add", "-qb", "feature", worktree);
  ok(f.repo, ["init"]);
  ok(worktree, ["claim", "src/search", ...owner]);
  assert.equal(ok(f.repo, ["list"]).claims[0].worktree, worktree);
  assert.notEqual(run(f.repo, ["claim", "src/search", ...peer]).status, 0);
  fs.mkdirSync(path.join(f.repo, "scripts"));
  fs.writeFileSync(path.join(f.repo, "scripts/master-claim.sh"), "existing\n");
  assert.notEqual(run(worktree, ["claim", "src/other", ...owner]).status, 0);
});

test("simultaneous writers cannot both acquire an overlapping path or lose independent claims", async (t) => {
  const f = fixture(t);
  ok(f.repo, ["init"]);
  function concurrent(args) {
    return new Promise((resolve, reject) => {
      const child = spawn(
        process.execPath,
        [cli, ...args, "--repo", f.repo, "--json"],
        { env, stdio: ["ignore", "pipe", "pipe"] },
      );
      child.on("error", reject);
      child.on("close", (code) => resolve(code));
    });
  }
  const results = await Promise.all(
    Array.from({ length: 8 }, (_, i) =>
      concurrent([
        "claim",
        "src/search",
        "--tool",
        "codex",
        "--session",
        `example-${i}`,
      ]),
    ),
  );
  assert.equal(results.filter((code) => code === 0).length, 1);
  assert.equal(ok(f.repo, ["list"]).claims.length, 1);
  ok(f.repo, ["claim", "src/other", ...peer]);
  assert.equal(ok(f.repo, ["list"]).claims.length, 2);
  assert.equal(fs.existsSync(path.join(f.directory, "write.lock")), false);
});

test("a busy lock and malformed state fail closed without deleting or replacing either", (t) => {
  const f = fixture(t);
  ok(f.repo, ["init"]);
  const before = fs.readFileSync(f.file);
  const lock = path.join(f.directory, "write.lock");
  fs.mkdirSync(lock);
  assert.notEqual(run(f.repo, ["claim", "src/search", ...owner]).status, 0);
  assert.deepEqual(fs.readFileSync(f.file), before);
  assert.equal(fs.existsSync(lock), true);
  fs.rmdirSync(lock);
  fs.writeFileSync(f.file, "malformed state");
  assert.notEqual(run(f.repo, ["init"]).status, 0);
  assert.notEqual(run(f.repo, ["claim", "src/search", ...owner]).status, 0);
  assert.equal(fs.readFileSync(f.file, "utf8"), "malformed state");
});

test("state symlinks cannot redirect reads or writes outside the private store", (t) => {
  const f = fixture(t);
  const outside = path.join(f.root, "outside");
  fs.mkdirSync(outside);
  fs.symlinkSync(outside, f.directory);
  assert.notEqual(run(f.repo, ["init"]).status, 0);
  assert.deepEqual(fs.readdirSync(outside), []);
  fs.unlinkSync(f.directory);
  ok(f.repo, ["init"]);
  const externalFile = path.join(outside, "state.json");
  fs.writeFileSync(externalFile, fs.readFileSync(f.file));
  fs.unlinkSync(f.file);
  fs.symlinkSync(externalFile, f.file);
  const before = fs.readFileSync(externalFile);
  assert.notEqual(run(f.repo, ["list"]).status, 0);
  assert.notEqual(run(f.repo, ["claim", "src/search", ...owner]).status, 0);
  assert.deepEqual(fs.readFileSync(externalFile), before);
});

test("an owner can release a claim after its source path becomes a symlink", (t) => {
  const f = fixture(t);
  ok(f.repo, ["init"]);
  ok(f.repo, ["claim", "src/search", ...owner]);
  fs.mkdirSync(path.join(f.repo, "src"));
  fs.symlinkSync(f.root, path.join(f.repo, "src/search"));
  ok(f.repo, ["release", "src/search", ...owner]);
  assert.equal(ok(f.repo, ["list"]).claims.length, 0);
});

test("unreadable portable records produce a warning while legacy discovery remains available", (t) => {
  const f = fixture(t);
  ok(f.repo, ["init"]);
  fs.writeFileSync(f.file, "malformed state");
  fs.mkdirSync(path.join(f.repo, ".session-state"));
  const legacy = path.join(f.repo, ".session-state/master-claims.tsv");
  const content = `${Math.floor(Date.now() / 1000)}\tuser\thost\tsrc/search\tExisting task\t${f.repo}\tlegacy-owner\n`;
  fs.writeFileSync(legacy, content);
  const result = spawnSync(
    process.execPath,
    [
      discovery,
      "list",
      "--repo",
      f.repo,
      "--json",
      "--state-dir",
      path.join(f.root, "registry"),
    ],
    { encoding: "utf8", env },
  );
  assert.equal(result.status, 0, result.stderr);
  const observed = JSON.parse(result.stdout);
  assert.equal(
    observed.rows.find((row) => row.kind === "master").session_id,
    "legacy-owner",
  );
  assert.equal(observed.warnings.length, 1);
  assert.match(observed.warnings[0], /portable claims unavailable/i);
  assert.equal(fs.readFileSync(legacy, "utf8"), content);
  assert.equal(fs.readFileSync(f.file, "utf8"), "malformed state");
});

test("discovery joins portable claims to the exact tool namespace and never writes the claim store", (t) => {
  const f = fixture(t);
  ok(f.repo, ["init"]);
  ok(f.repo, ["claim", "src/search", ...owner, "--note", "Search review"]);
  const stateDir = path.join(f.root, "registry");
  for (const tool of ["codex", "claude"]) {
    const result = spawnSync(
      process.execPath,
      [
        discovery,
        "register",
        "--repo",
        f.repo,
        "--tool",
        tool,
        "--session",
        "example-owner",
        "--state-dir",
        stateDir,
      ],
      { encoding: "utf8", env },
    );
    assert.equal(result.status, 0, result.stderr);
  }
  const before = fs.readFileSync(f.file);
  const result = spawnSync(
    process.execPath,
    [
      discovery,
      "list",
      "--repo",
      f.repo,
      "--query",
      "src/search",
      "--json",
      "--state-dir",
      stateDir,
    ],
    { encoding: "utf8", env },
  );
  assert.equal(result.status, 0, result.stderr);
  const rows = JSON.parse(result.stdout).rows;
  assert.equal(rows.length, 1);
  assert.equal(rows[0].kind, "path-claim");
  assert.equal(rows[0].tool, "codex");
  assert.equal(rows[0].session_id, "example-owner");
  assert.equal(rows[0].lifecycle, "active");
  assert.equal(rows[0].routes[0].verification, "unverified");
  assert.deepEqual(fs.readFileSync(f.file), before);
});
