#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { readPortableClaims, claimStatus } from "./claims-store.mjs";

const script = fileURLToPath(import.meta.url);
const args = process.argv.slice(2);
const command = args.shift() || "list";
const options = {};
const switches = new Set(["json", "all", "help"]);
const values = new Set([
  "repo",
  "query",
  "session",
  "branch",
  "tool",
  "task",
  "state-dir",
  "home",
]);
for (let i = 0; i < args.length; i++) {
  const name = args[i].replace(/^--/, "");
  if (!args[i].startsWith("--") || (!switches.has(name) && !values.has(name)))
    throw new Error(`Unknown option: ${args[i]}`);
  if (switches.has(name)) options[name] = true;
  else {
    if (!args[i + 1] || args[i + 1].startsWith("--"))
      throw new Error(`Missing value for --${name}`);
    options[name] = args[++i];
  }
}
const stateDir = path.resolve(
  options["state-dir"] ||
    process.env.AGENT_SESSIONS_DIR ||
    path.join(os.homedir(), ".local/state/agent-sessions"),
);
const now = Date.now();
const warnings = [];
const text = (value) =>
  typeof value === "string"
    ? value.replace(/[\x00-\x1f\x7f]/g, " ").slice(0, 1000)
    : "";
const canonical = (value) => {
  try {
    return fs.realpathSync(value);
  } catch {
    return path.resolve(value);
  }
};
const shellQuote = (value) => `'${value.replaceAll("'", "'\\''")}'`;

function git(cwd, ...argv) {
  try {
    return execFileSync("git", ["--no-optional-locks", "-C", cwd, ...argv], {
      encoding: "utf8",
      timeout: 3000,
      maxBuffer: 4 * 1024 * 1024,
      stdio: ["ignore", "pipe", "pipe"],
    }).trimEnd();
  } catch {
    return null;
  }
}

function repository(cwd) {
  const common = git(
    cwd,
    "rev-parse",
    "--path-format=absolute",
    "--git-common-dir",
  );
  if (!common) return null;
  const output = git(cwd, "worktree", "list", "--porcelain", "-z");
  if (output === null) return null;
  const worktrees = output
    .split("\0\0")
    .filter(Boolean)
    .map((entry) => {
      const fields = Object.fromEntries(
        entry
          .split("\0")
          .filter(Boolean)
          .map((line) => {
            const i = line.indexOf(" ");
            return i < 0 ? [line, true] : [line.slice(0, i), line.slice(i + 1)];
          }),
      );
      return {
        path: canonical(fields.worktree),
        branch: fields.branch?.replace(/^refs\/heads\//, "") || null,
        head: fields.HEAD || null,
      };
    });
  return {
    root: worktrees[0]?.path || canonical(cwd),
    common: canonical(common),
    worktrees,
  };
}

const recordLimit = 64 * 1024;
const configLimit = 1024 * 1024;
const directoryLimit = 512;

function plainDirectories(directory, root) {
  const relative = path.relative(root, directory);
  if (
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  )
    throw new Error("Metadata path is outside its root");
  let current = root;
  for (const part of ["", ...relative.split(path.sep).filter(Boolean)]) {
    current = path.join(current, part);
    const info = fs.lstatSync(current);
    if (info.isSymbolicLink())
      throw new Error(
        "Symlinked metadata/configuration directory; no changes made to it",
      );
    if (!info.isDirectory())
      throw new Error("Expected a metadata/configuration directory");
  }
}

function readText(file, root, limit = recordLimit) {
  plainDirectories(path.dirname(file), root);
  const before = fs.lstatSync(file);
  if (before.isSymbolicLink())
    throw new Error(
      "Symlinked metadata/configuration file; manage its canonical target explicitly",
    );
  if (!before.isFile())
    throw new Error("Expected a regular metadata/configuration file");
  // No-follow and nonblocking open also defend against a leaf replaced after lstat.
  const fd = fs.openSync(
    file,
    fs.constants.O_RDONLY |
      (fs.constants.O_NOFOLLOW || 0) |
      (fs.constants.O_NONBLOCK || 0),
  );
  try {
    const opened = fs.fstatSync(fd);
    plainDirectories(path.dirname(file), root);
    if (
      !opened.isFile() ||
      opened.dev !== before.dev ||
      opened.ino !== before.ino
    )
      throw new Error("Metadata/configuration file changed while opening it");
    if (opened.size > limit)
      throw new Error(`File exceeds the ${limit}-byte read limit`);
    // Bound the actual read too, including files that grow after the size check.
    const buffer = Buffer.alloc(limit + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = fs.readSync(
        fd,
        buffer,
        length,
        buffer.length - length,
        null,
      );
      if (!read) break;
      length += read;
    }
    if (length > limit)
      throw new Error(`File exceeds the ${limit}-byte read limit`);
    return buffer.toString("utf8", 0, length);
  } finally {
    fs.closeSync(fd);
  }
}

function optionalText(file, root, limit) {
  try {
    return readText(file, root, limit);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

function metadataEntries(directory, root) {
  try {
    plainDirectories(directory, root);
    const names = [];
    const handle = fs.opendirSync(directory);
    try {
      let entry;
      while ((entry = handle.readSync())) {
        if (names.length === directoryLimit)
          throw new Error(
            `Directory exceeds the ${directoryLimit}-entry limit`,
          );
        names.push(entry.name);
      }
    } finally {
      handle.closeSync();
    }
    return names;
  } catch (error) {
    if (error.code !== "ENOENT")
      warnings.push(
        `Skipped metadata directory ${text(directory)}: ${text(error.message)}`,
      );
    return [];
  }
}

function parseJson(source) {
  try {
    return JSON.parse(source);
  } catch {
    // Native parse errors can quote settings values or hook payload contents.
    throw new Error("Invalid JSON; contents omitted");
  }
}

function readJson(file) {
  return parseJson(readText(file, stateDir));
}

function secureDirectory(dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(dir);
  if (
    !stat.isDirectory() ||
    stat.isSymbolicLink() ||
    (process.getuid && stat.uid !== process.getuid())
  )
    throw new Error("Unsafe session metadata directory");
  fs.chmodSync(dir, 0o700);
}

function atomicWrite(file, value) {
  const temporary = `${file}.${process.pid}.${crypto.randomBytes(5).toString("hex")}.tmp`;
  try {
    fs.writeFileSync(temporary, value, { mode: 0o600, flag: "wx" });
    fs.renameSync(temporary, file);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

function register(payload, tool) {
  if (!["codex", "claude"].includes(tool))
    throw new Error("Choose --tool codex or claude");
  const id = text(payload.session_id);
  if (!id || id !== payload.session_id)
    throw new Error("A nonempty native session ID is required");
  // Subagent payloads carry the parent ID: do not overwrite the parent presence.
  if (payload.agent_id) return;
  const cwd = canonical(payload.new_cwd || payload.cwd || process.cwd());
  const repo = repository(cwd);
  const key = crypto.createHash("sha256").update(`${tool}:${id}`).digest("hex");
  secureDirectory(stateDir);
  const file = path.join(stateDir, `${key}.json`);
  let previous = {};
  try {
    previous = readJson(file);
  } catch {}
  const routes = [];
  if (tool === "codex")
    routes.push({
      kind: "codex-queue",
      thread_id: id,
      verification: "unverified",
    });
  if (tool === "claude" && process.env.CLAUDE_CODE_MESSAGING_SOCKET) {
    routes.push({
      kind: "claude-peer",
      address: text(process.env.CLAUDE_CODE_MESSAGING_SOCKET),
      verification: "unverified",
    });
  }
  if (process.env.CMUX_WORKSPACE_ID && process.env.CMUX_SURFACE_ID) {
    routes.push({
      kind: "cmux",
      workspace: text(process.env.CMUX_WORKSPACE_ID),
      surface: text(process.env.CMUX_SURFACE_ID),
      verification: "unverified",
    });
  }
  const event = payload.hook_event_name;
  const status =
    event === "SessionEnd"
      ? "ended"
      : event === "Stop"
        ? "idle"
        : event === "SessionStart"
          ? "recent"
          : "working";
  const record = {
    version: 1,
    tool,
    session_id: id,
    cwd,
    repository: repo?.root || null,
    git_common_dir: repo?.common || null,
    task: text(options.task || previous.task),
    status,
    first_seen: previous.first_seen || new Date(now).toISOString(),
    last_seen: new Date(now).toISOString(),
    routes,
    inbound: "unknown",
  };
  atomicWrite(file, `${JSON.stringify(record, null, 2)}\n`);
  if (
    tool === "claude" &&
    event === "SessionStart" &&
    process.env.CLAUDE_ENV_FILE
  ) {
    fs.appendFileSync(
      process.env.CLAUDE_ENV_FILE,
      `export CLAUDE_SESSION_ID=${shellQuote(id)}\nexport CLAUDE_INHERITED_CODEX_THREAD_ID=${shellQuote(process.env.CODEX_THREAD_ID || "")}\n`,
    );
  }
}

function readSessions() {
  const result = [];
  for (const name of metadataEntries(stateDir, stateDir).filter((name) =>
    /^[a-f0-9]{64}\.json$/.test(name),
  )) {
    try {
      const item = readJson(path.join(stateDir, name));
      if (
        item.version === 1 &&
        ["codex", "claude"].includes(item.tool) &&
        typeof item.session_id === "string"
      )
        result.push(item);
    } catch (error) {
      warnings.push(
        `Unreadable session metadata: ${name}: ${text(error.message)}`,
      );
    }
  }
  return result;
}

function envRecord(file, root) {
  return Object.fromEntries(
    readText(file, root)
      .split("\n")
      .filter((line) => line.includes("="))
      .map((line) => {
        const i = line.indexOf("=");
        return [line.slice(0, i), line.slice(i + 1)];
      }),
  );
}

function presence(record) {
  if (!record) return "unknown";
  if (record.status === "ended") return "ended";
  if (
    now - Date.parse(record.last_seen) > 30 * 60 * 1000 ||
    !Number.isFinite(Date.parse(record.last_seen))
  )
    return "stale";
  return record.status;
}

function list() {
  const sessions = readSessions();
  const selected = repository(options.repo || process.cwd());
  if (options.repo && !selected)
    throw new Error(`Not a readable Git repository: ${options.repo}`);
  const repos = new Map();
  if (selected) repos.set(selected.common, selected);
  else
    for (const s of sessions) {
      if (s.repository && !repos.has(s.git_common_dir)) {
        const repo = repository(s.repository);
        if (repo) repos.set(repo.common, repo);
      }
    }
  const rows = [];
  const attached = new Set();
  function enrich(row, repo) {
    const candidates = sessions.filter(
      (s) =>
        s.session_id === row.session_id &&
        s.git_common_dir === repo.common &&
        (!row.tool || row.tool === s.tool),
    );
    const record = candidates.length === 1 ? candidates[0] : null;
    if (record) attached.add(`${record.tool}:${record.session_id}`);
    return {
      ...row,
      tool: record?.tool || row.tool || null,
      presence: presence(record),
      last_seen: record?.last_seen || null,
      task: record?.task || row.task || "",
      claim_note: row.task || "",
      routes: record?.routes || [],
      inbound: record?.inbound || "unknown",
      ambiguous_identity: candidates.length > 1,
    };
  }
  for (const repo of repos.values()) {
    try {
      const portable = readPortableClaims(repo.common);
      for (const claim of portable.claims) {
        if (claim.released_at && !options.all) continue;
        const worktree = repo.worktrees.find(
          (item) => item.path === claim.worktree,
        );
        rows.push(
          enrich(
            {
              kind: "path-claim",
              repository: repo.root,
              worktree: claim.worktree,
              worktree_id: null,
              claim_id: claim.id,
              branch: worktree?.branch || null,
              head: worktree?.head || null,
              path_prefix: claim.path_prefix,
              lifecycle: claimStatus(claim, now),
              session_id: claim.session_id,
              tool: claim.tool,
              task: claim.note,
              registered: Boolean(worktree),
            },
            repo,
          ),
        );
      }
    } catch (error) {
      warnings.push(`Portable claims unavailable: ${error.message}`);
    }
    const claimsDir = path.join(repo.root, ".session-state/worktrees");
    const claims = [];
    for (const name of metadataEntries(claimsDir, repo.root).filter((n) =>
      n.endsWith(".env"),
    )) {
      try {
        claims.push(envRecord(path.join(claimsDir, name), repo.root));
      } catch (error) {
        warnings.push(
          `Unreadable claim in ${repo.root}: ${text(name)}: ${text(error.message)}`,
        );
      }
    }
    const matched = new Set();
    for (const wt of repo.worktrees) {
      const candidates = claims.filter(
        (claim) =>
          canonical(
            claim.canonical_path ||
              claim.worktree_path ||
              repo.root + "/missing",
          ) === wt.path &&
          !["retired", "merged"].includes(
            claim.lifecycle_state || claim.status,
          ),
      );
      if (candidates.length > 1)
        warnings.push(
          `Multiple ownership records for ${wt.path}; no owner inferred`,
        );
      const claim = candidates.length === 1 ? candidates[0] : {};
      if (candidates.length === 1) matched.add(claim);
      rows.push(
        enrich(
          {
            kind: "worktree",
            repository: repo.root,
            worktree: wt.path,
            worktree_id: claim.worktree_id || null,
            branch: wt.branch,
            head: wt.head,
            lifecycle: claim.lifecycle_state || claim.status || "unclaimed",
            session_id: claim.owner_session_id || claim.thread_id || null,
            task: text(claim.note),
            registered: true,
          },
          repo,
        ),
      );
    }
    if (options.all)
      for (const claim of claims.filter((c) => !matched.has(c))) {
        rows.push(
          enrich(
            {
              kind: "worktree",
              repository: repo.root,
              worktree: claim.canonical_path || claim.worktree_path || null,
              worktree_id: claim.worktree_id || null,
              branch: claim.initial_branch || claim.branch || null,
              head: null,
              lifecycle: claim.lifecycle_state || claim.status || "unknown",
              session_id: claim.owner_session_id || claim.thread_id || null,
              task: text(claim.note),
              registered: false,
            },
            repo,
          ),
        );
      }
    const masterFile = path.join(repo.root, ".session-state/master-claims.tsv");
    let masterClaims;
    try {
      masterClaims = optionalText(masterFile, repo.root, configLimit);
    } catch (error) {
      warnings.push(
        `Unreadable checkout claims in ${repo.root}: ${text(error.message)}`,
      );
    }
    if (masterClaims) {
      const ttl = Number(process.env.MASTER_CLAIMS_TTL_SECONDS || 28800);
      for (const line of masterClaims.split("\n").filter(Boolean)) {
        const [at, , , prefix, note, cwd, id] = line.split("\t");
        if (!/^\d+$/.test(at) || !prefix) continue;
        const expired = now / 1000 - Number(at) > ttl;
        if (expired && !options.all) continue;
        rows.push(
          enrich(
            {
              kind: "master",
              repository: repo.root,
              worktree: cwd || repo.root,
              worktree_id: null,
              branch: repo.worktrees[0]?.branch || null,
              head: repo.worktrees[0]?.head || null,
              path_prefix: prefix,
              lifecycle: expired ? "expired" : "active",
              session_id: id || null,
              task: text(note),
              registered: true,
            },
            repo,
          ),
        );
      }
    }
  }
  for (const record of sessions) {
    if (selected && record.git_common_dir !== selected.common) continue;
    if (attached.has(`${record.tool}:${record.session_id}`)) continue;
    if (!options.all && ["ended", "stale"].includes(presence(record))) continue;
    rows.push({
      kind: "session",
      repository: record.repository,
      worktree: record.cwd,
      worktree_id: null,
      branch: null,
      head: null,
      lifecycle: null,
      session_id: record.session_id,
      tool: record.tool,
      task: record.task,
      presence: presence(record),
      last_seen: record.last_seen,
      routes: record.routes,
      inbound: record.inbound,
      registered: null,
    });
  }
  const filtered = rows.filter(
    (row) =>
      (!options.session || row.session_id === options.session) &&
      (!options.branch || row.branch === options.branch) &&
      (!options.tool || row.tool === options.tool) &&
      (!options.query ||
        [
          row.task,
          row.claim_note,
          row.branch,
          row.session_id,
          row.worktree,
          row.path_prefix,
        ].some((v) => v?.toLowerCase().includes(options.query.toLowerCase()))),
  );
  const result = {
    version: 1,
    repository: selected?.root || null,
    observed_at: new Date(now).toISOString(),
    rows: filtered,
    warnings,
  };
  if (options.json) console.log(JSON.stringify(result, null, 2));
  else {
    console.log(
      "KIND\tTOOL\tSESSION\tPRESENCE\tCLAIM STATE\tBRANCH / PATH PREFIX\tTASK\tWORKTREE",
    );
    for (const r of filtered)
      console.log(
        [
          r.kind,
          r.tool || "unknown",
          r.session_id || "-",
          r.presence,
          r.lifecycle || "-",
          r.path_prefix || r.branch || "-",
          r.task || "-",
          r.worktree || "-",
        ]
          .map(text)
          .join("\t"),
      );
    for (const warning of warnings) console.error(warning);
  }
}

function installHooks() {
  const home = path.resolve(options.home || os.homedir());
  const changes = [];
  for (const tool of ["codex", "claude"]) {
    const file = path.join(
      home,
      tool === "codex" ? ".codex/hooks.json" : ".claude/settings.json",
    );
    const before = optionalText(file, home, configLimit);
    const config = before === null ? {} : parseJson(before);
    if (!config || typeof config !== "object" || Array.isArray(config))
      throw new Error("Agent configuration must be a JSON object");
    config.hooks ||= {};
    if (typeof config.hooks !== "object" || Array.isArray(config.hooks))
      throw new Error("Agent hooks must be a JSON object");
    const hookCommand = `${shellQuote(process.execPath)} ${shellQuote(script)} hook --tool ${tool}`;
    for (const event of [
      "SessionStart",
      "UserPromptSubmit",
      "PostToolUse",
      "Stop",
      "SessionEnd",
    ]) {
      config.hooks[event] ||= [];
      if (
        !config.hooks[event].some((group) =>
          group.hooks?.some((hook) => hook.command === hookCommand),
        )
      ) {
        config.hooks[event].push({
          hooks: [{ type: "command", command: hookCommand, timeout: 5 }],
        });
      }
    }
    const after = `${JSON.stringify(config, null, 2)}\n`;
    if (before !== after) changes.push({ file, before, after });
  }
  // Parse both configs before changing either; preserve every unrelated entry.
  for (const { file, before, after } of changes) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    if (before !== null) {
      const backup = path.join(stateDir, "config-backups");
      secureDirectory(backup);
      atomicWrite(
        path.join(
          backup,
          `${path.basename(path.dirname(file))}-${path.basename(file)}-${now}.json`,
        ),
        before,
      );
    }
    atomicWrite(file, after);
    console.log(`Updated ${file}`);
  }
  console.log(
    "Codex: review and trust the new definitions in /hooks. Existing sessions may need to resume before loading new hooks.",
  );
}

try {
  if (options.help || command === "help" || command === "--help") {
    console.log(
      "agent-sessions list [--repo PATH] [--query TEXT] [--session ID] [--branch NAME] [--tool codex|claude] [--all] [--json]\nagent-sessions register --tool codex|claude [--session ID] [--repo PATH] [--task TEXT]\nagent-sessions install-hooks [--home PATH]\nLists are read-only. Presence and routes are observations, never ownership or delivery authority.",
    );
  } else if (command === "list") list();
  else if (command === "hook")
    register(parseJson(fs.readFileSync(0, "utf8")), options.tool);
  else if (command === "register") {
    const id =
      options.session ||
      (options.tool === "claude"
        ? process.env.CLAUDE_SESSION_ID
        : process.env.CODEX_THREAD_ID);
    register(
      {
        session_id: id,
        cwd: options.repo || process.cwd(),
        hook_event_name: "SessionStart",
      },
      options.tool,
    );
  } else if (command === "install-hooks") installHooks();
  else throw new Error(`Unknown command: ${command}`);
} catch (error) {
  console.error(`agent-sessions: ${error.message}`);
  // Presence bookkeeping must never block an agent or alter its permissions.
  process.exitCode = command === "hook" ? 0 : 1;
}
