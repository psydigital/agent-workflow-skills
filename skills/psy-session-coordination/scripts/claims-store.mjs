import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";

function stat(file) {
  try {
    return fs.lstatSync(file);
  } catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

export function claimRepository(cwd) {
  const git = (...args) =>
    execFileSync("git", ["--no-optional-locks", "-C", cwd, ...args], {
      encoding: "utf8",
      timeout: 3000,
      stdio: ["ignore", "pipe", "pipe"],
    }).trimEnd();
  const worktree = fs.realpathSync(git("rev-parse", "--show-toplevel"));
  const common = fs.realpathSync(
    git("rev-parse", "--path-format=absolute", "--git-common-dir"),
  );
  const first = git("worktree", "list", "--porcelain", "-z").split("\0")[0];
  if (!first.startsWith("worktree "))
    throw new Error("Cannot identify the main checkout");
  return { worktree, common, root: fs.realpathSync(first.slice(9)) };
}

export function normalizePrefix(value) {
  if (
    typeof value !== "string" ||
    value.length > 1024 ||
    /[\x00-\x1f\x7f\\]/.test(value) ||
    /^(?:\/|[A-Za-z]:)/.test(value)
  )
    throw new Error(
      "Use a repository-relative path without control characters or backslashes",
    );
  const prefix = value.replace(/^\.\//, "").replace(/\/$/, "");
  const parts = prefix.split("/");
  if (
    parts.some((part) => !part || part === "." || part === "..") ||
    [".git", ".session-state"].includes(parts[0].toLowerCase())
  )
    throw new Error(
      "Use a nonempty path inside the repository, excluding ownership metadata",
    );
  return prefix;
}

export function claimStatus(claim, now = Date.now()) {
  return claim.released_at
    ? "released"
    : Date.parse(claim.expires_at) <= now
      ? "expired"
      : "active";
}

function safeText(value, label, max = 1000) {
  if (
    typeof value !== "string" ||
    value.length > max ||
    /[\x00-\x1f\x7f]/.test(value)
  )
    throw new Error(`Invalid ${label}`);
  return value;
}

function validIdentity(tool, session) {
  if (
    !["codex", "claude"].includes(tool) ||
    typeof session !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$/.test(session)
  )
    throw new Error(
      "An explicit tool and native session identity are required",
    );
}

function locations(common) {
  const directory = path.join(common, "agent-workflow-claims");
  return { directory, file: path.join(directory, "state.json") };
}

function checkDirectory(directory) {
  const info = stat(directory);
  if (!info) return false;
  if (
    !info.isDirectory() ||
    info.isSymbolicLink() ||
    (process.getuid && info.uid !== process.getuid()) ||
    info.mode & 0o022
  )
    throw new Error("Unsafe claim store directory");
  return true;
}

export function readPortableClaims(common) {
  const { directory, file } = locations(common);
  if (!checkDirectory(directory)) return { initialized: false, claims: [] };
  const info = stat(file);
  if (!info) return { initialized: false, claims: [] };
  if (
    !info.isFile() ||
    info.isSymbolicLink() ||
    (process.getuid && info.uid !== process.getuid()) ||
    info.mode & 0o022
  )
    throw new Error("Unsafe claim store file");
  let state;
  try {
    state = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    throw new Error("Malformed claim store; no data was changed");
  }
  if (state?.version !== 1 || !Array.isArray(state.claims))
    throw new Error("Unsupported claim store format");
  const ids = new Set();
  for (const claim of state.claims) {
    if (
      !claim ||
      typeof claim.id !== "string" ||
      !/^[a-f0-9-]{36}$/.test(claim.id) ||
      ids.has(claim.id)
    )
      throw new Error("Invalid or duplicate claim identity");
    ids.add(claim.id);
    validIdentity(claim.tool, claim.session_id);
    if (normalizePrefix(claim.path_prefix) !== claim.path_prefix)
      throw new Error("Noncanonical claim path");
    safeText(claim.note, "claim note");
    if (typeof claim.worktree !== "string" || !path.isAbsolute(claim.worktree))
      throw new Error("Invalid claim checkout");
    for (const field of ["created_at", "updated_at", "expires_at"])
      if (
        typeof claim[field] !== "string" ||
        !Number.isFinite(Date.parse(claim[field]))
      )
        throw new Error("Invalid claim timestamp");
    if (
      claim.released_at !== null &&
      (typeof claim.released_at !== "string" ||
        !Number.isFinite(Date.parse(claim.released_at)))
    )
      throw new Error("Invalid claim release timestamp");
  }
  return { initialized: true, claims: state.claims };
}

function assertNoExistingOwnership(repo) {
  const paths = [
    ".session-state/master-claims.tsv",
    ".session-state/master-freeze",
    ".session-state/worktrees",
    "scripts/master-claim.sh",
    "scripts/worktree-claim.sh",
  ];
  if (
    paths.some((file) => stat(path.join(repo.root, file))) ||
    process.env.MASTER_CLAIMS_FILE ||
    process.env.MASTER_FREEZE_FILE
  )
    throw new Error(
      "Use this repository's existing ownership tooling; portable claim writes are disabled",
    );
}

function rejectPathAliases(worktree, prefix) {
  let current = worktree;
  for (const part of prefix.split("/")) {
    current = path.join(current, part);
    if (stat(current)?.isSymbolicLink())
      throw new Error("Claim the real repository path, not a symlink alias");
  }
}

function atomicWrite(file, claims) {
  const temporary = `${file}.${crypto.randomUUID()}.tmp`;
  try {
    fs.writeFileSync(
      temporary,
      `${JSON.stringify({ version: 1, claims }, null, 2)}\n`,
      { mode: 0o600, flag: "wx" },
    );
    fs.renameSync(temporary, file);
  } finally {
    fs.rmSync(temporary, { force: true });
  }
}

function withWriteLock(repo, initialize, operation) {
  assertNoExistingOwnership(repo);
  const { directory, file } = locations(repo.common);
  if (initialize && !stat(directory)) {
    try {
      fs.mkdirSync(directory, { mode: 0o700 });
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
  }
  if (!checkDirectory(directory))
    throw new Error("Run explicit init before creating claims");
  const lock = path.join(directory, "write.lock");
  try {
    fs.mkdirSync(lock, { mode: 0o700 });
  } catch (error) {
    if (error.code === "EEXIST")
      throw new Error("Claim store is busy; no existing lock was removed");
    throw error;
  }
  const identity = fs.lstatSync(lock);
  try {
    // Recheck under the lock, including repositories that adopted other tooling.
    assertNoExistingOwnership(repo);
    const state = readPortableClaims(repo.common);
    if (!initialize && !state.initialized)
      throw new Error("Run explicit init before creating claims");
    return operation(state, (claims) => atomicWrite(file, claims));
  } finally {
    const current = stat(lock);
    if (
      current?.isDirectory() &&
      current.ino === identity.ino &&
      current.dev === identity.dev
    )
      fs.rmdirSync(lock);
  }
}

export function initializeClaims(repo) {
  return withWriteLock(repo, true, (state, save) => {
    if (!state.initialized) save([]);
    return { initialized: true, claims: state.claims };
  });
}

export function changeClaim(repo, action, prefix, options) {
  prefix = normalizePrefix(prefix);
  validIdentity(options.tool, options.session);
  const native =
    options.tool === "codex"
      ? process.env.CODEX_THREAD_ID
      : process.env.CLAUDE_SESSION_ID;
  if (native && native !== options.session)
    throw new Error(
      "The supplied session differs from this tool's native session identity",
    );
  const ttl = options.ttl ?? 28800;
  if (!Number.isSafeInteger(ttl) || ttl < 1 || ttl > 604800)
    throw new Error("TTL must be an integer from 1 to 604800 seconds");
  const note = safeText(options.note ?? "", "claim note");
  // Release changes ownership metadata only, even if source paths have moved.
  if (action !== "release") rejectPathAliases(repo.worktree, prefix);
  return withWriteLock(repo, false, (state, save) => {
    const claims = state.claims;
    const live = claims.filter((claim) => !claim.released_at);
    const sameOwner = (claim) =>
      claim.tool === options.tool && claim.session_id === options.session;
    const exact = live.find((claim) => claim.path_prefix === prefix);
    const now = new Date().toISOString();
    const expires = new Date(Date.now() + ttl * 1000).toISOString();
    let claim;
    if (action === "claim") {
      if (exact && sameOwner(exact))
        return { claim: { ...exact, status: claimStatus(exact) } };
      const normalized = prefix.toLowerCase();
      const overlap = live.some((existing) => {
        const other = existing.path_prefix.toLowerCase();
        return (
          normalized === other ||
          normalized.startsWith(other + "/") ||
          other.startsWith(normalized + "/")
        );
      });
      if (overlap)
        throw new Error(
          "Path overlaps an unreleased claim; expiry does not transfer ownership",
        );
      claim = {
        id: crypto.randomUUID(),
        path_prefix: prefix,
        tool: options.tool,
        session_id: options.session,
        note,
        worktree: repo.worktree,
        created_at: now,
        updated_at: now,
        expires_at: expires,
        released_at: null,
      };
      claims.push(claim);
    } else {
      if (!exact || !sameOwner(exact))
        throw new Error(
          "Only the exact owning tool and session may renew or release this path",
        );
      claim = exact;
      claim.updated_at = now;
      if (action === "renew") {
        claim.expires_at = expires;
        if (options.note !== undefined) claim.note = note;
      } else if (action === "release") claim.released_at = now;
      else throw new Error("Unknown claim action");
    }
    save(claims);
    return { claim: { ...claim, status: claimStatus(claim) } };
  });
}
