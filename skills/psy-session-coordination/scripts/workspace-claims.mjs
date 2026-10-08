#!/usr/bin/env node
import {
  claimRepository,
  readPortableClaims,
  claimStatus,
  initializeClaims,
  changeClaim,
} from "./claims-store.mjs";

try {
  const args = process.argv.slice(2);
  const command = args.shift() || "help";
  const options = {};
  const positional = [];
  const values = new Set(["repo", "tool", "session", "note", "ttl-seconds"]);
  for (let i = 0; i < args.length; i++) {
    if (!args[i].startsWith("--")) {
      positional.push(args[i]);
      continue;
    }
    const name = args[i].slice(2);
    if (["json", "all"].includes(name)) options[name] = true;
    else if (values.has(name) && args[i + 1] && !args[i + 1].startsWith("--"))
      options[name] = args[++i];
    else throw new Error("Unknown option or missing value");
  }
  if (["help", "--help", "-h"].includes(command)) {
    console.log(`workspace-claims init --repo PATH
workspace-claims list --repo PATH [--all] [--json]
workspace-claims claim|renew|release PATH --repo PATH --tool codex|claude [--session ID] [--note TEXT] [--ttl-seconds SECONDS] [--json]
Setup is opt-in. Existing repository ownership tools take precedence.
Claims are advisory. Expiry marks stale intent and does not transfer ownership.`);
  } else {
    if (!["init", "list", "claim", "renew", "release"].includes(command))
      throw new Error("Unknown command");
    const mutation = ["claim", "renew", "release"].includes(command);
    if (positional.length !== (mutation ? 1 : 0))
      throw new Error("Supply exactly one path for claim, renew or release");
    const repo = claimRepository(options.repo || process.cwd());
    let result;
    if (command === "init") result = initializeClaims(repo);
    else if (command === "list") {
      const state = readPortableClaims(repo.common);
      result = {
        initialized: state.initialized,
        claims: state.claims
          .filter((claim) => options.all || !claim.released_at)
          .map((claim) => ({ ...claim, status: claimStatus(claim) })),
      };
    } else {
      result = changeClaim(repo, command, positional[0], {
        tool: options.tool,
        session:
          options.session ||
          (options.tool === "codex"
            ? process.env.CODEX_THREAD_ID
            : process.env.CLAUDE_SESSION_ID),
        note: options.note,
        ttl:
          options["ttl-seconds"] === undefined
            ? undefined
            : Number(options["ttl-seconds"]),
      });
    }
    if (options.json) console.log(JSON.stringify(result, null, 2));
    else if (result.claim)
      console.log(
        `${result.claim.status}: ${result.claim.path_prefix} (${result.claim.tool}:${result.claim.session_id})`,
      );
    else if (!result.initialized)
      console.log("Portable claims are not initialized; no files changed.");
    else if (command === "init")
      console.log("Portable claims initialized; existing records preserved.");
    else {
      console.log("STATUS\tTOOL\tSESSION\tPATH\tNOTE");
      for (const claim of result.claims)
        console.log(
          [
            claim.status,
            claim.tool,
            claim.session_id,
            claim.path_prefix,
            claim.note,
          ].join("\t"),
        );
    }
  }
} catch (error) {
  console.error(`workspace-claims: ${error.message}`);
  process.exitCode = 1;
}
