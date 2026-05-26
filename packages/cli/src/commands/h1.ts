// `pwnkit h1` — read-only HackerOne hacker-API CLI.
//
// Subcommands implemented in this PR:
//   - auth                      verify credentials
//   - programs list             paginate / filter the program list
//   - programs show <handle>    program detail + scope summary
//   - scope dump <handle>       export structured_scopes as ScopeJson
//
// Subcommands deferred (filed as follow-on issues):
//   - fit-score, fit-rank, hacktivity
//
// Exit codes:
//   0 — ok
//   1 — user / data error (bad input, parse failure, missing handle)
//   2 — auth failure (missing creds or 401 from H1)
//   3 — rate-limit / network error
//
// SECURITY: the token is never printed. Identifier echoes are explicit;
// every error path goes through `formatError` which avoids leaking the
// token even if a future error type accidentally interpolates one.

import type { Command } from "commander";
import chalk from "chalk";
import {
  loadH1Credentials,
  H1AuthMissingError,
  H1Client,
  H1AuthError,
  H1ForbiddenError,
  H1RateLimitError,
  H1NetworkError,
  H1Error,
  listPrograms,
  getProgram,
  getStructuredScopes,
  automationVerdict,
  summariseScopes,
  toScopeFile,
  type H1Program,
} from "@pwnkit/core";

interface ProgramsListOptions {
  bounty?: boolean;
  vdp?: boolean;
  state?: string;
  limit?: string;
  json?: boolean;
}

interface ScopeDumpOptions {
  out?: string;
}

const EXIT_OK = 0;
const EXIT_USER_ERROR = 1;
const EXIT_AUTH = 2;
const EXIT_NET = 3;

export function registerH1Command(program: Command): void {
  const h1 = program
    .command("h1")
    .description("HackerOne hacker-API helpers (read-only)");

  // ── pwnkit h1 auth ──
  h1.command("auth")
    .description("Verify HackerOne API credentials")
    .action(async () => {
      const creds = loadCredsOrExit();
      if (!creds) return;
      const client = new H1Client(creds);
      try {
        await client.get("/v1/hackers/payments/balance");
        console.log(`OK (identifier=${creds.identifier})`);
        process.exitCode = EXIT_OK;
      } catch (err) {
        handleApiError(err, "auth");
      }
    });

  // ── pwnkit h1 programs ──
  const programs = h1
    .command("programs")
    .description("List or inspect HackerOne programs");

  programs
    .command("list")
    .description("List visible programs")
    .option("--bounty", "Only programs that pay bounties")
    .option("--vdp", "Only non-bounty (VDP) programs")
    .option("--state <state>", "Filter by program state (e.g. public_mode, soft_launched)")
    .option("--limit <n>", "Max programs to return (default 100, max 1000)")
    .option("--json", "Emit machine-readable JSON instead of a table")
    .action(async (opts: ProgramsListOptions) => {
      const creds = loadCredsOrExit();
      if (!creds) return;
      const limit = parseLimit(opts.limit, 100, 1000);
      if (limit === null) return;
      if (opts.bounty && opts.vdp) {
        console.error(chalk.red("Error: --bounty and --vdp are mutually exclusive."));
        process.exitCode = EXIT_USER_ERROR;
        return;
      }

      const client = new H1Client(creds);
      try {
        const list = await listPrograms(client, {
          limit,
          bountyOnly: opts.bounty,
          vdpOnly: opts.vdp,
          state: opts.state,
          pageSize: 100,
        });

        if (opts.json) {
          // Strip raw JSON:API noise; emit a compact view.
          const compact = list.map((p) => ({
            handle: p.attributes.handle,
            name: p.attributes.name,
            state: p.attributes.state ?? null,
            offers_bounties: p.attributes.offers_bounties ?? null,
            currency: p.attributes.currency ?? null,
          }));
          console.log(JSON.stringify(compact, null, 2));
        } else {
          renderProgramTable(list);
        }
        process.exitCode = EXIT_OK;
      } catch (err) {
        handleApiError(err, "programs list");
      }
    });

  programs
    .command("show")
    .description("Show details for a single program")
    .argument("<handle>", "Program handle (e.g. flutteruki)")
    .action(async (handle: string) => {
      const creds = loadCredsOrExit();
      if (!creds) return;
      const client = new H1Client(creds);
      try {
        const [prog, scopes] = await Promise.all([
          getProgram(client, handle),
          getStructuredScopes(client, handle),
        ]);
        renderProgramDetail(prog, scopes);
        process.exitCode = EXIT_OK;
      } catch (err) {
        handleApiError(err, `programs show ${handle}`);
      }
    });

  // ── pwnkit h1 scope ──
  const scope = h1
    .command("scope")
    .description("Export HackerOne scope into the pwnkit scope file format");

  scope
    .command("dump")
    .description("Write a program's structured_scopes to ~/.pwnkit/scopes/<handle>.json")
    .argument("<handle>", "Program handle")
    .option("--out <path>", "Override the output path")
    .action(async (handle: string, opts: ScopeDumpOptions) => {
      const creds = loadCredsOrExit();
      if (!creds) return;
      const client = new H1Client(creds);
      try {
        const [prog, scopes] = await Promise.all([
          getProgram(client, handle),
          getStructuredScopes(client, handle),
        ]);
        const result = toScopeFile(prog, scopes, { outPath: opts.out });
        console.log(result.path);
        if (result.dropped.length > 0) {
          console.error(
            chalk.yellow(
              `note: dropped ${result.dropped.length} unsupported scope ${result.dropped.length === 1 ? "entry" : "entries"} ` +
                `(non-network asset types or malformed identifiers)`,
            ),
          );
          for (const d of result.dropped.slice(0, 5)) {
            console.error(
              chalk.dim(`  - ${d.scope.attributes.asset_type} ${d.scope.attributes.asset_identifier}: ${d.reason}`),
            );
          }
          if (result.dropped.length > 5) {
            console.error(chalk.dim(`  …and ${result.dropped.length - 5} more`));
          }
        }
        process.exitCode = EXIT_OK;
      } catch (err) {
        handleApiError(err, `scope dump ${handle}`);
      }
    });
}

// ── helpers ──

function loadCredsOrExit(): { identifier: string; token: string } | null {
  try {
    const c = loadH1Credentials();
    return { identifier: c.identifier, token: c.token };
  } catch (err) {
    if (err instanceof H1AuthMissingError) {
      console.error(chalk.red(err.message));
      process.exitCode = EXIT_AUTH;
      return null;
    }
    console.error(chalk.red(err instanceof Error ? err.message : String(err)));
    process.exitCode = EXIT_AUTH;
    return null;
  }
}

function parseLimit(input: string | undefined, def: number, max: number): number | null {
  if (input === undefined) return def;
  const n = Number.parseInt(input, 10);
  if (!Number.isFinite(n) || n <= 0) {
    console.error(chalk.red(`Error: --limit must be a positive integer (got ${JSON.stringify(input)}).`));
    process.exitCode = EXIT_USER_ERROR;
    return null;
  }
  if (n > max) {
    console.error(chalk.red(`Error: --limit cannot exceed ${max} (got ${n}).`));
    process.exitCode = EXIT_USER_ERROR;
    return null;
  }
  return n;
}

function handleApiError(err: unknown, op: string): void {
  if (err instanceof H1AuthError) {
    console.error(`FAIL (HTTP 401)`);
    process.exitCode = EXIT_AUTH;
    return;
  }
  if (err instanceof H1ForbiddenError) {
    console.error(chalk.red(`FAIL (HTTP 403) — ${op}: ${err.message}`));
    process.exitCode = EXIT_AUTH;
    return;
  }
  if (err instanceof H1RateLimitError) {
    console.error(chalk.red(`FAIL (HTTP 429) — ${op}: rate limited (Retry-After=${err.retryAfterSec}s)`));
    process.exitCode = EXIT_NET;
    return;
  }
  if (err instanceof H1NetworkError) {
    console.error(chalk.red(`FAIL (network) — ${op}: ${err.message}`));
    process.exitCode = EXIT_NET;
    return;
  }
  if (err instanceof H1Error) {
    console.error(chalk.red(`FAIL (HTTP ${err.status ?? "?"}) — ${op}`));
    process.exitCode = EXIT_USER_ERROR;
    return;
  }
  console.error(chalk.red(`FAIL — ${op}: ${err instanceof Error ? err.message : String(err)}`));
  process.exitCode = EXIT_USER_ERROR;
}

function renderProgramTable(list: H1Program[]): void {
  if (list.length === 0) {
    console.log(chalk.gray("No programs match."));
    return;
  }
  // Compute column widths from the visible rows. We pad with spaces so
  // colourised text still aligns visually (chalk doesn't change visible
  // length; we measure pre-colour strings).
  const rows = list.map((p) => ({
    handle: p.attributes.handle,
    name: p.attributes.name,
    state: p.attributes.state ?? "",
    bounty: p.attributes.offers_bounties ? "yes" : "no",
    // We don't know scope-count without a second request per program;
    // emit "?" rather than fan out N parallel requests for a list view.
    // `pwnkit h1 programs show <handle>` is the right path for a real
    // count.
    scopes: "?",
  }));
  const colW = (key: keyof (typeof rows)[number]) =>
    Math.min(32, Math.max(key.length, ...rows.map((r) => r[key].length)));
  const w = {
    handle: colW("handle"),
    name: colW("name"),
    state: colW("state"),
    bounty: Math.max("bounty".length, 3),
    scopes: Math.max("scopes".length, 6),
  };
  const header = `${"handle".padEnd(w.handle)}  ${"name".padEnd(w.name)}  ${"state".padEnd(w.state)}  ${"bounty".padEnd(w.bounty)}  ${"scopes".padEnd(w.scopes)}`;
  console.log(chalk.bold(header));
  console.log(chalk.dim("-".repeat(header.length)));
  for (const r of rows) {
    const truncName = r.name.length > 32 ? r.name.slice(0, 29) + "..." : r.name;
    console.log(
      `${r.handle.padEnd(w.handle)}  ${truncName.padEnd(w.name)}  ${r.state.padEnd(w.state)}  ${r.bounty.padEnd(w.bounty)}  ${r.scopes.padEnd(w.scopes)}`,
    );
  }
  console.log("");
  console.log(chalk.dim(`${list.length} program(s). 'scopes' column is '?' here — run 'pwnkit h1 programs show <handle>' for an exact count.`));
}

function renderProgramDetail(
  program: H1Program,
  scopes: Parameters<typeof summariseScopes>[0],
): void {
  const a = program.attributes;
  console.log("");
  console.log(`  ${chalk.bold(a.name)} ${chalk.gray(`(${a.handle})`)}`);
  console.log(`  ${chalk.gray("state:")}    ${a.state ?? chalk.dim("?")}`);
  console.log(`  ${chalk.gray("bounty:")}   ${a.offers_bounties ? chalk.green("yes") : chalk.gray("no")}`);
  console.log(`  ${chalk.gray("currency:")} ${a.currency ?? chalk.dim("?")}`);

  const summary = summariseScopes(scopes);
  console.log("");
  console.log(`  ${chalk.bold("Scope summary")} (in:${summary.totalIn} / out:${summary.totalOut})`);
  for (const [type, count] of Object.entries(summary.inScopeByType).sort()) {
    console.log(`    ${chalk.green("in ")} ${type.padEnd(16)} ${count}`);
  }
  for (const [type, count] of Object.entries(summary.outOfScopeByType).sort()) {
    console.log(`    ${chalk.gray("out")} ${type.padEnd(16)} ${count}`);
  }

  // Automation verdict — heuristic over the policy text. H1's structured
  // program response doesn't always populate a free-text policy; in that
  // case we report "unclear" and tell the operator to read it manually.
  // The "mixed" verdict means the policy combines a prohibition with a
  // contrast clause that re-permits something — the operator MUST read
  // the policy themselves before running automated tooling. See issue
  // #266 (Flutter UK&I) for the canonical contrast-clause case.
  const policyText = a.policy ?? "";
  const verdict = automationVerdict(policyText);
  console.log("");
  console.log(`  ${chalk.bold("Automation verdict (heuristic):")} ${formatVerdict(verdict)}`);
  if (verdict === "mixed") {
    console.log(
      chalk.dim(
        `    The policy combines a prohibition with a contrast clause (e.g. "...although custom tools allowed at 5 rps").`,
      ),
    );
    console.log(
      chalk.dim(`    Read the full policy at https://hackerone.com/${a.handle} before running automated tooling.`),
    );
  } else if (verdict === "unclear") {
    console.log(chalk.dim(`    Read the policy at https://hackerone.com/${a.handle} before running automated tooling.`));
  }
  console.log("");
}

function formatVerdict(v: ReturnType<typeof automationVerdict>): string {
  switch (v) {
    case "forbidden":
      return chalk.red("forbidden");
    case "permitted":
      return chalk.green("permitted");
    case "mixed":
      return chalk.yellow("mixed (review policy directly)");
    case "unclear":
      return chalk.yellow("unclear");
  }
}
