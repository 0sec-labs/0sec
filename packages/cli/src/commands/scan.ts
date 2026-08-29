import { readFileSync, existsSync } from "node:fs";
import type { Command } from "commander";
import chalk from "chalk";
import { z } from "zod";
import type { ScanDepth, OutputFormat, RuntimeMode, ScanMode, AuthConfig } from "@0sec/shared";
import { networkScopeRequiredRefusal, targetRequiresScope } from "@0sec/core";
import { renderReplay } from "../formatters/replay.js";
import { runUnified } from "./run.js";
import { reportSummarySchema, formatZodError } from "./schemas.js";

/**
 * Parse the --auth flag value into an AuthConfig object.
 * Accepts either a JSON string or a path to a JSON file.
 */
function parseAuthFlag(value: string): AuthConfig {
  let raw: string;
  // If the value looks like a file path (no leading '{'), try reading it
  if (!value.trimStart().startsWith("{") && existsSync(value)) {
    raw = readFileSync(value, "utf-8");
  } else {
    raw = value;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      `Invalid --auth value: must be a JSON string or path to a JSON file.\n` +
      `Examples:\n` +
      `  --auth '{"type":"bearer","token":"xxx"}'\n` +
      `  --auth '{"type":"cookie","value":"session=abc123"}'\n` +
      `  --auth '{"type":"basic","username":"admin","password":"pass"}'\n` +
      `  --auth '{"type":"header","name":"X-API-Key","value":"xxx"}'\n` +
      `  --auth ./auth.json`,
    );
  }

  const obj = parsed as Record<string, unknown>;
  const validTypes = new Set(["bearer", "cookie", "basic", "header"]);
  if (!obj || typeof obj !== "object" || !validTypes.has(obj.type as string)) {
    throw new Error(
      `Invalid auth config: "type" must be one of: bearer, cookie, basic, header. Got: ${JSON.stringify(obj)}`,
    );
  }

  return obj as unknown as AuthConfig;
}

/**
 * Parse a JSON `string[]` env var. Returns `[]` for unset/empty. Throws a
 * clear, env-named error on malformed JSON or a non-string-array shape so a
 * worker misconfiguration fails the scan at boot rather than silently
 * degrading the scope.
 */
function parseStringArrayEnv(name: string, raw: string | undefined): string[] {
  const trimmed = raw?.trim();
  if (!trimmed) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error(`${name}: must be a JSON array of strings (got: ${trimmed.slice(0, 80)})`);
  }
  if (!Array.isArray(parsed) || parsed.some((x) => typeof x !== "string")) {
    throw new Error(`${name}: must be a JSON array of strings`);
  }
  return parsed as string[];
}

/**
 * Parse a positive-integer env var with a default. Throws on a value that is
 * present but not a non-negative integer.
 */
function parseIntEnv(name: string, raw: string | undefined, def: number): number {
  const trimmed = raw?.trim();
  if (!trimmed) return def;
  const n = Number(trimmed);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 0) {
    throw new Error(`${name}: must be a non-negative integer (got: ${trimmed})`);
  }
  return n;
}

/**
 * Resolve the http_audit FROZEN CONTRACT env vars into a normalized config.
 * Defaults: allowed hosts → [base host]; allowed paths → [] (allow all);
 * rate limit → 5 rps; kill switch → 1800s. Throws on malformed input.
 *
 * `target` is the resolved --target value; 0SEC_TARGET_BASE_URL takes
 * precedence as the base when both are set (the worker always sets it), but
 * either way the base host is the default sole allowed host.
 */
function parseHttpAuditEnv(
  target: string,
  env: NodeJS.ProcessEnv,
): { allowedHosts: string[]; allowedPaths: string[]; rateLimitRps: number; killAfterSec: number } {
  const baseUrl = env["0SEC_TARGET_BASE_URL"]?.trim() || target;
  let baseHost: string;
  try {
    baseHost = new URL(baseUrl).hostname;
  } catch {
    throw new Error(
      `http_audit: could not derive base host from '${baseUrl}'. Set 0SEC_TARGET_BASE_URL to an absolute http(s) URL.`,
    );
  }
  const allowedHosts = parseStringArrayEnv(
    "0SEC_TARGET_ALLOWED_HOSTS",
    env["0SEC_TARGET_ALLOWED_HOSTS"],
  );
  const allowedPaths = parseStringArrayEnv(
    "0SEC_TARGET_ALLOWED_PATHS",
    env["0SEC_TARGET_ALLOWED_PATHS"],
  );
  return {
    // Empty allowed-hosts list defaults to the base host only.
    allowedHosts: allowedHosts.length > 0 ? allowedHosts : [baseHost],
    allowedPaths,
    rateLimitRps: parseIntEnv("0SEC_TARGET_RATE_LIMIT_RPS", env["0SEC_TARGET_RATE_LIMIT_RPS"], 5),
    killAfterSec: parseIntEnv("0SEC_TARGET_KILL_AFTER_SEC", env["0SEC_TARGET_KILL_AFTER_SEC"], 1800),
  };
}

/**
 * Validate `--emit <target>` against the supported set (currently only `pr`).
 * Returns the typed value or undefined when no flag was passed; throws
 * (process.exit 2) on an unknown emitter so the user sees the typo early
 * rather than after a long scan.
 */
function validateEmitTarget(value: string | undefined): "pr" | undefined {
  if (value === undefined) return undefined;
  if (value === "pr") return "pr";
  console.error(chalk.red(`Unknown --emit target '${value}'. Supported: pr.`));
  process.exit(2);
}

/**
 * `--features` tokens that name a PRESET rather than a single flag.
 *
 * Kept as a literal here on purpose: this handler must not import
 * `@0sec/core` just to recognise a token, since core is loaded lazily so
 * `--help` stays fast. The authoritative expansion still lives in core — this
 * set only decides *which* tokens get forwarded as `0SEC_FEATURE_PRESET`.
 *
 * `feature-preset-tokens.test.ts` asserts every entry here resolves to a real
 * preset in core, so the two cannot drift apart silently.
 */
export const PRESET_TOKENS: ReadonlySet<string> = new Set([
  "fp-moat",
  "fp_moat",
  "fpmoat",
  "moat",
]);

export function registerScanCommand(program: Command): void {
  program
    .command("scan")
    .description("Run autonomous pentest against a URL, web app, or MCP server")
    .requiredOption("--target <target>", "Target URL or mcp:// endpoint")
    .option("--depth <depth>", "Scan depth: quick, default, deep", "default")
    .option("--format <format>", "Output format: terminal, json, md, html, sarif, pdf", "terminal")
    .option("--runtime <runtime>", "Runtime: auto (default), api, claude, codex, gemini", "auto")
    .option("--mode <mode>", "Scan mode: probe, deep, mcp, web, http_audit. `http_audit` is the worker-driven authed HTTP scan: it reads target config from 0SEC_TARGET_* env vars (0SEC_TARGET_BASE_URL, 0SEC_TARGET_AUTH_JSON, 0SEC_TARGET_ALLOWED_HOSTS, 0SEC_TARGET_ALLOWED_PATHS, 0SEC_TARGET_RATE_LIMIT_RPS, 0SEC_TARGET_KILL_AFTER_SEC), builds an in-memory ScopePolicy + path allowlist + per-host RateLimiter + wall-clock kill switch, runs the web-pentest loop, and emits an enforcement_summary block in the report JSON.")
    .option("--timeout <ms>", "Request timeout in milliseconds", "30000")
    .option("--db-path <path>", "Path to SQLite database")
    .option("--api-key <key>", "API key for LLM provider")
    .option("-m, --model <model>", "LLM model to use")
    .option("--repo <path>", "Source code path for white-box scanning (read code before attacking)")
    .option("--auth <json>", "Auth credentials as JSON string or path to JSON file (types: bearer, cookie, basic, header)")
    .option("--scope <path>", "Path to a JSON scope file ({in_scope, out_of_scope} arrays of host / *.domain / cidr rules). Out-of-scope URLs return as ToolResult.error at every fetch site. See 0sec#215.")
    .option("--allow-scanners", "Disable the generic-scanner suppression gate (0sec#217). When --scope is set, the agent refuses to spawn sqlmap/wpscan/nikto/gobuster/dirb/wfuzz/ffuf/`nmap -sV`/`nmap -A` by default; pass this flag only when the engagement explicitly permits generic-scanner traffic.", false)
    .option("--require-scope", "Refuse to start unless an engagement scope is configured (0sec#133). The bash egress guards (out-of-scope URL refusal, http_audit path allowlist, generic-scanner suppression, auth-header injection) only run when a ScopePolicy is set; without this flag a scan with no --scope warns loudly and records a `scope_guards_inert` event but still runs. Equivalent to 0SEC_REQUIRE_SCOPE=1.", false)
    .option(
      "--attribution-header <name=value>",
      "Attribution header to attach to in-scope outbound requests (0sec#216). Repeatable: pass `--attribution-header X-A=1 --attribution-header X-B=2`. Lower precedence than the scope file's `attribution.headers` block and 0SEC_ATTRIBUTION_HEADERS env var. NEVER attached to out-of-scope traffic.",
      (value: string, prev: string[] = []) => [...prev, value],
    )
    .option(
      "--attribution-ua <token>",
      "Engagement token to embed in the User-Agent on in-scope traffic (0sec#216). Resulting UA: `0sec/<ver> (engagement: <token>)`. Lower precedence than the scope file's `attribution.user_agent_token` and 0SEC_ATTRIBUTION_UA_TOKEN env var.",
    )
    .option("--api-spec <path>", "Path to OpenAPI 3.x / Swagger 2.0 spec file (JSON or YAML) for pre-loaded endpoint knowledge")
    .option("--export <target>", "Export findings to issue tracker (e.g. github:owner/repo)")
    .option("--race", "Enable benchmark/CTF best-of-N strategy racing: run multiple flag-oriented attack strategies in parallel. Do not use for normal live-target audits.", false)
    .option("--egats", "Enable EGATS (Evidence-Gated Attack Tree Search): beam-search over a hypothesis tree", false)
    .option("--cost-ceiling <usd>", "Hard per-scan USD cost ceiling. Aborts cleanly with partial findings if exceeded. Overrides 0SEC_COST_CEILING_USD.")
    .option(
      "--rate-limit <spec>",
      "Per-host requests-per-second cap for outbound scan traffic. Plain number (e.g. '5') sets the default rps; comma-separated form 'api.example.com=5,*.example.com=3:6,2' allows per-host overrides and a fallback default. Default is 5 rps when unset. Each host carries an independent token bucket; 429 responses honour Retry-After (with a conservative 60s floor).",
    )
    .option(
      "--engagement-profile <name>",
      "Engagement hardening posture for authorized enterprise work. 'standard' (default) is the existing behaviour. 'conservative' applies ONE quiet posture: no password-reset burst probe, the deterministic web-recon pre-pass routed through the per-host rate limiter, no adaptive WAF-evasion ladder, full jitter on the token bucket, and a reduced default of 1 rps/host. The applied posture is recorded in the report as `engagementPosture` so it can be handed to the client as evidence. Lower precedence than the scope file's `engagement` block and 0SEC_ENGAGEMENT_PROFILE.",
    )
    .option(
      "--no-waf-evasion",
      "Disable the adaptive WAF-evasion ladder (default: on). When a response classifies as blocked, the engine normally retries with encoding/casing/whitespace-mutated payload variants, which escalates a routine WAF block into a SOC incident. Detection and reporting of the block are unaffected. Independent of --engagement-profile; env form: 0SEC_WAF_EVASION=0.",
    )
    .option("--tui", "Open the local terminal UI after the scan completes", false)
    .option(
      "--features <list>",
      "Comma-separated list of opt-in feature flags to enable for this scan (e.g. 'wp_fingerprint,web_search'). Each flag maps to the corresponding 0SEC_FEATURE_<NAME> environment variable. The token 'fp-moat' is a preset that enables the full false-positive moat (reachability, multi-modal, publishability, pov-gate, poc-gen, consensus) for an A/B run; an env var you set yourself always wins over the preset, so '0SEC_FEATURE_POV_GATE=0 --features fp-moat' is a single-layer ablation.",
    )
    .option(
      "--no-decoy-detection",
      "Disable the anti-honeypot flag-shape validator (default: on). When enabled, the `done` tool rejects low-confidence flags (e.g. `FLAG{I'm_a_Script_Kiddie}`) once with a hint to keep exploring. See GitHub issue #82.",
    )
    .option(
      "--dispatch <mode>",
      "Tool-call protocol for the legacy text agent loop (0sec#232): 'json' (default TOOL_CALL JSON lines), 'xml' (<command>/<flag>/<finding>/<note> tags — survives malformed JSON from cheap OpenRouter / Gemini / DeepSeek models), or 'auto' (xml for cheap providers, json otherwise). No effect on the native API loop. Env override: 0SEC_DISPATCH=xml.",
      "auto",
    )
    .option(
      "--emit <target>",
      "Emit target. Default unset → existing terminal/json/etc. `pr` → emit each reproduced finding as a GitHub PR with repro + suggested patch (0sec#377). Unverified findings roll up into `hypotheses.md`.",
    )
    .option("--base <branch>", "Base branch for `--emit pr` (default: main)")
    .option("--dry-run", "For `--emit pr`: print git/gh commands instead of running them. Auto-enabled if `gh auth status` fails.", false)
    .option("--emit-out-dir <path>", "Directory for `--emit pr` rollup files (default: system temp)")
    .option("--resume <run-id>", "Resume a previous run from its journal on disk (0sec#374). Locates the run's journal, rehydrates agent state, and continues from the last entry.")
    .option("--branch-from <entry-index>", "Branch the journal at the given entry index before resuming (requires --resume). Copies entries 0..N into a new run and resumes from there.")
    .option("--verbose", "Show detailed output", false)
    .option("--replay", "Replay the last scan's results", false)
    .action(async (opts) => {
      // ── Replay last scan (--replay flag) ──
      if (opts.replay) {
        try {
          const { osecDB } = await import("@0sec/db");
          const db = new osecDB(opts.dbPath);
          const scans = db.listScans(1);
          if (scans.length === 0) {
            console.error(chalk.red("No scan history found. Run a scan first."));
            db.close();
            process.exit(2);
          }
          const lastScan = scans[0];
          const dbFindings = db.getFindings(lastScan.id);
          db.close();

          // Validated parse: zod enforces the ReportSummary shape so that an
          // older schema version or a corrupt DB row surfaces as a clear
          // error here rather than crashing the replay renderer downstream
          // (`data.summary.totalAttacks` is read without a nullish guard).
          // We zero-fill on missing column to preserve the original behaviour
          // for legitimate empty rows.
          const emptySummary = {
            totalAttacks: 0, totalFindings: 0,
            critical: 0, high: 0, medium: 0, low: 0, info: 0,
          };
          let summary;
          if (lastScan.summary) {
            try {
              const parsed: unknown = JSON.parse(lastScan.summary);
              summary = reportSummarySchema.parse(parsed);
            } catch (err) {
              if (err instanceof z.ZodError) {
                console.error(
                  chalk.red(
                    `[replay] scan summary failed validation: ${formatZodError(err, "summary")}`,
                  ),
                );
              } else if (err instanceof SyntaxError) {
                console.error(
                  chalk.red(`[replay] scan summary is not valid JSON: ${err.message}`),
                );
              } else {
                console.error(
                  chalk.red(`[replay] failed to parse scan summary: ${err instanceof Error ? err.message : String(err)}`),
                );
              }
              process.exit(2);
            }
          } else {
            summary = emptySummary;
          }

          const findings = dbFindings.map((f: any) => ({
            id: f.id, templateId: f.templateId, title: f.title,
            description: f.description, severity: f.severity,
            category: f.category, status: f.status,
            evidence: { request: f.evidenceRequest, response: f.evidenceResponse, analysis: f.evidenceAnalysis ?? undefined },
            timestamp: f.timestamp,
          }));

          await renderReplay({ target: lastScan.target, findings, summary, durationMs: lastScan.durationMs ?? 0 });
          return;
        } catch (err) {
          console.error(chalk.red("Failed to replay: " + (err instanceof Error ? err.message : String(err))));
          process.exit(2);
        }
      }

      // Auto-detect scan mode from the target URL scheme unless the user
      // explicitly passed --mode. Before this default, running
      //   0sec-cli scan --target https://example.com
      // silently used the LLM/AI-agent-focused `attackPrompt` (mode=deep)
      // against a plain web application, which gave the attack agent no
      // web-pentest-specific guidance and caused a "bundle paralysis"
      // failure mode — the agent would download a minified JS bundle once
      // and then spend 6-8 turns re-grepping it for secrets instead of
      // actually probing the live API endpoints it had discovered. For
      // http(s) targets the correct default is the shell-first web-
      // pentest prompt, which is what `mode: "web"` selects.
      const targetStr = String(opts.target);
      const mode = (opts.mode
        ? String(opts.mode)
        : targetStr.startsWith("mcp://")
          ? "mcp"
          : /^https?:\/\//i.test(targetStr)
            ? "web"
            : "deep") as ScanMode;
      const validModes = new Set<ScanMode>(["probe", "deep", "mcp", "web", "http_audit"]);
      if (!validModes.has(mode)) {
        console.error(chalk.red(`Unknown mode '${mode}'. Valid: ${[...validModes].join(", ")}`));
        process.exit(2);
      }

      // ── Parse --features flag: map each token to 0SEC_FEATURE_<UPPER>=1 ──
      // The core `features` object for most flags is captured at import time,
      // so in general you should prefer setting 0SEC_FEATURE_* env vars in
      // your shell. Flags that are declared as getters (e.g. wp_fingerprint)
      // re-read the env at access time and therefore honor this flag even
      // though it's applied inside the action handler.
      //
      // A token that names a PRESET (e.g. `fp-moat`) expands to that preset's
      // whole flag set instead of becoming a single env var. Without this, the
      // token would silently set the meaningless `0SEC_FEATURE_FP_MOAT` and
      // enable nothing — a failure mode that looks like success, which is the
      // worst possible one for a flag whose entire purpose is enabling an A/B.
      //
      // A preset token sets `0SEC_FEATURE_PRESET` instead of a single flag.
      // The expansion itself lives in core (`agent/features.ts` consults the
      // preset when a flag's own var is unset), so every entry point honours
      // it — this handler only has to forward the name. Without this branch
      // the token would set the meaningless `0SEC_FEATURE_FP_MOAT` and
      // enable nothing: a failure that looks like success, which is the worst
      // outcome for a flag whose only purpose is enabling an A/B.
      if (opts.features) {
        const tokens = String(opts.features)
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean);
        for (const token of tokens) {
          if (PRESET_TOKENS.has(token.toLowerCase())) {
            process.env["0SEC_FEATURE_PRESET"] = token.toLowerCase();
            continue;
          }
          const envName = `0SEC_FEATURE_${token.toUpperCase().replace(/[^A-Z0-9]/g, "_")}`;
          process.env[envName] = "1";
        }
      }

      // --no-decoy-detection → disable the anti-honeypot validator. The
      // core `features.decoyDetection` flag is a getter, so flipping this
      // env var inside the action handler is still honored at tool-dispatch
      // time. See GitHub issue #82.
      if (opts.decoyDetection === false) {
        process.env["0SEC_FEATURE_DECOY_DETECTION"] = "0";
      }

      // --require-scope → fail closed when no engagement scope is configured
      // (0sec#133). Same env-var mechanism as above: the core reads
      // 0SEC_REQUIRE_SCOPE at scan boot and at the bash tool, which is also
      // how the cloud worker (which builds argv from a fixed table) can turn
      // strictness on without an engine release.
      if (opts.requireScope) {
        process.env["0SEC_REQUIRE_SCOPE"] = "1";
      }

      // Parse --auth flag if provided
      let authConfig: AuthConfig | undefined;
      if (opts.auth) {
        try {
          authConfig = parseAuthFlag(opts.auth as string);
        } catch (err) {
          console.error(chalk.red(err instanceof Error ? err.message : String(err)));
          process.exit(2);
        }
      }

      // ── http_audit env bridge (FROZEN CONTRACT) ──
      // In `--mode http_audit` the worker drives the scan entirely through
      // 0SEC_TARGET_* env vars. We parse them here (fail-fast on malformed
      // JSON, same rationale as --scope/--auth pre-flight) and thread the
      // results through RunOptions → ScanConfig, where the core builds the
      // in-memory ScopePolicy + path allowlist + RateLimiter + kill switch.
      let httpAudit: {
        allowedHosts: string[];
        allowedPaths: string[];
        rateLimitRps: number;
        killAfterSec: number;
      } | undefined;
      if (mode === "http_audit") {
        try {
          httpAudit = parseHttpAuditEnv(targetStr, process.env);
        } catch (err) {
          console.error(chalk.red(err instanceof Error ? err.message : String(err)));
          process.exit(2);
        }
        // 0SEC_TARGET_AUTH_JSON (if set) wins over any --auth flag in
        // http_audit mode — the worker contract is env-driven.
        const authJson = process.env["0SEC_TARGET_AUTH_JSON"]?.trim();
        if (authJson) {
          try {
            authConfig = parseAuthFlag(authJson);
          } catch (err) {
            console.error(
              chalk.red(
                `0SEC_TARGET_AUTH_JSON: ${err instanceof Error ? err.message : String(err)}`,
              ),
            );
            process.exit(2);
          }
        }
      }

      // Validate --scope flag if provided. We intentionally fail HARD
      // here rather than soft-warning: a coordinated-disclosure scan with
      // a missing or malformed scope file is exactly the configuration
      // error that should block the scan from starting (see 0sec#215).
      let scopeFile: string | undefined;
      if (opts.scope) {
        scopeFile = String(opts.scope);
        if (!existsSync(scopeFile)) {
          console.error(chalk.red(`--scope: file not found: ${scopeFile}`));
          process.exit(2);
        }
        // Pre-validate that the file parses and the target is in scope.
        // We re-read inside the core runner anyway, but doing it here
        // gives the operator a clear error before the LLM/runtime cost
        // of starting a scan is incurred.
        try {
          const { loadScope } = await import("@0sec/core");
          const policy = loadScope(scopeFile);
          const verdict = policy.match(String(opts.target));
          if (!verdict.allowed) {
            console.error(
              chalk.red(
                `--target ${opts.target} is out of scope per ${scopeFile}: ${verdict.reason}`,
              ),
            );
            process.exit(2);
          }
        } catch (err) {
          console.error(chalk.red(err instanceof Error ? err.message : String(err)));
          process.exit(2);
        }
      }

      const hasNetworkScope = Boolean(scopeFile) || Boolean(httpAudit?.allowedHosts.length);
      if (targetRequiresScope(targetStr) && !hasNetworkScope) {
        console.error(chalk.red(networkScopeRequiredRefusal(targetStr)));
        process.exit(2);
        return;
      }

      // Pre-validate attribution config (0sec#216). Same rationale as
      // the --scope pre-flight: a malformed 0SEC_ATTRIBUTION_HEADERS
      // env var or an invalid scope-file `attribution` block is a config
      // error, and the operator should see it before the scan boots.
      try {
        const {
          loadScope,
          resolveAttribution,
          extractAttributionFromScopeJson,
        } = await import("@0sec/core");
        const policy = scopeFile ? loadScope(scopeFile) : undefined;
        resolveAttribution({
          scopeFileBlock: policy ? extractAttributionFromScopeJson(policy.raw) : undefined,
          env: process.env,
          cliHeaders: opts.attributionHeader as string[] | undefined,
          cliUaToken: opts.attributionUa as string | undefined,
        });
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exit(2);
      }

      // Pre-validate the engagement hardening posture. Same rationale as the
      // attribution pre-flight: a typo'd `--engagement-profile`, a bad
      // 0SEC_ENGAGEMENT_RATE_RPS, or a malformed scope-file `engagement`
      // block must fail here, not after the loud default already ran.
      // `--no-waf-evasion` sets opts.wafEvasion to false; commander leaves it
      // `true` when the flag is absent, which we map back to "unset" so the
      // scope file / env keep their precedence.
      const cliWafEvasion = opts.wafEvasion === false ? false : undefined;
      try {
        const {
          loadScope,
          resolveEngagementProfile,
          extractEngagementFromScopeJson,
        } = await import("@0sec/core");
        const policy = scopeFile ? loadScope(scopeFile) : undefined;
        resolveEngagementProfile({
          scopeFileBlock: policy ? extractEngagementFromScopeJson(policy.raw) : undefined,
          env: process.env,
          cliProfile: opts.engagementProfile as string | undefined,
          cliWafEvasion,
        });
      } catch (err) {
        console.error(chalk.red(err instanceof Error ? err.message : String(err)));
        process.exit(2);
      }

      // Resolve cost ceiling: --cost-ceiling flag wins over 0SEC_COST_CEILING_USD env.
      let costCeilingUsd: number | undefined;
      const ceilingSource =
        (opts.costCeiling as string | undefined) ?? process.env["0SEC_COST_CEILING_USD"];
      if (ceilingSource !== undefined && ceilingSource !== "") {
        const parsed = Number(ceilingSource);
        if (!Number.isFinite(parsed) || parsed <= 0) {
          console.error(
            chalk.red(
              `Invalid cost ceiling '${ceilingSource}': must be a positive number (USD).`,
            ),
          );
          process.exit(2);
        }
        costCeilingUsd = parsed;
      }

      // --rate-limit: validate the spec at start-of-scan rather than
      // discovering a typo five hours into a deep scan.
      const rateLimit = opts.rateLimit as string | undefined;
      if (rateLimit !== undefined && rateLimit !== "") {
        try {
          const { parseRateLimitFlag } = await import("@0sec/core");
          parseRateLimitFlag(rateLimit);
        } catch (err) {
          console.error(chalk.red(err instanceof Error ? err.message : String(err)));
          process.exit(2);
        }
      }

      const branchFrom = opts.branchFrom as string | undefined;
      await runUnified({
        target: opts.target,
        targetType: "url",
        resumeScanId: opts.resume as string | undefined,
        branchFromEntry: branchFrom !== undefined ? parseInt(branchFrom, 10) : undefined,
        mode,
        depth: opts.depth as ScanDepth,
        format: (opts.format === "md" ? "markdown" : opts.format) as OutputFormat,
        runtime: (opts.runtime as RuntimeMode) ?? "auto",
        timeout: parseInt(opts.timeout, 10),
        verbose: opts.verbose as boolean,
        dbPath: opts.dbPath as string | undefined,
        apiKey: opts.apiKey as string | undefined,
        model: opts.model as string | undefined,
        repoPath: opts.repo as string | undefined,
        auth: authConfig,
        apiSpecPath: opts.apiSpec as string | undefined,
        exportTarget: opts.export as string | undefined,
        race: opts.race as boolean | undefined,
        egats: opts.egats as boolean | undefined,
        costCeilingUsd,
        rateLimit,
        tui: opts.tui as boolean,
        scopeFile,
        allowScanners: opts.allowScanners as boolean | undefined,
        attributionHeaders: opts.attributionHeader as string[] | undefined,
        attributionUaToken: opts.attributionUa as string | undefined,
        engagementProfile: opts.engagementProfile as string | undefined,
        wafEvasion: cliWafEvasion,
        dispatchMode: opts.dispatch as "json" | "xml" | "auto" | undefined,
        emit: validateEmitTarget(opts.emit as string | undefined),
        emitPrBase: opts.base as string | undefined,
        emitPrDryRun: opts.dryRun as boolean | undefined,
        emitOutDir: opts.emitOutDir as string | undefined,
        // http_audit env-bridge config (FROZEN CONTRACT). Undefined for all
        // other modes; when set, core builds the in-memory enforcement stack.
        httpAuditAllowedHosts: httpAudit?.allowedHosts,
        httpAuditAllowedPaths: httpAudit?.allowedPaths,
        httpAuditRateLimitRps: httpAudit?.rateLimitRps,
        httpAuditKillAfterSec: httpAudit?.killAfterSec,
      });
    });
}
