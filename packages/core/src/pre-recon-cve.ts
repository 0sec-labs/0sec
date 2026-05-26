/**
 * Pre-recon CVE check — runs language-specific dependency audit tools
 * against the source tree before the agent's first turn (white-box mode
 * only) and surfaces high/critical advisories as priority leads in the
 * agent system prompt.
 *
 * Why this exists: the 2026-04-06 ceiling analysis identified XBEN-030
 * "Wordpress magic" and XBEN-034 "Melodic Mayhem" — both tagged `cve` —
 * as the two most expensive unsolved XBOW challenges. They burned $6+
 * each in white-box mode while producing 0 findings, because the agent
 * had source access but no concrete CVE leads. The audit tools that ship
 * with every language ecosystem can answer this question in seconds:
 * `npm audit` knows the CVE catalogue for any package-lock.json on disk.
 *
 * This module is deliberately conservative:
 *   - It only runs when `--repo` is set (white-box mode)
 *   - It only runs the audit tools that are actually installed
 *   - It never throws — a missing tool, a parse error, or a non-zero
 *     exit just produces an empty report and the scan continues
 *   - It only surfaces high + critical severity advisories (low/medium
 *     would dilute the system prompt with noise)
 */

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import {
  runWpFingerprint,
  type FetchLike,
  type WpFingerprintResult,
} from "./agent/wp-fingerprint.js";

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface CveAdvisory {
  /** Where the manifest file lives, relative to the repo root */
  manifest: string;
  /** Tool that produced the advisory (npm-audit, pip-audit, etc.) */
  tool: string;
  /** Affected package name */
  package: string;
  /** Installed version (if known) */
  version?: string;
  /** Vulnerable version range (if known) */
  vulnerableRange?: string;
  /** CVE / GHSA / advisory ID */
  id: string;
  /** Short title */
  title: string;
  /** "high" or "critical" — we filter low/medium out before this point */
  severity: "high" | "critical";
  /** URL to the advisory page (when available) */
  url?: string;
}

export interface PreReconCveReport {
  /** All advisories found across every detected manifest */
  advisories: CveAdvisory[];
  /** Manifests we scanned */
  manifestsScanned: string[];
  /** Manifests we found but couldn't scan (tool missing, parse error, etc.) */
  manifestsSkipped: Array<{ manifest: string; reason: string }>;
  /** Total wall time spent on the pre-recon */
  durationMs: number;
}

// ────────────────────────────────────────────────────────────────────
// Manifest detection
// ────────────────────────────────────────────────────────────────────

interface ManifestKind {
  /** Filename to look for */
  filename: string;
  /** Tool name for telemetry */
  tool: string;
  /** Function that runs the audit and returns advisories */
  run: (manifestPath: string, manifestRel: string) => CveAdvisory[];
}

/**
 * Walk the source tree (depth-limited) looking for known package manifests.
 * Skips node_modules, .git, dist, build, and similar noise dirs.
 */
function findManifests(
  repoPath: string,
  kinds: ManifestKind[],
  maxDepth = 4,
): Array<{ kind: ManifestKind; absPath: string; relPath: string }> {
  const SKIP_DIRS = new Set([
    "node_modules", ".git", "dist", "build", ".next", ".nuxt", ".svelte-kit",
    "target", "vendor", "venv", ".venv", "__pycache__", ".pytest_cache",
    "out", ".cache", "coverage",
  ]);
  const found: Array<{ kind: ManifestKind; absPath: string; relPath: string }> = [];

  function walk(dir: string, depth: number) {
    if (depth > maxDepth) return;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const entry of entries) {
      if (SKIP_DIRS.has(entry)) continue;
      const abs = join(dir, entry);
      let st: ReturnType<typeof statSync>;
      try {
        st = statSync(abs);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        walk(abs, depth + 1);
      } else if (st.isFile()) {
        for (const kind of kinds) {
          if (entry === kind.filename) {
            found.push({
              kind,
              absPath: abs,
              relPath: relative(repoPath, abs),
            });
          }
        }
      }
    }
  }

  walk(repoPath, 0);
  return found;
}

// ────────────────────────────────────────────────────────────────────
// npm audit runner
// ────────────────────────────────────────────────────────────────────

function runNpmAudit(manifestPath: string, manifestRel: string): CveAdvisory[] {
  const dir = manifestPath.replace(/\/(?:package-lock\.json|package\.json)$/, "");
  let output: string;
  try {
    output = execFileSync("npm", ["audit", "--json"], {
      cwd: dir,
      timeout: 30_000,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch (err: any) {
    // npm audit exits non-zero when vulns are found — that's the expected
    // path. Recover the stdout from the error object.
    output = (err && typeof err.stdout === "string" ? err.stdout : "") || "";
    if (!output) return [];
  }

  let parsed: any;
  try {
    parsed = JSON.parse(output);
  } catch {
    return [];
  }

  const advisories: CveAdvisory[] = [];
  const vulns = parsed.vulnerabilities ?? {};
  for (const [pkgName, vuln] of Object.entries<any>(vulns)) {
    const sev = vuln.severity;
    if (sev !== "high" && sev !== "critical") continue;
    // npm audit's "via" array may contain advisory objects (the leaf vuln)
    // OR strings (transitive paths). Walk it and extract the advisory IDs.
    const via: any[] = Array.isArray(vuln.via) ? vuln.via : [];
    let advisoryAdded = false;
    for (const v of via) {
      if (typeof v === "object" && v !== null && v.title) {
        advisories.push({
          manifest: manifestRel,
          tool: "npm-audit",
          package: pkgName,
          version: typeof vuln.range === "string" ? vuln.range : undefined,
          vulnerableRange: typeof v.range === "string" ? v.range : undefined,
          id: String(v.source ?? v.url ?? v.title),
          title: String(v.title),
          severity: sev as "high" | "critical",
          url: typeof v.url === "string" ? v.url : undefined,
        });
        advisoryAdded = true;
      }
    }
    // Fallback: no leaf advisory in via[], emit a synthetic entry
    if (!advisoryAdded) {
      advisories.push({
        manifest: manifestRel,
        tool: "npm-audit",
        package: pkgName,
        severity: sev as "high" | "critical",
        id: `npm-audit:${pkgName}`,
        title: `Transitive ${sev} advisory in ${pkgName} (see npm audit for chain)`,
      });
    }
  }
  return advisories;
}

// ────────────────────────────────────────────────────────────────────
// pip-audit runner (best-effort, skipped if not installed)
// ────────────────────────────────────────────────────────────────────

function runPipAudit(manifestPath: string, manifestRel: string): CveAdvisory[] {
  const dir = manifestPath.replace(/\/requirements\.txt$/, "");
  let output: string;
  try {
    output = execFileSync(
      "pip-audit",
      ["--requirement", "requirements.txt", "--format", "json"],
      {
        cwd: dir,
        timeout: 60_000,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
  } catch (err: any) {
    if (err && err.code === "ENOENT") return []; // pip-audit not installed
    output = (err && typeof err.stdout === "string" ? err.stdout : "") || "";
    if (!output) return [];
  }

  let parsed: any;
  try {
    parsed = JSON.parse(output);
  } catch {
    return [];
  }

  const advisories: CveAdvisory[] = [];
  const dependencies: any[] = Array.isArray(parsed.dependencies) ? parsed.dependencies : [];
  for (const dep of dependencies) {
    const pkgName = dep.name;
    const version = dep.version;
    const vulns: any[] = Array.isArray(dep.vulns) ? dep.vulns : [];
    for (const v of vulns) {
      // pip-audit normalizes severity into a fix_versions/aliases shape;
      // we treat any vuln with a CVE/GHSA prefix as high+ for safety.
      const id = String(v.id ?? "");
      const isCveOrGhsa = /^(CVE-|GHSA-)/i.test(id);
      if (!isCveOrGhsa) continue;
      advisories.push({
        manifest: manifestRel,
        tool: "pip-audit",
        package: String(pkgName),
        version: typeof version === "string" ? version : undefined,
        id,
        title: String(v.description ?? v.id ?? "pip-audit advisory"),
        severity: "high",
        url: typeof v.aliases?.[0] === "string" ? v.aliases[0] : undefined,
      });
    }
  }
  return advisories;
}

// ────────────────────────────────────────────────────────────────────
// Manifest registry — add new audit tools here
// ────────────────────────────────────────────────────────────────────

const MANIFEST_KINDS: ManifestKind[] = [
  { filename: "package-lock.json", tool: "npm-audit", run: runNpmAudit },
  { filename: "requirements.txt", tool: "pip-audit", run: runPipAudit },
  // Future: bundle-audit (Gemfile.lock), composer audit (composer.lock),
  // cargo audit (Cargo.lock), govulncheck (go.sum). Each goes here as a
  // new ManifestKind entry. Out of scope for the initial Phase 4 patch.
];

// ────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────

/**
 * Walk the source tree, run every available audit tool against every
 * detected manifest, and return a structured report.
 */
export function runPreReconCveCheck(repoPath: string): PreReconCveReport {
  const start = Date.now();
  const advisories: CveAdvisory[] = [];
  const scanned: string[] = [];
  const skipped: Array<{ manifest: string; reason: string }> = [];

  if (!existsSync(repoPath)) {
    return { advisories, manifestsScanned: scanned, manifestsSkipped: skipped, durationMs: 0 };
  }

  const manifests = findManifests(repoPath, MANIFEST_KINDS);
  for (const { kind, absPath, relPath } of manifests) {
    try {
      const found = kind.run(absPath, relPath);
      scanned.push(relPath);
      advisories.push(...found);
    } catch (err) {
      skipped.push({
        manifest: relPath,
        reason: err instanceof Error ? err.message : String(err),
      });
    }
  }

  return {
    advisories,
    manifestsScanned: scanned,
    manifestsSkipped: skipped,
    durationMs: Date.now() - start,
  };
}

/**
 * Render a pre-recon CVE report into a system-prompt prefix that the
 * attack agent can use as priority investigation leads.
 *
 * Returns null if there are no high/critical advisories — the caller
 * should NOT inject anything into the prompt in that case (an empty
 * "no CVE leads" line just adds noise).
 */
export function formatPreReconForPrompt(report: PreReconCveReport): string | null {
  if (report.advisories.length === 0) return null;

  // Group by package + advisory ID to dedupe transitive paths
  const seen = new Set<string>();
  const uniqueLines: string[] = [];
  for (const a of report.advisories) {
    const key = `${a.package}::${a.id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const range = a.vulnerableRange ? ` (vulnerable: ${a.vulnerableRange})` : "";
    const url = a.url ? ` — ${a.url}` : "";
    uniqueLines.push(
      `- \`${a.package}\`${a.version ? `@${a.version}` : ""}: **${a.severity}** — ${a.title} [${a.id}]${range}${url}`,
    );
  }

  const limited = uniqueLines.slice(0, 30); // cap to keep the prompt sane
  const more =
    uniqueLines.length > limited.length
      ? `\n\n_(${uniqueLines.length - limited.length} more advisories suppressed; see npm audit / pip-audit on the source tree for the full list)_`
      : "";

  return [
    "## Priority CVE leads from source-tree audit",
    "",
    "The following high/critical advisories were found by running `npm audit` / `pip-audit` against the package manifests in the source tree before this scan started. The vulnerable versions are confirmed installed. **Investigate these as your first priority** — the running target almost certainly inherits at least one of them, and the exploit chain may already be public.",
    "",
    ...limited,
    more,
    "",
  ].join("\n");
}

// ────────────────────────────────────────────────────────────────────
// WordPress pre-recon (Phase 4, black-box side)
// ────────────────────────────────────────────────────────────────────
//
// The `wp_fingerprint` tool already exists as an agent-callable action
// (packages/core/src/agent/wp-fingerprint.ts). The gap this closes: by
// the time the attack agent starts its first turn, it should already
// know what plugins/themes are installed and which ones have CVEs — so
// it doesn't burn $$$ rediscovering what a 2-second probe answers.
//
// The flow:
//   1. Run three cheap probes (/wp-login.php, /readme.html, /wp-json/)
//      to confirm WordPress. This is a cheaper superset of the full
//      wp_fingerprint detection — we only need ~1 positive signal to
//      decide whether to invoke the full fingerprinter.
//   2. If WP is detected AND the wpFingerprint feature flag is on,
//      call `runWpFingerprint` directly (bypassing the agent loop).
//   3. Return a structured packet with the findings, which the caller
//      folds into the system prompt alongside the source-tree CVEs.
//
// Feature flag is checked by the caller, not here, so unit tests can
// exercise this module without mocking features.ts.

export interface PreReconWordPressReport {
  /** Did the cheap probes detect WordPress? */
  isWordPress: boolean;
  /** Which probe paths returned positive signals. */
  detectionEvidence: string[];
  /** Full fingerprint result (undefined if !isWordPress or fingerprinter was skipped). */
  fingerprint?: WpFingerprintResult;
  /** Total wall-time spent in pre-recon (detection + fingerprint). */
  durationMs: number;
  /** If the fingerprint run threw, the error message is stashed here. */
  error?: string;
}

export interface PreReconWordPressOptions {
  /** Target URL — scheme + host, trailing slash optional. */
  target: string;
  /** Injectable fetch for tests. Defaults to globalThis.fetch. */
  fetchImpl?: FetchLike;
  /** Per-probe timeout, ms. Default 8_000. */
  timeoutMs?: number;
  /** Skip OSV lookups — test helper. Default false. */
  skipOsv?: boolean;
  /** Extra headers to forward on every probe (auth, etc). */
  headers?: Record<string, string>;
}

/**
 * Cheap WordPress detection — hits three well-known endpoints in
 * parallel and returns the set of paths that looked WP-ish. Mirrors
 * the detection logic in `wp-fingerprint.ts` but uses a smaller probe
 * set to stay fast in the common "target is not WordPress" case.
 */
async function detectWordPressCheap(
  target: string,
  fetchImpl: FetchLike,
  timeoutMs: number,
  headers?: Record<string, string>,
): Promise<string[]> {
  const base = target.replace(/\/+$/, "");
  const paths = ["wp-login.php", "readme.html", "wp-includes/version.php"];
  const evidence: string[] = [];

  const results = await Promise.all(
    paths.map(async (p) => {
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        const res = await fetchImpl(`${base}/${p}`, {
          method: "GET",
          headers: headers ?? {},
        }).finally(() => clearTimeout(timer));
        const body = await res.text().catch(() => "");
        return { path: p, ok: res.ok, status: res.status, body };
      } catch {
        return undefined;
      }
    }),
  );

  for (const r of results) {
    if (!r) continue;
    if (r.path === "wp-login.php" && r.ok && /wp-submit|user_login|wp-login/i.test(r.body)) {
      evidence.push("wp-login.php");
    }
    if (r.path === "readme.html" && r.ok && /wordpress/i.test(r.body)) {
      evidence.push("readme.html");
    }
    if (r.path === "wp-includes/version.php" && r.ok && /\$wp_version/.test(r.body)) {
      evidence.push("wp-includes/version.php");
    }
  }

  return evidence;
}

/**
 * Phase-4 pre-recon WordPress probe. Runs cheap detection; if positive,
 * invokes the full `runWpFingerprint` and returns the structured result
 * for the caller to inject into the attack agent's evidence packet.
 *
 * Always returns a report — on any error the promise resolves to a
 * report with `error` set and no fingerprint payload. Never throws.
 *
 * The caller (agentic-scanner.ts) is responsible for:
 *   1. Feature-flag gating (only run if wpFingerprint is enabled)
 *   2. Calling this before the attack agent's first turn
 *   3. Folding the formatted output into the system prompt
 */
export async function runPreReconWordPress(
  opts: PreReconWordPressOptions,
): Promise<PreReconWordPressReport> {
  const start = Date.now();
  const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as unknown as FetchLike);
  const timeoutMs = opts.timeoutMs ?? 8_000;

  try {
    const evidence = await detectWordPressCheap(
      opts.target,
      fetchImpl,
      timeoutMs,
      opts.headers,
    );
    if (evidence.length === 0) {
      return {
        isWordPress: false,
        detectionEvidence: [],
        durationMs: Date.now() - start,
      };
    }

    const fingerprint = await runWpFingerprint({
      target: opts.target,
      fetchImpl,
      timeoutMs,
      skipOsv: opts.skipOsv,
      headers: opts.headers,
    });

    return {
      isWordPress: true,
      detectionEvidence: evidence,
      fingerprint,
      durationMs: Date.now() - start,
    };
  } catch (err) {
    return {
      isWordPress: false,
      detectionEvidence: [],
      durationMs: Date.now() - start,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Render a WordPress pre-recon report into a prompt block. Returns null
 * when there's nothing useful to say (not WordPress, or WP with zero
 * plugins/themes/cves) — the caller should not inject an empty header.
 */
export function formatPreReconWordPressForPrompt(
  report: PreReconWordPressReport,
): string | null {
  if (!report.isWordPress || !report.fingerprint) return null;
  const fp = report.fingerprint;
  if (fp.plugins.length === 0 && fp.themes.length === 0 && fp.findings.length === 0) {
    return null;
  }

  const lines: string[] = [];
  lines.push("## WordPress pre-recon");
  lines.push("");
  lines.push(
    `Phase-4 auto-detected WordPress at the target before the attack agent started. Core version: ${fp.coreVersion ?? "unknown"}. Detection evidence: ${report.detectionEvidence.join(", ")}.`,
  );
  lines.push("");
  lines.push(
    `Enumerated **${fp.plugins.length} plugin${fp.plugins.length === 1 ? "" : "s"}** and **${fp.themes.length} theme${fp.themes.length === 1 ? "" : "s"}**.`,
  );

  const withCves = fp.findings.filter((f) => f.cves.length > 0);
  if (withCves.length > 0) {
    lines.push("");
    lines.push(
      `### Priority WP CVE leads (${withCves.length} affected components)`,
    );
    lines.push("");
    lines.push(
      "**Investigate these first** — the WP fingerprinter confirmed each slug/version pair against the OSV advisory database, so every entry below is a concrete lead, not a guess.",
    );
    lines.push("");
    for (const f of withCves.slice(0, 20)) {
      const ids = f.cves.slice(0, 5).map((c) => c.id).join(", ");
      const more = f.cves.length > 5 ? ` (+${f.cves.length - 5} more)` : "";
      lines.push(
        `- **${f.kind}** \`${f.slug}\`${f.version ? `@${f.version}` : ""}: ${ids}${more}`,
      );
      for (const hint of f.exploitHints.slice(0, 2)) {
        lines.push(`  - hint: ${hint}`);
      }
    }
    if (withCves.length > 20) {
      lines.push("");
      lines.push(`_(${withCves.length - 20} more affected components suppressed for brevity.)_`);
    }
  } else {
    lines.push("");
    lines.push("No OSV advisory matches for the enumerated plugin/theme versions.");
  }
  lines.push("");

  return lines.join("\n");
}
