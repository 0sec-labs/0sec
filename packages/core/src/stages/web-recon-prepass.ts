// Deterministic web-recon pre-pass (pwnkit web-recon integration).
//
// This stage wires the seven standalone web-recon modules into a single
// deterministic pass that runs BEFORE the attack agent's first turn on web
// scans. Unlike the agent loop it does not reason with an LLM — it runs cheap,
// non-destructive HTTP/DNS probes, EMITS FINDINGS DIRECTLY for the things it
// can prove, and injects a compact "pursue these leads" block into the agent
// system prompt for the things it can only hint at.
//
// Design rules (load-bearing — mirror the existing pre-recon blocks):
//   * NEVER throws. Every external call is wrapped so a failure degrades to a
//     partial result; the scan continues regardless.
//   * GET-only / non-destructive. The only POSTs allowed are the conservative
//     rate-limit probe with a clearly-invalid, non-existent email — and we
//     prefer skipping that entirely, leaving a prompt lead instead.
//   * Conservative findings. We emit a finding only on positive evidence
//     (e.g. exploitable===true for a framework CVE check); otherwise we add a
//     lead to the prompt block rather than risk a false positive.

import { randomUUID } from "node:crypto";
import type {
  AttackCategory,
  Finding,
  ScanConfig,
  ScanContext,
  Severity,
} from "@pwnkit/shared";
import { runBaselineWebChecks } from "./web.js";
import {
  enumerateJsChunkUrls,
  fingerprintWebStack,
  summarizeWebStackFingerprint,
  type WebStackFingerprint,
} from "../recon/stack-fingerprint.js";
import { lookupVersionCves, type VersionCve } from "../intel/version-cve.js";
import { scanJsArtifacts } from "../recon/js-artifacts.js";
import { checkEmailPosture } from "../recon/dns-email.js";
import { enumerateSubdomains, type DiscoveredHost } from "../recon/subdomains.js";
import { probeRateLimit } from "../recon/rate-limit.js";
import {
  runFrameworkCveChecks,
  type FrameworkCveResult,
  type WebCveHttpResponse,
} from "../agent/web-cve-codex.js";

/** Minimal response shape used by the local fetch wrapper. */
interface ReconResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface WebReconPrePassResult {
  findings: Finding[];
  promptBlock: string;
}

const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * Run the deterministic web-recon pre-pass against `config.target`.
 *
 * Returns the findings it could prove plus a system-prompt block summarizing
 * the detected stack and any unconfirmed leads. NEVER throws — on any failure
 * it returns whatever it gathered so far.
 */
export async function runWebReconPrePass(
  config: ScanConfig,
): Promise<WebReconPrePassResult> {
  const findings: Finding[] = [];
  const leads: string[] = [];

  let fingerprint: WebStackFingerprint | undefined;
  let subdomains: DiscoveredHost[] = [];

  const target = config.target;
  const timeout = config.timeout ?? DEFAULT_TIMEOUT_MS;
  const base = target.replace(/\/+$/, "");
  const targetHost = safeHost(target);
  const domain = registrableDomain(target);

  // A local, non-destructive GET wrapper used by every fetch-driven module.
  const fetchResponse = async (url: string): Promise<ReconResponse> => {
    // SSRF guard: never follow a target-derived URL (JS chunk src, etc.) off the
    // target's own host/domain or into private address space. Out-of-scope URLs
    // are treated as a failed fetch so callers skip them gracefully.
    if (!isInScopeUrl(url, targetHost, domain)) {
      return { status: 0, headers: {}, body: "" };
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      // url is scope-checked by isInScopeUrl() above: target host /
      // registrable-domain only; private/link-local/loopback refused.
      // foxguard: ignore[js/no-ssrf]
      const res = await fetch(url, {
        method: "GET",
        headers: { Accept: "*/*" },
        redirect: "manual",
        signal: controller.signal,
      });
      const body = await res.text();
      const headers: Record<string, string> = {};
      res.headers.forEach((value, key) => {
        headers[key.toLowerCase()] = value;
      });
      return { status: res.status, headers, body };
    } finally {
      clearTimeout(timer);
    }
  };
  const fetchText = async (url: string) => {
    const r = await fetchResponse(url);
    return { status: r.status, headers: r.headers, body: r.body };
  };

  // ── 1. Baseline web checks (reuse web.ts) ──
  // Reuses the header/clickjacking + CORS + sensitive-path findings the
  // existing baseline stage already builds.
  let baseline: ReconResponse | undefined;
  try {
    const ctx = buildScanContext(config);
    const result = await runBaselineWebChecks(ctx);
    findings.push(...result.findings);
  } catch {
    // Baseline failed — keep going with the rest of the pre-pass.
  }

  // Fetch the root once for fingerprinting + redirect-derived protected paths.
  try {
    baseline = await fetchResponse(base);
  } catch {
    baseline = undefined;
  }

  // ── 2. Stack fingerprint ──
  try {
    fingerprint = await fingerprintWebStack({ baseUrl: base, fetchText });
  } catch {
    fingerprint = undefined;
  }

  const chunkUrls = baseline?.body
    ? enumerateJsChunkUrls(baseline.body, base)
    : [];

  // Platform-mitigation awareness: detect Vercel hosting from the root response
  // headers. Several Next.js advisories are auto-mitigated at the Vercel edge.
  const onVercel = detectVercelHosting(baseline?.headers);

  // ── 3a. Framework CVE active checks (Next.js) ──
  // We run the codex's ACTIVE checks BEFORE consolidating the version→CVE list
  // so the two reconcile: an actively-confirmed CVE becomes its own finding and
  // is marked confirmed in the consolidated list; an actively-tested-but-not-
  // exploitable CVE is annotated and excluded from inflating the rollup severity.
  // The check is GET-only and version-gated inside the codex.
  const activeByCveId = new Map<string, FrameworkCveResult>();
  if (
    fingerprint?.framework &&
    isNextFramework(fingerprint.framework.name) &&
    fingerprint.framework.version &&
    baseline
  ) {
    const redirect = deriveProtectedAndLogin(base, baseline);
    if (redirect) {
      try {
        const httpGet = async (
          path: string,
          headers?: Record<string, string>,
        ): Promise<WebCveHttpResponse> => {
          const url = new URL(path, `${base}/`).toString();
          // SSRF guard (defense-in-depth: `path` resolves against the target,
          // so this is same-origin by construction, but never fetch off-scope).
          if (!isInScopeUrl(url, targetHost, domain)) {
            return { status: 0, headers: {}, body: "" };
          }
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          try {
            // url is scope-checked by isInScopeUrl() above; `path` resolves
            // against the target base (same-origin by construction).
            // foxguard: ignore[js/no-ssrf]
            const res = await fetch(url, {
              method: "GET",
              headers: { Accept: "*/*", ...(headers ?? {}) },
              redirect: "manual",
              signal: controller.signal,
            });
            const body = await res.text();
            const h: Record<string, string> = {};
            res.headers.forEach((value, key) => {
              h[key.toLowerCase()] = value;
            });
            return { status: res.status, headers: h, body };
          } finally {
            clearTimeout(timer);
          }
        };

        const results = await runFrameworkCveChecks({
          framework: fingerprint.framework.name,
          version: fingerprint.framework.version,
          baseUrl: base,
          protectedPath: redirect.protectedPath,
          loginPath: redirect.loginPath,
          httpGet,
        });
        for (const r of results) {
          activeByCveId.set(r.cve, r);
          if (!r.exploitable) continue; // only emit own findings on positive proof
          findings.push(
            createFinding({
              templateId: "web-recon-framework-cve",
              title: `${r.title} (${r.cve})`,
              description: `Active check confirmed ${r.cve} is exploitable on the target.`,
              severity: r.severityIfExploitable,
              category: "security-misconfiguration",
              request: `GET ${redirect.protectedPath} (crafted ${r.cve} check)`,
              response: r.evidence,
              analysis: r.evidence,
            }),
          );
        }
      } catch {
        // Framework CVE check failed — continue.
      }
    } else {
      leads.push(
        `Framework is ${fingerprint.framework.name}${fingerprint.framework.version ? ` v${fingerprint.framework.version}` : ""}; could not auto-derive an auth-gated route — manually identify a protected path and test known middleware-bypass CVEs.`,
      );
    }
  }

  // ── 3b. Version → CVE lookups, CONSOLIDATED per component ──
  // The version→CVE mapper can return dozens of advisories for one popular
  // framework version (e.g. next@15.0.7 → ~24 HIGH/CRITICAL advisories). Emitting
  // one finding per CVE floods a pentest report with version-affected-but-often-
  // mitigated noise. Instead we emit ONE consolidated SCA finding per component,
  // calibrate severity against active-check + platform-mitigation reconciliation,
  // and carry the full CVE list in the evidence.
  if (fingerprint) {
    const versioned: Array<{ name: string; version: string }> = [];
    if (fingerprint.framework?.version) {
      versioned.push({
        name: npmPackageName(fingerprint.framework.name),
        version: fingerprint.framework.version,
      });
    }
    for (const lib of fingerprint.libraries) {
      if (lib.version) versioned.push({ name: lib.name, version: lib.version });
    }

    for (const { name, version } of versioned) {
      let cves: VersionCve[] = [];
      try {
        cves = await lookupVersionCves({ ecosystem: "npm", name, version });
      } catch {
        continue;
      }
      const consolidated = buildConsolidatedCveFinding({
        name,
        version,
        base,
        cves,
        activeByCveId,
        onVercel,
      });
      if (consolidated) findings.push(consolidated);
    }
  }

  // ── 4. JS artifact scan (source maps + secrets) ──
  if (chunkUrls.length > 0) {
    try {
      const artifacts = await scanJsArtifacts({ baseUrl: base, chunkUrls, fetchText });
      for (const sm of artifacts.sourceMaps) {
        if (!sm.exposed) continue;
        findings.push(
          createFinding({
            templateId: "web-recon-source-map",
            title: "Exposed JavaScript source map",
            description:
              "A production JavaScript bundle ships a source map that is served publicly, leaking original (pre-minification) source.",
            severity: "medium",
            category: "information-disclosure",
            request: `GET ${sm.url}`,
            response: "HTTP 200 (source map served)",
            analysis: `The source map at ${sm.url} is publicly reachable and discloses original source code.`,
          }),
        );
      }
      for (const secret of artifacts.secrets) {
        if (secret.confidence !== "high") continue; // drop low-confidence (public) keys
        findings.push(
          createFinding({
            templateId: "web-recon-leaked-secret",
            title: `Leaked credential in JS bundle (${secret.kind})`,
            description:
              `A high-confidence ${secret.kind} credential was found in a client-side JavaScript bundle.`,
            severity: "high",
            category: "information-disclosure",
            request: `GET ${secret.chunk}`,
            response: `Matched ${secret.kind}: ${secret.match}`,
            analysis: `A ${secret.kind} value (${secret.match}) was found in ${secret.chunk}. A genuine credential shipped to the browser should be treated as compromised and rotated.`,
          }),
        );
      }
    } catch {
      // JS artifact scan failed — continue.
    }
  }

  // ── 5. DNS / email posture ──
  if (domain) {
    try {
      const posture = await checkEmailPosture({ domain });
      for (const f of posture.findings) {
        findings.push(
          createFinding({
            templateId: "web-recon-email-posture",
            title: f.title,
            description: f.detail,
            severity: f.severity,
            category: "security-misconfiguration",
            request: `DNS TXT lookup for ${domain}`,
            response: f.detail,
            analysis: `Email anti-spoofing posture for ${domain}: ${f.title}.`,
          }),
        );
      }
    } catch {
      // DNS posture failed — continue.
    }
  }

  // ── 6. Subdomain enumeration ──
  if (domain) {
    try {
      subdomains = await enumerateSubdomains({ domain });
      for (const host of subdomains) {
        if (host.host === targetHost) continue; // skip the target itself
        findings.push(
          createFinding({
            templateId: "web-recon-subdomain",
            title: `Additional exposed host: ${host.host}`,
            description: `A subdomain of ${domain} resolves in DNS and may expand the attack surface.`,
            severity: "info",
            category: "information-disclosure",
            request: `crt.sh + DNS resolution for ${host.host}`,
            response:
              `host=${host.host}` +
              (host.addresses?.length ? `, addresses=${host.addresses.join(", ")}` : "") +
              (host.cname ? `, cname=${host.cname}` : ""),
            analysis: `Discovered via ${host.source}. Additional exposed host worth including in the engagement scope.`,
          }),
        );
      }
    } catch {
      subdomains = [];
    }
  }

  // ── 7. Rate-limit lead (prefer skipping speculative POSTs) ──
  // Only probe when a password-reset-style endpoint is obvious from the
  // baseline body; otherwise leave a lead and send no POSTs.
  const resetEndpoint = baseline?.body
    ? findPasswordResetEndpoint(base, baseline.body)
    : undefined;
  // SSRF guard: only POST to a reset endpoint that is on the target's own
  // host/domain — never one a hostile target's HTML steered us to off-scope.
  if (resetEndpoint && isInScopeUrl(resetEndpoint, targetHost, domain)) {
    try {
      const invalidEmail = `pwnkit-noreply-${randomUUID().slice(0, 8)}@invalid.example`;
      const probe = await probeRateLimit({
        request: async () => {
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeout);
          try {
            // resetEndpoint was validated by isInScopeUrl() before this probe
            // runs (target host/domain only).
            // foxguard: ignore[js/no-ssrf]
            const res = await fetch(resetEndpoint, {
              method: "POST",
              headers: { "content-type": "application/json", Accept: "*/*" },
              body: JSON.stringify({ email: invalidEmail }),
              redirect: "manual",
              signal: controller.signal,
            });
            return { status: res.status };
          } finally {
            clearTimeout(timer);
          }
        },
      });
      if (!probe.throttled) {
        findings.push(
          createFinding({
            templateId: "web-recon-rate-limit",
            title: "Password-reset endpoint lacks rate limiting",
            description:
              "A small bounded burst of password-reset requests (with a clearly-invalid, non-existent email) saw no throttling — no HTTP 429 and no status change.",
            severity: "medium",
            category: "security-misconfiguration",
            request: `POST ${resetEndpoint} x${probe.sent} (invalid email ${invalidEmail})`,
            response: probe.note,
            analysis: `${probe.note}. Missing anti-automation controls on a sensitive endpoint enable account enumeration and abuse.`,
          }),
        );
      }
    } catch {
      // Rate-limit probe failed — continue.
    }
  } else {
    leads.push(
      "If you find a password-reset or OTP endpoint, test rate limiting with a safe, clearly-invalid email (e.g. a non-existent @invalid.example address) — no real mail should be triggered.",
    );
  }

  // ── Build the prompt block ──
  const promptBlock = buildPromptBlock(fingerprint, findings, subdomains, leads);

  return { findings, promptBlock };
}

// ── Prompt block ──

function buildPromptBlock(
  fingerprint: WebStackFingerprint | undefined,
  findings: Finding[],
  subdomains: DiscoveredHost[],
  leads: string[],
): string {
  const lines: string[] = [];
  lines.push("## Deterministic web recon (pursue these leads)");
  lines.push("");
  lines.push(
    "A deterministic pre-pass already ran cheap, non-destructive probes against this target. Use the results below as priority leads. Findings it could prove are already saved — do not re-discover them; build on them.",
  );
  lines.push("");

  if (fingerprint) {
    lines.push("### Detected stack");
    lines.push(summarizeWebStackFingerprint(fingerprint));
    lines.push("");
  }

  const cveFindings = findings.filter((f) => f.templateId === "web-recon-version-cve" || f.templateId === "web-recon-framework-cve");
  if (cveFindings.length > 0) {
    lines.push(`### CVEs already surfaced (${cveFindings.length})`);
    for (const f of cveFindings) {
      lines.push(`- ${f.title}`);
    }
    lines.push("");
  }

  if (subdomains.length > 0) {
    lines.push(`### Additional exposed hosts (${subdomains.length})`);
    for (const host of subdomains.slice(0, 20)) {
      lines.push(`- ${host.host}${host.cname ? ` (cname ${host.cname})` : ""}`);
    }
    lines.push("");
  }

  if (leads.length > 0) {
    lines.push("### Unconfirmed leads to chase");
    for (const lead of leads) {
      lines.push(`- ${lead}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

// ── Helpers ──

/** Build a minimal ScanContext for the baseline web checks. */
function buildScanContext(config: ScanConfig): ScanContext {
  return {
    config,
    target: { url: config.target, type: "web-app" },
    findings: [],
    attacks: [],
    warnings: [],
    startedAt: Date.now(),
  };
}

/** Map a VersionCve severity (which may be undefined) onto a Finding severity. */
function mapCveSeverity(severity: VersionCve["severity"]): Severity {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

// ── Consolidated SCA (version → CVE) finding ──

/** Severity rank for picking the max among a list. Higher = more severe. */
const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

/**
 * CVE ids that Vercel's edge auto-mitigates for apps deployed on Vercel. Kept
 * deliberately small and justifiable — we only down-rank ids we can defend:
 *
 *   - CVE-2025-29927: the x-middleware-subrequest middleware-bypass header is
 *     stripped at the Vercel edge before it reaches the app, so the bypass is
 *     not reachable on Vercel-hosted deployments (verified against a real pilot
 *     where every payload still returned 307 to login).
 *
 * Everything else stays at full weight; we do not speculatively down-rank.
 */
const VERCEL_EDGE_MITIGATED_CVES: ReadonlySet<string> = new Set([
  "CVE-2025-29927",
]);

/**
 * Reconcile a version→CVE id against the codex's active-check result ids.
 * The codex uses canonical ids for one CVE (`CVE-2025-29927`) and a stable
 * label for the not-yet-numbered RSC/segment-prefetch bypass
 * (`NEXT-RSC-PREFETCH-BYPASS-2026-05`). Map a version-CVE onto whichever active
 * check covers it so the two reconcile.
 */
function reconcileActiveResult(
  cve: VersionCve,
  activeByCveId: Map<string, FrameworkCveResult>,
): FrameworkCveResult | undefined {
  // Direct id match (e.g. CVE-2025-29927 appears in both).
  const direct = activeByCveId.get(cve.id);
  if (direct) return direct;
  // The RSC/segment-prefetch advisory rarely has a numbered CVE in OSV; match it
  // by recognizing RSC / segment-prefetch wording in the advisory text.
  if (/\brsc\b|segment[\s-]?prefetch/i.test(`${cve.id} ${cve.summary}`)) {
    return activeByCveId.get("NEXT-RSC-PREFETCH-BYPASS-2026-05");
  }
  return undefined;
}

/** Highest fixedVersion among a set of advisories (semver-ish, string-safe). */
function highestFixedVersion(versions: string[]): string | undefined {
  const cmp = (a: string, b: string): number => {
    const pa = a.replace(/^v/i, "").split(/[-+]/, 1)[0]!.split(".").map((n) => Number.parseInt(n, 10) || 0);
    const pb = b.replace(/^v/i, "").split(/[-+]/, 1)[0]!.split(".").map((n) => Number.parseInt(n, 10) || 0);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const d = (pa[i] ?? 0) - (pb[i] ?? 0);
      if (d !== 0) return d;
    }
    return 0;
  };
  let best: string | undefined;
  for (const v of versions) {
    if (!v) continue;
    if (!best || cmp(v, best) > 0) best = v;
  }
  return best;
}

interface ConsolidateInput {
  name: string;
  version: string;
  base: string;
  cves: VersionCve[];
  activeByCveId: Map<string, FrameworkCveResult>;
  onVercel: boolean;
}

/**
 * Collapse the per-component version→CVE list into a SINGLE SCA finding.
 *
 * Severity is the MAX advisory severity among the CVEs that still count toward
 * the rollup — i.e. excluding any CVE that an active check tested-but-found-
 * not-exploitable, and (on Vercel) excluding known-Vercel-edge-mitigated ids.
 * Confirmed-exploitable CVEs are emitted as their own findings elsewhere; here
 * they are marked confirmed in the list and DO count toward severity.
 *
 * Returns undefined when no HIGH/CRITICAL advisory affects this component (we
 * keep the original signal floor: low/medium SCA noise is not surfaced).
 */
function buildConsolidatedCveFinding(input: ConsolidateInput): Finding | undefined {
  const { name, version, base, cves, activeByCveId, onVercel } = input;

  // Only consider HIGH/CRITICAL advisories, matching the prior signal floor.
  const relevant = cves.filter((c) => {
    const sev = mapCveSeverity(c.severity);
    return sev === "high" || sev === "critical";
  });
  if (relevant.length === 0) return undefined;

  interface Annotated {
    cve: VersionCve;
    sev: Severity;
    /** Active check tested this id and confirmed it exploitable. */
    confirmed: boolean;
    /** Active check tested this id and found it NOT exploitable on this deploy. */
    testedNotExploitable: boolean;
    /** Known to be auto-mitigated at the Vercel edge (only when onVercel). */
    vercelMitigated: boolean;
    /** Counts toward the rollup severity. */
    countsTowardSeverity: boolean;
    note?: string;
  }

  const annotated: Annotated[] = relevant.map((cve) => {
    const sev = mapCveSeverity(cve.severity);
    const active = reconcileActiveResult(cve, activeByCveId);
    const confirmed = active?.tested === true && active.exploitable === true;
    const testedNotExploitable = active?.tested === true && active.exploitable === false;
    const vercelMitigated = onVercel && VERCEL_EDGE_MITIGATED_CVES.has(cve.id);

    // A CVE stops inflating the rollup severity when an active check proved it
    // not exploitable here, or when it is a known Vercel-edge-mitigated id.
    // Confirmed-exploitable always counts.
    const countsTowardSeverity = confirmed || (!testedNotExploitable && !vercelMitigated);

    let note: string | undefined;
    if (confirmed) note = "active check: CONFIRMED exploitable";
    else if (testedNotExploitable) note = "active check: NOT exploitable on this deployment";
    else if (vercelMitigated) note = "auto-mitigated at the Vercel edge";

    return {
      cve,
      sev,
      confirmed,
      testedNotExploitable,
      vercelMitigated,
      countsTowardSeverity,
      note,
    };
  });

  // Rollup severity = max among the CVEs that still count. If everything is
  // mitigated/not-exploitable, fall back to "medium" (still a real SCA gap worth
  // upgrading, just not a live critical).
  const counting = annotated.filter((a) => a.countsTowardSeverity);
  const rollupSeverity: Severity = counting.length
    ? counting.reduce<Severity>(
        (max, a) => (SEVERITY_RANK[a.sev] > SEVERITY_RANK[max] ? a.sev : max),
        "info",
      )
    : "medium";

  const fixedTarget = highestFixedVersion(
    relevant.map((c) => c.fixedVersion).filter((v): v is string => !!v),
  );

  const confirmedCount = annotated.filter((a) => a.confirmed).length;
  const mitigatedCount = annotated.filter(
    (a) => a.testedNotExploitable || a.vercelMitigated,
  ).length;

  // Per-CVE evidence lines: id, severity, fixedVersion, and any annotation.
  const cveLines = annotated
    .map((a) => {
      const fixed = a.cve.fixedVersion ? ` fixed in ${a.cve.fixedVersion}` : " no fixed version published";
      const annotation = a.note ? ` — ${a.note}` : "";
      return `- ${a.cve.id} (${a.sev}, ${a.cve.source}):${fixed}${annotation}`;
    })
    .join("\n");

  const remediation = fixedTarget
    ? `Upgrade ${name} to >= ${fixedTarget} to clear all listed advisories.`
    : `Upgrade ${name} to the latest patched release.`;

  const vercelNote = onVercel
    ? `\n\nPlatform note: target appears to be hosted on Vercel. Several Next.js advisories — the x-middleware-subrequest middleware bypass (CVE-2025-29927) and the middleware-bypass / DoS classes — are auto-mitigated at the Vercel edge and are down-ranked here accordingly.`
    : "";

  const activeNote =
    confirmedCount > 0 || mitigatedCount > 0
      ? `\n\nActive checks reconciled: ${confirmedCount} confirmed exploitable, ${mitigatedCount} tested/known-mitigated (excluded from the rollup severity).`
      : "";

  const description =
    `${name}@${version} is VERSION-AFFECTED by ${relevant.length} published ` +
    `HIGH/CRITICAL advisor${relevant.length === 1 ? "y" : "ies"}. This is an SCA ` +
    `(software-composition) signal: the detected version falls in each advisory's ` +
    `affected range, but exploitability against this deployment is NOT confirmed ` +
    `unless an advisory is annotated CONFIRMED below.`;

  const analysis =
    `Consolidated SCA finding for ${name}@${version} (${relevant.length} advisories).\n\n` +
    `${cveLines}` +
    vercelNote +
    activeNote +
    `\n\nRemediation: ${remediation}`;

  return createFinding({
    templateId: "web-recon-version-cve",
    title: `Known-vulnerable dependency: ${name}@${version} (${relevant.length} published advisor${relevant.length === 1 ? "y" : "ies"})`,
    description,
    severity: rollupSeverity,
    category: "known-vulnerable-package",
    request: `GET ${base} (stack fingerprint: ${name}@${version})`,
    response: `${relevant.length} advisories affect ${name}@${version}: ${relevant.map((c) => c.id).join(", ")}`,
    analysis,
  });
}

/**
 * Detect Vercel hosting from the root response headers. Vercel sets `server:
 * Vercel` and an `x-vercel-id` header on edge responses; either is sufficient.
 */
function detectVercelHosting(headers: Record<string, string> | undefined): boolean {
  if (!headers) return false;
  if (typeof headers["x-vercel-id"] === "string" && headers["x-vercel-id"]) return true;
  const server = headers["server"];
  if (typeof server === "string" && /vercel/i.test(server)) return true;
  return false;
}

/**
 * Canonical framework display name → npm package name for the advisory lookup.
 * Most libraries already use their npm name; meta-frameworks need a small map.
 */
function npmPackageName(frameworkName: string): string {
  const map: Record<string, string> = {
    "next.js": "next",
    nuxt: "nuxt",
    remix: "@remix-run/server-runtime",
    sveltekit: "@sveltejs/kit",
    gatsby: "gatsby",
    astro: "astro",
    react: "react",
    vue: "vue",
    express: "express",
  };
  return map[frameworkName.toLowerCase()] ?? frameworkName.toLowerCase();
}

function isNextFramework(name: string): boolean {
  return /^next(\.?js)?$/i.test(name.trim());
}

/** Hostname of a URL, lowercased, or undefined if unparseable. */
function safeHost(target: string): string | undefined {
  try {
    return new URL(target).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

/**
 * Best-effort registrable domain from a target URL. Strips a leading `www.`
 * and otherwise keeps the last two labels (good enough for the recon modules,
 * which only use it to query crt.sh / DNS — they tolerate over-broad apexes).
 */
function registrableDomain(target: string): string | undefined {
  const host = safeHost(target);
  if (!host) return undefined;
  // IP addresses have no registrable domain.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) return undefined;
  const stripped = host.replace(/^www\./, "");
  const labels = stripped.split(".");
  if (labels.length <= 2) return stripped;
  return labels.slice(-2).join(".");
}

/**
 * Is `host` a private / loopback / link-local / CGNAT address? Used by the SSRF
 * guard to refuse cloud-metadata (169.254.169.254) and internal targets.
 */
function isPrivateHost(host: string): boolean {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h === "0.0.0.0") return true;
  const v4 = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true; // link-local incl. cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 192 && b === 168) return true; // private
    if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT
    return false;
  }
  if (h.includes(":")) {
    if (h === "::1" || /^f[cd][0-9a-f]{2}:/.test(h) || /^fe80:/.test(h)) return true;
  }
  return false;
}

/**
 * SSRF guard. The pre-pass fetches URLs derived from the SCAN TARGET's own HTML
 * (JS chunk `src`s, a discovered password-reset endpoint). A hostile target
 * could embed a cross-origin or internal `src` to steer the worker into a
 * server-side request forgery. Only follow http(s) URLs on the target's own
 * host or registrable domain, never into private/internal address space.
 */
export function isInScopeUrl(
  rawUrl: string,
  targetHost: string | undefined,
  domain: string | undefined,
): boolean {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return false;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return false;
  const host = u.hostname.toLowerCase();
  if (isPrivateHost(host)) return false;
  if (targetHost && host === targetHost.toLowerCase()) return true;
  if (domain && (host === domain || host.endsWith("." + domain))) return true;
  return false;
}

/**
 * Derive a protected path + login path from a baseline redirect. We only treat
 * the root as a usable gate when it returns a 3xx whose Location looks like a
 * login route. Otherwise return undefined (skip the framework CVE check).
 */
function deriveProtectedAndLogin(
  base: string,
  baseline: ReconResponse,
): { protectedPath: string; loginPath: string } | undefined {
  if (baseline.status < 300 || baseline.status >= 400) return undefined;
  const location = baseline.headers["location"];
  if (!location) return undefined;
  let loginPath: string;
  try {
    loginPath = new URL(location, `${base}/`).pathname;
  } catch {
    loginPath = location;
  }
  if (!/login|signin|sign-in|auth/i.test(loginPath)) return undefined;
  // The protected path is the route that redirected — the root here.
  return { protectedPath: "/", loginPath };
}

/**
 * Find a password-reset-style endpoint referenced from the baseline HTML.
 * Conservative: only matches obvious reset/forgot-password form actions or
 * links, and resolves them against the base. Returns the first match.
 */
function findPasswordResetEndpoint(base: string, html: string): string | undefined {
  const refs = [...html.matchAll(/(?:href|action)=["']([^"']+)["']/gi)].map((m) => m[1]);
  const match = refs.find((r) =>
    /(forgot|reset).*(password|pwd)|password.*(reset|forgot)|reset-password|forgot-password/i.test(r),
  );
  if (!match) return undefined;
  try {
    return new URL(match, `${base}/`).toString();
  } catch {
    return undefined;
  }
}

function createFinding(input: {
  templateId: string;
  title: string;
  description: string;
  severity: Severity;
  category: AttackCategory;
  request: string;
  response: string;
  analysis: string;
}): Finding {
  return {
    id: randomUUID(),
    templateId: input.templateId,
    title: input.title,
    description: input.description,
    severity: input.severity,
    category: input.category,
    status: "discovered",
    evidence: {
      request: input.request,
      response: input.response,
      analysis: input.analysis,
    },
    timestamp: Date.now(),
  };
}
