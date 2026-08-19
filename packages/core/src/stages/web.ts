import { randomUUID } from "node:crypto";
import type { AttackResult, AttackOutcome, Finding, ScanConfig, ScanContext, TargetInfo } from "@pwnkit/shared";
import { RateLimiter, parseRateLimitFlag } from "../scope/rate-limit.js";

/**
 * Per-scan rate-limiter cache (#214). Keyed on ScanConfig identity so
 * every `requestUrl` call inside a single scan shares one set of
 * per-host buckets — critical for 429 cool-off propagation across
 * baseline checks, CORS probes, and sensitive-path scans, all of
 * which hit the same target host.
 *
 * Default 5 rps when `config.rateLimit` is unset, matching the issue's
 * "default conservative" guidance and the agentic-scanner default.
 */
const RATE_LIMITER_CACHE = new WeakMap<ScanConfig, RateLimiter>();
function getStageRateLimiter(config: ScanConfig): RateLimiter {
  let rl = RATE_LIMITER_CACHE.get(config);
  if (!rl) {
    rl = new RateLimiter(parseRateLimitFlag(config.rateLimit ?? "", 5));
    RATE_LIMITER_CACHE.set(config, rl);
  }
  return rl;
}

interface WebProbeResponse {
  url: string;
  status: number;
  body: string;
  headers: Record<string, string>;
  latencyMs: number;
}

interface WebCheckResult {
  findings: Finding[];
  results: AttackResult[];
}

const EVIL_ORIGIN = "https://evil.example";

export async function runWebDiscoveryProbe(
  ctx: ScanContext,
): Promise<TargetInfo> {
  const response = await requestUrl(ctx.config.target, {
    method: "GET",
    headers: {
      Accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    },
    timeout: ctx.config.timeout,
    rateLimiter: getStageRateLimiter(ctx.config),
  });

  return {
    url: ctx.config.target,
    type: "web-app",
    endpoints: discoverInterestingEndpoints(response.body),
    detectedFeatures: detectWebFeatures(response.body, response.headers),
  };
}

export async function runBaselineWebChecks(ctx: ScanContext): Promise<WebCheckResult> {
  const findings: Finding[] = [];
  const results: AttackResult[] = [];

  const baseResponse = await requestUrl(ctx.config.target, {
    method: "GET",
    headers: {
      Accept: "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    },
    timeout: ctx.config.timeout,
    rateLimiter: getStageRateLimiter(ctx.config),
  });

  results.push(
    createAttackResult(
      "web-root-fetch",
      "baseline-get",
      "GET /",
      summarizeResponse(baseResponse),
      "safe",
      baseResponse.latencyMs,
    ),
  );

  const headerFinding = buildSecurityHeadersFinding(ctx, baseResponse);
  results.push(
    createAttackResult(
      "web-security-headers",
      "missing-headers",
      "GET / (security header audit)",
      summarizeResponse(baseResponse),
      headerFinding ? "vulnerable" : "safe",
      baseResponse.latencyMs,
    ),
  );
  if (headerFinding) findings.push(headerFinding);

  const disclosureFinding = buildHeaderDisclosureFinding(baseResponse);
  results.push(
    createAttackResult(
      "web-header-disclosure",
      "server-fingerprint",
      "GET / (response header disclosure check)",
      summarizeResponse(baseResponse),
      disclosureFinding ? "vulnerable" : "safe",
      baseResponse.latencyMs,
    ),
  );
  if (disclosureFinding) findings.push(disclosureFinding);

  const corsCheck = await runCorsCheck(ctx);
  results.push(corsCheck.result);
  if (corsCheck.finding) findings.push(corsCheck.finding);

  const sensitivePathChecks = await runSensitivePathChecks(ctx);
  results.push(...sensitivePathChecks.results);
  findings.push(...sensitivePathChecks.findings);

  return { findings, results };
}

async function runCorsCheck(
  ctx: ScanContext,
): Promise<{ finding?: Finding; result: AttackResult }> {
  const headers = {
    Origin: EVIL_ORIGIN,
    "Access-Control-Request-Method": "POST",
    "Access-Control-Request-Headers": "content-type,authorization",
  };

  let response: WebProbeResponse;
  try {
    response = await requestUrl(ctx.config.target, {
      method: "OPTIONS",
      headers,
      timeout: ctx.config.timeout,
      rateLimiter: getStageRateLimiter(ctx.config),
    });
  } catch {
    response = await requestUrl(ctx.config.target, {
      method: "GET",
      headers: { Origin: EVIL_ORIGIN },
      timeout: ctx.config.timeout,
      rateLimiter: getStageRateLimiter(ctx.config),
    });
  }

  const origin = response.headers["access-control-allow-origin"];
  const credentials = response.headers["access-control-allow-credentials"]?.toLowerCase() === "true";

  let severity: Finding["severity"] | null = null;
  let description = "";
  if ((origin === "*" || origin === EVIL_ORIGIN) && credentials) {
    severity = "high";
    description =
      "The application allows a hostile origin and also permits credentialed cross-origin requests, enabling browser-based data theft.";
  } else if (origin === EVIL_ORIGIN) {
    severity = "medium";
    description =
      "The application reflects an arbitrary Origin value, which weakens same-origin protections for browser clients.";
  } else if (origin === "*") {
    severity = "medium";
    description =
      "The application allows any origin with Access-Control-Allow-Origin: *, expanding cross-origin data exposure.";
  }

  return {
    finding: severity
      ? createFinding({
          templateId: "web-cors",
          title: "Permissive CORS policy",
          description,
          severity,
          category: "cors",
          request: `OPTIONS ${ctx.config.target}\nOrigin: ${EVIL_ORIGIN}\nAccess-Control-Request-Method: POST`,
          response: summarizeResponse(response),
          analysis: `Observed CORS headers: Access-Control-Allow-Origin=${origin ?? "<absent>"}, Access-Control-Allow-Credentials=${response.headers["access-control-allow-credentials"] ?? "<absent>"}.`,
        })
      : undefined,
    result: createAttackResult(
      "web-cors",
      "arbitrary-origin",
      `OPTIONS / with Origin: ${EVIL_ORIGIN}`,
      summarizeResponse(response),
      severity ? "vulnerable" : "safe",
      response.latencyMs,
    ),
  };
}

async function runSensitivePathChecks(ctx: ScanContext): Promise<WebCheckResult> {
  const candidates = [
    {
      path: "/.git/config",
      title: "Exposed Git metadata",
      severity: "high" as const,
      analysis: "The repository's Git config is directly accessible over HTTP, which can disclose repository layout and deployment details.",
      matcher: /\[core\]|\[remote/i,
    },
    {
      path: "/.env",
      title: "Exposed environment file",
      severity: "critical" as const,
      analysis: "The application exposes its .env file over HTTP, which commonly contains secrets and deployment configuration.",
      // Require at least two KEY=value lines to avoid matching random HTML attributes
      matcher: /^[A-Z][A-Z0-9_]+=\S+/m,
      minMatches: 2,
    },
    {
      path: "/server-status",
      title: "Exposed server status endpoint",
      severity: "medium" as const,
      analysis: "A live server-status style endpoint is publicly reachable, leaking operational details about the web stack.",
      matcher: /server version|total accesses|uptime|busyworkers/i,
    },
  ];

  const findings: Finding[] = [];
  const results: AttackResult[] = [];

  for (const candidate of candidates) {
    try {
      const url = new URL(candidate.path, ctx.config.target).toString();
      const response = await requestUrl(url, {
        method: "GET",
        headers: { Accept: "*/*" },
        timeout: ctx.config.timeout,
        rateLimiter: getStageRateLimiter(ctx.config),
      });

      const contentType = response.headers["content-type"]?.toLowerCase() ?? "";
      const isHtmlResponse =
        contentType.includes("text/html")
        || /^\s*<!doctype html/i.test(response.body)
        || /<html[\s>]/i.test(response.body);

      // A 2xx response that matches the signature is only vulnerable if it's
      // NOT an HTML page (SPA catch-all routes return 200 + HTML for every path).
      const matchCount = (response.body.match(new RegExp(candidate.matcher, "gm")) ?? []).length;
      const minRequired = ("minMatches" in candidate ? candidate.minMatches : 1) as number;
      const vulnerable =
        response.status >= 200
        && response.status < 300
        && !isHtmlResponse
        && matchCount >= minRequired;
      results.push(
        createAttackResult(
          "web-sensitive-paths",
          candidate.path,
          `GET ${candidate.path}`,
          summarizeResponse(response),
          vulnerable ? "vulnerable" : "safe",
          response.latencyMs,
        ),
      );

      if (!vulnerable) continue;

      findings.push(
        createFinding({
          templateId: "web-sensitive-paths",
          title: candidate.title,
          description: candidate.analysis,
          severity: candidate.severity,
          category: "security-misconfiguration",
          request: `GET ${candidate.path}`,
          response: summarizeResponse(response),
          analysis: `The response from ${candidate.path} matched sensitive content signatures and should not be publicly accessible.`,
        }),
      );
    } catch {
      results.push(
        createAttackResult(
          "web-sensitive-paths",
          candidate.path,
          `GET ${candidate.path}`,
          "Request failed",
          "error",
          0,
          "Request failed",
        ),
      );
    }
  }

  return { findings, results };
}

function buildSecurityHeadersFinding(ctx: ScanContext, response: WebProbeResponse): Finding | null {
  const requiredHeaders = [
    {
      name: "content-security-policy",
      label: "Content-Security-Policy",
      impact: "without CSP, browsers have fewer defenses against injected script execution",
    },
    {
      name: "x-frame-options",
      label: "X-Frame-Options",
      impact: "without X-Frame-Options, the site is more exposed to clickjacking",
    },
    {
      name: "x-content-type-options",
      label: "X-Content-Type-Options",
      impact: "without X-Content-Type-Options, some browsers may MIME-sniff responses unexpectedly",
    },
  ];

  if (ctx.config.target.startsWith("https://")) {
    requiredHeaders.push({
      name: "strict-transport-security",
      label: "Strict-Transport-Security",
      impact: "without HSTS, browsers may downgrade future visits to plaintext HTTP",
    });
  }

  const missing = requiredHeaders.filter((header) => !response.headers[header.name]);
  if (missing.length === 0) return null;

  const severity = missing.some((header) => header.name === "content-security-policy" || header.name === "x-frame-options")
    ? "medium"
    : "low";

  const summary = missing.map((header) => `${header.label} (${header.impact})`).join("; ");

  return createFinding({
    templateId: "web-security-headers",
    title: "Missing recommended security headers",
    description: `The application is missing ${missing.map((header) => header.label).join(", ")}.`,
    severity,
    category: "security-misconfiguration",
    request: `GET ${ctx.config.target}`,
    response: summarizeResponse(response),
    analysis: summary,
  });
}

function buildHeaderDisclosureFinding(response: WebProbeResponse): Finding | null {
  const exposed = ["server", "x-powered-by"]
    .filter((header) => response.headers[header])
    .map((header) => `${header}: ${response.headers[header]}`);

  if (exposed.length === 0) return null;

  return createFinding({
    templateId: "web-header-disclosure",
    title: "Technology fingerprint exposed in response headers",
    description: "The application discloses server/framework details in response headers.",
    severity: "low",
    category: "information-disclosure",
    request: `GET ${response.url}`,
    response: summarizeResponse(response),
    analysis: `Observed fingerprinting headers: ${exposed.join(", ")}.`,
  });
}

async function requestUrl(
  url: string,
  options: {
    method: string;
    headers?: Record<string, string>;
    timeout?: number;
    /** Optional shared rate limiter; threaded through from ScanContext. */
    rateLimiter?: RateLimiter;
  },
): Promise<WebProbeResponse> {
  const start = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeout ?? 30_000);

  try {
    // #214: pace per-host before each baseline / CORS / sensitive-path probe.
    if (options.rateLimiter) await options.rateLimiter.acquire(url);
    const response = await fetch(url, {
      method: options.method,
      headers: options.headers,
      redirect: "manual",
      signal: controller.signal,
    });
    if (options.rateLimiter) options.rateLimiter.noteResponse(url, response);

    const body = await response.text();
    const headers: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      headers[key] = value;
    });

    return {
      url,
      status: response.status,
      body,
      headers,
      latencyMs: Date.now() - start,
    };
  } finally {
    clearTimeout(timer);
  }
}

function createAttackResult(
  templateId: string,
  payloadId: string,
  request: string,
  response: string,
  outcome: AttackOutcome,
  latencyMs: number,
  error?: string,
): AttackResult {
  return {
    templateId,
    payloadId,
    outcome,
    request,
    response,
    latencyMs,
    timestamp: Date.now(),
    error,
  };
}

function createFinding(input: {
  templateId: string;
  title: string;
  description: string;
  severity: Finding["severity"];
  category: Finding["category"];
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

function summarizeResponse(response: WebProbeResponse): string {
  const headers = Object.entries(response.headers)
    .map(([key, value]) => `${key}: ${value}`)
    .join("\n");

  const bodyPreview = response.body.length > 800
    ? `${response.body.slice(0, 800)}...`
    : response.body;

  return `HTTP ${response.status}\n${headers}${headers ? "\n\n" : ""}${bodyPreview}`;
}

function discoverInterestingEndpoints(body: string): string[] {
  const matches = [...body.matchAll(/(?:href|action)=["']([^"']+)["']/gi)]
    .map((match) => match[1])
    .filter((value) => value.startsWith("/"));

  return [...new Set(matches)].slice(0, 20);
}

function detectWebFeatures(body: string, headers: Record<string, string>): string[] {
  const features: string[] = [];
  const lower = body.toLowerCase();

  if (lower.includes("<form")) features.push("forms");
  if (lower.includes("csrf")) features.push("csrf");
  if (lower.includes("graphql")) features.push("graphql");
  if (lower.includes("<script")) features.push("javascript");
  if (headers["set-cookie"]) features.push("session-cookies");

  return features;
}
