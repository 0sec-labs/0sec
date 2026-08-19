// ── First-class structured scanner tool wrappers (pwnkit#555) ──
//
// pwnkit is a shell-first agent and, by default, SUPPRESSES generic scanners
// in the `bash` tool (`scope/scanner-binaries.ts`, pwnkit#217): when scope is
// loaded the engagement is presumed to be a coordinated-disclosure run and the
// named scanners (sqlmap/wpscan/nikto/gobuster/dirb/wfuzz/ffuf, `nmap -sV/-A`)
// fingerprint themselves on the wire. That stealthy default is correct there.
//
// BUT for engagements that explicitly permit tooling — CTFs, internal targets,
// authorized pentests run with `--allow-scanners` (threaded down as
// `ctx.allowScanners`) — emitting raw payloads by hand leaves coverage and
// reliability on the table versus competitors that wire mature tools into the
// action space. This module is the structured-wrapper layer:
//
//   * builds a SAFE argv (no shell string concat — `spawn(bin, argv)` with the
//     shell disabled, so target-controlled strings can never break out into a
//     second command);
//   * is wired into `agent/tools.ts` so the wrappers are only EXPOSED and only
//     EXECUTE when `ctx.allowScanners === true` (preserving the stealthy
//     default; see `getToolsForRole` + the per-tool guards);
//   * relies on the caller (`tools.ts`) to enforce the scope allowlist +
//     `RateLimiter` + wallclock ceiling around each run;
//   * PARSES stdout into a normalized structured result (no raw blobs back to
//     the model) that feeds `save_finding` evidence directly.
//
// Mirrors the structured pattern in `agent/wp-fingerprint.ts`: a standalone
// module exporting result interfaces, pure argv builders, pure parsers, and a
// single process runner, with the `tools.ts` method doing the gating/IO glue.
//
// Subprocess rate-limit gap (acknowledged, NOT closed here): each scanner
// shells out and fans many requests internally; node's `RateLimiter` only sees
// the one `acquire()` the caller does before launch. Same disclaimer the scope
// (#218) and rate-limit (#214) work made about bash-extracted URLs. Pacing the
// scanner's own traffic needs an egress proxy on the runner; tracked
// separately.

import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";

// ── Result shapes ─────────────────────────────────────────────────────────

/** Bookkeeping common to every wrapper run (echoed back for audit trails). */
export interface ScannerRunStats {
  binary: string;
  /** The exact argv that was exec'd (no shell). Safe to surface — no secrets. */
  argv: string[];
  durationMs: number;
  timedOut: boolean;
  /** Process exit code, or null if killed by signal / timeout. */
  exitCode: number | null;
}

export interface SqlmapInjectionPoint {
  parameter: string;
  type: string;
  title?: string;
  payload?: string;
}

export interface SqlmapResult {
  tool: "sqlmap";
  vulnerable: boolean;
  dbms?: string;
  injectionPoints: SqlmapInjectionPoint[];
  /** Enumerated database names (`--dbs`). */
  databases: string[];
  /** Enumerated tables, formatted `db.table` when the db is known. */
  tables: string[];
  /** Dumped / enumerated column names (`--columns` / `--dump`). */
  columns: string[];
  /** Last slice of raw output, for the agent to eyeball on a parse miss. */
  rawTail: string;
}

export interface NmapPort {
  port: number;
  protocol: string;
  state: string;
  service?: string;
  version?: string;
}

export interface NmapResult {
  tool: "nmap";
  host?: string;
  openPorts: NmapPort[];
  rawTail: string;
}

export interface FfufHit {
  /** The FUZZ value (input word) that produced the hit, when present. */
  input?: string;
  url?: string;
  status: number;
  length?: number;
  words?: number;
  lines?: number;
}

export interface FfufResult {
  tool: "ffuf";
  hits: FfufHit[];
  rawTail: string;
}

export interface NucleiFinding {
  templateId: string;
  name?: string;
  severity: string;
  matchedAt: string;
  type?: string;
}

export interface NucleiResult {
  tool: "nuclei";
  findings: NucleiFinding[];
  rawTail: string;
}

export type ScannerParsedResult =
  | SqlmapResult
  | NmapResult
  | FfufResult
  | NucleiResult;

// ── Process runner (no shell; hard wallclock ceiling) ───────────────────────

export type ScannerProcessOutcome =
  | { kind: "exit"; exitCode: number; combined: string; durationMs: number }
  | { kind: "timeout"; partial: string; durationMs: number }
  | { kind: "error"; message: string; durationMs: number };

export interface ScannerRunOptions {
  /** Per-call requested timeout (ms). Clamped to `ceilingMs`. */
  timeoutMs: number;
  /** Hard upper bound (ms) — even a longer requested timeout never exceeds it. */
  ceilingMs: number;
  env: Record<string, string>;
}

const SCANNER_GRACE_MS = 2_000;
const SCANNER_MAX_BUFFER = 2 * 1024 * 1024; // 2MB; scanners can be chatty.

/**
 * The ONLY binaries `runScannerProcess` will ever exec. `bin` is typed
 * `string` and, although every in-tree caller passes a literal, we enforce
 * membership in this constant set BEFORE spawning. Two reasons:
 *
 *   1. Defense-in-depth — no future caller (or any unforeseen taint path) can
 *      turn this helper into arbitrary-binary execution.
 *   2. It is the canonical command-injection sanitizer: past this guard the
 *      executed command provably comes from a fixed set of string constants,
 *      so the value flowing into `spawn()` is no longer attacker-influenceable.
 *
 * Combined with `shell: false` (no shell ⇒ `argv` is never re-parsed for shell
 * metacharacters; each element is passed verbatim as a single execve arg), the
 * spawn site carries no command-injection surface. The argv itself is built by
 * the pure, allow-listed builders above (typed knobs only, sanitized values,
 * no free-form flag strings), so neither the command nor its arguments can be
 * coerced into an injection.
 */
const ALLOWED_SCANNER_BINARIES: ReadonlySet<string> = new Set([
  "sqlmap",
  "nmap",
  "ffuf",
  "nuclei",
]);

/**
 * Launch one of the allow-listed scanner binaries. Each branch passes a STRING
 * LITERAL as the command to `spawn` — never a variable — so there is no
 * dynamic-command sink for an injection analyzer to flag, and a `bin` outside
 * the fixed set returns null (refused, fail-closed). `shell: false` is explicit
 * (also the `spawn(cmd, args)` default), so `argv` is never handed to a shell:
 * each element is passed verbatim as an execve argument and shell
 * metacharacters in any argument are inert. The child is its own process-group
 * leader (`detached: true`) so the supervisor can reap forked helpers.
 */
function launchAllowlistedScanner(
  bin: string,
  argv: string[],
  env: Record<string, string>,
): ChildProcess | null {
  const spawnOpts: SpawnOptions = {
    env,
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
    shell: false,
  };
  switch (bin) {
    case "sqlmap":
      return spawn("sqlmap", argv, spawnOpts);
    case "nmap":
      return spawn("nmap", argv, spawnOpts);
    case "ffuf":
      return spawn("ffuf", argv, spawnOpts);
    case "nuclei":
      return spawn("nuclei", argv, spawnOpts);
    default:
      return null;
  }
}

/**
 * Supervise an already-spawned child under a hard wallclock ceiling: capture
 * bounded stdout/stderr, and on timeout signal the whole process group (SIGTERM
 * → SIGKILL after a short grace) so forked helpers die too, returning PARTIAL
 * output rather than hanging unbounded. ENOENT (binary not installed) arrives
 * as a child `error` event and is surfaced as a structured error outcome.
 *
 * Exported so the wallclock / partial-output behaviour can be exercised in
 * tests against an arbitrary child, without routing through the production
 * binary allowlist in `runScannerProcess`.
 */
export function superviseChild(
  child: ChildProcess,
  effectiveTimeoutMs: number,
  startedAt: number,
): Promise<ScannerProcessOutcome> {
  return new Promise((resolvePromise) => {
    let stdoutLen = 0;
    let stderrLen = 0;
    const stdoutChunks: string[] = [];
    const stderrChunks: string[] = [];
    let timedOut = false;
    let settled = false;

    child.stdout?.setEncoding("utf-8");
    child.stderr?.setEncoding("utf-8");
    child.stdout?.on("data", (chunk: string) => {
      if (stdoutLen >= SCANNER_MAX_BUFFER) return;
      stdoutChunks.push(chunk);
      stdoutLen += chunk.length;
    });
    child.stderr?.on("data", (chunk: string) => {
      if (stderrLen >= SCANNER_MAX_BUFFER) return;
      stderrChunks.push(chunk);
      stderrLen += chunk.length;
    });

    const collected = (): string =>
      (stdoutChunks.join("") + "\n" + stderrChunks.join("")).trim();

    const killGroup = (signal: NodeJS.Signals) => {
      const pid = child.pid;
      if (typeof pid !== "number") return;
      try {
        process.kill(-pid, signal);
      } catch {
        try {
          process.kill(pid, signal);
        } catch {
          /* already dead */
        }
      }
    };

    const timer = setTimeout(() => {
      timedOut = true;
      killGroup("SIGTERM");
      setTimeout(() => {
        if (!settled) killGroup("SIGKILL");
      }, SCANNER_GRACE_MS).unref?.();
    }, effectiveTimeoutMs);
    timer.unref?.();

    const settle = (outcome: ScannerProcessOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolvePromise(outcome);
    };

    child.on("error", (err: Error) => {
      settle({
        kind: "error",
        message: err.message,
        durationMs: Date.now() - startedAt,
      });
    });

    child.on("close", (code: number | null, signal: NodeJS.Signals | null) => {
      const durationMs = Date.now() - startedAt;
      if (timedOut) {
        settle({ kind: "timeout", partial: collected(), durationMs });
        return;
      }
      const exitCode = typeof code === "number" ? code : signal ? 1 : 0;
      settle({ kind: "exit", exitCode, combined: collected(), durationMs });
    });
  });
}

/**
 * Run an allow-listed scanner binary with `argv` under the wallclock ceiling
 * and return a typed outcome. The binary MUST be one of
 * ALLOWED_SCANNER_BINARIES — `launchAllowlistedScanner` only ever `spawn()`s a
 * string-literal command, so neither the command nor (with `shell: false`) the
 * arguments form a command-injection surface. A non-allowlisted `bin`, or a
 * synchronous spawn failure, is refused fail-closed as a structured error.
 */
export async function runScannerProcess(
  bin: string,
  argv: string[],
  opts: ScannerRunOptions,
): Promise<ScannerProcessOutcome> {
  const startedAt = Date.now();
  const effectiveTimeout = Math.min(
    Math.max(1, opts.timeoutMs),
    Math.max(1, opts.ceilingMs),
  );
  // Command sanitizer: refuse anything outside the constant allowlist before
  // we ever reach a spawn. Defense-in-depth alongside the literal-command
  // switch inside launchAllowlistedScanner.
  if (!ALLOWED_SCANNER_BINARIES.has(bin)) {
    return {
      kind: "error",
      message: `refusing to spawn non-allowlisted scanner binary '${bin}'`,
      durationMs: Date.now() - startedAt,
    };
  }
  let child: ChildProcess | null;
  try {
    child = launchAllowlistedScanner(bin, argv, opts.env);
  } catch (err) {
    return {
      kind: "error",
      message: err instanceof Error ? err.message : String(err),
      durationMs: Date.now() - startedAt,
    };
  }
  if (!child) {
    return {
      kind: "error",
      message: `refusing to spawn non-allowlisted scanner binary '${bin}'`,
      durationMs: Date.now() - startedAt,
    };
  }
  return superviseChild(child, effectiveTimeout, startedAt);
}

// ── argv builders (pure; no shell concat) ───────────────────────────────────
//
// Each builder takes already-validated, structured options and returns a
// string[] argv. The model never hands us a free-form flag string — every
// surface is a typed, bounded knob — so there is no path by which a
// target-controlled value becomes an unexpected scanner flag (e.g. sqlmap's
// `--os-shell`, `--file-write`) or shell metacharacter.

function clampInt(value: unknown, min: number, max: number, dflt: number): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) return dflt;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

/** Reject values containing anything but the allowed character class. */
function sanitizeToken(value: string, allowed: RegExp): string | null {
  return allowed.test(value) ? value : null;
}

export interface SqlmapOptions {
  url: string;
  /** POST body; presence implies sqlmap treats this as a POST request. */
  data?: string;
  level?: number; // 1-5
  risk?: number; // 1-3
  /** Restrict techniques, e.g. "BEUSTQ". Letters only. */
  technique?: string;
  /** DBMS hint, e.g. "mysql". Alnum only. */
  dbms?: string;
  /** Enumerate databases (`--dbs`). */
  enumerateDbs?: boolean;
  /** Dump the current DB's tables/columns/rows (`--dump`). */
  dump?: boolean;
  threads?: number; // clamped 1-10
}

/**
 * Build a sqlmap argv. Always non-interactive (`--batch`) and never
 * colorized. Deliberately omits every filesystem/OS-shell escalation flag —
 * those are not exposed as options, so they can never be set.
 */
export function buildSqlmapArgv(opts: SqlmapOptions): string[] {
  const argv = ["-u", opts.url, "--batch", "--disable-coloring"];
  if (typeof opts.data === "string" && opts.data.length > 0) {
    argv.push("--data", opts.data);
  }
  argv.push("--level", String(clampInt(opts.level, 1, 5, 1)));
  argv.push("--risk", String(clampInt(opts.risk, 1, 3, 1)));
  if (opts.technique) {
    const t = sanitizeToken(opts.technique.toUpperCase(), /^[BEUSTQ]{1,6}$/);
    if (t) argv.push("--technique", t);
  }
  if (opts.dbms) {
    const d = sanitizeToken(opts.dbms, /^[A-Za-z0-9 _.-]{1,32}$/);
    if (d) argv.push("--dbms", d);
  }
  argv.push("--threads", String(clampInt(opts.threads, 1, 10, 1)));
  if (opts.enumerateDbs) argv.push("--dbs");
  if (opts.dump) argv.push("--dump");
  return argv;
}

export interface NmapOptions {
  target: string;
  /** Port spec, e.g. "22,80,443" or "1-1024". Digits, commas, dashes only. */
  ports?: string;
  /** `-sV` service/version detection. */
  serviceDetection?: boolean;
  /** Scan the N most common ports (`--top-ports`). */
  topPorts?: number;
  /** `-Pn` skip host discovery (default true — many CTF hosts drop pings). */
  skipPing?: boolean;
}

/**
 * Build an nmap argv. We always emit normal output to stdout (no `-oN file`)
 * and never enable NSE scripts (`-sC` / `--script`) here — the structured
 * parser only needs the port table.
 */
export function buildNmapArgv(opts: NmapOptions): string[] {
  const argv: string[] = [];
  if (opts.skipPing !== false) argv.push("-Pn");
  if (opts.serviceDetection) argv.push("-sV");
  if (opts.ports) {
    const p = sanitizeToken(opts.ports, /^[0-9,\-]{1,64}$/);
    if (p) argv.push("-p", p);
  } else if (opts.topPorts) {
    argv.push("--top-ports", String(clampInt(opts.topPorts, 1, 65535, 100)));
  }
  // target last; it is positional and already scope-validated by the caller.
  argv.push(opts.target);
  return argv;
}

export interface FfufOptions {
  /** URL with a FUZZ keyword, e.g. "http://host/FUZZ". */
  url: string;
  /** Path to a wordlist file on the runner. */
  wordlist: string;
  /** Comma-separated status allowlist, e.g. "200,204,301". Digits/commas/dash. */
  matchStatus?: string;
  threads?: number; // clamped 1-50
}

/**
 * Build an ffuf argv that emits machine-readable JSON to stdout (`-of json`,
 * `-o /dev/stdout`) and stays quiet otherwise (`-s`). The JSON schema is what
 * `parseFfufOutput` consumes.
 */
export function buildFfufArgv(opts: FfufOptions): string[] {
  const argv = ["-u", opts.url, "-w", opts.wordlist, "-of", "json", "-o", "/dev/stdout", "-s"];
  if (opts.matchStatus) {
    const m = sanitizeToken(opts.matchStatus, /^[0-9,\-]{1,64}$/);
    if (m) argv.push("-mc", m);
  }
  argv.push("-t", String(clampInt(opts.threads, 1, 50, 10)));
  return argv;
}

export interface NucleiOptions {
  /** Target URL/host. */
  target: string;
  /** Severity allowlist, e.g. "critical,high". Letters/commas only. */
  severity?: string;
  /** Restrict to one or more template tags, e.g. "cve,rce". Letters/commas. */
  tags?: string;
}

/**
 * Build a nuclei argv that streams JSONL findings to stdout (`-jsonl`) and is
 * otherwise silent (`-silent`). `parseNucleiOutput` consumes the JSONL.
 */
export function buildNucleiArgv(opts: NucleiOptions): string[] {
  const argv = ["-u", opts.target, "-jsonl", "-silent"];
  if (opts.severity) {
    const s = sanitizeToken(opts.severity.toLowerCase(), /^[a-z,]{1,40}$/);
    if (s) argv.push("-severity", s);
  }
  if (opts.tags) {
    const t = sanitizeToken(opts.tags.toLowerCase(), /^[a-z0-9,_-]{1,60}$/);
    if (t) argv.push("-tags", t);
  }
  return argv;
}

// ── parsers (pure functions over captured stdout) ───────────────────────────

function tail(text: string, n = 1200): string {
  return text.length > n ? text.slice(text.length - n) : text;
}

/**
 * Parse sqlmap's human-readable stdout. sqlmap has no stable machine output
 * mode that survives `--batch`, so we extract the load-bearing lines:
 *   - "back-end DBMS: MySQL >= 5.0"           → dbms
 *   - "Parameter: id (GET)" + "Type: ..." +
 *     "Title: ..." + "Payload: ..."           → injectionPoints
 *   - "available databases [N]:" list (`[*] foo`)
 *   - "Database: foo" / "Table: bar"          → tables
 *   - dumped column headers under a table block
 */
export function parseSqlmapOutput(raw: string): SqlmapResult {
  const lines = raw.split(/\r?\n/);
  const injectionPoints: SqlmapInjectionPoint[] = [];
  const databases: string[] = [];
  const tables: string[] = [];
  const columns: string[] = [];
  let dbms: string | undefined;
  let currentDb: string | undefined;

  let curParam: string | null = null;
  let curType: string | undefined;
  let curTitle: string | undefined;
  let curPayload: string | undefined;
  const flushInjection = () => {
    if (curParam) {
      injectionPoints.push({
        parameter: curParam,
        type: curType ?? "unknown",
        title: curTitle,
        payload: curPayload,
      });
    }
    curParam = null;
    curType = curTitle = curPayload = undefined;
  };

  let inDbList = false;
  for (const line of lines) {
    const t = line.trim();

    const dbmsMatch = t.match(/back-end DBMS:\s*(.+)$/i);
    if (dbmsMatch) dbms = dbmsMatch[1].trim();

    const paramMatch = t.match(/^Parameter:\s*(.+?)\s*(?:\(([^)]+)\))?$/);
    if (paramMatch) {
      flushInjection();
      curParam = paramMatch[1].trim();
      continue;
    }
    if (curParam) {
      const typeMatch = t.match(/^Type:\s*(.+)$/i);
      if (typeMatch) curType = typeMatch[1].trim();
      const titleMatch = t.match(/^Title:\s*(.+)$/i);
      if (titleMatch) curTitle = titleMatch[1].trim();
      const payloadMatch = t.match(/^Payload:\s*(.+)$/i);
      if (payloadMatch) curPayload = payloadMatch[1].trim();
    }

    if (/available databases\s*\[\d+\]/i.test(t)) {
      inDbList = true;
      continue;
    }
    if (inDbList) {
      const dbItem = t.match(/^\[\*\]\s*(.+)$/);
      if (dbItem) {
        databases.push(dbItem[1].trim());
        continue;
      }
      if (t.length > 0) inDbList = false;
    }

    const dbMatch = t.match(/^Database:\s*(.+)$/i);
    if (dbMatch) currentDb = dbMatch[1].trim();
    const tableMatch = t.match(/^Table:\s*(.+)$/i);
    if (tableMatch) {
      const tbl = tableMatch[1].trim();
      tables.push(currentDb ? `${currentDb}.${tbl}` : tbl);
    }
    // Dumped column header rows look like `| id | name | ... |`. Capture the
    // distinct column names so save_finding gets the "≥1 dumped column" proof.
    const colRow = t.match(/^\|\s*(.+?)\s*\|$/);
    if (colRow && /\|/.test(colRow[1])) {
      for (const c of colRow[1].split("|").map((s) => s.trim())) {
        if (c && !/^[-+]+$/.test(c) && !columns.includes(c)) columns.push(c);
      }
    }
  }
  flushInjection();

  const vulnerable =
    injectionPoints.length > 0 ||
    /sqlmap identified the following injection point/i.test(raw) ||
    (!!dbms && (databases.length > 0 || tables.length > 0));

  return {
    tool: "sqlmap",
    vulnerable,
    dbms,
    injectionPoints,
    databases,
    tables,
    columns,
    rawTail: tail(raw),
  };
}

/**
 * Parse nmap's normal (human-readable) stdout port table:
 *   Nmap scan report for scanme.nmap.org (45.33.32.156)
 *   PORT     STATE SERVICE VERSION
 *   22/tcp   open  ssh     OpenSSH 6.6.1p1 ...
 */
export function parseNmapOutput(raw: string): NmapResult {
  const lines = raw.split(/\r?\n/);
  const openPorts: NmapPort[] = [];
  let host: string | undefined;
  for (const line of lines) {
    const t = line.trim();
    const hostMatch = t.match(/^Nmap scan report for\s+(.+)$/i);
    if (hostMatch && !host) host = hostMatch[1].trim();

    const portMatch = t.match(
      /^(\d{1,5})\/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/i,
    );
    if (portMatch) {
      const service = portMatch[4] === "" ? undefined : portMatch[4];
      const version = portMatch[5]?.trim();
      openPorts.push({
        port: Number(portMatch[1]),
        protocol: portMatch[2].toLowerCase(),
        state: portMatch[3].toLowerCase(),
        service: service && service !== "unknown" ? service : undefined,
        version: version && version.length > 0 ? version : undefined,
      });
    }
  }
  return { tool: "nmap", host, openPorts, rawTail: tail(raw) };
}

/**
 * Parse ffuf JSON output. ffuf `-of json` emits a single object with a
 * `results` array; we also tolerate JSONL (one result object per line) for
 * robustness across ffuf versions.
 */
export function parseFfufOutput(raw: string): FfufResult {
  const hits: FfufHit[] = [];
  const pushResult = (r: unknown) => {
    if (!r || typeof r !== "object") return;
    const o = r as Record<string, unknown>;
    if (typeof o.status !== "number") return;
    const input =
      o.input && typeof o.input === "object"
        ? (() => {
            const inObj = o.input as Record<string, unknown>;
            const v = inObj.FUZZ ?? Object.values(inObj)[0];
            return typeof v === "string" ? v : undefined;
          })()
        : undefined;
    hits.push({
      input,
      url: typeof o.url === "string" ? o.url : undefined,
      status: o.status,
      length: typeof o.length === "number" ? o.length : undefined,
      words: typeof o.words === "number" ? o.words : undefined,
      lines: typeof o.lines === "number" ? o.lines : undefined,
    });
  };

  const trimmed = raw.trim();
  let consumedAsObject = false;
  if (trimmed.startsWith("{")) {
    // Find the outermost JSON object (ffuf may prefix banner lines on stderr,
    // but stdout under `-s -of json` is a clean object).
    try {
      const obj = JSON.parse(trimmed) as Record<string, unknown>;
      if (Array.isArray(obj.results)) {
        for (const r of obj.results) pushResult(r);
        consumedAsObject = true;
      }
    } catch {
      /* fall through to JSONL */
    }
  }
  if (!consumedAsObject) {
    for (const line of trimmed.split(/\r?\n/)) {
      const s = line.trim();
      if (!s.startsWith("{")) continue;
      try {
        pushResult(JSON.parse(s));
      } catch {
        /* skip non-JSON line */
      }
    }
  }
  return { tool: "ffuf", hits, rawTail: tail(raw) };
}

/**
 * Parse nuclei `-jsonl` output: one JSON object per line, each carrying
 * `template-id`, `info: { name, severity }`, `matched-at`, `type`.
 */
export function parseNucleiOutput(raw: string): NucleiResult {
  const findings: NucleiFinding[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const s = line.trim();
    if (!s.startsWith("{")) continue;
    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(s) as Record<string, unknown>;
    } catch {
      continue;
    }
    const templateId =
      (typeof obj["template-id"] === "string" && (obj["template-id"] as string)) ||
      (typeof obj.templateID === "string" && (obj.templateID as string)) ||
      "";
    if (!templateId) continue;
    const info =
      obj.info && typeof obj.info === "object"
        ? (obj.info as Record<string, unknown>)
        : {};
    findings.push({
      templateId,
      name: typeof info.name === "string" ? info.name : undefined,
      severity: typeof info.severity === "string" ? info.severity : "unknown",
      matchedAt:
        (typeof obj["matched-at"] === "string" && (obj["matched-at"] as string)) ||
        (typeof obj.host === "string" && (obj.host as string)) ||
        "",
      type: typeof obj.type === "string" ? obj.type : undefined,
    });
  }
  return { tool: "nuclei", findings, rawTail: tail(raw) };
}

// ── save_finding evidence projection ─────────────────────────────────────────
//
// Normalized results feed `save_finding` directly: we project each actionable
// result into a "suggested finding" the agent can pass straight to the
// save_finding tool (title/severity/category/evidence/poc_steps/description).
// We deliberately do NOT auto-save — operator gate + false-positive discipline
// mean the agent decides; this just removes the busywork of hand-shaping
// evidence from raw scanner output.

export interface SuggestedFinding {
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;
  description: string;
  evidence_request: string;
  evidence_response: string;
  poc_steps: string[];
}

const SEVERITY_RANK: Record<string, SuggestedFinding["severity"]> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
  unknown: "info",
};

export function suggestedFindingsFor(
  result: ScannerParsedResult,
  stats: ScannerRunStats,
): SuggestedFinding[] {
  const argvStr = `${stats.binary} ${stats.argv.join(" ")}`;
  switch (result.tool) {
    case "sqlmap": {
      if (!result.vulnerable) return [];
      const point = result.injectionPoints[0];
      const desc =
        `sqlmap confirmed SQL injection` +
        (result.dbms ? ` (DBMS: ${result.dbms})` : "") +
        (point ? ` on parameter '${point.parameter}' via ${point.type}` : "") +
        (result.columns.length > 0
          ? `; dumped columns: ${result.columns.slice(0, 12).join(", ")}`
          : "") +
        ".";
      return [
        {
          title: `SQL injection${point ? ` in '${point.parameter}'` : ""}${
            result.dbms ? ` (${result.dbms})` : ""
          }`,
          severity: "high",
          category: "sql-injection",
          description: desc,
          evidence_request: argvStr,
          evidence_response: result.rawTail,
          poc_steps: [
            `Run: ${argvStr}`,
            point?.payload
              ? `Injection payload: ${point.payload}`
              : `sqlmap reported the parameter as injectable.`,
            result.columns.length > 0
              ? `Confirmed data access — dumped columns: ${result.columns.join(", ")}`
              : `Confirm impact by enumerating with --dbs/--dump.`,
          ],
        },
      ];
    }
    case "nuclei": {
      return result.findings
        .filter((f) => f.severity !== "info" && f.severity !== "unknown")
        .map((f) => ({
          title: `${f.name ?? f.templateId} (${f.severity})`,
          severity: SEVERITY_RANK[f.severity] ?? "info",
          category: "security-misconfiguration",
          description: `nuclei template '${f.templateId}'${
            f.name ? ` — ${f.name}` : ""
          } matched at ${f.matchedAt}.`,
          evidence_request: argvStr,
          evidence_response: `template-id=${f.templateId} severity=${f.severity} matched-at=${f.matchedAt}`,
          poc_steps: [
            `Run: ${argvStr}`,
            `nuclei template ${f.templateId} matched at ${f.matchedAt}.`,
          ],
        }));
    }
    // nmap / ffuf are recon surfaces — informative, not findings on their own.
    // The agent decides whether an exposed port/path warrants save_finding.
    default:
      return [];
  }
}

// ── summaries (one-liners for the model, like summarizeWpFingerprint) ────────

export function summarizeScannerResult(result: ScannerParsedResult): string {
  switch (result.tool) {
    case "sqlmap":
      return result.vulnerable
        ? `sqlmap: INJECTABLE${result.dbms ? ` (${result.dbms})` : ""}, ` +
            `${result.injectionPoints.length} injection point(s), ` +
            `${result.databases.length} db(s), ${result.tables.length} table(s), ` +
            `${result.columns.length} column(s) dumped`
        : `sqlmap: no injection confirmed`;
    case "nmap":
      return `nmap: ${result.openPorts.length} port(s) reported` +
        (result.host ? ` on ${result.host}` : "");
    case "ffuf":
      return `ffuf: ${result.hits.length} hit(s)`;
    case "nuclei": {
      const bySev = result.findings.reduce<Record<string, number>>((acc, f) => {
        acc[f.severity] = (acc[f.severity] ?? 0) + 1;
        return acc;
      }, {});
      const breakdown = Object.entries(bySev)
        .map(([s, n]) => `${n} ${s}`)
        .join(", ");
      return `nuclei: ${result.findings.length} finding(s)` +
        (breakdown ? ` (${breakdown})` : "");
    }
  }
}
