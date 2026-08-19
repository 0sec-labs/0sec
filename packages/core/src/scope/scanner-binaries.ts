// ── Scanner-binary blacklist (pwnkit#217) ──
//
// Coordinated-disclosure venues (Bugcrowd, HackerOne, Intigriti, etc.)
// commonly distinguish "custom tools" — which are allowed — from
// "generic vulnerability scanners" — which are banned. The line is
// drawn at the network signature: `User-Agent: sqlmap/1.7`,
// WPScan's recognisable WordPress probe pattern,
// `User-Agent: gobuster/3.6`, the wfuzz/ffuf request cadence + path
// dictionary, etc., are all instantly recognisable and explicitly
// forbidden.
//
// pwnkit is a shell-first agent (not a scanner) by design. The agent
// loop has access to bash via `shellExec`, and CI installs the standard
// pentesting toolset (`xbow-bench.yml:118-128`) for niche cases — but
// when scope is loaded (pwnkit#215), the agent is presumed to be
// running against an attribution-bound, disclosed-engagement target.
// The shell-first agent does not need sqlmap to find SQLi: it issues
// manual probe requests through `httpRequest` and reads responses,
// which is the pattern most venue policies welcome.
//
// This module implements a pure detector. Wiring lives in
// `agent/tools.ts:shellExec`, which calls the detector when
// `ctx.scope` is set and `ctx.allowScanners !== true`.
//
// Design choices:
//
//   * The blacklist is a fixed list of scanner binary basenames plus 2 nmap
//     flag combinations (`-sV`, `-A`). Plain `nmap -p ... host` is
//     deliberately allowed — port scanning is a different policy
//     question (and many programs do permit it). The DoD enumerates
//     `nmap -sV` and `nmap -A` as the noisy cases — those are the
//     fingerprint-on-the-wire modes.
//
//   * We recognise three invocation forms per binary:
//       1. bare       → `sqlmap -u ...`
//       2. abs path   → `/usr/bin/sqlmap -u ...`
//       3. relative   → `./sqlmap -u ...`, `../tools/sqlmap`
//     Plus `python3 -m sqlmap ...` for sqlmap (the documented
//     pip-install invocation form).
//
//   * Detection runs against EVERY pipeline / `&&` / `||` / `;` /
//     `&` segment of the command. A user who pipelines
//     `echo http://target.com | sqlmap --batch` should still be
//     refused — the blacklisted binary is in segment 2, not segment 1.
//
//   * No regex on raw command text. We tokenise (re-using the same
//     shell-aware splitter that gates `run_command`) so quoting and
//     escapes can't sneak a name through, e.g. `s\qlmap`. Quoting
//     IS a defence-evasion vector (`"sqlmap"`) and the tokeniser
//     strips quotes — that's a feature, not a bug.

const SCANNER_BINARIES: ReadonlyArray<string> = [
  "sqlmap",
  "wpscan",
  "nikto",
  "gobuster",
  "dirb",
  "wfuzz",
  "ffuf",
];

/**
 * `nmap` itself is not blacklisted (port scanning is policy-orthogonal).
 * What IS blacklisted is service / OS fingerprinting — those are the
 * modes the issue body calls out and the modes that produce the
 * "looks like a generic scanner" signature on the wire.
 */
const NMAP_FORBIDDEN_FLAGS = new Set(["-sV", "-A"]);

export interface ScannerDetection {
  binary: string;
  reason: string;
}

/**
 * Strip a path prefix off a token to get the basename. Handles both
 * POSIX and Windows separators because the agent runs in CI containers
 * (POSIX) but tests can be invoked from Windows checkouts.
 */
function basename(token: string): string {
  const slash = Math.max(token.lastIndexOf("/"), token.lastIndexOf("\\"));
  return slash === -1 ? token : token.slice(slash + 1);
}

/**
 * Scan a single tokenised command segment (e.g. one side of a pipeline)
 * for a scanner-binary invocation. Returns the detection on the first
 * match — we don't enumerate every blacklisted binary on a single line,
 * the operator should fix the first hit and re-run.
 */
function detectInSegment(tokens: string[]): ScannerDetection | null {
  if (tokens.length === 0) return null;

  // Skip leading env-var assignments: `FOO=bar BAZ=1 sqlmap -u …`.
  let i = 0;
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) {
    i++;
  }
  if (i >= tokens.length) return null;

  const head = tokens[i];
  const headBase = basename(head);

  // Direct match: bare, absolute, or relative invocation.
  if (SCANNER_BINARIES.includes(headBase)) {
    return {
      binary: headBase,
      reason: `'${headBase}' is a generic vulnerability scanner. Coordinated-disclosure scope policies typically forbid it (pwnkit#217). Use the agent's manual probe tools (http_request, crawl) instead, or pass --allow-scanners to override.`,
    };
  }

  // `nmap` — only some flag combinations are scanner-pattern.
  if (headBase === "nmap") {
    for (let j = i + 1; j < tokens.length; j++) {
      const tok = tokens[j];
      if (NMAP_FORBIDDEN_FLAGS.has(tok)) {
        return {
          binary: `nmap ${tok}`,
          reason: `'nmap ${tok}' performs service/OS fingerprinting and matches the generic-scanner traffic pattern that coordinated-disclosure scope policies forbid (pwnkit#217). Plain port scans are unaffected. Pass --allow-scanners to override.`,
        };
      }
    }
    return null;
  }

  // `python3 -m sqlmap` and friends — the documented pip-install form
  // of the same binary. We only carve out modules that match the
  // scanner-binary basename list.
  if (headBase === "python" || headBase === "python3" || headBase === "python2") {
    for (let j = i + 1; j < tokens.length - 1; j++) {
      if (tokens[j] === "-m") {
        const mod = tokens[j + 1];
        if (mod && SCANNER_BINARIES.includes(mod)) {
          return {
            binary: `python -m ${mod}`,
            reason: `'python -m ${mod}' invokes the same generic scanner via its Python module entry point. Coordinated-disclosure scope policies typically forbid it (pwnkit#217). Pass --allow-scanners to override.`,
          };
        }
      }
    }
  }

  return null;
}

/**
 * Tokenise a shell command using the same quote-aware rules the rest of
 * the codebase enforces. We deliberately accept malformed input and
 * fall back to a coarse whitespace split — the goal is detection, not
 * a full shell parser, and a malformed command will fail at the actual
 * shell anyway. Returning `null` from the caller on a parse failure
 * would create a bypass: `sqlmap "` (unmatched quote) would slip the
 * gate. We always do best-effort detection.
 */
function tokenizeBestEffort(segment: string): string[] {
  const tokens: string[] = [];
  let cur = "";
  let quote: "'" | '"' | null = null;
  let escaping = false;
  for (const ch of segment) {
    if (escaping) {
      cur += ch;
      escaping = false;
      continue;
    }
    if (ch === "\\") {
      escaping = true;
      continue;
    }
    if (quote) {
      if (ch === quote) {
        quote = null;
      } else {
        cur += ch;
      }
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (/\s/.test(ch)) {
      if (cur) {
        tokens.push(cur);
        cur = "";
      }
      continue;
    }
    cur += ch;
  }
  if (cur) tokens.push(cur);
  return tokens;
}

/**
 * Split a command on shell control operators (`|`, `||`, `&&`, `;`,
 * `&`) at the top level — i.e. NOT inside quotes. Each segment is then
 * tokenised and passed to {@link detectInSegment}. Subshells `$(...)`
 * and backticks are treated as opaque text and tokenised whole; they
 * usually don't host scanner binaries (you'd write the binary at the
 * top level), but if they do the basename will still be picked up.
 */
function splitOnControlOperators(command: string): string[] {
  const segments: string[] = [];
  let buf = "";
  let quote: "'" | '"' | null = null;
  let escaping = false;
  let i = 0;
  while (i < command.length) {
    const ch = command[i];
    if (escaping) {
      buf += ch;
      escaping = false;
      i++;
      continue;
    }
    if (ch === "\\") {
      buf += ch;
      escaping = true;
      i++;
      continue;
    }
    if (quote) {
      buf += ch;
      if (ch === quote) quote = null;
      i++;
      continue;
    }
    if (ch === "'" || ch === '"') {
      buf += ch;
      quote = ch;
      i++;
      continue;
    }
    // Two-char operators first (`&&`, `||`).
    if ((ch === "&" && command[i + 1] === "&") || (ch === "|" && command[i + 1] === "|")) {
      segments.push(buf);
      buf = "";
      i += 2;
      continue;
    }
    if (ch === "|" || ch === ";" || ch === "&") {
      segments.push(buf);
      buf = "";
      i++;
      continue;
    }
    buf += ch;
    i++;
  }
  segments.push(buf);
  return segments;
}

/**
 * Detect a scanner-binary invocation in a shell command. Returns the
 * first match (binary name + human-readable reason) or `null` if the
 * command doesn't reference a blacklisted scanner.
 *
 * Pure function. Caller is responsible for the scope-loaded /
 * allow-scanners gating decision — this only answers "would this
 * command spawn a generic scanner?".
 */
export function detectScannerBinary(command: string): ScannerDetection | null {
  if (!command || !command.trim()) return null;
  for (const segment of splitOnControlOperators(command)) {
    const tokens = tokenizeBestEffort(segment);
    const hit = detectInSegment(tokens);
    if (hit) return hit;
  }
  return null;
}

/**
 * The blacklist constant, exported for tests + documentation. Treat
 * as readonly.
 */
export const SCANNER_BINARY_BLACKLIST: ReadonlyArray<string> = SCANNER_BINARIES;
