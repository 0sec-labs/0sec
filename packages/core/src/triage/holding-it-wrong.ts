/**
 * "Holding It Wrong" Filter
 *
 * Filters out false-positive findings where the "vulnerability" is really
 * just the documented behavior of the function being flagged. These arise
 * when a scanner identifies a sink like `fs.writeFile`, `compile(code)`, or
 * `toFunction(cb)` and reports it as a vulnerability — ignoring the fact
 * that the function's documented purpose IS to take that kind of input.
 *
 * This filter catches the common "holding it wrong" patterns the CVE-hunt
 * verification surfaced. Findings that match are downgraded to `info` and
 * skipped from further verification.
 */

import type { Finding } from "@pwnkit/shared";

// ────────────────────────────────────────────────────────────────────
// Sink name blocklist
// ────────────────────────────────────────────────────────────────────

/**
 * Function / method names whose documented purpose is exactly to perform an
 * I/O, eval, compile, or persistence operation. Flagging these as vulns just
 * because they accept the argument the developer passes in is "holding it wrong".
 */
const SINK_NAME_BLOCKLIST: string[] = [
  // eval / code construction
  "eval",
  "new Function",
  "Function(",
  "vm.runInNewContext",
  "vm.runInThisContext",
  "vm.runInContext",
  "vm.compileFunction",
  "runInNewContext",
  "runInThisContext",
  "compileFunction",
  // templating / compilation (libraries whose job is to compile user templates)
  "compile",
  "renderFile",
  "render",
  "toFunction",
  "template",
  // filesystem (documented write sinks)
  "writeFile",
  "writeFileSync",
  "write",
  "appendFile",
  "appendFileSync",
  "createWriteStream",
  "mkdir",
  "unlink",
  "rmdir",
  "rm",
  // persistence / storage helpers whose contract includes "write where I tell you"
  "persistData",
  "persist",
  "save",
  "store",
  "setItem",
  // shell / child process (documented exec sinks)
  "exec",
  "execSync",
  "spawn",
  "spawnSync",
  "execFile",
  "execFileSync",
];

// Regex built once for fast blocklist match. We look for the name followed by
// an opening paren (with optional whitespace) to avoid spurious substring hits.
const SINK_NAME_REGEX = new RegExp(
  "\\b(" +
    SINK_NAME_BLOCKLIST.map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|") +
    ")\\s*\\(",
  "i",
);

// ────────────────────────────────────────────────────────────────────
// Heuristic patterns
// ────────────────────────────────────────────────────────────────────

/**
 * Does the PoC require the attacker to supply a callable — a function
 * reference, class constructor, lambda, etc.? If so, the "attacker" has to
 * already be running trusted code, which is not a vulnerability.
 */
const CALLABLE_ARG_PATTERNS: RegExp[] = [
  /function\s*\(/i,
  /=>\s*[\{(]/, // arrow function
  /\bnew\s+[A-Z][A-Za-z0-9_]*\s*\(/, // `new ClassName(`
  /\bclass\s+[A-Z]/, // class body
  /pass(?:es|ing|ed)?\s+a\s+(?:callback|function|constructor|class)/i,
  /requires?\s+a\s+(?:callable|callback|function|constructor|class)/i,
  /\bcb\s*=\s*function/i,
  /\bcallback\s*:\s*function/i,
];

/**
 * "If the developer passes untrusted input..." language — a clear tell that
 * the finding is describing the documented contract, not an attack.
 */
const DEVELOPER_PASSES_UNTRUSTED_PATTERNS: RegExp[] = [
  /if\s+(?:the|a)\s+developer\s+passes?\s+untrusted/i,
  /if\s+the\s+(?:caller|user|application|host)\s+passes?\s+untrusted/i,
  /if\s+untrusted\s+(?:input|data|content)\s+is\s+passed/i,
  /when\s+(?:the\s+)?(?:developer|caller|application)\s+(?:passes?|provides?)\s+(?:untrusted|user|attacker)/i,
  /assumes?\s+(?:the\s+)?(?:caller|developer)\s+(?:sanitize|validate|trust)/i,
  /documented\s+(?:purpose|behavior|contract)/i,
  /by\s+design/i,
  /expected\s+behavior/i,
  /intended\s+(?:use|behavior|purpose)/i,
];

/**
 * Patterns describing an "attacker" who is actually the trusted backend —
 * provider SDK pattern, library's own callsite, etc.
 */
const TRUSTED_BACKEND_ATTACKER_PATTERNS: RegExp[] = [
  /\bprovider\s+sdk\b/i,
  /\bbackend\s+(?:service|sdk|caller)\b/i,
  /\btrusted\s+(?:backend|caller|sdk|server|service)\b/i,
  /\battacker\s+(?:is|would\s+be|must\s+be)\s+(?:the\s+)?(?:backend|server|provider|sdk|library|host)/i,
  /requires?\s+(?:the\s+)?(?:backend|server|provider|sdk)\s+to\s+be\s+(?:malicious|compromised)/i,
  /assumes?\s+(?:a\s+)?(?:malicious|compromised)\s+(?:backend|server|provider|sdk|host)/i,
  /host\s+application\s+(?:pipes?|passes?|forwards?)/i,
];

// ────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────

export interface HoldingItWrongResult {
  isHoldingItWrong: boolean;
  reason: string | null;
}

/**
 * Decide whether a finding represents a real vulnerability or a
 * "holding it wrong" mis-report against a sink that is documented to do
 * exactly what the finding flags it for.
 *
 * Returns `{ isHoldingItWrong: true, reason }` if the finding should be
 * rejected; `{ isHoldingItWrong: false, reason: null }` otherwise.
 */
export function isHoldingItWrong(finding: Finding): HoldingItWrongResult {
  const title = finding.title ?? "";
  const description = finding.description ?? "";
  const analysis = finding.evidence?.analysis ?? "";
  const request = finding.evidence?.request ?? "";
  const response = finding.evidence?.response ?? "";
  const allText = `${title}\n${description}\n${analysis}`;
  const codeText = `${allText}\n${request}\n${response}`;

  // 1. Sink-name blocklist — is the flagged sink just a documented I/O fn?
  const sinkMatch = codeText.match(SINK_NAME_REGEX);
  if (sinkMatch) {
    return {
      isHoldingItWrong: true,
      reason: `Flagged sink \`${sinkMatch[1]}\` is a documented I/O / eval / compilation / persistence operation; accepting its argument is the function's contract, not a vulnerability.`,
    };
  }

  // 2. PoC requires a callable argument — attacker would already be running code
  for (const pattern of CALLABLE_ARG_PATTERNS) {
    if (pattern.test(request) || pattern.test(allText)) {
      return {
        isHoldingItWrong: true,
        reason: `PoC requires a callable argument (function / constructor / class). An attacker who can pass executable code is already running code — this is not a vulnerability.`,
      };
    }
  }

  // 3. "If the developer passes untrusted input..." language
  for (const pattern of DEVELOPER_PASSES_UNTRUSTED_PATTERNS) {
    if (pattern.test(allText)) {
      return {
        isHoldingItWrong: true,
        reason: `Description uses "if the developer passes untrusted input" language — describes documented behavior, not an exploit reachable through realistic input.`,
      };
    }
  }

  // 4. "Attacker" is really a trusted backend
  for (const pattern of TRUSTED_BACKEND_ATTACKER_PATTERNS) {
    if (pattern.test(allText)) {
      return {
        isHoldingItWrong: true,
        reason: `The described "attacker" is actually a trusted backend / provider SDK / host application. No untrusted data crosses a real trust boundary.`,
      };
    }
  }

  return { isHoldingItWrong: false, reason: null };
}
