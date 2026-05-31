/**
 * PoV (Proof-of-Vulnerability) Generation Gate
 *
 * Empirical ground truth from "All You Need Is A Fuzzing Brain"
 * (arXiv:2509.07225): if the agent can't build a working PoC in N turns,
 * the finding is almost certainly a false positive.
 *
 * This module spins up a narrowly-scoped mini agent loop whose ONE job is
 * to produce a concrete, executable exploit that demonstrably works. No
 * speculation, no "would-be" payloads — it must run the exploit and the
 * response must contain category-specific proof of exploitation.
 *
 * Outcome flow:
 *   hasPov:true  → boost confidence, attach artifact to finding.evidence
 *   hasPov:false → downgrade severity to "info", triageNote = "no_pov"
 */
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type {
  NativeRuntime,
  NativeMessage,
  NativeContentBlock,
  NativeToolDef,
} from "../runtime/types.js";
import type { Finding, AttackCategory } from "@pwnkit/shared";
import { verifyOracleByCategory, type OracleResult } from "./oracles.js";
import type { VerifyVerdict } from "./verify-verdict.js";
import type { CrashArtifact } from "./memsafety-types.js";
import { classifyUserspacePrimitive } from "./userspace-primitive.js";

const execFileAsync = promisify(execFile);

// ────────────────────────────────────────────────────────────────────
// Public API
// ────────────────────────────────────────────────────────────────────

export type PovArtifactType =
  | "curl"
  | "python"
  | "javascript"
  | "bash"
  | "none";

/**
 * Which oracle decided the verdict.
 *  - `headless-browser`: real Playwright dialog/execution capture (XSS).
 *  - `oast-callback`: out-of-band collector hit (SSRF / blind RCE / blind
 *    injection).
 *  - `regex-fallback`: no deterministic oracle for the category, so we fell
 *    back to regex over the agent-supplied execution evidence.
 */
export type PovOracle = "headless-browser" | "oast-callback" | "regex-fallback";

export interface PovResult {
  hasPov: boolean;
  /** The concrete working PoC (curl command, script, etc.) or null. */
  povArtifact: string | null;
  artifactType: PovArtifactType;
  /** Raw response/output proving the exploit worked. */
  executionEvidence: string;
  /** 0.0–1.0 confidence that this PoC genuinely demonstrates exploitation. */
  confidence: number;
  /** Number of agent turns used. Equals maxTurns when the gate times out. */
  turnsUsed: number;
  /** Short human-readable reason for the verdict. */
  reason: string;
  /** Which oracle produced the verdict (deterministic vs regex fallback). */
  oracle: PovOracle;
  /**
   * True when the deciding oracle could not run to a conclusion (e.g. browser
   * launch failed, collector errored). Inconclusive means "do not trust the
   * verdict" — we NEVER upgrade an inconclusive oracle to a pass.
   */
  inconclusive?: boolean;
}

/**
 * Map a finding category to the deterministic oracle that should adjudicate
 * its PoV, if any. Categories without a deterministic oracle fall back to the
 * regex judge.
 *
 * This is the single source of truth the PoV gate uses to decide whether to
 * delegate to `oracles.ts` or to regex-judge the agent's evidence. It is kept
 * deliberately conservative: only categories whose oracle produces an
 * out-of-model, reproducible artifact (a fired browser dialog or an OAST
 * callback) are delegated. Response-pattern oracles (sqli error strings,
 * /etc/passwd content, IDOR diffs) still flow through the regex judge here —
 * they are run separately as the `oracle` triage layer in agentic-scanner and
 * do not need to be re-run inside the PoV gate.
 */
export function oracleForCategory(category: AttackCategory): PovOracle {
  switch (category) {
    case "xss":
      return "headless-browser";
    case "ssrf":
    case "command-injection":
    case "code-injection":
      return "oast-callback";
    default:
      return "regex-fallback";
  }
}

// ────────────────────────────────────────────────────────────────────
// Mini-loop tools
//
// We intentionally expose a *minimal* tool set — bash (for curl/scripts)
// and http_request (for typed HTTP). A narrow surface keeps the agent
// focused on producing executables rather than drifting into
// reconnaissance.
// ────────────────────────────────────────────────────────────────────

const POV_TOOLS: NativeToolDef[] = [
  {
    name: "bash",
    description:
      "Execute a shell command (curl, python, etc.) to run the exploit. " +
      "Use this to actually invoke your PoC and capture its output.",
    input_schema: {
      type: "object",
      properties: {
        command: { type: "string", description: "Shell command to run" },
      },
      required: ["command"],
    },
  },
  {
    name: "http_request",
    description:
      "Send a raw HTTP request. Returns the response body/status. " +
      "Useful when you want a typed request without shelling out to curl.",
    input_schema: {
      type: "object",
      properties: {
        url: { type: "string", description: "Target URL" },
        method: { type: "string", description: "HTTP method (default GET)" },
        body: { type: "string", description: "Request body" },
        headers: {
          type: "object",
          description: "Additional headers as key-value pairs",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "submit_pov",
    description:
      "Submit the final proof-of-vulnerability once you have confirmed " +
      "the exploit works. Call this EXACTLY ONCE with the working artifact " +
      "and the execution output that proves exploitation. Only call this " +
      "after you have actually run the exploit and seen category-specific " +
      "proof in the response.",
    input_schema: {
      type: "object",
      properties: {
        artifact_type: {
          type: "string",
          description: "Type of artifact",
          enum: ["curl", "python", "javascript", "bash"],
        },
        artifact: {
          type: "string",
          description:
            "The concrete PoC (e.g. the full curl command or script source).",
        },
        execution_evidence: {
          type: "string",
          description:
            "The response / output from running the artifact, showing " +
            "category-specific proof (extracted data, /etc/passwd, whoami, " +
            "reflected script, etc.).",
        },
      },
      required: ["artifact_type", "artifact", "execution_evidence"],
    },
  },
  {
    name: "give_up",
    description:
      "Call this if you CANNOT produce a working exploit. Do NOT speculate " +
      "or describe what would happen — if you cannot run it and see real " +
      "proof, give up honestly.",
    input_schema: {
      type: "object",
      properties: {
        reason: { type: "string", description: "Why no PoV was possible" },
      },
      required: ["reason"],
    },
  },
];

// ────────────────────────────────────────────────────────────────────
// Evidence judging — category-specific regex oracles
//
// These are deliberately strict: a PoC is only accepted if the claimed
// execution_evidence actually contains proof specific to the category.
// Generic 200 OK responses are not proof.
// ────────────────────────────────────────────────────────────────────

interface CategoryJudge {
  /** Regex patterns; matching ANY is sufficient proof. */
  patterns: RegExp[];
  /** Human-readable description for the judge's "reason" field. */
  label: string;
}

const CATEGORY_JUDGES: Partial<Record<AttackCategory, CategoryJudge>> = {
  "sql-injection": {
    label: "SQLi: extracted DB data / error / version string",
    patterns: [
      /\b(mysql|mariadb|postgres|postgresql|sqlite|oracle)\b.*\bversion\b/i,
      /\b\d+\.\d+\.\d+[-\w]*-?(mariadb|mysql|ubuntu|debian|log)\b/i,
      /you have an error in your sql syntax/i,
      /ORA-\d{5}/,
      /pg_(sleep|version|database)/i,
      /information_schema\.(tables|columns|schemata)/i,
      /union\s+select/i,
      /\bsqlite_version\(\)/i,
      // Extracted user/hash row patterns
      /['"]\s*,\s*['"][0-9a-f]{32,}['"]/,
    ],
  },
  xss: {
    label: "XSS: script reflected unencoded or dialog fired",
    patterns: [
      /<script[^>]*>[^<]*(alert|confirm|prompt)\s*\(/i,
      /on(error|load|click|mouseover)\s*=\s*["']?\s*(alert|confirm|prompt)\s*\(/i,
      /dialog\s+(fired|opened|appeared)/i,
      /\balert\(1\)/i,
      /javascript:alert/i,
    ],
  },
  ssrf: {
    label: "SSRF: internal IP/metadata endpoint responded",
    patterns: [
      /169\.254\.169\.254/,
      /metadata\.google\.internal/i,
      /instance-identity/i,
      /iam\/security-credentials/i,
      /127\.0\.0\.1|localhost/i,
      /10\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
      /192\.168\.\d{1,3}\.\d{1,3}/,
      /172\.(1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}/,
    ],
  },
  "command-injection": {
    label: "RCE: command output in response",
    patterns: [
      /uid=\d+\([^)]+\)\s+gid=\d+/,
      /\broot:x:0:0:/,
      /Linux\s+[\w.-]+\s+\d+\.\d+\.\d+/,
      /^\/bin\/(bash|sh)/m,
      /PATH=[^\n]{5,}/,
      /^(usr|bin|etc|var|tmp|home|root)\b/m,
      /\bwhoami\b\s*[\r\n]+\s*\w+/i,
    ],
  },
  "code-injection": {
    label: "Code injection: arbitrary code output in response",
    patterns: [
      /uid=\d+\([^)]+\)/,
      /\broot:x:0:0:/,
      /__import__|eval\(|exec\(/,
      /\bpython\d?\b.*traceback/i,
    ],
  },
  "path-traversal": {
    label: "LFI: sensitive file contents in response",
    patterns: [
      /\broot:x:0:0:/,
      /\bdaemon:x:\d+:\d+:/,
      /\[boot loader\]/i,
      /-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
      /\/etc\/shadow/,
    ],
  },
  "information-disclosure": {
    label: "IDOR / info disclosure: access to restricted data",
    patterns: [
      /"(email|password|ssn|credit_?card|api[_-]?key|token)"\s*:/i,
      /\broot:x:0:0:/,
      /-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
      /user\s*id\s*[:=]\s*\d+/i,
    ],
  },
  "heap-overflow": {
    label: "Heap overflow: KASAN out-of-bounds or crash evidence",
    patterns: [
      /BUG:\s*KASAN:\s*(slab-)?out-of-bounds/i,
      /heap-buffer-overflow/i,
      /\bKASAN\b.*\b(read|write)\b.*\bsize\s+\d+\b/i,
      /allocated by task/i,
      /Oops:.*\[#\d+\]/,
    ],
  },
  "use-after-free": {
    label: "UAF: KASAN use-after-free or freed-object access",
    patterns: [
      /BUG:\s*KASAN:\s*(slab-)?use-after-free/i,
      /Freed by task/i,
      /\buse-after-free\b/i,
      /\bKASAN\b.*\bfreed\b/i,
      /allocated by task.*\nfreed by task/is,
    ],
  },
  "stack-buffer-overflow": {
    label: "Stack overflow: KASAN stack-out-of-bounds",
    patterns: [
      /BUG:\s*KASAN:\s*stack-out-of-bounds/i,
      /stack-buffer-overflow/i,
      /\bKASAN\b.*\bstack\b/i,
    ],
  },
  "null-pointer-deref": {
    label: "Null deref: kernel NULL pointer dereference",
    patterns: [
      /BUG:\s*kernel NULL pointer dereference/i,
      /unable to handle kernel NULL pointer/i,
      /general protection fault.*0000/i,
      /Oops:.*\[#\d+\]/,
      /IP:.*\+0x/,
    ],
  },
  "integer-overflow": {
    label: "Integer overflow: UBSAN or arithmetic overflow",
    patterns: [
      /UBSAN:\s*(shift|integer|array)/i,
      /signed integer overflow/i,
      /unsigned integer overflow/i,
      /shift.*out of range/i,
      /division by zero/i,
    ],
  },
  "race-condition": {
    label: "Race: RCU stall or lock dependency violation",
    patterns: [
      /rcu.*stall/i,
      /INFO:\s*possible circular locking/i,
      /WARNING:.*lockdep/i,
      /DEADLOCK/i,
      /inconsistent lock state/i,
    ],
  },
  "double-free": {
    label: "Double free: KASAN double-free detection",
    patterns: [
      /BUG:\s*KASAN:\s*double-free/i,
      /KASAN.*double.?free/i,
      /Object already free/i,
    ],
  },
  "type-confusion": {
    label: "Type confusion: invalid cast or type mismatch",
    patterns: [
      /UBSAN:\s*member access.*type/i,
      /type.*confusion/i,
      /invalid.*downcast/i,
      /load of misaligned address/i,
    ],
  },
};

interface JudgeVerdict {
  passed: boolean;
  matchedPattern?: string;
  label: string;
}

/**
 * Judge whether `executionEvidence` actually proves exploitation for the
 * finding's category. If there is no judge for the category, we fall back
 * to a conservative set of generic proof patterns.
 */
export function judgePovEvidence(
  finding: Finding,
  executionEvidence: string,
): JudgeVerdict {
  const judge = CATEGORY_JUDGES[finding.category];
  if (judge) {
    for (const pat of judge.patterns) {
      const m = executionEvidence.match(pat);
      if (m) {
        return { passed: true, matchedPattern: m[0], label: judge.label };
      }
    }
    return { passed: false, label: judge.label };
  }

  // Generic fallback — any of these strongly suggests exploitation.
  const generic: RegExp[] = [
    /uid=\d+\([^)]+\)/,
    /\broot:x:0:0:/,
    /flag\{[^}]+\}/i,
    /-----BEGIN (RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----/,
    /HTTP\/\d\.\d\s+200\s+OK[\s\S]{0,2000}password/i,
  ];
  for (const pat of generic) {
    const m = executionEvidence.match(pat);
    if (m) {
      return {
        passed: true,
        matchedPattern: m[0],
        label: "generic exploitation proof",
      };
    }
  }
  return { passed: false, label: "no category-specific proof" };
}

// ────────────────────────────────────────────────────────────────────
// Prompt construction
// ────────────────────────────────────────────────────────────────────

function buildPovSystemPrompt(
  finding: Finding,
  target: string,
  maxTurns: number,
): string {
  return `You are the PoV (Proof-of-Vulnerability) agent.

You have ONE JOB: demonstrate that this finding is actually exploitable by
RUNNING a working exploit against the target and capturing output that
proves the vulnerability is real.

# Target
${target}

# Finding under test
- id: ${finding.id}
- title: ${finding.title}
- category: ${finding.category}
- severity: ${finding.severity}

# Evidence from the original agent
Request:
${(finding.evidence.request ?? "").slice(0, 2000)}

Response:
${(finding.evidence.response ?? "").slice(0, 2000)}

Analysis:
${(finding.evidence.analysis ?? "").slice(0, 1000)}

# Rules (these override any general instincts)
1. You MUST produce a CONCRETE, EXECUTABLE exploit (curl/python/bash/js).
2. You MUST actually RUN it via the \`bash\` or \`http_request\` tool and
   capture the response.
3. The captured response MUST contain category-specific proof of
   exploitation (extracted data, /etc/passwd, uid=0, reflected <script>,
   169.254.169.254 metadata, etc.). A 200 OK alone is NOT proof.
4. DO NOT speculate, DO NOT describe what would happen, DO NOT paraphrase.
   If you cannot run it and see real proof, call \`give_up\`.
5. When you have working proof, call \`submit_pov\` ONCE with the exact
   artifact and the exact output.
6. You have at most ${maxTurns} turns. Be decisive.

# Accepted proof by category
- sql-injection: extracted rows, version strings, SQL error, union select data
- xss: <script> reflected unencoded, or dialog fired
- ssrf: 169.254.169.254 or internal network response
- command-injection / code-injection: uid=, /etc/passwd, kernel version
- path-traversal: /etc/passwd, shadow, private keys
- information-disclosure: sensitive fields (password, api_key, tokens)

Start by writing the exploit and running it. No preamble.`;
}

// ────────────────────────────────────────────────────────────────────
// Lightweight tool handlers
//
// These are deliberately inlined and self-contained so the PoV gate
// doesn't depend on the full ToolExecutor/DB machinery — which makes
// unit testing trivial (mock runtime only, no sandbox setup).
// ────────────────────────────────────────────────────────────────────

const MAX_OUTPUT_CHARS = 8000;
const BASH_TIMEOUT_MS = 15_000;

function clip(s: string): string {
  if (s.length <= MAX_OUTPUT_CHARS) return s;
  return `${s.slice(0, MAX_OUTPUT_CHARS)}\n…[truncated ${s.length - MAX_OUTPUT_CHARS} chars]`;
}

async function runBash(command: string): Promise<string> {
  try {
    const { stdout, stderr } = await execFileAsync("bash", ["-lc", command], {
      timeout: BASH_TIMEOUT_MS,
      maxBuffer: 2 * 1024 * 1024,
    });
    return clip(`$ ${command}\n${stdout}${stderr ? `\n[stderr]\n${stderr}` : ""}`);
  } catch (err) {
    const e = err as NodeJS.ErrnoException & { stdout?: string; stderr?: string };
    return clip(
      `$ ${command}\n[error] ${e.message}\n${e.stdout ?? ""}${e.stderr ?? ""}`,
    );
  }
}

async function runHttp(input: Record<string, unknown>): Promise<string> {
  const url = String(input.url ?? "");
  const method = String(input.method ?? "GET");
  const body = input.body !== undefined ? String(input.body) : undefined;
  const headers = (input.headers as Record<string, string> | undefined) ?? {};
  if (!url) return "[error] url is required";
  try {
    const res = await fetch(url, {
      method,
      headers,
      body,
    });
    const text = await res.text();
    return clip(`HTTP/${res.status} ${method} ${url}\n${text}`);
  } catch (err) {
    return clip(`[error] fetch ${url}: ${(err as Error).message}`);
  }
}

// ────────────────────────────────────────────────────────────────────
// Main entry point
// ────────────────────────────────────────────────────────────────────

export interface GeneratePovOptions {
  /**
   * Override the regex judge (used only for `regex-fallback` categories or as
   * a last resort). Tests can inject a deterministic verdict here.
   */
  judge?: (finding: Finding, evidence: string) => JudgeVerdict;
  /**
   * Override the deterministic oracle. Defaults to the shared
   * `verifyOracleByCategory` from `oracles.ts`. Tests inject a mocked browser /
   * collector here. If this throws, the verdict is INCONCLUSIVE (never a pass).
   */
  oracle?: (finding: Finding, target: string) => Promise<OracleResult>;
  /**
   * Pre-computed oracle result from an upstream stage (e.g. the `oracle` triage
   * layer in agentic-scanner already ran `verifyOracleByCategory`). When
   * supplied for a category that delegates to an oracle, the PoV gate reuses it
   * instead of running the oracle a second time.
   */
  precomputedOracle?: OracleResult;
  /** Skip bash execution (tests). If set, bash returns a stub. */
  disableBash?: boolean;
  /** Skip http fetch (tests). If set, http_request returns a stub. */
  disableHttp?: boolean;
}

/**
 * Heuristic: does an `OracleResult.reason` describe an *infrastructure* error
 * (browser failed to launch, collector failed to bind, probe failed to send)
 * rather than a clean "exploit did not reproduce"? Infra errors must surface as
 * INCONCLUSIVE so we never silently fall through to a pass and never downgrade a
 * real finding just because the oracle harness broke.
 */
function isOracleInfraError(reason: string): boolean {
  return /\b(failed|error|threw|exception|unavailable|timed? ?out)\b/i.test(
    reason,
  );
}

export async function generatePov(
  finding: Finding,
  target: string,
  runtime: NativeRuntime,
  maxTurns: number = 5,
  opts: GeneratePovOptions = {},
): Promise<PovResult> {
  const oracleKind = oracleForCategory(finding.category);
  const system = buildPovSystemPrompt(finding, target, maxTurns);
  const messages: NativeMessage[] = [
    {
      role: "user",
      content: [
        {
          type: "text",
          text: "Build and run a working PoC for the finding above. Remember: real execution, real output, no speculation.",
        },
      ],
    },
  ];

  const judge = opts.judge ?? judgePovEvidence;

  let submitted: {
    artifact_type: PovArtifactType;
    artifact: string;
    execution_evidence: string;
  } | null = null;
  let gaveUpReason: string | null = null;
  let turnsUsed = 0;

  for (let turn = 1; turn <= maxTurns; turn++) {
    turnsUsed = turn;

    const result = await runtime.executeNative(system, messages, POV_TOOLS);

    if (result.error) {
      return {
        hasPov: false,
        povArtifact: null,
        artifactType: "none",
        executionEvidence: "",
        confidence: 0,
        turnsUsed,
        reason: `runtime error: ${result.error}`,
        oracle: oracleKind,
      };
    }

    messages.push({ role: "assistant", content: result.content });

    const toolUseBlocks = result.content.filter(
      (b): b is Extract<NativeContentBlock, { type: "tool_use" }> =>
        b.type === "tool_use",
    );

    // Model replied with text only — nudge it once, then bail.
    if (toolUseBlocks.length === 0) {
      messages.push({
        role: "user",
        content: [
          {
            type: "text",
            text: "No tool call detected. Either RUN the exploit via `bash`/`http_request` and then call `submit_pov`, or call `give_up`. No speculation.",
          },
        ],
      });
      continue;
    }

    const toolResults: NativeContentBlock[] = [];
    for (const block of toolUseBlocks) {
      let output: string;
      switch (block.name) {
        case "bash": {
          const cmd = String(block.input.command ?? "");
          output = opts.disableBash
            ? `[bash disabled in test mode] would run: ${cmd}`
            : await runBash(cmd);
          break;
        }
        case "http_request": {
          output = opts.disableHttp
            ? `[http disabled in test mode] would fetch: ${JSON.stringify(block.input)}`
            : await runHttp(block.input);
          break;
        }
        case "submit_pov": {
          const art = String(block.input.artifact ?? "");
          const ev = String(block.input.execution_evidence ?? "");
          const at = String(block.input.artifact_type ?? "bash");
          submitted = {
            artifact: art,
            execution_evidence: ev,
            artifact_type: (["curl", "python", "javascript", "bash"].includes(at)
              ? at
              : "bash") as PovArtifactType,
          };
          output = "submitted";
          break;
        }
        case "give_up": {
          gaveUpReason = String(block.input.reason ?? "agent gave up");
          output = "acknowledged";
          break;
        }
        default:
          output = `[error] unknown tool ${block.name}`;
      }
      toolResults.push({
        type: "tool_result",
        tool_use_id: block.id,
        content: output,
      });
    }
    messages.push({ role: "user", content: toolResults });

    if (submitted) break;
    if (gaveUpReason) break;
  }

  // ── Finalize verdict ──

  if (gaveUpReason) {
    return {
      hasPov: false,
      povArtifact: null,
      artifactType: "none",
      executionEvidence: "",
      confidence: 0,
      turnsUsed,
      reason: `agent gave up: ${gaveUpReason}`,
      oracle: oracleKind,
    };
  }

  if (!submitted) {
    return {
      hasPov: false,
      povArtifact: null,
      artifactType: "none",
      executionEvidence: "",
      confidence: 0,
      turnsUsed,
      reason:
        turnsUsed >= maxTurns
          ? `max turns (${maxTurns}) exceeded without a working PoC`
          : "agent exited without submitting a PoC",
      oracle: oracleKind,
    };
  }

  // ── Adjudicate the submitted PoC ──
  //
  // The agent claims it has a working exploit. For categories with a
  // deterministic oracle (XSS → headless browser, SSRF / blind RCE / blind
  // injection → OAST callback) we DO NOT trust the regex over the agent's
  // self-reported evidence — that is "an LLM guarding an LLM". Instead we
  // delegate to the real oracle, which reproduces the exploit out-of-band.
  // Regex remains the fallback only when no deterministic oracle applies.
  if (oracleKind !== "regex-fallback") {
    return adjudicateWithOracle(
      finding,
      target,
      submitted,
      turnsUsed,
      maxTurns,
      oracleKind,
      opts,
    );
  }

  // ── Regex fallback (no deterministic oracle for this category) ──
  const verdict = judge(finding, submitted.execution_evidence);
  if (!verdict.passed) {
    return {
      hasPov: false,
      povArtifact: submitted.artifact || null,
      artifactType: submitted.artifact_type,
      executionEvidence: submitted.execution_evidence,
      confidence: 0.2,
      turnsUsed,
      reason: `submitted PoC did not contain category-specific proof (${verdict.label})`,
      oracle: "regex-fallback",
    };
  }

  // Confidence scales with how quickly the agent nailed it:
  // turn 1 → 1.0, turn maxTurns → ~0.7.
  const confidence = Math.max(0.7, 1 - (turnsUsed - 1) * (0.3 / Math.max(1, maxTurns - 1)));

  return {
    hasPov: true,
    povArtifact: submitted.artifact,
    artifactType: submitted.artifact_type,
    executionEvidence: submitted.execution_evidence,
    confidence,
    turnsUsed,
    reason: `PoV confirmed: ${verdict.label}${verdict.matchedPattern ? ` (matched: ${verdict.matchedPattern.slice(0, 80)})` : ""}`,
    oracle: "regex-fallback",
  };
}

/**
 * Adjudicate a submitted PoC by running the deterministic oracle for the
 * finding's category, instead of regex-matching the agent's evidence.
 *
 * Contract:
 *  - oracle verifies      → hasPov:true,  oracle tag set.
 *  - oracle clean-fails   → hasPov:false (intentional regression of the regex
 *                           pass: a reflected `<script>alert(1)` that never
 *                           fires in the browser is NOT a PoV).
 *  - oracle throws / infra
 *    error in reason       → INCONCLUSIVE: hasPov:false, inconclusive:true,
 *                           NEVER a silent pass ("inconclusive on error, not
 *                           a false pass").
 */
async function adjudicateWithOracle(
  finding: Finding,
  target: string,
  submitted: {
    artifact_type: PovArtifactType;
    artifact: string;
    execution_evidence: string;
  },
  turnsUsed: number,
  maxTurns: number,
  oracleKind: Exclude<PovOracle, "regex-fallback">,
  opts: GeneratePovOptions,
): Promise<PovResult> {
  const runOracle = opts.oracle ?? verifyOracleByCategory;

  let oracleResult: OracleResult;
  try {
    // Reuse an upstream oracle run when available to avoid double-firing the
    // browser / collector.
    oracleResult =
      opts.precomputedOracle ?? (await runOracle(finding, target));
  } catch (err) {
    // Oracle harness blew up → inconclusive, never a pass.
    return {
      hasPov: false,
      povArtifact: submitted.artifact || null,
      artifactType: submitted.artifact_type,
      executionEvidence: submitted.execution_evidence,
      confidence: 0,
      turnsUsed,
      reason: `oracle (${oracleKind}) errored, inconclusive: ${(err as Error).message}`,
      oracle: oracleKind,
      inconclusive: true,
    };
  }

  if (oracleResult.verified) {
    // Blend oracle confidence with how quickly the agent produced the PoC.
    const speed = Math.max(
      0.7,
      1 - (turnsUsed - 1) * (0.3 / Math.max(1, maxTurns - 1)),
    );
    return {
      hasPov: true,
      povArtifact: submitted.artifact,
      artifactType: submitted.artifact_type,
      // Prefer the oracle's reproduced evidence; keep the agent's as context.
      executionEvidence: oracleResult.evidence || submitted.execution_evidence,
      confidence: Math.min(speed, oracleResult.confidence || speed),
      turnsUsed,
      reason: `PoV confirmed by ${oracleKind} oracle: ${oracleResult.evidence}`,
      oracle: oracleKind,
    };
  }

  // Not verified. Distinguish a clean "did not reproduce" from an infra error.
  if (isOracleInfraError(oracleResult.reason)) {
    return {
      hasPov: false,
      povArtifact: submitted.artifact || null,
      artifactType: submitted.artifact_type,
      executionEvidence: submitted.execution_evidence,
      confidence: 0,
      turnsUsed,
      reason: `oracle (${oracleKind}) inconclusive: ${oracleResult.reason}`,
      oracle: oracleKind,
      inconclusive: true,
    };
  }

  // Clean negative: the exploit genuinely did not fire under the oracle. This
  // is the intentional regression — a payload reflected as text but never
  // executed is hasPov:false.
  return {
    hasPov: false,
    povArtifact: submitted.artifact || null,
    artifactType: submitted.artifact_type,
    executionEvidence: submitted.execution_evidence,
    confidence: 0,
    turnsUsed,
    reason: `${oracleKind} oracle did not reproduce the exploit: ${oracleResult.reason}`,
    oracle: oracleKind,
  };
}

// ────────────────────────────────────────────────────────────────────
// Memory-safety PoV verdict (pwnkit#698, Track C)
//
// The userspace / Rust analogue of the web PoV verdict above. Where the web
// path proves exploitation by capturing category-specific output, the
// memory-safety path proves it by reproducing a real crash UNDER THE SANITIZER
// BUILD: an ASan/UBSan/MSan report or a Miri UB diagnostic that fired from a
// saved reproducing input. That is the `reproduced-memcorruption-poc` evidence
// kind — the strongest basis the userspace pipeline can carry.
//
// SCOPE / DISCIPLINE: this function ONLY adjudicates a verdict. It does not
// submit, drop, or disclose anything (the operator + disclosure gate own that),
// and it does not synthesise an exploit. Assume-FP holds: a CrashArtifact is
// only treated as a reproduced PoC when it carries a saved reproducing input
// AND its raw output actually shows a sanitizer/Miri corruption signature.
// Anything weaker (a bare panic, a timeout/OOM, no saved input, no signature)
// is INCONCLUSIVE — never a confirmation, never a rejection.
// ────────────────────────────────────────────────────────────────────

/** Crash kinds whose raw output is a genuine memory-corruption signal. */
const MEMCORRUPTION_CRASH_KINDS = new Set<CrashArtifact["kind"]>([
  "asan",
  "ubsan",
  "msan",
  "miri",
  "segfault",
]);

/**
 * Does a crash artifact constitute a reproduced memory-corruption PoC? True only
 * when a reproducing input was saved AND the crash kind is a real corruption
 * detector hit (sanitizer / Miri / segfault) with non-empty raw output. A Rust
 * panic, a timeout, or an OOM is a robustness/availability bug, not a
 * memory-corruption PoC — those return false.
 */
export function isReproducedMemCorruption(crash: CrashArtifact): boolean {
  return (
    Boolean(crash.inputPath) &&
    MEMCORRUPTION_CRASH_KINDS.has(crash.kind) &&
    Boolean(crash.rawOutput && crash.rawOutput.trim().length > 0)
  );
}

/**
 * Map a captured {@link CrashArtifact} onto the unified {@link VerifyVerdict},
 * mirroring how a reproduced web PoC yields a `confirmed` verdict tagged
 * `reproduced-poc`.
 *
 *   - A reproduced memory-corruption crash (see {@link isReproducedMemCorruption})
 *     → `confirmed`, `evidenceKind: "reproduced-memcorruption-poc"`, with the
 *     classified primitive folded into the reasoning.
 *   - Anything weaker → `inconclusive` (NEVER `rejected`). A non-reproducing
 *     crash artifact did not prove the finding is a false positive; it just
 *     failed to prove it real. Treating it as a rejection is the #518 failure
 *     mode (silently burying a real finding).
 */
export function memCorruptionVerdict(crash: CrashArtifact): VerifyVerdict {
  const reproduced = isReproducedMemCorruption(crash);
  const exploit = classifyUserspacePrimitive(crash);

  if (!reproduced) {
    return {
      verdict: "inconclusive",
      confidence: 0,
      reasoning:
        `Crash artifact (kind=${crash.kind}) is not a reproduced memory-corruption` +
        ` PoC — ${crash.inputPath ? "no sanitizer/Miri corruption signature" : "no saved reproducing input"}.` +
        " Inconclusive, not a rejection.",
      signals: [
        {
          name: "memcorruption_repro",
          passed: false,
          confidence: 0,
          reasoning: `kind=${crash.kind}, primitive=${exploit.primitive}, savedInput=${Boolean(crash.inputPath)}`,
        },
      ],
    };
  }

  return {
    verdict: "confirmed",
    confidence: 0.95,
    reasoning:
      `Reproduced under the sanitizer/Miri build (kind=${crash.kind}): ` +
      `${exploit.primitive} (${exploit.readWrite}). ${exploit.rationale}`,
    signals: [
      {
        name: "memcorruption_repro",
        passed: true,
        confidence: 0.95,
        reasoning: `signature=${crash.signature}, input=${crash.inputPath}`,
      },
    ],
    evidenceKind: "reproduced-memcorruption-poc",
  };
}
