/**
 * `pwnkit protocol-check` — Tier-1 HTTP spec-vs-implementation conformance
 * differential (issue #972).
 *
 * Reads an authoritative spec excerpt + an implementation source excerpt, asks
 * the unified LLM service to hypothesize where the implementation DIVERGES from
 * the spec, then SENDS each exercise at a real target and lets a deterministic
 * oracle confirm/refute the divergence. Only MUST-level violations backed by a
 * concrete observation are reported as `confirmed` — the conservative FP
 * discipline that mirrors `pwnkit verify`'s promotion contract.
 *
 * This command is GLUE: it builds the unified `NativeRuntime` (via the same
 * codex-login / API path the rest of the CLI uses — NO raw vendor keys) and the
 * live `fetch`-based HTTP sender, then calls `@pwnkit/core`
 * `runHttpConformanceCheck`. All the analysis lives in the engine.
 *
 * Exit codes (mirroring `pwnkit verify` so a dispatcher can branch on the code):
 *   0 → ran; at least one CONFIRMED divergence
 *   1 → ran; no confirmed divergence
 *   2 → conformance-gen produced no validated model (nothing exercised)
 *   3 → error (bad flags, unreadable file)
 */

import type { Command } from "commander";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  createLiveHttpSender,
  createRuntime,
  LlmApiRuntime,
  runHttpConformanceCheck,
  type ConformanceAttempt,
  type HttpConformanceResult,
  type NativeRuntime,
} from "@pwnkit/core";

interface ProtocolCheckOpts {
  spec?: string;
  impl?: string;
  target?: string;
  json?: boolean;
  maxExercises?: string;
  runtime?: string;
  protocol?: string;
  specVersion?: string;
  specRef?: string;
}

/**
 * Resolve a `NativeRuntime` (the `executeNative` seam conformance-gen needs)
 * from the `--runtime` flag, via the SAME unified path the rest of the CLI uses:
 *   - api / auto → `LlmApiRuntime` (resolves the chatgpt-codex login token, an
 *     Anthropic/OpenAI/etc. key, in priority order — never a hand-rolled fetch).
 *   - claude / codex / gemini → `createRuntime` (`CliNativeRuntime`), the
 *     subscription-CLI path.
 *
 * `ProcessRuntime` (the legacy single-shot `createRuntime` codex path) does NOT
 * implement `executeNative`, so we route codex/claude/gemini through the
 * native-capable runtimes and surface a clear error if the chosen one lacks it.
 */
function resolveNativeRuntime(runtimeFlag: string | undefined): NativeRuntime {
  const choice = (runtimeFlag ?? "auto").toLowerCase();
  const timeout = 60_000;
  if (choice === "auto" || choice === "api") {
    return new LlmApiRuntime({ type: "api", timeout });
  }
  const rt = createRuntime({
    type: choice as "claude" | "codex" | "gemini",
    timeout,
  });
  if (typeof (rt as Partial<NativeRuntime>).executeNative !== "function") {
    throw new Error(
      `runtime "${choice}" does not support the native (multi-turn) interface ` +
        `required by protocol-check. Use --runtime api (codex login / API key) ` +
        `or --runtime claude.`,
    );
  }
  return rt as unknown as NativeRuntime;
}

function readExcerpt(path: string, label: string): string {
  const abs = resolve(path);
  try {
    return readFileSync(abs, "utf8");
  } catch (err) {
    throw new Error(
      `failed to read ${label} from ${abs}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

/** Counts of each oracle verdict across all exercised hypotheses. */
function tallyVerdicts(attempts: ConformanceAttempt[]): {
  confirmed: number;
  refuted: number;
  inconclusive: number;
} {
  const t = { confirmed: 0, refuted: 0, inconclusive: 0 };
  for (const a of attempts) t[a.verdict.status]++;
  return t;
}

/** Render a human-readable report to stderr (stdout is reserved for --json). */
function printReport(
  result: HttpConformanceResult,
  target: string,
  log: (line: string) => void,
): void {
  if (!result.ok) {
    log(`✗ conformance-gen produced no validated model.`);
    log(`  ${result.reason ?? "unknown reason"}`);
    log(`  LLM iterations: ${result.genIterations}`);
    return;
  }

  const t = tallyVerdicts(result.attempts);
  log(`Protocol conformance check against ${target}`);
  log(`  LLM gen iterations:   ${result.genIterations}`);
  log(`  hypotheses exercised: ${result.attempts.length}`);
  log(`  confirmed:            ${t.confirmed}`);
  log(`  refuted:              ${t.refuted}`);
  log(`  inconclusive:         ${t.inconclusive}`);
  log("");

  if (result.findings.length === 0) {
    log("No CONFIRMED divergences. (Confirmed requires a concrete MUST-level");
    log("violation backed by a real observation — the conservative FP gate.)");
  } else {
    log(`CONFIRMED divergences (${result.findings.length}):`);
    for (const a of result.attempts) {
      if (a.verdict.status !== "confirmed") continue;
      const ex = a.hypothesis.exercise;
      log("");
      log(`  ● ${a.hypothesis.ruleId} [${a.hypothesis.level}] ${a.hypothesis.specCitation}`);
      log(`    sent:     ${ex.method} ${ex.path ?? "/"}`);
      log(`    observed: status ${a.observed.status}`);
      log(`    evidence: ${a.verdict.evidence}`);
    }
  }

  // Surface refuted controls too — proving the loop didn't just blanket-confirm.
  const refuted = result.attempts.filter((a) => a.verdict.status === "refuted");
  if (refuted.length > 0) {
    log("");
    log(`Refuted (conformant) controls (${refuted.length}):`);
    for (const a of refuted) {
      const ex = a.hypothesis.exercise;
      log(`  ○ ${a.hypothesis.ruleId}: sent ${ex.method} ${ex.path ?? "/"} → ${a.observed.status} (conformant)`);
    }
  }
}

export async function protocolCheckAction(
  opts: ProtocolCheckOpts,
): Promise<number> {
  if (!opts.spec) throw new Error("--spec <file> is required");
  if (!opts.impl) throw new Error("--impl <file> is required");
  if (!opts.target) throw new Error("--target <url> is required");

  const specExcerpt = readExcerpt(opts.spec, "spec excerpt");
  const implExcerpt = readExcerpt(opts.impl, "implementation excerpt");
  const target = opts.target;

  const maxExercises = opts.maxExercises
    ? Number.parseInt(opts.maxExercises, 10)
    : undefined;
  if (maxExercises !== undefined && (!Number.isFinite(maxExercises) || maxExercises < 0)) {
    throw new Error(`--max-exercises must be a non-negative integer (got "${opts.maxExercises}")`);
  }

  const llm = resolveNativeRuntime(opts.runtime);
  const send = createLiveHttpSender();

  const result = await runHttpConformanceCheck(
    specExcerpt,
    implExcerpt,
    target,
    llm,
    send,
    {
      name: opts.protocol ?? "HTTP/1.1",
      version: opts.specVersion ?? "RFC 9110",
      specRef: opts.specRef ?? "operator-supplied excerpt",
    },
    maxExercises !== undefined ? { maxExercises } : {},
  );

  if (opts.json) {
    // Machine-readable on stdout: the full result (findings + every attempt).
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  } else {
    printReport(result, target, (line) => process.stderr.write(line + "\n"));
  }

  if (!result.ok) return 2;
  return result.findings.length > 0 ? 0 : 1;
}

export function registerProtocolCheckCommand(program: Command): void {
  program
    .command("protocol-check")
    .description(
      "Tier-1 HTTP spec-vs-implementation conformance differential (issue " +
        "#972). The unified LLM hypothesizes where an implementation diverges " +
        "from a spec excerpt; each exercise is SENT at a real target and a " +
        "deterministic oracle confirms only concrete MUST-level violations.",
    )
    .requiredOption(
      "--spec <file>",
      "Path to the authoritative specification excerpt (RFC/ABNF prose, text).",
    )
    .requiredOption(
      "--impl <file>",
      "Path to the implementation source excerpt the divergence is hypothesized in.",
    )
    .requiredOption(
      "--target <url>",
      "Base URL of the live target to exercise (e.g. http://127.0.0.1:8080).",
    )
    .option("--json", "Emit the full result (findings + attempts) as JSON on stdout.")
    .option(
      "--max-exercises <N>",
      "Cap how many ranked hypotheses to exercise against the target (default 8).",
    )
    .option(
      "--runtime <runtime>",
      "LLM runtime: auto/api (codex login or API key), claude, codex, gemini.",
      "auto",
    )
    .option("--protocol <name>", "Protocol name for the report/finding (default HTTP/1.1).")
    .option("--spec-version <version>", "Spec edition for the report (default RFC 9110).")
    .option("--spec-ref <ref>", "Auditable spec citation (e.g. 'RFC 9110 §9.3.6').")
    .action(async (opts: ProtocolCheckOpts) => {
      try {
        process.exitCode = await protocolCheckAction(opts);
      } catch (err) {
        const reason = err instanceof Error ? err.message : String(err);
        if (opts.json) {
          process.stdout.write(
            JSON.stringify({ ok: false, error: reason }, null, 2) + "\n",
          );
        } else {
          process.stderr.write(`protocol-check error: ${reason}\n`);
        }
        process.exitCode = 3;
      }
    });
}
