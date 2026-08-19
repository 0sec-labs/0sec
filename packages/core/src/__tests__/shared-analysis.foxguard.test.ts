/**
 * Foxguard / semgrep parity fixture test.
 *
 * The `fixtures/vuln-eval.js` file is an obvious `eval(req.body.code)`
 * snippet. Both scanners must fire on the same path and within ±1 line
 * of each other, with severities no more than one tier apart. We mock
 * the subprocess shell (no real semgrep / foxguard invocations in CI)
 * and feed each scanner a canned output payload that mirrors what they
 * actually produce on this fixture in local manual runs.
 *
 * The point of this test isn't to exercise the real binaries — that's
 * what the manual ablation harness in
 * `packages/benchmark/scripts/foxguard-ablation.mjs` is for. The point
 * is to lock in the **translator contract**: after both runners return
 * a `SemgrepFinding[]`, downstream pipeline code can treat them
 * interchangeably.
 */
import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

// Hoisted subprocess mock — `runSemgrepScan` calls `execFileSync` directly
// (no test seam), so we intercept it at the module boundary. The mock
// dispatches by command name (`semgrep` vs `npx`) and returns the canned
// JSON the corresponding parser expects.
const execFileSyncMock = vi.fn();
vi.mock("node:child_process", async () => {
  const actual = await vi.importActual<typeof import("node:child_process")>(
    "node:child_process",
  );
  return { ...actual, execFileSync: execFileSyncMock };
});

const { runFoxguardScan, runSemgrepScan, FOXGUARD_PINNED_TAG } = await import(
  "../shared-analysis.js"
);

const __dirname = fileURLToPath(new URL(".", import.meta.url));
const fixturePath = join(__dirname, "fixtures", "vuln-eval.js");

const SEVERITY_RANKS: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function withinOneTier(a: string, b: string): boolean {
  const ra = SEVERITY_RANKS[a] ?? -1;
  const rb = SEVERITY_RANKS[b] ?? -1;
  return Math.abs(ra - rb) <= 1;
}

describe("scanner parity: runSemgrepScan vs runFoxguardScan on vuln-eval.js", () => {
  it("both scanners produce ≥1 finding on the eval() fixture with consistent path/line/severity", () => {
    // Sanity: the fixture exists where we expect it.
    const fixtureSource = readFileSync(fixturePath, "utf-8");
    expect(fixtureSource).toContain("eval(code)");

    // Locate the `eval(code)` line in the fixture. Both scanners should
    // point at this line (±1).
    const fixtureLines = fixtureSource.split("\n");
    const evalLine =
      fixtureLines.findIndex((line) => line.includes("eval(code)")) + 1; // 1-indexed
    expect(evalLine).toBeGreaterThan(0);

    execFileSyncMock.mockReset();
    execFileSyncMock.mockImplementation((cmd: string, args: string[]) => {
      if (cmd === "semgrep") {
        // Semgrep's `--config auto` output for an eval() sink (truncated
        // to the shape `runSemgrepScan` parses).
        expect(args[0]).toBe("scan");
        expect(args).toContain("--json");
        return JSON.stringify({
          results: [
            {
              check_id: "javascript.lang.security.audit.eval-detected.eval-detected",
              extra: {
                message: "Detected the use of eval(). eval() can be dangerous.",
                severity: "ERROR",
                lines: "eval(code);",
                metadata: { cwe: "CWE-95" },
              },
              path: fixturePath,
              start: { line: evalLine, col: 3 },
              end: { line: evalLine, col: 14 },
            },
          ],
        });
      }
      if (cmd === "npx") {
        // Foxguard's JSON output for the same fixture, canned to mirror
        // foxguard@v0.8.1's `Finding` struct (see src/lib.rs).
        expect(args).toContain("--yes");
        expect(args).toContain(`foxguard@${FOXGUARD_PINNED_TAG}`);
        expect(args).toContain("--format");
        expect(args).toContain("json");
        return JSON.stringify([
          {
            rule_id: "js/no-eval",
            severity: "critical",
            cwe: "CWE-94",
            description: "Use of eval() allows arbitrary code execution",
            file: fixturePath,
            line: evalLine,
            column: 3,
            end_line: evalLine,
            end_column: 14,
            snippet: "eval(code);",
            taint_hops: 1,
          },
        ]);
      }
      throw new Error(`unexpected subprocess command in test: ${cmd}`);
    });

    const semgrepFindings = runSemgrepScan(fixturePath, () => {});
    const foxguardFindings = runFoxguardScan(fixturePath, () => {});

    // Both produced ≥1 finding.
    expect(semgrepFindings.length).toBeGreaterThanOrEqual(1);
    expect(foxguardFindings.length).toBeGreaterThanOrEqual(1);

    const sem = semgrepFindings[0]!;
    const fox = foxguardFindings[0]!;

    // Same file path.
    expect(fox.path).toBe(sem.path);

    // Same start line within ±1 (rules occasionally disagree on whether
    // to anchor the finding at the statement start or at the eval token).
    expect(Math.abs(fox.startLine - sem.startLine)).toBeLessThanOrEqual(1);

    // Severities within one tier of each other.
    expect(withinOneTier(fox.severity, sem.severity)).toBe(true);

    // The foxguard finding carries scanner provenance so downstream
    // triage code can tell them apart when needed.
    expect(fox.metadata).toMatchObject({ scanner: "foxguard" });
  });
});
