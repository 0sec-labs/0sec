import { describe, it, expect } from "vitest";
import { mkdtempSync, existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, PocStep } from "@0sec/shared";
import { composeExploitSession, composeStepSession, renderExploitScreenshot, isFreezeAvailable } from "./screenshots.js";
import type { PocStepResult } from "./poc-runtime.js";
import { renderAdvisoryMarkdown } from "./template.js";

function baseFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "finding-abcdef123456",
    templateId: "ssrf-template",
    title: "SSRF via /api/foo",
    description: "Attacker-controlled URL reaches fetch without allowlist.",
    severity: "medium",
    category: "ssrf",
    status: "verified",
    evidence: {
      request: "GET /api/foo?url=http://169.254.169.254/ HTTP/1.1\nHost: target:3108",
      response: '{"status":"reachable","httpStatus":200,"durationMs":12}',
      analysis: "Full SSRF with response reflection.",
    },
    timestamp: 1712345678,
    ...overrides,
  };
}

describe("composeExploitSession", () => {
  it("includes the finding title, category, and severity as header comments", () => {
    const text = composeExploitSession(baseFinding());
    expect(text).toContain("# PoC for: SSRF via /api/foo");
    expect(text).toContain("Category: ssrf");
    expect(text).toContain("severity: medium");
  });

  it("prefixes the first request line with $ and indents the rest", () => {
    const text = composeExploitSession(baseFinding());
    const lines = text.split("\n");
    const reqIdx = lines.findIndex((l) => l.startsWith("$ GET /api/foo"));
    expect(reqIdx).toBeGreaterThan(-1);
    expect(lines[reqIdx + 1]).toMatch(/^  Host: target:3108$/);
  });

  it("appends the response body unprefixed", () => {
    const text = composeExploitSession(baseFinding());
    expect(text).toContain('{"status":"reachable"');
  });

  it("comments the agent analysis block", () => {
    const text = composeExploitSession(baseFinding());
    expect(text).toContain("# Agent analysis:");
    expect(text).toContain("# Full SSRF with response reflection.");
  });
});

describe("isFreezeAvailable", () => {
  it("returns boolean for a missing binary without throwing", () => {
    const result = isFreezeAvailable("this-binary-definitely-does-not-exist-0sec-test");
    expect(typeof result).toBe("boolean");
    expect(result).toBe(false);
  });
});

describe("renderExploitScreenshot", () => {
  it("returns null when available=false and still writes no files", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "0sec-shot-"));
    const result = renderExploitScreenshot(baseFinding(), { outputDir, available: false });
    expect(result).toBeNull();
  });

  it("writes a session file and a stub output file when a fake binary is provided", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "0sec-shot-"));
    // Stub freeze: just `touch` the file at the -o position.
    const stubBinary = join(outputDir, "fake-freeze");
    writeFileSync(stubBinary, `#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "-o" ]]; then
    touch "$2"
    shift 2
    continue
  fi
  shift
done
`);
    chmodSync(stubBinary, 0o755);

    const result = renderExploitScreenshot(baseFinding(), {
      outputDir,
      binary: stubBinary,
      available: true,
    });
    expect(result).not.toBeNull();
    expect(existsSync(result!.path)).toBe(true);
    const sessionFile = result!.path.replace(/\.png$/, ".session.txt");
    expect(existsSync(sessionFile)).toBe(true);
    const sessionText = readFileSync(sessionFile, "utf8");
    expect(sessionText).toContain("SSRF via /api/foo");
  });

  it("returns null when the rendering binary exits nonzero", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "0sec-shot-"));
    const stubBinary = join(outputDir, "broken-freeze");
    writeFileSync(stubBinary, "#!/usr/bin/env bash\nexit 1\n");
    chmodSync(stubBinary, 0o755);
    const result = renderExploitScreenshot(baseFinding(), {
      outputDir,
      binary: stubBinary,
      available: true,
    });
    expect(result).toBeNull();
  });

  it("produces a relativePath when markdownDir is passed", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "0sec-shot-"));
    const markdownDir = outputDir;
    const imagesDir = join(outputDir, "images");
    const stubBinary = join(outputDir, "fake-freeze-rel");
    writeFileSync(stubBinary, `#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "-o" ]]; then
    mkdir -p "$(dirname "$2")"
    touch "$2"
    shift 2
    continue
  fi
  shift
done
`);
    chmodSync(stubBinary, 0o755);
    const result = renderExploitScreenshot(baseFinding(), {
      outputDir: imagesDir,
      markdownDir,
      binary: stubBinary,
      available: true,
    });
    expect(result).not.toBeNull();
    expect(result!.relativePath.startsWith("./images/")).toBe(true);
  });
});

describe("template integration", () => {
  it("embeds screenshot img tags into the PoC section when passed", () => {
    const { markdown } = renderAdvisoryMarkdown(baseFinding(), {
      screenshots: [
        { alt: "exploit-demo", relativePath: "./images/shot.png", caption: "Exploit in action", width: 1200 },
      ],
    });
    expect(markdown).toContain('<img width="1200" alt="exploit-demo" src="./images/shot.png" />');
    expect(markdown).toContain("> Exploit in action");
  });

  it("suppresses the 'to fill in' PoC placeholder once a screenshot is attached even without evidence", () => {
    const noEvidenceFinding = {
      ...baseFinding(),
      evidence: { request: "", response: "", analysis: undefined },
    };
    const { markdown } = renderAdvisoryMarkdown(noEvidenceFinding, {
      screenshots: [{ alt: "shot", relativePath: "./images/shot.png" }],
    });
    expect(markdown).not.toContain("To fill in: concrete reproduction steps");
  });
});

// ── Multi-frame rendering (#168 / #170) ──────────────────────────────────────

function makeStep(id: string, kind: PocStep["kind"], summary: string, action: PocStep["action"], expect?: PocStep["expect"]): PocStep {
  return { id, kind, summary, action, expect };
}

const STEPS: PocStep[] = [
  makeStep("setup-1", "setup", "Provision the docker target", { type: "shell", cmd: "docker compose up -d" }, { type: "exit-zero" }),
  makeStep("auth-1", "auth", "Sign in as the attacker persona", { type: "http", method: "POST", url: "/login", headers: { "Content-Type": "application/json" }, body: '{"u":"a","p":"b"}' }, { type: "http-status", status: 200 }),
  makeStep("exploit-1", "exploit", "Trigger the SSRF", { type: "http", method: "GET", url: "/api/foo?url=http://169.254.169.254/" }, { type: "body-contains", text: "reachable" }),
];

function freezeStub(outputDir: string, name = "fake-freeze"): string {
  const stubBinary = join(outputDir, name);
  writeFileSync(stubBinary, `#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "-o" ]]; then
    mkdir -p "$(dirname "$2")"
    touch "$2"
    shift 2
    continue
  fi
  shift
done
`);
  chmodSync(stubBinary, 0o755);
  return stubBinary;
}

describe("composeStepSession", () => {
  it("renders shell action with the cmd verbatim and the expected predicate when no result is provided", () => {
    const text = composeStepSession(baseFinding(), STEPS[0], 0, STEPS.length);
    expect(text).toContain("PoC step 1/3 — setup: Provision the docker target");
    expect(text).toContain("$ docker compose up -d");
    expect(text).toContain("# expected: exit-zero");
  });

  it("renders http action with method, url, headers, and body", () => {
    const text = composeStepSession(baseFinding(), STEPS[1], 1, STEPS.length);
    expect(text).toContain("$ POST /login");
    expect(text).toContain("Content-Type: application/json");
    expect(text).toContain('{"u":"a","p":"b"}');
  });

  it("embeds the observed effect from a behavioural result when present", () => {
    const result: PocStepResult = {
      stepId: "exploit-1",
      kind: "passed",
      observedStatus: 200,
      observedResponseBody: '{"status":"reachable"}',
      durationMs: 12,
    };
    const text = composeStepSession(baseFinding(), STEPS[2], 2, STEPS.length, result);
    expect(text).toContain("# http-status=200");
    expect(text).toContain('{"status":"reachable"}');
    expect(text).toContain("# verdict: passed");
  });

  it("annotates the verdict line with the error when the step failed", () => {
    const result: PocStepResult = {
      stepId: "exploit-1",
      kind: "failed",
      observedStatus: 403,
      durationMs: 5,
      error: "expected http-status in [200], got 403",
    };
    const text = composeStepSession(baseFinding(), STEPS[2], 2, STEPS.length, result);
    expect(text).toContain("# verdict: failed (expected http-status in [200], got 403)");
  });
});

describe("renderExploitScreenshot multi-frame (#168 / #170)", () => {
  it("returns one frame per pocStep in order, each with a unique stepId / frame index", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "0sec-mframe-"));
    const stubBinary = freezeStub(outputDir);
    const frames = renderExploitScreenshot(baseFinding(), {
      outputDir,
      binary: stubBinary,
      available: true,
      pocSteps: STEPS,
    });
    expect(Array.isArray(frames)).toBe(true);
    expect(frames).toHaveLength(STEPS.length);
    expect(frames.map((f) => f.stepId)).toEqual(["setup-1", "auth-1", "exploit-1"]);
    expect(frames.map((f) => f.frame)).toEqual([1, 2, 3]);
    for (const f of frames) expect(existsSync(f.path)).toBe(true);
  });

  it("returns an empty array (not null) when pocSteps is provided but empty", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "0sec-mframe-"));
    const stubBinary = freezeStub(outputDir);
    const result = renderExploitScreenshot(baseFinding(), {
      outputDir,
      binary: stubBinary,
      available: true,
      pocSteps: [],
    });
    expect(result).toEqual([]);
  });

  it("returns an empty array when freeze is unavailable (multi-frame branch never returns null)", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "0sec-mframe-"));
    const result = renderExploitScreenshot(baseFinding(), {
      outputDir,
      available: false,
      pocSteps: STEPS,
    });
    expect(result).toEqual([]);
  });

  it("threads stepResults into the corresponding frame's session text", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "0sec-mframe-"));
    const stubBinary = freezeStub(outputDir);
    const stepResults: Record<string, PocStepResult> = {
      "exploit-1": {
        stepId: "exploit-1",
        kind: "passed",
        observedStatus: 200,
        observedResponseBody: "REACHABLE_TOKEN_FROM_RESULT",
        durationMs: 7,
      },
    };
    const frames = renderExploitScreenshot(baseFinding(), {
      outputDir,
      binary: stubBinary,
      available: true,
      pocSteps: STEPS,
      stepResults,
    });
    const exploitFrame = frames.find((f) => f.stepId === "exploit-1");
    expect(exploitFrame).toBeDefined();
    expect(exploitFrame!.sessionText).toContain("REACHABLE_TOKEN_FROM_RESULT");
    expect(exploitFrame!.sessionText).toContain("# verdict: passed");
  });

  it("falls back to single-frame return shape when pocSteps is omitted (backward compat)", () => {
    const outputDir = mkdtempSync(join(tmpdir(), "0sec-mframe-"));
    const stubBinary = freezeStub(outputDir);
    const result = renderExploitScreenshot(baseFinding(), {
      outputDir,
      binary: stubBinary,
      available: true,
    });
    // Legacy contract: ScreenshotResult | null. No `frame` / `stepId` set.
    expect(result).not.toBeNull();
    expect(Array.isArray(result)).toBe(false);
    expect((result as { stepId?: string }).stepId).toBeUndefined();
  });
});
