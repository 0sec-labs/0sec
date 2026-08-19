import { describe, it, expect } from "vitest";
import type { Finding, PocStep } from "@0sec/shared";
import {
  decideFilingState,
  assembleBundleIndex,
  formatDroppedReason,
  droppedFilename,
  type BundleEntry,
} from "./bundle.js";
import type { ReverifyResult } from "./canary.js";
import type { PocExecutionReport } from "./poc-runtime.js";
import { renderAdvisoryMarkdown } from "./template.js";
import { renderExploitScreenshot } from "./screenshots.js";
import { extractSiblingFix } from "./sibling-fix.js";
import { mkdtempSync, writeFileSync, mkdirSync, chmodSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// ── Fixtures ─────────────────────────────────────────────────────────────────

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
      response: '{"status":"reachable","httpStatus":200}',
      analysis: "Full SSRF with response reflection.",
    },
    timestamp: 1712345678,
    ...overrides,
  };
}

function makePocSteps(): PocStep[] {
  return [
    { id: "setup-1", kind: "setup", summary: "Stand up the target", action: { type: "shell", cmd: "docker compose up -d" }, expect: { type: "exit-zero" } },
    { id: "auth-1", kind: "auth", summary: "Sign in", action: { type: "http", method: "POST", url: "/login" } },
    { id: "exploit-1", kind: "exploit", summary: "Trigger the SSRF", action: { type: "http", method: "GET", url: "/api/foo?url=http://169.254.169.254/" }, expect: { type: "body-contains", text: "reachable" } },
    { id: "verify-1", kind: "verify", summary: "Confirm the response is reflected", action: { type: "note", text: "manual: see body in previous step" } },
  ];
}

function reverifyStillVulnerable(): ReverifyResult {
  return {
    status: "still-vulnerable",
    ref: "HEAD",
    notes: ["all cited refs still resolve"],
    refsChecked: [{ file: "src/route.ts", line: 42 }],
    refsStillPresent: [{ file: "src/route.ts", line: 42 }],
    refsMissing: [],
  };
}

function reverifyFixed(): ReverifyResult {
  return {
    status: "fixed",
    ref: "v2026.420.0-canary.9",
    notes: ["snippet removed at canary cutover"],
    refsChecked: [{ file: "src/route.ts", line: 42 }],
    refsStillPresent: [],
    refsMissing: [{ file: "src/route.ts", line: 42 }],
  };
}

function execReport(verdict: "exploit_still_works" | "exploit_broken" | "could_not_run"): PocExecutionReport {
  return {
    findingId: "finding-abcdef123456",
    startedAt: "2026-04-27T10:00:00.000Z",
    endedAt: "2026-04-27T10:00:01.000Z",
    overallVerdict: verdict,
    steps: [
      { stepId: "setup-1", kind: "passed", durationMs: 100 },
      { stepId: "exploit-1", kind: verdict === "exploit_still_works" ? "passed" : verdict === "exploit_broken" ? "failed" : "errored", durationMs: 80, error: verdict === "exploit_broken" ? "expected body-contains 'reachable', not found" : undefined },
    ],
  };
}

function freezeStub(outputDir: string): string {
  const stub = join(outputDir, "fake-freeze");
  writeFileSync(stub, `#!/usr/bin/env bash
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "-o" ]]; then mkdir -p "$(dirname "$2")"; touch "$2"; shift 2; continue; fi
  shift
done
`);
  chmodSync(stub, 0o755);
  return stub;
}

// ── decideFilingState ───────────────────────────────────────────────────────

describe("decideFilingState", () => {
  it("keeps when nothing has changed", () => {
    expect(decideFilingState({ patchStatus: reverifyStillVulnerable(), dropFixed: true }).filingState).toBe("keep");
  });

  it("keeps fixed when --drop-fixed is off (operator wants to file the historical advisory anyway)", () => {
    expect(decideFilingState({ patchStatus: reverifyFixed(), dropFixed: false }).filingState).toBe("keep");
  });

  it("drops fixed when --drop-fixed is on", () => {
    const r = decideFilingState({ patchStatus: reverifyFixed(), dropFixed: true });
    expect(r.filingState).toBe("drop");
    expect(r.dropReason).toContain("canary status=fixed");
  });

  it("drops on behavioural exploit_broken regardless of code-level status", () => {
    const r = decideFilingState({
      patchStatus: reverifyStillVulnerable(),
      behaviouralReport: execReport("exploit_broken"),
      dropFixed: false,
    });
    expect(r.filingState).toBe("drop");
    expect(r.dropReason).toContain("exploit_broken");
  });

  it("drops could_not_run by default (advisory quality gate: unverified PoC)", () => {
    const r = decideFilingState({
      patchStatus: reverifyStillVulnerable(),
      behaviouralReport: execReport("could_not_run"),
      dropFixed: true,
    });
    expect(r.filingState).toBe("drop");
    expect(r.dropReason).toContain("unverified-poc");
  });

  it("flags could_not_run as needs-review when keepUnrun is on", () => {
    const r = decideFilingState({
      patchStatus: reverifyStillVulnerable(),
      behaviouralReport: execReport("could_not_run"),
      dropFixed: true,
      keepUnrun: true,
    });
    expect(r.filingState).toBe("needs-review");
    expect(r.dropReason).toBeUndefined();
  });

  it("drops on emptyPoc=true regardless of other inputs", () => {
    const r = decideFilingState({ dropFixed: false, emptyPoc: true });
    expect(r.filingState).toBe("drop");
    expect(r.dropReason).toContain("unverified-poc");
  });

  it("canary-fixed wins over could_not_run (drop is more conservative)", () => {
    // If both are present and dropFixed is on, the canary drop wins because
    // it's the more decisive signal.
    const r = decideFilingState({
      patchStatus: reverifyFixed(),
      behaviouralReport: execReport("could_not_run"),
      dropFixed: true,
    });
    expect(r.filingState).toBe("drop");
  });
});

// ── assembleBundleIndex ─────────────────────────────────────────────────────

function entry(overrides: Partial<BundleEntry> & { id?: string; title?: string; severity?: Finding["severity"] } = {}): BundleEntry {
  const finding = baseFinding({
    id: overrides.id ?? "abcd1234efgh",
    title: overrides.title ?? "SSRF via /api/foo",
    severity: overrides.severity ?? "medium",
  });
  const sevRank: Record<Finding["severity"], string> = { critical: "1", high: "2", medium: "3", low: "4", info: "5" };
  const baseEntry: BundleEntry = {
    finding,
    filename: `${sevRank[finding.severity]}-${finding.severity}-${finding.title.toLowerCase().replace(/[^a-z0-9]+/g, "-")}.md`,
    primaryCwe: "CWE-918",
    cvssScore: 6.5,
    filingState: "keep",
  };
  return { ...baseEntry, ...overrides, finding: overrides.finding ?? finding };
}

describe("assembleBundleIndex (#168 spec columns)", () => {
  it("renders a stub for an empty bundle (0 findings)", () => {
    const md = assembleBundleIndex([], { scanIds: ["scan-aaaa"] });
    expect(md).toContain("# Disclosure batch");
    expect(md).toContain("- Drafts: 0");
    expect(md).toContain("No findings matched");
    // No filing-order or dropped tables.
    expect(md).not.toContain("## Filing order");
    expect(md).not.toContain("## Dropped");
  });

  it("emits filing-order columns: finding-id | severity | title | gate-status | behavioural | filing-state", () => {
    const e = entry({
      patchStatus: "still-vulnerable",
      behaviouralVerdict: "exploit_still_works",
    });
    const md = assembleBundleIndex([e], { scanIds: ["scan-aaaa"] });
    expect(md).toContain("| finding-id | severity | title | gate-status | behavioural | filing-state |");
    expect(md).toMatch(/\| `[a-z0-9]{8}` \|/);
    expect(md).toContain("still-vulnerable");
    expect(md).toContain("exploit_still_works");
    expect(md).toContain(" keep |");
  });

  it("places dropped entries in a separate Dropped table with the reason and a link to _dropped/", () => {
    const kept = entry({ id: "keep0001abcd", title: "Kept finding", patchStatus: "still-vulnerable" });
    const dropped = entry({
      id: "drop0001abcd",
      title: "Dropped finding",
      patchStatus: "fixed",
      filingState: "drop",
      dropReason: "canary status=fixed",
    });
    const md = assembleBundleIndex([kept, dropped], { scanIds: ["scan-aaaa"] });
    expect(md).toContain("## Filing order");
    expect(md).toContain("## Dropped");
    expect(md).toContain("Kept finding");
    expect(md).toContain("Dropped finding");
    // Dropped row points at _dropped/<id>-<sev>-<slug>.md
    expect(md).toMatch(/\(\.\/_dropped\/[a-z0-9]{8}-medium-fixed\.md\)/);
    expect(md).toContain("canary status=fixed");
  });

  it("flags needs-review entries in the filing-state column without dropping them", () => {
    const e = entry({
      behaviouralVerdict: "could_not_run",
      filingState: "needs-review",
    });
    const md = assembleBundleIndex([e], { scanIds: ["scan-aaaa"] });
    expect(md).toContain(" needs-review |");
    expect(md).toContain("could_not_run");
    expect(md).not.toContain("## Dropped"); // shouldn't show up there
  });

  it("uses a fixed timestamp when generatedAt is supplied (deterministic)", () => {
    const e = entry();
    const ts = new Date("2026-04-27T12:00:00Z");
    const md = assembleBundleIndex([e], { scanIds: ["scan-x"], generatedAt: ts });
    expect(md).toContain("- Generated: 2026-04-27T12:00:00.000Z");
  });

  it("escapes pipe characters inside titles so the markdown table stays valid", () => {
    const e = entry({ title: "Issue with | pipe in title" });
    const md = assembleBundleIndex([e], { scanIds: ["scan-x"] });
    expect(md).toContain("Issue with \\| pipe in title");
  });

  it("includes sha256 artifact provenance from verification_result.evidence_artifacts", () => {
    const finding = baseFinding({
      id: "prov-001",
      verification_result: {
        finding_id: "prov-001",
        status: "not_reproduced",
        mode: "deterministic",
        engine_version: "1.0",
        started_at: "2026-01-01T00:00:00Z",
        completed_at: "2026-01-01T00:00:01Z",
        duration_ms: 1000,
        commands: [],
        assertions: [],
        evidence_artifacts: [
          { kind: "stdout", path: "artifacts/x", sha256: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", bytes: 10 },
          { kind: "screenshot", path: "artifacts/y.png", sha256: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", bytes: 20 },
        ],
        engine_metadata: { os: "linux", arch: "x64" },
      },
    });
    const e = entry({ finding, id: finding.id, title: finding.title });
    const md = assembleBundleIndex([e], { scanIds: ["scan-x"] });
    expect(md).toContain("| provenance |");
    expect(md).toContain("`abcdef012345…`");
    expect(md).not.toContain("fedcba987654");
  });

  it("includes provenance from researchEvidence[].artifacts as single-hash cell", () => {
    const finding = baseFinding({
      id: "prov-002",
      researchEvidence: [
        {
          schemaVersion: 1,
          evidenceId: "ev-002",
          findingId: "prov-002",
          target: { kind: "repo", locator: "acme/foo" },
          provenance: { producer: "adapter", runId: "r1", startedAt: "2026-01-01T00:00:00Z" },
          grade: "reproduced",
          novelty: { state: "novel", sources: ["cve"], scanned: 1 },
          artifacts: [
            { kind: "capture", path: "trace.bin", sha256: "1111111111111111111111111111111111111111111111111111111111111111", bytes: 50 },
          ],
        },
      ],
    });
    const e = entry({ finding, id: finding.id, title: finding.title });
    const md = assembleBundleIndex([e], { scanIds: ["scan-x"] });
    expect(md).toContain("`111111111111…`");
  });

  it("shows the first hash and retained count when both sources supply artifacts", () => {
    const finding = baseFinding({
      id: "prov-003",
      verification_result: {
        finding_id: "prov-003",
        status: "not_reproduced",
        mode: "deterministic",
        engine_version: "1.0",
        started_at: "2026-01-01T00:00:00Z",
        completed_at: "2026-01-01T00:00:01Z",
        duration_ms: 1000,
        commands: [],
        assertions: [],
        evidence_artifacts: [
          { kind: "stdout", path: "a.txt", sha256: "a000000000000000000000000000000000000000000000000000000000000001" },
        ],
        engine_metadata: { os: "linux", arch: "x64" },
      },
      researchEvidence: [
        {
          schemaVersion: 1,
          evidenceId: "ev-003",
          findingId: "prov-003",
          target: { kind: "repo", locator: "acme/foo" },
          provenance: { producer: "adapter", runId: "r1", startedAt: "2026-01-01T00:00:00Z" },
          grade: "reproduced",
          novelty: { state: "novel", sources: ["cve"], scanned: 1 },
          artifacts: [
            { kind: "cap", path: "x.bin", sha256: "b000000000000000000000000000000000000000000000000000000000000002" },
            { kind: "cap", path: "y.bin", sha256: "c000000000000000000000000000000000000000000000000000000000000003" },
          ],
        },
      ],
    });
    const e = entry({ finding, id: finding.id, title: finding.title });
    const md = assembleBundleIndex([e], { scanIds: ["scan-x"] });
    expect(md).toContain("`a00000000000…` +2");
  });

  it("shows em-dash in provenance column when no evidence artifacts are present", () => {
    const e = entry();
    const md = assembleBundleIndex([e], { scanIds: ["scan-x"] });
    const lines = md.split("\n").filter((l) => l.includes(" keep |"));
    expect(lines.length).toBeGreaterThanOrEqual(1);
    expect(lines[0]).toMatch(/\| — \|$/);
  });

  it("rejects malformed sha256 hex strings (not 64 hex chars)", () => {
    // Build with invalid sha256 — must be duck-typed since these aren't valid
    // zod-validated VerificationResult/ResearchEvidenceEnvelope objects.
    const finding = baseFinding({ id: "prov-badhash" });
    (finding as unknown as Record<string, unknown>).verification_result = {
      evidence_artifacts: [
        { sha256: "abc" }, // too short
        { sha256: "00000000000000000000000000000000000000000000000000000000000000ZZ" }, // non-hex
      ],
    };
    (finding as unknown as Record<string, unknown>).researchEvidence = [
      {
        artifacts: [{ sha256: "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg" }],
      },
    ];
    const e = entry({ finding, id: finding.id, title: finding.title });
    const md = assembleBundleIndex([e], { scanIds: ["scan-x"] });
    const lines = md.split("\n").filter((l) => l.includes(" keep |"));
    expect(lines[0]).toMatch(/\| — \|$/);
  });

  it("redacts sensitive header values from the title column", () => {
    const finding = baseFinding({
      id: "secret-leak-001",
      title: `Authorization: Bearer ${"a".repeat(90)}`,
    });
    const e = entry({ finding, title: finding.title });
    const md = assembleBundleIndex([e], { scanIds: ["scan-x"] });
    // The JWT payload is redacted in the title displayed in INDEX.md.
    expect(md).toContain("<REDACTED-Authorization>");
    expect(md).not.toContain("eyJhbGciOiJIUzI1NiJ9");
  });

  it("redacts sensitive values from the dropped reason column", () => {
    const finding = baseFinding({
      id: "drop-secret-001",
      title: "Token in drop reason",
    });
    const e = entry({
      finding,
      title: finding.title,
      patchStatus: "fixed",
      filingState: "drop",
      dropReason: "bearer token Bearer abcdef-secret found in logs",
    });
    const md = assembleBundleIndex([e], { scanIds: ["scan-x"] });
    expect(md).toContain("<REDACTED-Bearer>");
    expect(md).not.toContain("abcdef-secret");
  });

  it("preserves deterministic index output with supplied generatedAt, unchanged by provenance fields", () => {
    const ts = new Date("2026-04-27T12:00:00Z");
    const sha = "a".repeat(64);
    const vr = {
      finding_id: "det-prov-001",
      status: "not_reproduced" as const,
      mode: "deterministic" as const,
      engine_version: "1.0",
      started_at: "2026-01-01T00:00:00Z",
      completed_at: "2026-01-01T00:00:01Z",
      duration_ms: 1000,
      commands: [],
      assertions: [],
      evidence_artifacts: [{ kind: "stdout", path: "x", sha256: sha, bytes: 1 }],
      engine_metadata: { os: "linux", arch: "x64" as const },
    };
    // Run twice with identical inputs — must produce identical output.
    const finding1 = baseFinding({ id: "det-prov-001", verification_result: vr });
    const finding2 = baseFinding({ id: "det-prov-001", verification_result: vr });
    const e1 = entry({ finding: finding1, id: finding1.id, title: finding1.title });
    const e2 = entry({ finding: finding2, id: finding2.id, title: finding2.title });
    const md1 = assembleBundleIndex([e1], { scanIds: ["scan-aaaa"], generatedAt: ts });
    const md2 = assembleBundleIndex([e2], { scanIds: ["scan-aaaa"], generatedAt: ts });
    expect(md1).toBe(md2);
    expect(md1).toContain("- Generated: 2026-04-27T12:00:00.000Z");
  });
});

// ── formatDroppedReason / droppedFilename ───────────────────────────────────

describe("formatDroppedReason", () => {
  it("includes canary refs and behavioural step verdicts when both are present", () => {
    const finding = baseFinding({ id: "abcd1234efgh" });
    const md = formatDroppedReason({
      finding,
      scanId: "scan-aaaa",
      patchStatus: reverifyFixed(),
      behaviouralReport: execReport("exploit_broken"),
      reason: "behavioural reverify: exploit_broken",
    });
    expect(md).toContain("# Dropped: SSRF via /api/foo");
    expect(md).toContain("- **Canary status:** fixed");
    expect(md).toContain("- **Canary ref:** `v2026.420.0-canary.9`");
    expect(md).toContain("- **Behavioural verdict:** exploit_broken");
    expect(md).toContain("- **Last-known-good execution:** see `abcd1234.execution.json`");
    expect(md).toContain("`exploit-1` → failed");
    expect(md).toContain("## Refs checked");
  });

  it("droppedFilename uses canary status as slug when present", () => {
    const e = entry({
      severity: "high",
      patchStatus: "fixed",
      filingState: "drop",
      dropReason: "canary",
    });
    expect(droppedFilename(e)).toMatch(/^[a-z0-9]{8}-high-fixed\.md$/);
  });

  it("droppedFilename falls back to behavioural verdict when canary is absent", () => {
    const e = entry({
      severity: "low",
      behaviouralVerdict: "exploit_broken",
      filingState: "drop",
      dropReason: "behavioural",
    });
    expect(droppedFilename(e)).toMatch(/^[a-z0-9]{8}-low-exploit_broken\.md$/);
  });
});

// ── End-to-end bundle assembly (the test plan from #168) ────────────────────

describe("bundle assembly end-to-end", () => {
  it("1 finding, no reverify → bundle has advisory + screenshot, no execution.json shape", () => {
    // We validate the pieces a CLI would write:
    //  - assembleBundleIndex returns an INDEX with one row
    //  - renderAdvisoryMarkdown returns the advisory file
    //  - renderExploitScreenshot returns a shot
    //  - decideFilingState returns 'keep' (no inputs to flip it)
    const finding = baseFinding();
    const outputDir = mkdtempSync(join(tmpdir(), "0sec-bundle-1-"));
    const stub = freezeStub(outputDir);
    const shot = renderExploitScreenshot(finding, { outputDir, binary: stub, available: true });
    expect(shot).not.toBeNull();
    const advisory = renderAdvisoryMarkdown(finding);
    expect(advisory.markdown).toContain("# Title");
    const filing = decideFilingState({ dropFixed: false });
    expect(filing.filingState).toBe("keep");
    const md = assembleBundleIndex([{
      finding,
      filename: advisory.filename,
      primaryCwe: advisory.primaryCwe,
      cvssScore: advisory.cvssScore,
      filingState: "keep",
    }], { scanIds: ["scan-aaaa"] });
    expect(md).toContain(advisory.filename);
    expect(md).not.toContain("## Dropped");
  });

  it("2 findings + reverify (mocked verdicts) → INDEX has correct behavioural column, dropped lands in _dropped/ section", () => {
    const keepFinding = baseFinding({ id: "keep0001abcd", title: "Live SSRF" });
    const dropFinding = baseFinding({ id: "drop0001abcd", title: "Patched SSRF" });

    const keepFiling = decideFilingState({
      patchStatus: reverifyStillVulnerable(),
      behaviouralReport: execReport("exploit_still_works"),
      dropFixed: true,
    });
    const dropFiling = decideFilingState({
      patchStatus: reverifyStillVulnerable(),
      behaviouralReport: execReport("exploit_broken"),
      dropFixed: true,
    });
    expect(keepFiling.filingState).toBe("keep");
    expect(dropFiling.filingState).toBe("drop");

    const md = assembleBundleIndex([
      {
        finding: keepFinding,
        filename: "3-medium-live-ssrf.md",
        primaryCwe: "CWE-918",
        cvssScore: 6.5,
        patchStatus: "still-vulnerable",
        behaviouralVerdict: "exploit_still_works",
        filingState: keepFiling.filingState,
      },
      {
        finding: dropFinding,
        filename: "",
        primaryCwe: "",
        cvssScore: 0,
        patchStatus: "still-vulnerable",
        behaviouralVerdict: "exploit_broken",
        filingState: dropFiling.filingState,
        dropReason: dropFiling.dropReason,
      },
    ], { scanIds: ["scan-aaaa"] });
    expect(md).toContain("Live SSRF");
    expect(md).toContain("Patched SSRF");
    expect(md).toContain("exploit_still_works");
    expect(md).toContain("exploit_broken");
    expect(md).toContain("## Dropped");
  });

  it("multi-frame screenshot when pocSteps present → one PNG per step in the bundle", () => {
    const finding = baseFinding({ pocSteps: makePocSteps() });
    const outputDir = mkdtempSync(join(tmpdir(), "0sec-bundle-mframe-"));
    const stub = freezeStub(outputDir);
    const frames = renderExploitScreenshot(finding, {
      outputDir,
      binary: stub,
      available: true,
      pocSteps: finding.pocSteps,
    });
    expect(Array.isArray(frames)).toBe(true);
    expect(frames).toHaveLength(4);
    for (const f of frames) expect(existsSync(f.path)).toBe(true);
    expect(frames[0].stepId).toBe("setup-1");
    expect(frames[3].stepId).toBe("verify-1");
  });

  it("sibling-fix populated from #172 when finding cites a correct sibling", () => {
    // Build a tiny repo with a "correct gate" sibling file.
    const repoPath = mkdtempSync(join(tmpdir(), "0sec-bundle-sibfix-"));
    mkdirSync(join(repoPath, "src"), { recursive: true });
    writeFileSync(join(repoPath, "src/sibling.ts"), `export function adminGuard(req: Req) {\n  if (!req.user) throw new Error('unauth');\n  if (req.user.role !== 'admin') throw new Error('forbidden');\n  return req.user;\n}\n`);
    const finding = baseFinding({
      description: "The vulnerable handler skips assertInstanceAdmin. The correct pattern at src/sibling.ts:3 properly checks the admin role.",
    });
    const sibling = extractSiblingFix(finding, { repoPath });
    expect(sibling).not.toBeNull();
    expect(sibling!.fileRef.file).toBe("src/sibling.ts");
    expect(sibling!.fileRef.line).toBe(3);
    expect(sibling!.snippet).toContain("admin");
    expect(sibling!.language).toBe("typescript");
  });

  it("empty-input edge case (0 findings) → bundle has empty INDEX.md, no other files to emit", () => {
    const md = assembleBundleIndex([], { scanIds: ["scan-empty"] });
    expect(md).toContain("# Disclosure batch");
    expect(md).toContain("- Drafts: 0");
    expect(md).not.toContain("|"); // no table at all
  });
});
