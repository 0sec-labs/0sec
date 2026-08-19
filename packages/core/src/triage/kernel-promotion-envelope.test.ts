import { describe, it, expect } from "vitest";
import {
  buildKernelPromotionEnvelope,
  isConfirmed,
  isHypothesisOnly,
} from "./kernel-promotion-envelope.js";
import type {
  KernelCandidateIdentity,
  KernelSourceSinkContext,
  KernelCleanControlReceipt,
  SemanticValidationStatus,
} from "./kernel-promotion-envelope.js";
import type {
  RankSinkReachabilityResult,
  SinkLocation,
} from "../kernel/reachability-rank.js";
import type {
  VerificationResult,
  ResearchNoveltyReceipt,
} from "@0sec/shared";

// ── Fixtures ────────────────────────────────────────────────────────────────

const SAMPLE_IDENTITY: KernelCandidateIdentity = {
  crashType: "kasan-uaf",
  faultingFunction: "nfs4_proc_getattr",
  sourcePath: "fs/nfs/nfs4proc.c",
  subsystem: "nfs",
  kernelVersion: "v6.8",
};

const SAMPLE_CONTEXT: KernelSourceSinkContext = {
  source: "nfs4_proc_getattr",
  sink: "__nfs4_getattr",
  preconditions: ["NFSv4 mount", "READDIR attribute cache miss"],
  sinkLocation: {
    file: "fs/nfs/nfs4proc.c",
    line: 842,
    function: "__nfs4_getattr",
  },
};

const RANKED_REACHABLE: RankSinkReachabilityResult = {
  sink: { file: "fs/nfs/nfs4proc.c", line: 842, function: "__nfs4_getattr" },
  sinkFunction: "__nfs4_getattr",
  candidates: [
    {
      entry: { name: "sys_nfs4_getattr", file: "fs/nfs/super.c", line: 1234 },
      pathLength: 3,
      path: ["sys_nfs4_getattr", "nfs4_proc_getattr", "__nfs4_getattr"],
      confidence: "direct",
      score: 0.92,
    },
  ],
  edgeCount: 7,
  warnings: [],
};

const RANKED_NO_CANDIDATES: RankSinkReachabilityResult = {
  sink: { file: "fs/nfs/nfs4proc.c", line: 842 },
  sinkFunction: "__nfs4_getattr",
  candidates: [],
  edgeCount: 0,
  warnings: ["Sink function __nfs4_getattr not found in call graph"],
};

const NOVEL_WITH_SOURCES: ResearchNoveltyReceipt = {
  state: "novel",
  checkedAt: "2026-08-02T00:00:00Z",
  sources: ["nvd-official", "oss-security"],
  scanned: 42,
};

const NOVELTY_UNCHECKED: ResearchNoveltyReceipt = {
  state: "unchecked",
};

const NOVELTY_DUPLICATE: ResearchNoveltyReceipt = {
  state: "duplicate",
  sources: ["nvd-official"],
  scanned: 5,
};

const NOVELTY_NOVEL_NO_SOURCES: ResearchNoveltyReceipt = {
  state: "novel",
  sources: [],
  scanned: 0,
};

const VERIFIED_REPRODUCED: VerificationResult = {
  status: "reproduced",
  mode: "deterministic_replay",
  runner: "local",
  engine: { os: "darwin", arch: "arm64" },
  commands: [
    {
      argv: ["/bin/sh", "-c", "./reproducer"],
      cwd: "/tmp/test",
      exitCode: 0,
      stdout: "",
      stderr: "KASAN: use-after-free in nfs4_proc_getattr",
      timedOut: false,
    },
  ],
  assertions: [
    {
      kind: "string_in_output",
      target: "step-1-stderr",
      expected: "KASAN: use-after-free",
      actual: "KASAN: use-after-free in nfs4_proc_getattr",
      passed: true,
    },
  ],
  evidenceArtifacts: [
    { ref: "dmesg.log", sha256: "a".repeat(64), kind: "dmesg" },
  ],
  startedAt: "2026-08-01T12:00:00Z",
  completedAt: "2026-08-01T12:00:10Z",
  runId: "verify-run-001",
  producer: "tier1-oracle",
  succeeded: true,
};

const VERIFIED_NOT_REPRODUCED: VerificationResult = {
  ...VERIFIED_REPRODUCED,
  status: "not_reproduced",
  runId: "verify-run-002",
  succeeded: false,
};

const VERIFIED_ERROR: VerificationResult = {
  ...VERIFIED_REPRODUCED,
  status: "error",
  runId: "verify-run-003",
  succeeded: false,
};

const PASSING_CONTROL: KernelCleanControlReceipt = {
  clean: true,
  controlMethod: "Patched kernel v6.8-5-gabcdef",
  evidence: "Same reproducer produced no crash on patched kernel.",
};

const FAILING_CONTROL: KernelCleanControlReceipt = {
  clean: false,
  controlMethod: "Patched kernel v6.8-5-gabcdef",
  evidence: "Reproducer crashed on both vulnerable and patched kernel.",
};

const VALID_VALIDATION: SemanticValidationStatus = {
  kind: "compiled-and-valid",
};

const INVALID_VALIDATION: SemanticValidationStatus = {
  kind: "invalid",
  reason: "Reproducer uses undefined struct nfs4_fattr",
};

// ── The ALL-PASSING inputs envelope must provide every gate. ──────────────

function allPassingInputs(
  overrides?: Partial<{
    validation: SemanticValidationStatus | undefined;
    cleanControl: KernelCleanControlReceipt | undefined;
    novelty: ResearchNoveltyReceipt;
    verificationReceipt: VerificationResult | undefined;
  }>,
) {
  return {
    candidateId: "cand-001",
    runId: "run-001",
    identity: SAMPLE_IDENTITY,
    context: SAMPLE_CONTEXT,
    reachability: RANKED_REACHABLE,
    validation: overrides && "validation" in overrides ? overrides.validation : VALID_VALIDATION,
    novelty: overrides && "novelty" in overrides ? overrides.novelty : NOVEL_WITH_SOURCES,
    cleanControl: overrides && "cleanControl" in overrides ? overrides.cleanControl : PASSING_CONTROL,
    verificationReceipt:
      overrides && "verificationReceipt" in overrides
        ? overrides.verificationReceipt
        : VERIFIED_REPRODUCED,
  };
}

// ── Tests ───────────────────────────────────────────────────────────────────

describe("buildKernelPromotionEnvelope", () => {
  it("returns `confirmed` when all four gates pass", () => {
    const envelope = buildKernelPromotionEnvelope(allPassingInputs());

    expect(envelope.status.kind).toBe("confirmed");
    expect(isConfirmed(envelope)).toBe(true);
    expect(isHypothesisOnly(envelope)).toBe(false);
    expect(envelope.reachability.candidates.length).toBeGreaterThan(0);
    expect(envelope.reachability.candidates[0]!.score).toBe(0.92);
    expect(envelope.reachability.warnings).toHaveLength(0);
  });

  it("normalizes novelty and still confirms when novelty had sources", () => {
    const envelope = buildKernelPromotionEnvelope(allPassingInputs());
    expect(envelope.novelty.state).toBe("novel");
    expect(envelope.status.kind).toBe("confirmed");
  });

  it("returns `hypothesis-only` when validation is absent", () => {
    const envelope = buildKernelPromotionEnvelope(
      allPassingInputs({ validation: undefined }),
    );

    expect(envelope.status.kind).toBe("hypothesis-only");
    expect(envelope.status.reason).toContain("validation: absent");
    expect(isConfirmed(envelope)).toBe(false);
  });

  it("returns `hypothesis-only` when validation is invalid", () => {
    const envelope = buildKernelPromotionEnvelope(
      allPassingInputs({ validation: INVALID_VALIDATION }),
    );

    expect(envelope.status.kind).toBe("hypothesis-only");
    expect(envelope.status.reason).toContain("validation: invalid");
  });

  it("returns `hypothesis-only` when clean control is absent", () => {
    const envelope = buildKernelPromotionEnvelope(
      allPassingInputs({ cleanControl: undefined }),
    );

    expect(envelope.status.kind).toBe("hypothesis-only");
    expect(envelope.status.reason).toContain("cleanControl: absent");
  });

  it("returns `hypothesis-only` when clean control failed", () => {
    const envelope = buildKernelPromotionEnvelope(
      allPassingInputs({ cleanControl: FAILING_CONTROL }),
    );

    expect(envelope.status.kind).toBe("hypothesis-only");
    expect(envelope.status.reason).toContain("cleanControl: clean=false");
    expect(envelope.status.reason).toContain("crashed on both");
  });

  it("returns `hypothesis-only` when novelty is unchecked", () => {
    const envelope = buildKernelPromotionEnvelope(
      allPassingInputs({ novelty: NOVELTY_UNCHECKED }),
    );

    expect(envelope.status.kind).toBe("hypothesis-only");
    expect(envelope.status.reason).toContain("novelty: unchecked");
  });

  it("returns `hypothesis-only` when novelty is duplicate", () => {
    const envelope = buildKernelPromotionEnvelope(
      allPassingInputs({ novelty: NOVELTY_DUPLICATE }),
    );

    expect(envelope.status.kind).toBe("hypothesis-only");
    expect(envelope.status.reason).toContain("novelty: duplicate");
  });

  it("normalizes bogus-novel-without-sources to unchecked and fails closed", () => {
    const envelope = buildKernelPromotionEnvelope(
      allPassingInputs({ novelty: NOVELTY_NOVEL_NO_SOURCES }),
    );

    // normalizeResearchNovelty demotes to "unchecked" when no sources checked
    expect(envelope.novelty.state).toBe("unchecked");
    expect(envelope.status.kind).toBe("hypothesis-only");
    expect(envelope.status.reason).toContain("novelty: unchecked");
  });

  it("returns `hypothesis-only` when verification receipt is absent", () => {
    const envelope = buildKernelPromotionEnvelope(
      allPassingInputs({ verificationReceipt: undefined }),
    );

    expect(envelope.status.kind).toBe("hypothesis-only");
    expect(envelope.status.reason).toContain("verificationReceipt: absent");
  });

  it("returns `hypothesis-only` when verification receipt is not_reproduced", () => {
    const envelope = buildKernelPromotionEnvelope(
      allPassingInputs({ verificationReceipt: VERIFIED_NOT_REPRODUCED }),
    );

    expect(envelope.status.kind).toBe("hypothesis-only");
    expect(envelope.status.reason).toContain(
      "verificationReceipt: status=not_reproduced",
    );
  });

  it("returns `hypothesis-only` when verification receipt is error", () => {
    const envelope = buildKernelPromotionEnvelope(
      allPassingInputs({ verificationReceipt: VERIFIED_ERROR }),
    );

    expect(envelope.status.kind).toBe("hypothesis-only");
    expect(envelope.status.reason).toContain(
      "verificationReceipt: status=error",
    );
  });

  it("reports ALL gaps when multiple inputs are missing", () => {
    const envelope = buildKernelPromotionEnvelope({
      candidateId: "cand-all-missing",
      runId: "run-all-missing",
      identity: SAMPLE_IDENTITY,
      context: SAMPLE_CONTEXT,
      reachability: RANKED_REACHABLE,
      // validation: absent
      novelty: NOVELTY_UNCHECKED,
      // cleanControl: absent
      // verificationReceipt: absent
    });

    expect(envelope.status.kind).toBe("hypothesis-only");
    const r = envelope.status.reason;
    expect(r).toContain("validation: absent");
    expect(r).toContain("cleanControl: absent");
    expect(r).toContain("novelty: unchecked");
    expect(r).toContain("verificationReceipt: absent");
  });

  it("still contains reachability warnings in envelope data", () => {
    const envelope = buildKernelPromotionEnvelope({
      candidateId: "cand-warn",
      runId: "run-warn",
      identity: SAMPLE_IDENTITY,
      context: SAMPLE_CONTEXT,
      reachability: RANKED_NO_CANDIDATES,
      novelty: NOVEL_WITH_SOURCES,
    });

    expect(envelope.status.kind).toBe("hypothesis-only");
    expect(envelope.reachability.warnings.length).toBeGreaterThan(0);
    expect(envelope.reachability.candidates).toHaveLength(0);
  });

  it("confirmed envelope includes a descriptive basis string", () => {
    const envelope = buildKernelPromotionEnvelope(allPassingInputs());

    expect(envelope.status.kind).toBe("confirmed");
    expect(envelope.status.basis).toContain("reproduced verification receipt");
  });
});

describe("isConfirmed / isHypothesisOnly", () => {
  it("isConfirmed returns true only when status is confirmed", () => {
    const confirmed = buildKernelPromotionEnvelope(allPassingInputs());
    expect(isConfirmed(confirmed)).toBe(true);
    expect(isHypothesisOnly(confirmed)).toBe(false);
  });

  it("isHypothesisOnly returns true for hypothesis-only status", () => {
    const hypothesis = buildKernelPromotionEnvelope({
      candidateId: "cand-pred",
      runId: "run-pred",
      identity: SAMPLE_IDENTITY,
      context: SAMPLE_CONTEXT,
      reachability: RANKED_REACHABLE,
      novelty: NOVEL_WITH_SOURCES,
    });
    expect(isConfirmed(hypothesis)).toBe(false);
    expect(isHypothesisOnly(hypothesis)).toBe(true);
  });
});