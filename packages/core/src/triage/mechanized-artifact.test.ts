import { describe, it, expect } from "vitest";
import type { Finding } from "@0sec/shared";
import type { CrashArtifact } from "./memsafety-types.js";
import type { HuntCandidate } from "../stages/hunt-scan.js";
import {
  mechanizedArtifactVerdict,
  verifyStructuralProof,
  parseMechanizedArtifact,
  makeMechanizedArtifactGate,
  synthesizeMechanizedArtifact,
  type MechanizedArtifact,
  type SourceLoader,
} from "./mechanized-artifact.js";

// ── Fixtures ──────────────────────────────────────────────────────────────

/** A tiny fake source tree — the "real bytes" claims are grep-checked against. */
const SOURCES: Record<string, string> = {
  "net/tipc/socket.c": [
    "static void tipc_sk_free(struct sock *sk) {", // line 1
    "  kfree(sk->sk_user_data);", // line 2  <- the free
    "}", // line 3
    "static int tipc_sk_use(struct sock *sk) {", // line 4
    "  return read_field(sk->sk_user_data);", // line 5  <- the use, no lock
    "}", // line 6
  ].join("\n"),
  "driver.sys::DispatchDeviceControl": [
    "NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT dev, PIRP irp) {", // 1
    "  if (code == 0x222004) {", // 2  <- the ioctl code
    "    memcpy(out, in, in_len);", // 3  <- the sink
    "  }", // 4
    "}", // 5
  ].join("\n"),
};

const loadSource: SourceLoader = (file) => SOURCES[file] ?? null;

function fakeFinding(over: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    templateId: "t1",
    title: "UAF in tipc_sk_use",
    description: "sk->sk_user_data freed in tipc_sk_free, read in tipc_sk_use with no lock",
    severity: "high",
    category: "use-after-free",
    status: "open" as Finding["status"],
    evidence: { analysis: "" },
    ...over,
  } as Finding;
}

const candidate: HuntCandidate = { path: "net/tipc/socket.c" };

function reproducedCrash(over: Partial<CrashArtifact> = {}): CrashArtifact {
  return {
    kind: "kasan" as CrashArtifact["kind"],
    signature: "slab-use-after-free/tipc_sk_use",
    rawOutput: "BUG: KASAN: slab-use-after-free in tipc_sk_use",
    inputPath: "/tmp/repro.c",
    reproConfirmations: 2,
    reproAttempts: 3,
    ...over,
  };
}
// NOTE: memsafety CrashArtifact kinds are asan/ubsan/msan/miri/panic/segfault/
// timeout/oom. Kernel KASAN maps onto "asan" for isReproducedMemCorruption.
function reproducedKasan(over: Partial<CrashArtifact> = {}): CrashArtifact {
  return reproducedCrash({ kind: "asan", ...over });
}

// ── Structural-proof grep core ──────────────────────────────────────────────

describe("verifyStructuralProof", () => {
  it("verifies claims whose needles exist in the real source", async () => {
    const r = await verifyStructuralProof(
      [
        { kind: "freed-field", file: "net/tipc/socket.c", needle: "kfree(sk->sk_user_data)" },
        { kind: "sink", file: "net/tipc/socket.c", needle: "read_field(sk->sk_user_data)" },
      ],
      loadSource,
    );
    expect(r.verified).toBe(true);
    expect(r.failures).toHaveLength(0);
  });

  it("FAILS a claim whose needle is not in the source (hallucination)", async () => {
    const r = await verifyStructuralProof(
      [{ kind: "sink", file: "net/tipc/socket.c", needle: "kfree(sk->NONEXISTENT)" }],
      loadSource,
    );
    expect(r.verified).toBe(false);
    expect(r.failures[0]!.reason).toMatch(/NOT found|hallucination/);
  });

  it("FAILS a claim about a file that does not exist", async () => {
    const r = await verifyStructuralProof(
      [{ kind: "sink", file: "made/up/file.c", needle: "anything" }],
      loadSource,
    );
    expect(r.verified).toBe(false);
    expect(r.failures[0]!.reason).toMatch(/file not found/);
  });

  it("verifies a NEGATIVE (missing-lock) claim when the lock is absent in the span", async () => {
    const r = await verifyStructuralProof(
      [{ kind: "missing-lock", file: "net/tipc/socket.c", needle: "lock_sock", absent: true, spanStart: 4, spanEnd: 6 }],
      loadSource,
    );
    expect(r.verified).toBe(true);
  });

  it("FAILS a negative claim when the 'absent' needle is actually present", async () => {
    const r = await verifyStructuralProof(
      [{ kind: "missing-lock", file: "net/tipc/socket.c", needle: "read_field", absent: true, spanStart: 4, spanEnd: 6 }],
      loadSource,
    );
    expect(r.verified).toBe(false);
    expect(r.failures[0]!.reason).toMatch(/IS present/);
  });
});

// ── The gate — verdict semantics ────────────────────────────────────────────

describe("mechanizedArtifactVerdict", () => {
  it("REJECTS when a structural claim does not grep-verify (mechanized FP-kill)", async () => {
    const artifact: MechanizedArtifact = {
      structuralProof: [{ kind: "sink", file: "net/tipc/socket.c", needle: "kfree(sk->FABRICATED)" }],
      reproducedCrash: reproducedKasan(),
    };
    const v = await mechanizedArtifactVerdict(artifact, loadSource);
    expect(v.verdict).toBe("rejected");
    expect(v.mechanizedBasis).toBe("none");
    // Even WITH a reproduced crash, a fabricated structural claim is rejected —
    // stricter than memCorruptionVerdict, which would confirm on the crash alone.
  });

  it("is INCONCLUSIVE (not rejected) when no structural proof is supplied — held, #518", async () => {
    const artifact = { structuralProof: [] } as unknown as MechanizedArtifact;
    const v = await mechanizedArtifactVerdict(artifact, loadSource);
    expect(v.verdict).toBe("inconclusive");
    expect(v.mechanizedBasis).toBe("none");
  });

  it("CONFIRMS on verified structural proof + reproduced sanitizer crash (N× folded)", async () => {
    const artifact: MechanizedArtifact = {
      structuralProof: [
        { kind: "freed-field", file: "net/tipc/socket.c", needle: "kfree(sk->sk_user_data)" },
        { kind: "sink", file: "net/tipc/socket.c", needle: "read_field(sk->sk_user_data)" },
      ],
      reproducedCrash: reproducedKasan({ reproConfirmations: 2, reproAttempts: 3 }),
    };
    const v = await mechanizedArtifactVerdict(artifact, loadSource, { minClaims: 2 });
    expect(v.verdict).toBe("confirmed");
    expect(v.mechanizedBasis).toBe("reproduced-sanitizer-crash");
    expect(v.evidenceKind).toBe("reproduced-memcorruption-poc");
    expect(v.confidence).toBeGreaterThanOrEqual(0.95);
  });

  it("dampens confidence for a single-shot (1-of-N) reproduction", async () => {
    const artifact: MechanizedArtifact = {
      structuralProof: [{ kind: "sink", file: "net/tipc/socket.c", needle: "read_field(sk->sk_user_data)" }],
      reproducedCrash: reproducedKasan({ reproConfirmations: 1, reproAttempts: 5 }),
    };
    const v = await mechanizedArtifactVerdict(artifact, loadSource);
    expect(v.verdict).toBe("confirmed");
    expect(v.confidence).toBeCloseTo(0.82, 2);
  });

  it("CONFIRMS a non-crashing bug on a passing bounded structural check", async () => {
    const artifact: MechanizedArtifact = {
      structuralProof: [{ kind: "freed-field", file: "net/tipc/socket.c", needle: "kfree(sk->sk_user_data)" }],
      boundedCheck: {
        kind: "unbalanced-free",
        assertion: "sk_user_data freed at line 2, no re-init/null before use at line 5",
        evidence: [
          { kind: "call-site", file: "net/tipc/socket.c", needle: "kfree(sk->sk_user_data)" },
          // No re-assignment of sk_user_data between free and use.
          { kind: "guard", file: "net/tipc/socket.c", needle: "sk->sk_user_data =", absent: true, spanStart: 3, spanEnd: 5 },
        ],
      },
    };
    const v = await mechanizedArtifactVerdict(artifact, loadSource);
    expect(v.verdict).toBe("confirmed");
    expect(v.mechanizedBasis).toBe("bounded-structural-check");
    expect(v.confidence).toBeCloseTo(0.75, 2);
  });

  it("is INCONCLUSIVE when the bounded check's evidence does not hold", async () => {
    const artifact: MechanizedArtifact = {
      structuralProof: [{ kind: "freed-field", file: "net/tipc/socket.c", needle: "kfree(sk->sk_user_data)" }],
      boundedCheck: {
        kind: "unbalanced-free",
        assertion: "no re-init before use",
        // This negative claim FAILS: read_field IS in the span, so 'absent' is false.
        evidence: [{ kind: "guard", file: "net/tipc/socket.c", needle: "read_field", absent: true, spanStart: 4, spanEnd: 6 }],
      },
    };
    const v = await mechanizedArtifactVerdict(artifact, loadSource);
    expect(v.verdict).toBe("inconclusive");
  });

  it("is INCONCLUSIVE (held for the prover) when proof verifies but no crash/bounded check", async () => {
    const artifact: MechanizedArtifact = {
      structuralProof: [{ kind: "sink", file: "net/tipc/socket.c", needle: "read_field(sk->sk_user_data)" }],
    };
    const v = await mechanizedArtifactVerdict(artifact, loadSource);
    expect(v.verdict).toBe("inconclusive");
    expect(v.mechanizedBasis).toBe("none");
    expect(v.confidence).toBeCloseTo(0.4, 2);
  });

  it("catches a decompiled-Windows hallucinated IOCTL code", async () => {
    // Ghidra produced 0x222004; the model claimed 0x999999 — refuted.
    const artifact: MechanizedArtifact = {
      structuralProof: [{ kind: "ioctl-code", file: "driver.sys::DispatchDeviceControl", needle: "0x999999" }],
    };
    const v = await mechanizedArtifactVerdict(artifact, loadSource);
    expect(v.verdict).toBe("rejected");
  });
});

// ── Structured-output parsing ────────────────────────────────────────────────

describe("parseMechanizedArtifact", () => {
  it("parses a well-formed payload and strips unknown keys", async () => {
    const r = parseMechanizedArtifact({
      structural_proof: [
        { kind: "sink", file: "a.c", needle: "memcpy(", span_start: 3, junk: "dropme" },
      ],
      unknownTop: 1,
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.artifact.structuralProof[0]!.spanStart).toBe(3);
      expect((r.artifact.structuralProof[0]! as Record<string, unknown>).junk).toBeUndefined();
    }
  });

  it("rejects a payload with no structural claims", async () => {
    const r = parseMechanizedArtifact({ structural_proof: [] });
    expect(r.ok).toBe(false);
  });

  it("rejects a non-object payload", async () => {
    expect(parseMechanizedArtifact(null).ok).toBe(false);
    expect(parseMechanizedArtifact("nope").ok).toBe(false);
  });
});

// ── The HuntVerifier adapter ─────────────────────────────────────────────────

describe("makeMechanizedArtifactGate", () => {
  it("confirms a finding whose synthesised artifact reproduces + grep-verifies", async () => {
    const gate = makeMechanizedArtifactGate({
      synthesize: async () => ({
        structuralProof: [{ kind: "sink", file: "net/tipc/socket.c", needle: "read_field(sk->sk_user_data)" }],
        reproducedCrash: reproducedKasan(),
      }),
      loadSource,
    });
    const v = await gate(fakeFinding(), candidate);
    expect(v.confirmed).toBe(true);
    expect(v.reason).toMatch(/confirmed\/reproduced-sanitizer-crash/);
  });

  it("does NOT confirm (rejects) a hallucinated finding", async () => {
    const gate = makeMechanizedArtifactGate({
      synthesize: async () => ({
        structuralProof: [{ kind: "sink", file: "net/tipc/socket.c", needle: "read_field(sk->GHOST)" }],
        reproducedCrash: reproducedKasan(),
      }),
      loadSource,
    });
    const v = await gate(fakeFinding(), candidate);
    expect(v.confirmed).toBe(false);
    expect(v.reason).toMatch(/rejected/);
  });

  it("uses the injected reproduce lane when the artifact has no crash", async () => {
    let reproduceCalled = false;
    const gate = makeMechanizedArtifactGate({
      synthesize: async () => ({
        structuralProof: [{ kind: "sink", file: "net/tipc/socket.c", needle: "read_field(sk->sk_user_data)" }],
      }),
      loadSource,
      reproduce: async () => {
        reproduceCalled = true;
        return reproducedKasan();
      },
    });
    const v = await gate(fakeFinding(), candidate);
    expect(reproduceCalled).toBe(true);
    expect(v.confirmed).toBe(true);
  });

  it("holds (does not confirm) when no artifact is synthesised", async () => {
    const gate = makeMechanizedArtifactGate({ synthesize: async () => null, loadSource });
    const v = await gate(fakeFinding(), candidate);
    expect(v.confirmed).toBe(false);
    expect(v.reason).toMatch(/no mechanized artifact/);
  });
});

// ── LLM synthesis (injected model) ───────────────────────────────────────────

describe("synthesizeMechanizedArtifact", () => {
  it("returns the parsed artifact from the model tool-call", async () => {
    const artifact = await synthesizeMechanizedArtifact(fakeFinding(), candidate, async () => ({
      structural_proof: [{ kind: "sink", file: "net/tipc/socket.c", needle: "read_field(sk->sk_user_data)" }],
    }));
    expect(artifact).not.toBeNull();
    expect(artifact!.structuralProof).toHaveLength(1);
  });

  it("returns null on a malformed model reply (held, not confirmed)", async () => {
    const artifact = await synthesizeMechanizedArtifact(fakeFinding(), candidate, async () => ({ garbage: true }));
    expect(artifact).toBeNull();
  });

  it("returns null when the model call throws", async () => {
    const artifact = await synthesizeMechanizedArtifact(fakeFinding(), candidate, async () => {
      throw new Error("model down");
    });
    expect(artifact).toBeNull();
  });
});
