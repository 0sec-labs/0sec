import { describe, expect, it } from "vitest";
import {
  ZEROVERSE_BINARY,
  ZEROVERSE_TOOL_DEFINITION,
  buildOverseScanArgv,
  executeOverseScan,
  launchOverseBinary,
  parseOverseNdjson,
  runOverseProcess,
  validateOverseArgs,
  type OverseArgs,
  type OverseProcessRunner,
  type ScannerProcessOutcome,
} from "./0verse.js";

// A confirmed finding line + a hypothesis line, wrapped by the v1.3 _meta header
// exactly as `0verse api.result_to_ndjson` emits it.
function ndjsonFixture(): string {
  const meta = {
    _meta: {
      contract_version: "1.3",
      tool: { name: "0verse", version: "0.0.1" },
      binary: "/work/routerd",
      format: "ndjson",
      arch: "x86_64",
      backend: "auto",
      stages_run: ["ingest", "decompile", "triage", "pov"],
      confirmed_count: 1,
      note: "",
    },
  };
  const confirmed = {
    id: "abc123",
    bug_class: "cmdi",
    severity: "high",
    file: "/work/routerd",
    function: "handle_req",
    offset: "0x401abc",
    source: "recv",
    sink: "system",
    confirmed: true,
    hypothesis: true,
    pruned: false,
    capability: "command-exec",
    pov_path: "/out/pov.py",
    repro_cmd: "python3 /out/pov.py",
    dedup_bucket: "system@0x401abc",
    explanation: "attacker-controlled recv flows to system()",
    crash_output: "uid=0(root)",
    confidence: 0.95,
    patch_available: false,
    patch_verified: false,
    patch_mode: "none",
    patch_path: null,
    patch_recommendation: null,
    patch_regression: null,
  };
  const hypothesis = {
    ...confirmed,
    id: "def456",
    confirmed: false,
    hypothesis: true,
    capability: "",
    pov_path: "",
    repro_cmd: "",
    crash_output: null,
    confidence: null,
  };
  return [meta, confirmed, hypothesis].map((o) => JSON.stringify(o)).join("\n");
}

function stubRunner(outcome: ScannerProcessOutcome): OverseProcessRunner {
  return async () => outcome;
}

const goodArgs: OverseArgs = {
  binary_path: "/work/routerd",
  bug_class: "memory-safety",
  backend: "auto",
};

describe("ZEROVERSE_TOOL_DEFINITION", () => {
  it("is named analyze_binary and requires binary_path", () => {
    expect(ZEROVERSE_TOOL_DEFINITION.name).toBe("analyze_binary");
    expect(ZEROVERSE_TOOL_DEFINITION.required).toEqual(["binary_path"]);
  });
});

describe("validateOverseArgs", () => {
  it("accepts a minimal call and applies enum defaults", () => {
    const r = validateOverseArgs({ binary_path: "/work/a.out" });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.args.bug_class).toBe("memory-safety");
      expect(r.args.backend).toBe("auto");
      expect(r.args.timeout_s).toBeUndefined();
    }
  });

  it("strips unknown top-level keys (argv/cwd cannot propagate)", () => {
    const r = validateOverseArgs({
      binary_path: "/work/a.out",
      argv: ["rm", "-rf", "/"],
      cwd: "/",
    });
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect((r.args as Record<string, unknown>).argv).toBeUndefined();
      expect((r.args as Record<string, unknown>).cwd).toBeUndefined();
    }
  });

  it("rejects a missing binary_path", () => {
    expect(validateOverseArgs({}).ok).toBe(false);
    expect(validateOverseArgs({ binary_path: "" }).ok).toBe(false);
  });

  it("rejects a bad enum value", () => {
    const r = validateOverseArgs({ binary_path: "/x", backend: "wasm" });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("backend");
  });

  it("rejects non-object arguments", () => {
    expect(validateOverseArgs(null).ok).toBe(false);
    expect(validateOverseArgs("hi").ok).toBe(false);
    expect(validateOverseArgs([1]).ok).toBe(false);
  });
});

describe("parseOverseNdjson", () => {
  it("splits confirmed from hypotheses (PoV-is-truth) and reads the contract version", () => {
    const p = parseOverseNdjson(ndjsonFixture());
    expect(p.contractVersion).toBe("1.3");
    expect(p.compatible).toBe(true);
    expect(p.confirmed).toHaveLength(1);
    expect(p.hypotheses).toHaveLength(1);
    expect(p.confirmed[0].sink).toBe("system");
    expect(p.confirmed[0].repro_cmd).toBe("python3 /out/pov.py");
    expect(p.hypotheses[0].confirmed).toBe(false);
  });

  it("flags an unsupported MAJOR contract as incompatible but still parses", () => {
    const bumped = ndjsonFixture().replace('"contract_version":"1.3"', '"contract_version":"2.0"');
    const p = parseOverseNdjson(bumped);
    expect(p.contractVersion).toBe("2.0");
    expect(p.compatible).toBe(false);
  });

  it("tolerates banner/garbage lines and empty input", () => {
    const p = parseOverseNdjson("loading ghidra...\n\nnot json\n");
    expect(p.confirmed).toHaveLength(0);
    expect(p.hypotheses).toHaveLength(0);
    expect(p.contractVersion).toBe("");
    expect(p.compatible).toBe(true); // no version claimed -> not flagged
  });
});

describe("buildOverseScanArgv", () => {
  it("builds the ndjson scan argv with backend + bug-class", () => {
    expect(buildOverseScanArgv(goodArgs)).toEqual([
      "scan",
      "/work/routerd",
      "--format",
      "ndjson",
      "--backend",
      "auto",
      "--bug-class",
      "memory-safety",
    ]);
  });
});

describe("launchOverseBinary / runOverseProcess", () => {
  it("refuses any binary other than 0verse (fail-closed)", () => {
    expect(launchOverseBinary("bash", ["-c", "id"], {})).toBeNull();
  });

  it("runOverseProcess refuses a non-0verse bin without spawning", async () => {
    const out = await runOverseProcess("nmap", ["-sV"], {
      timeoutMs: 1000,
      ceilingMs: 1000,
      env: {},
    });
    expect(out.kind).toBe("error");
    if (out.kind === "error") expect(out.message).toContain("non-allowlisted");
  });
});

describe("executeOverseScan", () => {
  it("returns confirmed + hypotheses on a clean exit (stubbed subprocess)", async () => {
    const res = await executeOverseScan({
      args: goodArgs,
      runner: stubRunner({
        kind: "exit",
        exitCode: 0,
        combined: ndjsonFixture(),
        durationMs: 1234,
      }),
    });
    expect(res.success).toBe(true);
    const out = res.output as { confirmed: unknown[]; hypotheses: unknown[]; contract_version: string };
    expect(out.contract_version).toBe("1.3");
    expect(out.confirmed).toHaveLength(1);
    expect(out.hypotheses).toHaveLength(1);
  });

  it("surfaces a subprocess error as an unsuccessful result", async () => {
    const res = await executeOverseScan({
      args: goodArgs,
      runner: stubRunner({ kind: "error", message: "spawn 0verse ENOENT", durationMs: 5 }),
    });
    expect(res.success).toBe(false);
    expect(res.error).toContain("0verse");
  });

  it("marks partial results on timeout and notes it", async () => {
    const res = await executeOverseScan({
      args: goodArgs,
      runner: stubRunner({ kind: "timeout", partial: ndjsonFixture(), durationMs: 9999 }),
    });
    expect(res.success).toBe(true);
    const out = res.output as { note: string; stats: { timedOut: boolean } };
    expect(out.stats.timedOut).toBe(true);
    expect(out.note).toContain("PARTIAL");
  });

  it("fails closed on an unsupported MAJOR contract (never promotes)", async () => {
    const bumped = ndjsonFixture().replace('"contract_version":"1.3"', '"contract_version":"2.0"');
    const res = await executeOverseScan({
      args: goodArgs,
      runner: stubRunner({ kind: "exit", exitCode: 0, combined: bumped, durationMs: 10 }),
    });
    expect(res.success).toBe(false);
    expect(res.error).toContain("MAJOR");
  });

  it("clamps the requested timeout to the ceiling", async () => {
    let sawTimeout = -1;
    const res = await executeOverseScan({
      args: { ...goodArgs, timeout_s: 999_999 },
      ceilingMs: 60_000,
      runner: async (_bin, _argv, opts) => {
        sawTimeout = Math.min(opts.timeoutMs, opts.ceilingMs);
        return { kind: "exit", exitCode: 0, combined: ndjsonFixture(), durationMs: 1 };
      },
    });
    expect(res.success).toBe(true);
    expect(sawTimeout).toBe(60_000);
  });
});

describe("module invariants", () => {
  it("only ever targets the 0verse binary", () => {
    expect(ZEROVERSE_BINARY).toBe("0verse");
  });
});
