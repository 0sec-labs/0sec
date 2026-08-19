import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createDefaultResearchRegistry, ResearchAdapterRegistry } from "../adapter-registry.js";
import { runResearch } from "../research-runner.js";
import {
  WindowsVariantResearchAdapter,
  type WindowsVariantArtifactBinding,
  type WindowsVariantRankExecution,
  type WindowsVariantTarget,
} from "./windows-variant-adapter.js";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const proofLimit = "Static lexical guard-delta evidence only. This result cannot establish a crash, security impact, exploitability, novelty, or bounty eligibility.";

function artifact(tag: string): Record<string, unknown> {
  return {
    binary_sha256: tag.repeat(64),
    ghidra_export_sha256: String.fromCharCode(tag.charCodeAt(0) + 1).repeat(64),
    pdb_identity: "",
    pdb_sha256: "",
    analysis_receipt_sha256: String.fromCharCode(tag.charCodeAt(0) + 2).repeat(64),
    ghidra_version: "fixture-11.4",
    cache_key: tag.repeat(16),
    synthetic_fixture: true,
  };
}

function expected(value: Record<string, unknown>): WindowsVariantArtifactBinding {
  return {
    binarySha256: String(value.binary_sha256),
    ghidraExportSha256: String(value.ghidra_export_sha256),
    pdbIdentity: String(value.pdb_identity),
    pdbSha256: String(value.pdb_sha256),
    analysisReceiptSha256: String(value.analysis_receipt_sha256),
    ghidraVersion: String(value.ghidra_version),
    cacheKey: String(value.cache_key),
    syntheticFixture: Boolean(value.synthetic_fixture),
  };
}

function setup(): {
  target: WindowsVariantTarget;
  result: Record<string, unknown>;
  root: string;
} {
  const root = mkdtempSync(join(tmpdir(), "0sec-windows-variant-"));
  roots.push(root);
  const manifest = join(root, "campaign.json");
  writeFileSync(manifest, '{"schema_version":"0verse.windows-variant-campaign/v1"}\n');
  const campaignSha256 = createHash("sha256").update(
    '{"schema_version":"0verse.windows-variant-campaign/v1"}\n',
  ).digest("hex");
  const vulnerable = artifact("1");
  const fixed = artifact("4");
  const current = artifact("7");
  const result: Record<string, unknown> = {
    schema_version: "0verse.windows-variant/v1",
    campaign_sha256: campaignSha256,
    seed: {
      function: "SeedDispatch",
      reference: "synthetic missing count bound before copy",
      guard_delta: ["bounds"],
      sink_geometry: ["copy"],
      vulnerable,
      fixed,
    },
    current,
    candidate_count: 2,
    candidates: [
      {
        function: "OrdinaryChildDispatch",
        function_address: "0x1100",
        status: "candidate",
        score: 85,
        matched_sinks: ["copy"],
        missing_seed_guards: ["bounds"],
        present_guards: [],
        lexical_parameter_sink_hint: ["parameter:packet", "sink:copy"],
        reachability_grade: "ordinary-child",
        reachability_evidence: "synthetic annotation only",
        required_next_validator: "establish a supported unprivileged or ordinary-child caller before dynamic testing",
        rank: 1,
      },
      {
        function: "UnknownDispatch",
        function_address: "0x1200",
        status: "candidate",
        score: 70,
        matched_sinks: ["copy"],
        missing_seed_guards: ["bounds"],
        present_guards: [],
        lexical_parameter_sink_hint: [],
        reachability_grade: "unknown",
        reachability_evidence: "",
        required_next_validator: "establish a supported unprivileged or ordinary-child caller before dynamic testing",
        rank: 2,
      },
    ],
    proof_limit: proofLimit,
    all_results_are_candidates: true,
    weaponization: false,
    automatic_disclosure: false,
  };
  const target: WindowsVariantTarget = {
    kind: "windows.binary-variant",
    id: "windows-variant-fixture",
    location: manifest,
    config: {
      expectedCampaignSha256: campaignSha256,
      expectedSeedFunction: "SeedDispatch",
      expectedArtifacts: {
        vulnerable: expected(vulnerable),
        fixed: expected(fixed),
        current: expected(current),
      },
      timeoutMs: 5_000,
    },
  };
  return { target, result, root };
}

function execution(result: unknown): WindowsVariantRankExecution {
  return {
    stdout: Buffer.from(JSON.stringify(result)),
    stderr: "",
    exitCode: 0,
    signal: null,
    timedOut: false,
  };
}

describe("WindowsVariantResearchAdapter", () => {
  it("imports exact candidates but never emits findings or evidence envelopes", async () => {
    const { target, result, root } = setup();
    const runner = vi.fn(async () => execution(result));
    const run = await runResearch(new WindowsVariantResearchAdapter(runner), target, {
      artifactRoot: join(root, "artifacts"),
      runId: "variant-run",
    });

    expect(runner).toHaveBeenCalledOnce();
    expect(runner).toHaveBeenCalledWith(expect.objectContaining({
      manifestPath: target.location,
      timeoutMs: 5_000,
      signal: expect.any(AbortSignal),
    }));
    expect(run.candidates).toHaveLength(2);
    expect(run.findings).toHaveLength(0);
    expect(run.envelopes).toHaveLength(0);
    expect(run.candidates[0]?.payload).toMatchObject({
      campaignSha256: target.config.expectedCampaignSha256,
      row: { status: "candidate", function: "OrdinaryChildDispatch", rank: 1 },
    });
    expect(run.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ stage: "reachability", status: "inconclusive" }),
      expect.objectContaining({ stage: "verify", status: "inconclusive" }),
    ]));
    const retained = join(root, "artifacts", "variant-run", "windows-variant-result.json");
    expect(existsSync(retained)).toBe(true);
    expect(JSON.parse(readFileSync(retained, "utf8"))).toEqual(result);
  });

  it("is opt-in and absent from the default registry", async () => {
    expect(createDefaultResearchRegistry().kinds()).not.toContain("windows.binary-variant");
    const { target, result, root } = setup();
    const registry = new ResearchAdapterRegistry().register(
      "windows.binary-variant",
      () => new WindowsVariantResearchAdapter(async () => execution(result)),
    );
    const run = await registry.run(target, { artifactRoot: join(root, "artifacts") });
    expect(run.candidates).toHaveLength(2);
    expect(run.findings).toHaveLength(0);
  });

  it.each([
    ["schema", (value: Record<string, unknown>) => { value.schema_version = "0verse.windows-variant/v2"; }],
    ["candidate flag", (value: Record<string, unknown>) => { value.all_results_are_candidates = false; }],
    ["weaponization", (value: Record<string, unknown>) => { value.weaponization = true; }],
    ["disclosure", (value: Record<string, unknown>) => { value.automatic_disclosure = true; }],
    ["proof limit", (value: Record<string, unknown>) => { value.proof_limit = "weaker"; }],
  ])("rejects %s drift without candidates", async (_name, mutate) => {
    const { target, result, root } = setup();
    mutate(result);
    const run = await runResearch(
      new WindowsVariantResearchAdapter(async () => execution(result)),
      target,
      { artifactRoot: join(root, "artifacts") },
    );
    expect(run.candidates).toHaveLength(0);
    expect(run.findings).toHaveLength(0);
    expect(run.evidence).toEqual(expect.arrayContaining([
      expect.objectContaining({ stage: "discover", status: "failed" }),
    ]));
  });

  it("rejects artifact provenance, count, rank, and subset mismatches", async () => {
    const cases = [
      (result: Record<string, unknown>) => {
        (result.current as Record<string, unknown>).binary_sha256 = "a".repeat(64);
      },
      (result: Record<string, unknown>) => {
        (result.current as Record<string, unknown>).cache_key = "bad-cache-key";
      },
      (result: Record<string, unknown>) => { result.candidate_count = 3; },
      (result: Record<string, unknown>) => {
        ((result.candidates as Record<string, unknown>[])[0]!).rank = 2;
      },
      (result: Record<string, unknown>) => {
        ((result.candidates as Record<string, unknown>[])[0]!).matched_sinks = ["fill"];
      },
    ];
    for (const mutate of cases) {
      const { target, result, root } = setup();
      mutate(result);
      const run = await runResearch(
        new WindowsVariantResearchAdapter(async () => execution(result)),
        target,
        { artifactRoot: join(root, "artifacts", String(roots.length)) },
      );
      expect(run.candidates).toHaveLength(0);
    }
  });

  it.each([
    { ...execution({}), exitCode: 2 },
    { ...execution({}), signal: "SIGKILL" },
    { ...execution({}), timedOut: true },
    { ...execution({}), stdout: Buffer.from("not json") },
    { ...execution({}), stdout: Buffer.alloc(32 * 1024 * 1024 + 1) },
  ])("fails closed on runner failure %#", async (bad) => {
    const { target, root } = setup();
    const run = await runResearch(
      new WindowsVariantResearchAdapter(async () => bad),
      target,
      { artifactRoot: join(root, "artifacts") },
    );
    expect(run.candidates).toHaveLength(0);
    expect(run.findings).toHaveLength(0);
  });

  it("rejects a changed or symlinked manifest before invoking the runner", async () => {
    const changed = setup();
    writeFileSync(changed.target.location, "changed");
    const changedRunner = vi.fn(async () => execution(changed.result));
    const changedRun = await runResearch(
      new WindowsVariantResearchAdapter(changedRunner),
      changed.target,
      { artifactRoot: join(changed.root, "artifacts") },
    );
    expect(changedRun.candidates).toHaveLength(0);
    expect(changedRunner).not.toHaveBeenCalled();

    const linked = setup();
    const real = join(linked.root, "real.json");
    writeFileSync(real, '{"schema_version":"0verse.windows-variant-campaign/v1"}\n');
    rmSync(linked.target.location);
    symlinkSync(real, linked.target.location);
    const linkedRunner = vi.fn(async () => execution(linked.result));
    const linkedRun = await runResearch(
      new WindowsVariantResearchAdapter(linkedRunner),
      linked.target,
      { artifactRoot: join(linked.root, "artifacts") },
    );
    expect(linkedRun.candidates).toHaveLength(0);
    expect(linkedRunner).not.toHaveBeenCalled();
  });

  it("propagates abort authority and bounds timeout", async () => {
    const { target, result, root } = setup();
    const controller = new AbortController();
    const runner = vi.fn(async () => execution(result));
    await runResearch(new WindowsVariantResearchAdapter(runner), target, {
      artifactRoot: join(root, "artifacts"),
      signal: controller.signal,
    });
    expect(runner.mock.calls[0]?.[0].signal).toBeInstanceOf(AbortSignal);

    target.config.timeoutMs = 300_001;
    const rejected = await runResearch(new WindowsVariantResearchAdapter(runner), target, {
      artifactRoot: join(root, "rejected"),
    });
    expect(rejected.candidates).toHaveLength(0);
    expect(runner).toHaveBeenCalledOnce();
  });

  it("accepts the CWE-59 link-following vocabulary", async () => {
    const { target, result, root } = setup();
    const seed = result.seed as Record<string, unknown>;
    seed.guard_delta = ["reparse-check"];
    seed.sink_geometry = ["file-mutate", "file-open"];
    seed.reference = "CWE-59 fixture: missing reparse check before path resolution";
    const rows = result.candidates as Record<string, unknown>[];
    rows[0]!.matched_sinks = ["file-mutate"];
    rows[0]!.missing_seed_guards = ["reparse-check"];
    rows[0]!.present_guards = [];
    rows[0]!.lexical_parameter_sink_hint = ["parameter:found", "sink:file-mutate"];
    rows[1]!.matched_sinks = ["file-open"];
    rows[1]!.missing_seed_guards = ["reparse-check"];
    rows[1]!.present_guards = ["client-impersonation", "no-reparse-open"];
    rows[1]!.lexical_parameter_sink_hint = [];
    const run = await runResearch(
      new WindowsVariantResearchAdapter(async () => execution(result)),
      target,
      { artifactRoot: join(root, "artifacts") },
    );
    expect(run.candidates).toHaveLength(2);
    expect(run.findings).toHaveLength(0);
    expect(run.candidates[0]?.payload.row.matched_sinks).toEqual(["file-mutate"]);
    expect(run.candidates[1]?.payload.row.present_guards).toEqual([
      "client-impersonation",
      "no-reparse-open",
    ]);
  });

  it("accepts opaque decorated PDB symbols without putting them raw in the locator", async () => {
    const { target, result, root } = setup();
    const row = (result.candidates as Record<string, unknown>[])[0]!;
    row.function = "?operator new@@YAPEAX_K@Z `template<int, 4>`";
    const run = await runResearch(
      new WindowsVariantResearchAdapter(async () => execution(result)),
      target,
      { artifactRoot: join(root, "artifacts") },
    );
    expect(run.candidates).toHaveLength(2);
    expect(run.candidates[0]?.payload.row.function).toBe(row.function);
    expect(run.candidates[0]?.location).toBe(`${target.location}#0x1100`);
    expect(run.candidates[0]?.location).not.toContain(String(row.function));
  });

  it("returns on its own timeout and aborts a runner that never settles", async () => {
    vi.useFakeTimers();
    try {
      const { target, root } = setup();
      target.config.timeoutMs = 100;
      let observedSignal: AbortSignal | undefined;
      const runner = vi.fn((request: { signal?: AbortSignal }) => {
        observedSignal = request.signal;
        return new Promise<WindowsVariantRankExecution>(() => {});
      });
      const pending = runResearch(
        new WindowsVariantResearchAdapter(runner),
        target,
        { artifactRoot: join(root, "artifacts") },
      );
      await vi.advanceTimersByTimeAsync(101);
      const run = await pending;
      expect(run.candidates).toHaveLength(0);
      expect(observedSignal?.aborted).toBe(true);
      expect(run.evidence).toEqual(expect.arrayContaining([
        expect.objectContaining({ stage: "discover", status: "failed" }),
      ]));
    } finally {
      vi.useRealTimers();
    }
  });

  it.each(["timeout", "external abort"] as const)(
    "rejects the %s boundary before an abort-aware runner can report clean success",
    async (boundary) => {
      vi.useFakeTimers();
      try {
        const { target, result, root } = setup();
        target.config.timeoutMs = 100;
        const controller = new AbortController();
        const runner = vi.fn((request: { signal?: AbortSignal }) => new Promise<WindowsVariantRankExecution>((resolve) => {
          request.signal?.addEventListener("abort", () => resolve(execution(result)), { once: true });
        }));
        const pending = runResearch(
          new WindowsVariantResearchAdapter(runner),
          target,
          {
            artifactRoot: join(root, "artifacts"),
            signal: controller.signal,
          },
        );
        if (boundary === "timeout") await vi.advanceTimersByTimeAsync(101);
        else controller.abort(new Error("operator abort"));
        const run = await pending;
        expect(run.candidates).toHaveLength(0);
        expect(run.evidence).toEqual(expect.arrayContaining([
          expect.objectContaining({ stage: "discover", status: "failed" }),
        ]));
      } finally {
        vi.useRealTimers();
      }
    },
  );
});
