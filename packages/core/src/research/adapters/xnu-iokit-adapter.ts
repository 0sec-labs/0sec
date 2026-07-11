import {
  TartVmLane,
  enumerateTargetModelFromKext,
  generateInputsForSelector,
  makeRng,
  type EnumerateOptions,
  type FuzzInput,
  type ShardRunResult,
  type ShardSpec,
  type TargetModel,
  type VmLaneConfig,
} from "../../xnu-fuzz/index.js";
import type {
  ResearchCandidate,
  ResearchContext,
  ResearchEvidence,
  ResearchStageResult,
  ResearchTarget,
  TargetResearchAdapter,
} from "../target-research-adapter.js";

export interface XnuIokitTargetConfig {
  model?: TargetModel;
  kextPath?: string;
  enumerate?: EnumerateOptions;
  vm: VmLaneConfig;
  seed?: number;
  privilege?: "sandbox" | "root";
}
export type XnuIokitTarget = ResearchTarget<"xnu.iokit-fuzz", XnuIokitTargetConfig>;
export type XnuSelectorCandidate = ResearchCandidate<{
  model: TargetModel;
  userClient: TargetModel["userClients"][number];
  selector: TargetModel["userClients"][number]["selectors"][number];
}>;
export interface XnuHarnessPlan {
  candidateId: string;
  shard: ShardSpec;
  programs: FuzzInput[][];
}
export interface XnuExecution { candidateId: string; result: ShardRunResult }

interface XnuLane {
  preflight(): { ok: boolean; reason?: string };
  runShard(shard: ShardSpec, programs: FuzzInput[][]): ShardRunResult;
}

export class XnuIokitResearchAdapter
  implements TargetResearchAdapter<XnuIokitTarget, XnuSelectorCandidate, XnuHarnessPlan, XnuExecution>
{
  readonly kind = "xnu.iokit-fuzz" as const;
  constructor(private readonly laneFactory: (config: VmLaneConfig) => XnuLane = (config) => new TartVmLane(config)) {}

  async discover(target: XnuIokitTarget): Promise<ResearchStageResult<XnuSelectorCandidate>> {
    let model = target.config.model;
    if (!model && target.config.kextPath && target.config.enumerate) {
      model = enumerateTargetModelFromKext(target.config.kextPath, target.config.enumerate);
    }
    if (!model) {
      return {
        items: [],
        evidence: [{ stage: "discover", status: "failed", summary: "XNU target needs a prebuilt model or kextPath plus enumeration options" }],
      };
    }
    const items = model.userClients.flatMap((userClient) => userClient.selectors.map((selector) => ({
      id: `${target.id}:${userClient.class}:${selector.sel}`,
      title: `${userClient.class} external method selector ${selector.sel}`,
      location: `${model!.source}:${userClient.table}[${selector.sel}]`,
      hypothesis: selector.hasEntitlementCheck
        ? "selector is entitlement-gated; static fuzz candidate only"
        : "selector input contract can be exercised through the IOKit opener",
      payload: { model: model!, userClient, selector },
    })));
    items.sort((a, b) => {
      const av = a.payload.selector.structInSize === 0xffffffff ? 1 : 0;
      const bv = b.payload.selector.structInSize === 0xffffffff ? 1 : 0;
      return bv - av;
    });
    return {
      items,
      evidence: [{ stage: "discover", status: items.length > 0 ? "passed" : "inconclusive", summary: `enumerated ${items.length} IOKit selector candidate(s)`, data: model }],
    };
  }

  async assessReachability(
    _target: XnuIokitTarget,
    candidates: XnuSelectorCandidate[],
  ): Promise<ResearchStageResult<XnuSelectorCandidate>> {
    return {
      items: candidates,
      evidence: candidates.map((candidate) => ({
        stage: "reachability",
        status: candidate.payload.selector.hasEntitlementCheck || !candidate.payload.userClient.matchingService
          ? "inconclusive"
          : "passed",
        summary: candidate.payload.selector.hasEntitlementCheck
          ? "dispatch entry carries an entitlement check"
          : candidate.payload.userClient.matchingService
            ? `matching service known: ${candidate.payload.userClient.matchingService}`
            : "matching service is unknown; static reachability only",
      })),
    };
  }

  async buildHarness(
    target: XnuIokitTarget,
    candidates: XnuSelectorCandidate[],
  ): Promise<ResearchStageResult<XnuHarnessPlan>> {
    const rng = makeRng(target.config.seed ?? 0x50574e4b);
    const items = candidates.map((candidate, shardId) => ({
      candidateId: candidate.id,
      shard: { shardId, selectors: [candidate.payload.selector.sel], privilege: target.config.privilege ?? "sandbox" },
      programs: generateInputsForSelector(candidate.payload.selector, rng).map((input) => [input]),
    }));
    return {
      items,
      evidence: [{ stage: "harness", status: items.length > 0 ? "passed" : "skipped", summary: `generated deterministic programs for ${items.length} selector shard(s)`, data: items }],
    };
  }

  async execute(
    target: XnuIokitTarget,
    harnesses: XnuHarnessPlan[],
    _ctx: ResearchContext,
  ): Promise<ResearchStageResult<XnuExecution>> {
    const lane = this.laneFactory(target.config.vm);
    const preflight = lane.preflight();
    if (!preflight.ok) {
      return {
        items: [],
        evidence: [{ stage: "execute", status: "inconclusive", summary: preflight.reason ?? "XNU VM preflight failed" }],
        warnings: [preflight.reason ?? "XNU VM preflight failed"],
      };
    }
    const items = harnesses.map((harness) => ({ candidateId: harness.candidateId, result: lane.runShard(harness.shard, harness.programs) }));
    const evidence: ResearchEvidence[] = items.map((item) => ({
      stage: "execute",
      status: item.result.panic.panicked ? "passed" : "inconclusive",
      summary: item.result.panic.panicked
        ? `VM produced an unattributed panic after ${item.result.programsRun} program(s)`
        : `no panic observed after ${item.result.programsRun} program(s); absence is not proven`,
      data: item.result,
    }));
    return { items, evidence };
  }

  async verify(
    _target: XnuIokitTarget,
    input: { executions?: XnuExecution[] },
  ): Promise<ResearchStageResult<never>> {
    const panics = (input.executions ?? []).filter((execution) => execution.result.panic.panicked);
    return {
      items: [],
      evidence: [{
        stage: "verify",
        status: "inconclusive",
        summary: panics.length > 0
          ? `${panics.length} panic observation(s) require signature normalization, minimization and repeated fresh-VM reproduction`
          : "XNU verification has no repeated attributed panic proof",
        data: panics,
      }],
    };
  }
}
