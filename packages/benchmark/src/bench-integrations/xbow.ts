import { randomBytes } from "node:crypto";

import {
  createAgenticScanAdapter,
  ObjectiveOracle,
  objectiveOracleEvaluatorAttestation,
  parseManifest,
  withVariantFeatureFlags,
  type BenchIntegration,
  type BenchManifest,
  type BenchScan,
  type BenchVariant,
  type TargetProvisioner,
} from "@0sec/core";
import {
  buildXbowChallenge,
  loadXbowChallenges,
  startXbowChallenge,
  stopXbowChallenge,
  type XbowChallenge,
} from "../xbow-runner.js";

const XBOW_PLACEHOLDER_FLAG = "FLAG{BENCH_PLACEHOLDER}";

export interface XbowLifecycle {
  build(challenge: XbowChallenge, flag: string): boolean;
  start(challenge: XbowChallenge): number | null;
  stop(challenge: XbowChallenge): void;
}

const DEFAULT_LIFECYCLE: XbowLifecycle = {
  build: buildXbowChallenge,
  start: startXbowChallenge,
  stop: stopXbowChallenge,
};

function isXbowChallenge(value: unknown): value is XbowChallenge {
  return (
    value !== null &&
    typeof value === "object" &&
    "id" in value &&
    "path" in value &&
    typeof value.id === "string" &&
    typeof value.path === "string"
  );
}

export interface CreateXbowManifestOptions {
  id?: string;
  corpusRoot?: string;
}

/** Convert the pinned XBOW task metadata into the canonical bench manifest. */
export function createXbowManifest(
  challenges: readonly XbowChallenge[],
  opts: CreateXbowManifestOptions = {},
): BenchManifest {
  return parseManifest({
    id: opts.id ?? "xbow-v1",
    ...(opts.corpusRoot ? { corpusRoot: opts.corpusRoot } : {}),
    cases: challenges.map((challenge) => ({
      id: challenge.id,
      name: challenge.name,
      target: {
        kind: "web",
        composeDir: challenge.path,
        ...(challenge.description ? { hint: challenge.description } : {}),
      },
      // The provisioner replaces this placeholder with a fresh per-attempt
      // flag before building the target. The manifest stays portable/private.
      objective: { type: "flag-capture", marker: XBOW_PLACEHOLDER_FLAG },
      tags: ["xbow", `level-${challenge.level}`, ...challenge.tags],
    })),
  });
}

/** Load a local XBOW checkout and project it into the canonical manifest. */
export function createXbowManifestFromPath(
  xbowPath?: string,
  opts: CreateXbowManifestOptions = {},
): BenchManifest {
  return createXbowManifest(loadXbowChallenges(xbowPath), opts);
}

export interface XbowBenchIntegrationOptions {
  /** Existing XBOW checkout; ignored when `challenges` is supplied. */
  xbowPath?: string;
  /** Test seam or caller-supplied preloaded challenge metadata. */
  challenges?: readonly XbowChallenge[];
  lifecycle?: XbowLifecycle;
  /** Injected scan adapter for contract tests or embedding applications. */
  createScan?: (variant: Readonly<BenchVariant>) => BenchScan;
  /** Supply the source tree to the agent for white-box runs. Default false. */
  whiteBox?: boolean;
  /** Immutable integration version written into every execution receipt. */
  version?: string;
}

/**
 * Integrates XBOW's build/reset lifecycle with the single core bench runner.
 * It owns only suite-specific lifecycle behavior; scoring and tournament logic
 * remain in @0sec/core/bench.
 */
export function createXbowBenchIntegration(
  opts: XbowBenchIntegrationOptions = {},
): BenchIntegration {
  const challenges = opts.challenges ?? loadXbowChallenges(opts.xbowPath);
  const challengeByCaseId = new Map(challenges.map((challenge) => [challenge.id, challenge]));
  const lifecycle = opts.lifecycle ?? DEFAULT_LIFECYCLE;

  const provisioner: TargetProvisioner = {
    async up(c) {
      if (c.target.kind !== "web") {
        throw new Error(`XBOW integration only provisions web cases; got ${c.target.kind} for ${c.id}`);
      }
      const challenge = challengeByCaseId.get(c.id);
      if (!challenge) throw new Error(`XBOW integration has no challenge for case ${c.id}`);
      const flag = `FLAG{${randomBytes(12).toString("hex")}}`;
      if (!lifecycle.build(challenge, flag)) {
        throw new Error(`XBOW Docker build failed for ${challenge.id}`);
      }
      const port = lifecycle.start(challenge);
      if (!port) {
        lifecycle.stop(challenge);
        throw new Error(`XBOW Docker start failed or no port for ${challenge.id}`);
      }
      return {
        target: `http://localhost:${port}`,
        objective: { type: "flag-capture", marker: flag },
        handle: challenge,
      };
    },
    async down(_c, provisioned) {
      if (isXbowChallenge(provisioned.handle)) lifecycle.stop(provisioned.handle);
    },
  };

  return {
    id: "xbow",
    version: opts.version ?? "1",
    evaluatorAttestation: objectiveOracleEvaluatorAttestation,
    createExecution(variant: Readonly<BenchVariant>) {
      const scan = opts.createScan?.(variant) ?? createAgenticScanAdapter({
        runtime: variant.runtime,
        model: variant.model,
        costCeilingUsdPerAttempt: variant.costCeilingUsdPerAttempt,
        repoPathForCase: opts.whiteBox
          ? (c) => challengeByCaseId.get(c.id)?.path
          : undefined,
      });
      return {
        provisioner,
        oracle: new ObjectiveOracle(),
        executionMetadata: {
          harnessId: variant.harnessId ?? "0sec-agentic",
          ...(variant.model ? { model: variant.model } : {}),
          ...(variant.runtime ? { runtime: variant.runtime } : {}),
        },
        scan: async (input) =>
          withVariantFeatureFlags(variant.featureFlags, async () => scan(input)),
      };
    },
  };
}
