/** Default @0sec/core integration for web and source-audit manifests. */

import { createDockerWebProvisioner } from "./adapters.js";
import type { BenchIntegration } from "./integration.js";
import { ObjectiveOracle, objectiveOracleEvaluatorAttestation } from "./oracle.js";
import { createDefaultVariantScan } from "./variant.js";

export interface CoreBenchIntegrationOptions {
  corpusRoot?: string;
  webTimeoutMs?: number;
  dbPath?: string;
}

/**
 * Default integration expressed through the same registry contract as XBOW and
 * CyberGym. This is the clean cutover point for callers that previously wired
 * createDefaultVariantScan plus Docker directly.
 */
export function createCoreBenchIntegration(
  opts: CoreBenchIntegrationOptions = {},
): BenchIntegration {
  return {
    id: "core",
    version: "1",
    evaluatorAttestation: objectiveOracleEvaluatorAttestation,
    createExecution(variant) {
      return {
        provisioner: createDockerWebProvisioner(opts.corpusRoot),
        oracle: new ObjectiveOracle(),
        executionMetadata: {
          harnessId: variant.harnessId ?? "0sec-agentic",
          ...(variant.model ? { model: variant.model } : {}),
          ...(variant.runtime ? { runtime: variant.runtime } : {}),
        },
        scan: createDefaultVariantScan(variant, {
          webTimeoutMs: opts.webTimeoutMs,
          dbPath: opts.dbPath,
        }),
      };
    },
  };
}
