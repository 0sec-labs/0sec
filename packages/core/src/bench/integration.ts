/**
 * Bench integration registry.
 *
 * The bench runner owns one execution protocol. Integrations only provide the
 * suite-/harness-specific edges: scan adapter, target provisioner, and oracle.
 * That keeps XBOW, CyberGym, and future external agents out of the generic
 * runner/scorecard/ledger path.
 */

import type {
  BenchEvaluatorAttestation,
  BenchExecutionMetadata,
  BenchOracle,
} from "./oracle.js";
import type { BenchScan, TargetProvisioner } from "./runner.js";
import type { BenchVariant } from "./variant.js";

export interface BenchExecution {
  scan: BenchScan;
  provisioner?: TargetProvisioner;
  oracle?: BenchOracle;
  /** Adapter-supplied actual runtime metadata; registry identity is authoritative. */
  executionMetadata?: BenchExecutionMetadata;
}

export interface BenchIntegration {
  /** Stable extension id selected by the CLI or embedding application. */
  id: string;
  /** Immutable adapter implementation/version identifier. */
  version: string;
  /** Hashes the exact oracle code and fixed evaluator configuration. */
  evaluatorAttestation(): BenchEvaluatorAttestation;
  /** Create the suite/harness edges for one frozen benchmark variant. */
  createExecution(variant: Readonly<BenchVariant>): BenchExecution;
}

export type VariantExecutionFactory = (variant: Readonly<BenchVariant>) => BenchExecution;

const INTEGRATION_ID = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/**
 * Validated registry for integrations supplied by core, @0sec/benchmark, or a
 * host application. It deliberately has no module-loading behavior: callers
 * register constructed integrations, keeping execution provenance explicit.
 */
export class BenchIntegrationRegistry {
  private readonly integrations: Map<string, BenchIntegration>;

  constructor(integrations: readonly BenchIntegration[]) {
    this.integrations = new Map();
    for (const integration of integrations) {
      if (!INTEGRATION_ID.test(integration.id)) {
        throw new Error(`bench integration id must be filesystem-safe: ${integration.id}`);
      }
      if (!integration.version.trim()) {
        throw new Error(`bench integration "${integration.id}" must declare a version`);
      }
      if (typeof integration.evaluatorAttestation !== "function") {
        throw new Error(`bench integration "${integration.id}" must declare an evaluator attestation`);
      }
      if (this.integrations.has(integration.id)) {
        throw new Error(`duplicate bench integration id: ${integration.id}`);
      }
      this.integrations.set(integration.id, integration);
    }
  }

  resolve(id: string): BenchIntegration {
    const integration = this.integrations.get(id);
    if (!integration) throw new Error(`unknown bench integration: ${id}`);
    return integration;
  }

  createExecution(id: string, variant: Readonly<BenchVariant>): BenchExecution {
    const integration = this.resolve(id);
    const execution = integration.createExecution(variant);
    if (typeof execution.scan !== "function") {
      throw new Error(`bench integration "${id}" did not return a scan adapter`);
    }
    return {
      ...execution,
      executionMetadata: {
        ...execution.executionMetadata,
        ...(variant.harnessId ? { harnessId: variant.harnessId } : {}),
        integrationId: integration.id,
        integrationVersion: integration.version,
      },
    };
  }
}

export function createBenchIntegrationRegistry(
  integrations: readonly BenchIntegration[],
): BenchIntegrationRegistry {
  return new BenchIntegrationRegistry(integrations);
}

export function createVariantExecutionFactory(
  registry: BenchIntegrationRegistry,
  integrationId: string,
): VariantExecutionFactory {
  return (variant) => registry.createExecution(integrationId, variant);
}
