import type { SemgrepFinding, NpmAuditFinding } from "@0sec/shared";
import type { ScanListener } from "./scanner.js";
import type { PrepareResult } from "./prepare.js";
import { runSelectedStaticScan } from "./shared-analysis.js";
import { runDependencyAuditForEcosystem } from "./package-ecosystems.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface StaticAnalysisResult {
  semgrepFindings: SemgrepFinding[];
  npmAuditFindings: NpmAuditFinding[];
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Run static analysis tools against a prepared target.
 *
 * - npm-package / pypi-package / cargo-package / oci-image: static scanner + dependency audit
 * - source-code: static scanner only
 * - url / web-app: skip (return empty results)
 */
export async function runStaticAnalysis(
  prepared: PrepareResult,
  emit: ScanListener,
): Promise<StaticAnalysisResult> {
  switch (prepared.targetType) {
    case "npm-package": {
      const semgrepFindings = runSelectedStaticScan(prepared.resolvedTarget, emit, {
        noGitIgnore: true,
      });
      const npmAuditFindings = prepared.packageInfo
        ? runDependencyAuditForEcosystem(prepared.packageInfo.ecosystem, prepared.packageInfo.tempDir, emit, prepared.packageInfo)
        : [];
      return { semgrepFindings, npmAuditFindings };
    }

    case "pypi-package": {
      const semgrepFindings = runSelectedStaticScan(prepared.resolvedTarget, emit, {
        noGitIgnore: true,
      });
      const npmAuditFindings = prepared.packageInfo
        ? runDependencyAuditForEcosystem(prepared.packageInfo.ecosystem, prepared.packageInfo.tempDir, emit, prepared.packageInfo)
        : [];
      return { semgrepFindings, npmAuditFindings };
    }

    case "cargo-package": {
      const semgrepFindings = runSelectedStaticScan(prepared.resolvedTarget, emit, {
        noGitIgnore: true,
      });
      const npmAuditFindings = prepared.packageInfo
        ? runDependencyAuditForEcosystem(prepared.packageInfo.ecosystem, prepared.packageInfo.tempDir, emit, prepared.packageInfo)
        : [];
      return { semgrepFindings, npmAuditFindings };
    }

    case "oci-image": {
      const semgrepFindings = runSelectedStaticScan(prepared.resolvedTarget, emit, {
        noGitIgnore: true,
      });
      const npmAuditFindings = prepared.packageInfo
        ? runDependencyAuditForEcosystem(prepared.packageInfo.ecosystem, prepared.packageInfo.tempDir, emit, prepared.packageInfo)
        : [];
      return { semgrepFindings, npmAuditFindings };
    }

    case "source-code": {
      const semgrepFindings = runSelectedStaticScan(prepared.resolvedTarget, emit);
      return { semgrepFindings, npmAuditFindings: [] };
    }

    case "url":
    case "web-app": {
      return { semgrepFindings: [], npmAuditFindings: [] };
    }

    default: {
      const _exhaustive: never = prepared.targetType;
      throw new Error(`Unknown target type: ${_exhaustive}`);
    }
  }
}
