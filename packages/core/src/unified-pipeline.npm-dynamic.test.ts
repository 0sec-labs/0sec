import { describe, it, expect, afterEach, vi } from "vitest";
import {
  shouldRunNpmDynamicDiscovery,
  runNpmDynamicDiscoveryStage,
} from "./unified-pipeline.js";
import type { NpmPackageRunner } from "./stages/npm-detectors/sandbox-probe.js";
import type { DetectorRunOutcome } from "./stages/npm-detectors/base.js";

const ENV_KEY = "0SEC_NPM_DYNAMIC_DISCOVERY";

afterEach(() => {
  delete process.env[ENV_KEY];
});

describe("shouldRunNpmDynamicDiscovery (opt-in gate)", () => {
  const npmPrepared = { packageEcosystem: "npm" as const, resolvedType: "source-code" as const, packageName: "es-toolkit" };

  it("is OFF by default even for an npm target", () => {
    expect(shouldRunNpmDynamicDiscovery({}, npmPrepared)).toBe(false);
  });

  it("is ON when the flag is set AND the target is an npm package-source review", () => {
    expect(shouldRunNpmDynamicDiscovery({ npmDynamicDiscovery: true }, npmPrepared)).toBe(true);
  });

  it("is ON for a plain npm-package audit target", () => {
    expect(
      shouldRunNpmDynamicDiscovery(
        { npmDynamicDiscovery: true },
        { packageEcosystem: undefined, resolvedType: "npm-package", packageName: "lodash" },
      ),
    ).toBe(true);
  });

  it("stays OFF for a non-npm target even with the flag set (cost discipline)", () => {
    expect(
      shouldRunNpmDynamicDiscovery(
        { npmDynamicDiscovery: true },
        { packageEcosystem: "pypi", resolvedType: "source-code", packageName: "requests" },
      ),
    ).toBe(false);
    expect(
      shouldRunNpmDynamicDiscovery(
        { npmDynamicDiscovery: true },
        { packageEcosystem: undefined, resolvedType: "source-code", packageName: undefined },
      ),
    ).toBe(false);
  });

  it("honors the 0SEC_NPM_DYNAMIC_DISCOVERY env toggle (cloud config)", () => {
    expect(shouldRunNpmDynamicDiscovery({}, npmPrepared)).toBe(false);
    process.env[ENV_KEY] = "1";
    expect(shouldRunNpmDynamicDiscovery({}, npmPrepared)).toBe(true);
    process.env[ENV_KEY] = "false";
    expect(shouldRunNpmDynamicDiscovery({}, npmPrepared)).toBe(false);
  });
});

describe("runNpmDynamicDiscoveryStage (invokes the injected runner, emits findings)", () => {
  function outcome(): DetectorRunOutcome {
    return {
      detectorId: "sspp-fuzz",
      ran: true,
      candidates: 1,
      leads: [
        {
          detectorId: "sspp-fuzz",
          candidateId: "merge@es-toolkit",
          confirmation: {
            confirmed: true,
            severity: "high",
            source: "es-toolkit.merge",
            evidence: { observation: "Object.prototype polluted at runtime" },
          },
          dedup: { novel: true, source: "novel", advisories: [] },
        },
      ],
      warnings: [],
    };
  }

  it("invokes the runner for the target package and returns canonical findings", async () => {
    const runner: NpmPackageRunner = vi.fn(async () => ({ outcomes: [outcome()], warnings: [] }));
    const { findings, warnings } = await runNpmDynamicDiscoveryStage({
      packageName: "es-toolkit",
      packageVersion: "1.39.0",
      runner,
    });

    expect(runner).toHaveBeenCalledOnce();
    expect(runner).toHaveBeenCalledWith({ name: "es-toolkit", version: "1.39.0" }, expect.any(Array));
    expect(findings).toHaveLength(1);
    expect(findings[0].title).toContain("es-toolkit");
    expect(findings[0].status).toBe("discovered");
    expect(warnings).toHaveLength(0);
  });

  it("a runner fault becomes a warning, not a thrown error (can't abort the scan)", async () => {
    const runner: NpmPackageRunner = async () => {
      throw new Error("sandbox exploded");
    };
    const { findings, warnings } = await runNpmDynamicDiscoveryStage({ packageName: "pkg", runner });
    expect(findings).toHaveLength(0);
    expect(warnings.join(" ")).toContain("sandbox exploded");
  });
});
