import { describe, expect, it } from "vitest";
import {
  normalizeResearchNovelty,
  researchDisclosureReady,
  researchGradeAtLeast,
  researchLpeDisclosureReady,
  researchPlatformLpeDisclosureReady,
  researchWindowsLpeDisclosureReady,
  researchWindowsTokenTransitionProven,
  researchZeroCapProven,
  type ResearchEvidenceEnvelope,
} from "./research-evidence.js";

function envelope(): ResearchEvidenceEnvelope {
  return {
    schemaVersion: 1,
    evidenceId: "e-1",
    findingId: "f-1",
    target: { kind: "source", locator: "/src" },
    provenance: { producer: "test", runId: "r-1", startedAt: "2026-07-11T00:00:00Z" },
    grade: "reproduced",
    novelty: { state: "novel", sources: ["git"], scanned: 12 },
    artifacts: [],
  };
}

describe("research evidence promotion", () => {
  it("keeps proof strength monotone", () => {
    expect(researchGradeAtLeast("impact-proven", "reproduced")).toBe(true);
    expect(researchGradeAtLeast("observed", "reproduced")).toBe(false);
  });

  it("fails novelty closed when no source records were actually checked", () => {
    expect(normalizeResearchNovelty({ state: "novel", sources: [], scanned: 0 }).state).toBe("unchecked");
  });

  it("requires both reproduction and a real novelty receipt for disclosure readiness", () => {
    expect(researchDisclosureReady(envelope())).toBe(true);
    expect(researchDisclosureReady({ ...envelope(), grade: "observed" })).toBe(false);
    expect(researchDisclosureReady({ ...envelope(), novelty: { state: "novel", sources: [], scanned: 0 } })).toBe(false);
  });

  it("requires runtime-attested non-root uid and zero capabilities for zero-cap proof", () => {
    const proven = {
      ...envelope(),
      executionContext: {
        privilege: "zero-cap" as const,
        basis: "runtime-attested" as const,
        realUid: 65534,
        effectiveUid: 65534,
        effectiveCapabilities: "0000000000000000",
        noNewPrivileges: true,
        attestationArtifact: { ref: "attestation.json", sha256: "a".repeat(64) },
      },
    };
    expect(researchZeroCapProven(proven)).toBe(true);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, basis: "campaign-config" } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, realUid: 0 } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, effectiveUid: 0 } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, effectiveCapabilities: "0000000000002000" } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, effectiveCapabilities: "0" } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, noNewPrivileges: false } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, realUid: Number.POSITIVE_INFINITY } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: { ...proven.executionContext, attestationArtifact: undefined } })).toBe(false);
    expect(researchZeroCapProven({ ...proven, grade: "candidate" })).toBe(false);
    expect(researchZeroCapProven({ ...proven, executionContext: undefined })).toBe(false);
    expect(researchLpeDisclosureReady(proven)).toBe(true);
    expect(researchPlatformLpeDisclosureReady(proven, "linux")).toBe(false);
    expect(researchPlatformLpeDisclosureReady({
      ...proven,
      executionContext: { ...proven.executionContext, platform: "linux" },
    }, "linux")).toBe(true);
    expect(researchZeroCapProven({
      ...proven,
      executionContext: { ...proven.executionContext, platform: "windows" },
    })).toBe(false);
    expect(researchLpeDisclosureReady({ ...proven, novelty: { state: "unchecked" } })).toBe(false);
  });

  it("requires a retained, build-bound Windows token transition and human reporting gate", () => {
    const attestationSha = "a".repeat(64);
    const receiptSha = "b".repeat(64);
    const windows: ResearchEvidenceEnvelope = {
      ...envelope(),
      target: {
        kind: "windows.lpe",
        locator: "authorized-canary-worker",
        buildId: "28020.1.amd64fre.rs_prerelease",
      },
      executionContext: {
        platform: "windows",
        privilege: "windows-restricted",
        basis: "runtime-attested",
        campaignId: "campaign-1",
        configDigest: "c".repeat(64),
        attestationArtifact: { ref: "token-transition.json", sha256: attestationSha },
        windowsTokenTransition: {
          buildLabEx: "28020.1.amd64fre.rs_prerelease",
          campaignId: "campaign-1",
          workerId: "canary-worker-1",
          startingContext: "standard-user",
          finishingPrincipal: "local-system",
          startToken: {
            tokenId: "start_token_00001",
            userSid: "S-1-5-21-1000",
            integrityRid: 0x2000,
            elevationType: "default",
            elevated: false,
            adminGroup: "absent",
            appContainer: false,
            restrictedSidCount: 0,
            enabledPrivileges: ["SeChangeNotifyPrivilege"],
          },
          finishToken: {
            tokenId: "finish_token_0001",
            userSid: "S-1-5-18",
            integrityRid: 0x4000,
            elevationType: "full",
            elevated: true,
            adminGroup: "enabled",
            appContainer: false,
            restrictedSidCount: 0,
            enabledPrivileges: ["SeDebugPrivilege"],
          },
          scopeManifestSha256: "f".repeat(64),
          receiptArtifact: { ref: "receipt.json", sha256: receiptSha },
          targetTrials: 2,
          cleanControls: 2,
          claimEligible: true,
          fixture: false,
        },
      },
      reportingPolicy: {
        automaticDisclosure: false,
        humanReviewRequired: true,
        benchmarkCase: false,
      },
      artifacts: [
        { kind: "windows_token_transition", path: "token-transition.json", sha256: attestationSha },
        { kind: "windows_evidence_receipt", path: "receipt.json", sha256: receiptSha },
      ],
    };
    expect(researchWindowsTokenTransitionProven(windows)).toBe(true);
    expect(researchWindowsLpeDisclosureReady(windows)).toBe(true);
    expect(researchPlatformLpeDisclosureReady(windows, "windows")).toBe(true);
    expect(researchPlatformLpeDisclosureReady(windows, "linux")).toBe(false);

    const mutate = (
      change: (copy: ResearchEvidenceEnvelope) => void,
    ): ResearchEvidenceEnvelope => {
      const copy = structuredClone(windows);
      change(copy);
      return copy;
    };
    expect(researchWindowsTokenTransitionProven(mutate((copy) => {
      copy.executionContext!.basis = "declared";
    }))).toBe(false);
    expect(researchWindowsTokenTransitionProven(mutate((copy) => {
      copy.target.buildId = "different-build";
    }))).toBe(false);
    expect(researchWindowsTokenTransitionProven(mutate((copy) => {
      copy.executionContext!.windowsTokenTransition!.startToken.tokenId = "finish_token_0001";
    }))).toBe(false);
    expect(researchWindowsTokenTransitionProven(mutate((copy) => {
      copy.executionContext!.windowsTokenTransition!.targetTrials = 1;
    }))).toBe(false);
    expect(researchWindowsTokenTransitionProven(mutate((copy) => {
      copy.executionContext!.windowsTokenTransition!.cleanControls = 1;
    }))).toBe(false);
    expect(researchWindowsTokenTransitionProven(mutate((copy) => {
      copy.artifacts[0]!.sha256 = "f".repeat(64);
    }))).toBe(false);
    expect(researchWindowsTokenTransitionProven(mutate((copy) => {
      copy.artifacts.push({ ...copy.artifacts[0]! });
    }))).toBe(false);
    expect(researchWindowsTokenTransitionProven(mutate((copy) => {
      copy.executionContext!.windowsTokenTransition!.claimEligible = false;
    }))).toBe(false);
    expect(researchWindowsTokenTransitionProven(mutate((copy) => {
      copy.executionContext!.windowsTokenTransition!.fixture = true;
    }))).toBe(false);
    expect(researchWindowsTokenTransitionProven(mutate((copy) => {
      copy.executionContext!.windowsTokenTransition!.startToken.enabledPrivileges = ["SeImpersonatePrivilege"];
    }))).toBe(false);
    expect(researchWindowsTokenTransitionProven(mutate((copy) => {
      copy.executionContext!.windowsTokenTransition!.startToken.elevated = true;
    }))).toBe(false);
    expect(researchWindowsLpeDisclosureReady(mutate((copy) => {
      copy.reportingPolicy!.benchmarkCase = true;
    }))).toBe(false);
    expect(researchWindowsLpeDisclosureReady(mutate((copy) => {
      copy.reportingPolicy = undefined;
    }))).toBe(false);
    expect(researchWindowsLpeDisclosureReady(mutate((copy) => {
      copy.reportingPolicy = {
        ...copy.reportingPolicy!,
        automaticDisclosure: true as false,
      };
    }))).toBe(false);
    expect(researchWindowsLpeDisclosureReady(mutate((copy) => {
      copy.novelty = { state: "duplicate", sources: ["msrc"], scanned: 1 };
    }))).toBe(false);
  });

  it("validates Windows starting and finishing integrity semantics", () => {
    const base = envelope();
    const transition = {
      buildLabEx: "canary-build",
      campaignId: "campaign-1",
      workerId: "worker-1",
      startingContext: "lpac" as const,
      finishingPrincipal: "elevated-user" as const,
      startToken: {
        tokenId: "start_token_00001",
        userSid: "S-1-5-21-1000",
        integrityRid: 0x1000,
        elevationType: "limited" as const,
        elevated: false,
        adminGroup: "deny-only" as const,
        appContainer: true,
        restrictedSidCount: 1,
        enabledPrivileges: [] as string[],
      },
      finishToken: {
        tokenId: "finish_token_0001",
        userSid: "S-1-5-21-1000",
        integrityRid: 0x3000,
        elevationType: "full" as const,
        elevated: true,
        adminGroup: "enabled" as const,
        appContainer: false,
        restrictedSidCount: 0,
        enabledPrivileges: ["SeDebugPrivilege"],
      },
      scopeManifestSha256: "6".repeat(64),
      receiptArtifact: { ref: "receipt.json", sha256: "3".repeat(64) },
      targetTrials: 2,
      cleanControls: 2,
      claimEligible: true,
      fixture: false,
    };
    const windows: ResearchEvidenceEnvelope = {
      ...base,
      target: { kind: "windows.lpe", locator: "worker", buildId: "canary-build" },
      executionContext: {
        platform: "windows",
        privilege: "windows-restricted",
        basis: "runtime-attested",
        campaignId: "campaign-1",
        configDigest: "4".repeat(64),
        attestationArtifact: { ref: "transition.json", sha256: "5".repeat(64) },
        windowsTokenTransition: transition,
      },
      artifacts: [
        { kind: "transition", path: "transition.json", sha256: "5".repeat(64) },
        { kind: "receipt", path: "receipt.json", sha256: "3".repeat(64) },
      ],
    };
    expect(researchWindowsTokenTransitionProven(windows)).toBe(true);
    expect(researchWindowsTokenTransitionProven({
      ...windows,
      executionContext: {
        ...windows.executionContext!,
        windowsTokenTransition: {
          ...transition,
          startToken: { ...transition.startToken, integrityRid: 0x2200 },
        },
      },
    })).toBe(false);
    expect(researchWindowsTokenTransitionProven({
      ...windows,
      executionContext: {
        ...windows.executionContext!,
        windowsTokenTransition: {
          ...transition,
          finishingPrincipal: "local-system",
          finishToken: { ...transition.finishToken, userSid: "S-1-5-18", integrityRid: 0x3000 },
        },
      },
    })).toBe(false);
  });
});
