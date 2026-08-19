import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  buildMsrcWindowsLpeInventory,
  buildMsrcWindowsLpeTrancheLock,
  validateMsrcWindowsLpeTrancheLock,
  type MsrcInventorySelection,
  type MsrcWindowsLpeInventory,
} from "./msrc-windows-lpe-inventory.js";

const selection: MsrcInventorySelection = {
  currentRelease: "2025-Mar",
  previousRelease: "2025-Feb",
  productName: "Windows 11 Version 24H2 for x64-based Systems",
  architecture: "x64",
  currentBuildNumber: "26100",
};

function remediation(kb: string, build: string, supersededKb: string): Record<string, unknown> {
  return {
    Description: { Value: kb },
    URL: `https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB${kb}`,
    Supercedence: supersededKb,
    ProductID: ["product-x64"],
    Type: 2,
    SubType: "Security Update",
    FixedBuild: build,
  };
}

function vulnerability(
  cve: string,
  vector: string,
  boundary: Record<string, unknown>,
): Record<string, unknown> {
  return {
    CVE: cve,
    Title: { Value: "Windows Contract Component Elevation of Privilege Vulnerability" },
    CWE: [{ ID: "CWE-000", Value: "Contract weakness" }],
    ProductStatuses: [{ ProductID: ["product-x64"], Type: 3 }],
    Remediations: [boundary],
    Threats: [
      { Description: { Value: "Elevation of Privilege" }, ProductID: ["product-x64"], Type: 0 },
      { Description: { Value: "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely" }, Type: 1 },
    ],
    CVSSScoreSets: [{ BaseScore: 7.8, Vector: vector, ProductID: ["product-x64"] }],
  };
}

function document(release: string, build: string, vulnerabilities: unknown[]): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    DocumentTracking: {
      Identification: { ID: { Value: release } },
      Version: "1.0",
      Status: 2,
      RevisionHistory: [{ Number: "1", Date: `${release.slice(0, 4)}-01-02T00:00:00`, Description: { Value: "contract" } }],
      InitialReleaseDate: `${release.slice(0, 4)}-01-01T00:00:00`,
      CurrentReleaseDate: `${release.slice(0, 4)}-01-02T00:00:00`,
    },
    ProductTree: {
      FullProductName: [
        {
          ProductID: "product-x64",
          CPE: `cpe:2.3:o:microsoft:windows_11_24H2:${build}:*:*:*:*:*:x64:*`,
          Value: "Windows 11 Version 24H2 for x64-based Systems",
        },
      ],
    },
    Vulnerability: vulnerabilities,
  }));
}

function fixtures(): { current: Uint8Array; previous: Uint8Array } {
  const previousBoundary = remediation("5051987", "10.0.26100.3194", "5050009");
  const current = document("2025-Mar", "10.0.26100.3476", [
    vulnerability("CVE-2025-24044", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", remediation("5053598", "10.0.26100.3476", "5051987")),
    vulnerability("CVE-2025-24045", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", remediation("5053598", "10.0.26100.3476", "5051987")),
    vulnerability("CVE-2025-24046", "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", remediation("5054000", "10.0.26100.3500", "5053999")),
  ]);
  const previous = document("2025-Feb", "10.0.26100.3194", [
    { CVE: "CVE-2025-20000", Remediations: [previousBoundary] },
  ]);
  return { current, previous };
}

function trancheFixtures(): [MsrcWindowsLpeInventory, MsrcWindowsLpeInventory] {
  const jan = document("2025-Jan", "10.0.26100.2894", [
    { CVE: "CVE-2025-10000", Remediations: [remediation("5050009", "10.0.26100.2894", "5048667")] },
  ]);
  const feb = document("2025-Feb", "10.0.26100.3194", Array.from({ length: 11 }, (_, index) =>
    vulnerability(`CVE-2025-${21182 + index}`, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      remediation("5051987", "10.0.26100.3194", "5050009"))));
  const mar = document("2025-Mar", "10.0.26100.3476", Array.from({ length: 9 }, (_, index) =>
    vulnerability(`CVE-2025-${24044 + index}`, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
      remediation("5053598", "10.0.26100.3476", "5051987"))));
  return [
    buildMsrcWindowsLpeInventory(feb, jan, { ...selection, currentRelease: "2025-Feb", previousRelease: "2025-Jan" }),
    buildMsrcWindowsLpeInventory(mar, feb, selection),
  ];
}

function canonicalTestJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalTestJson).join(",")}]`;
  const object = value as Record<string, unknown>;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalTestJson(object[key])}`).join(",")}}`;
}

function recommit(lock: Record<string, unknown>): void {
  const { lockId: ignored, ...body } = lock;
  void ignored;
  lock.lockId = `sha256:${createHash("sha256").update(canonicalTestJson(body)).digest("hex")}`;
}

describe("MSRC Windows LPE staging inventory", () => {
  it("stages a synthetic supersedence/fix candidate without promoting it", () => {
    const input = fixtures();
    const result = buildMsrcWindowsLpeInventory(input.current, input.previous, selection);
    expect(result.counts).toEqual({
      selected: 1,
      unresolvedPatchBoundary: 1,
      excludedBySafeLocalProfile: 1,
      distinctPatchBoundaries: 1,
      distinctTitles: 1,
      distinctCwes: 1,
    });
    expect(result.sourceDocuments.current.rawBytesSha256).toMatch(/^[a-f0-9]{64}$/);
    expect(result.cases[0]).toMatchObject({
      caseId: "msrc-cve-2025-24044-product-x64-x64",
      cve: "CVE-2025-24044",
      advisoryUrl: "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-24044",
      cvss: { attackVector: "local" },
      cwes: [{ id: "CWE-000", name: "Contract weakness" }],
      exploitability: { publiclyDisclosed: "no", exploited: "no" },
      supersededBoundaryCandidate: { release: "2025-Feb", kb: "5051987", build: "10.0.26100.3194", updateBuildRevision: 3194 },
      fixedBoundary: { release: "2025-Mar", kb: "5053598", build: "10.0.26100.3476", updateBuildRevision: 3476 },
      empiricalStatus: "unverified-candidate-boundary",
      promotion: { artifactBindingRequired: true, scopeBindingRequired: true, evaluatorLabelsRequired: true, ready: false },
      policy: { stagingOnly: true, benchmarkEligible: false, bountyClaimEligible: false, weaponization: false },
    });
    expect(JSON.stringify(result)).not.toMatch(/exploit_payload|poc_source|artifactSha256/);
    expect(result.policy).toEqual({ stagingOnly: true, containsExploitMaterial: false, promotableWithoutArtifactBindings: false });
  });

  it("is deterministic and binds both raw source documents", () => {
    const input = fixtures();
    const first = buildMsrcWindowsLpeInventory(input.current, input.previous, selection);
    const second = buildMsrcWindowsLpeInventory(input.current, input.previous, selection);
    expect(second).toEqual(first);
    const changedPrevious = new Uint8Array([...input.previous, 0x20]);
    expect(buildMsrcWindowsLpeInventory(input.current, changedPrevious, selection).sourceDocuments.previous.rawBytesSha256)
      .not.toBe(first.sourceDocuments.previous.rawBytesSha256);
  });

  it("fails closed on release, product, and conflicting boundary ambiguity", () => {
    const input = fixtures();
    expect(() => buildMsrcWindowsLpeInventory(input.current, input.previous, { ...selection, currentRelease: "2025-Apr" }))
      .toThrow(/release mismatch/);

    const wrongProduct = new TextEncoder().encode(new TextDecoder().decode(input.previous).replace(/product-x64/g, "changed-product-id"));
    expect(() => buildMsrcWindowsLpeInventory(input.current, wrongProduct, selection)).toThrow(/product ID changed/);

    const parsed = JSON.parse(new TextDecoder().decode(input.current)) as { Vulnerability: Array<{ Remediations: unknown[] }> };
    parsed.Vulnerability[0]!.Remediations.push(remediation("5053597", "10.0.26100.3477", "5051987"));
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection)).toThrow(/conflicting MSRC.*fixed boundaries/);
  });

  it("rejects architecture and build mismatches instead of relabeling them", () => {
    const input = fixtures();
    expect(() => buildMsrcWindowsLpeInventory(input.current, input.previous, { ...selection, architecture: "arm64" }))
      .toThrow(/CPE does not match arm64/);
    expect(() => buildMsrcWindowsLpeInventory(input.current, input.previous, { ...selection, currentBuildNumber: "22631" }))
      .toThrow(/does not match 22631/);
  });

  it("uses affected status and impact evidence rather than trusting the title", () => {
    const input = fixtures();
    const parsed = JSON.parse(new TextDecoder().decode(input.current)) as {
      Vulnerability: Array<{
        Title: { Value: string };
        ProductStatuses: Array<{ Type: number; ProductID: string[] }>;
        Threats: Array<{ Type: number; ProductID?: string[]; Description: { Value: string } }>;
      }>;
    };
    parsed.Vulnerability[0]!.Title.Value = "Opaque contract advisory title";
    const retitled = buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection);
    expect(retitled.cases.map((entry) => entry.cve)).toContain("CVE-2025-24044");

    parsed.Vulnerability[0]!.Threats.push({
      Type: 0,
      ProductID: ["product-x64"],
      Description: { Value: "Remote Code Execution" },
    });
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection))
      .toThrow(/conflicting impact/);
    parsed.Vulnerability[0]!.Threats.pop();

    parsed.Vulnerability[0]!.Threats.push({ Type: 0, ProductID: ["product-x64"], Description: {} as { Value: string } });
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection))
      .toThrow(/malformed impact/);
    parsed.Vulnerability[0]!.Threats.pop();

    parsed.Vulnerability[0]!.ProductStatuses.push({ Type: 4, ProductID: ["product-x64"] });
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection))
      .toThrow(/conflicting affected-status/);
  });

  it("excludes interactive, publicly disclosed, or known-exploited candidates", () => {
    const input = fixtures();
    const parsed = JSON.parse(new TextDecoder().decode(input.current)) as {
      Vulnerability: Array<{
        Threats: Array<{ Type: number; Description: { Value: string } }>;
        CVSSScoreSets: Array<{ Vector: string }>;
      }>;
    };
    const exploitability = parsed.Vulnerability[0]!.Threats.find((threat) => threat.Type === 1)!;
    exploitability.Description.Value = "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected";
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection))
      .toThrow(/selection produced no resolved/);

    exploitability.Description.Value = "Publicly Disclosed:Yes;Exploited:No;Latest Software Release:Exploitation Less Likely";
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection))
      .toThrow(/selection produced no resolved/);

    exploitability.Description.Value = "Publicly Disclosed:No;Exploited:No;Latest Software Release:Exploitation Less Likely";
    parsed.Vulnerability[0]!.CVSSScoreSets[0]!.Vector = "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H";
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection))
      .toThrow(/selection produced no resolved/);
  });

  it("fails closed on contradictory CVSS and exploitability records", () => {
    const input = fixtures();
    const parsed = JSON.parse(new TextDecoder().decode(input.current)) as {
      Vulnerability: Array<{
        CVSSScoreSets: unknown[];
        Threats: Array<{ Type: number; Description: { Value: string } }>;
      }>;
    };
    parsed.Vulnerability[0]!.CVSSScoreSets.push({
      BaseScore: 8.8,
      Vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H",
      ProductID: ["product-x64"],
    });
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection))
      .toThrow(/conflicting CVSS/);
    parsed.Vulnerability[0]!.CVSSScoreSets.pop();

    parsed.Vulnerability[0]!.Threats.push({
      Type: 1,
      Description: { Value: "Publicly Disclosed:No;Exploited:Yes;Latest Software Release:Exploitation Detected" },
    });
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection))
      .toThrow(/conflicting MSRC exploitability/);
    parsed.Vulnerability[0]!.Threats.pop();

    const exploitability = parsed.Vulnerability[0]!.Threats.find((threat) => threat.Type === 1)!;
    exploitability.Description.Value = "Publicly Disclosed:No;Exploited:No;Exploited:Yes";
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection))
      .toThrow(/duplicate MSRC exploitability field/);

    exploitability.Description.Value = "Publicly Disclosed:No;Exploited:No";
    const cvss = parsed.Vulnerability[0]!.CVSSScoreSets[0] as { Vector: string };
    cvss.Vector = "CVSS:3.1/AV:N/AV:L/AC:L/PR:L/UI:R/UI:N/S:U/C:H/I:H/A:H";
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection))
      .toThrow(/duplicate MSRC CVSS metric/);
  });

  it("rejects ambiguous JSON, invalid UTF-8, and malformed relevant remediations", () => {
    const input = fixtures();
    expect(() => buildMsrcWindowsLpeInventory(
      new TextEncoder().encode('{"DocumentTracking":{},"DocumentTracking":{}}'),
      input.previous,
      selection,
    )).toThrow(/duplicate JSON key/);
    expect(() => buildMsrcWindowsLpeInventory(new Uint8Array([0xff]), input.previous, selection)).toThrow();

    const parsed = JSON.parse(new TextDecoder().decode(input.current)) as {
      Vulnerability: Array<{ Remediations: Array<{ URL: string }> }>;
    };
    parsed.Vulnerability[0]!.Remediations[0]!.URL = "http://catalog.update.microsoft.com/unsafe";
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection))
      .toThrow(/lacks a matching Update Catalog URL/);

    parsed.Vulnerability[0]!.Remediations[0]!.URL = "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=prefix-KB5053598-suffix";
    expect(() => buildMsrcWindowsLpeInventory(new TextEncoder().encode(JSON.stringify(parsed)), input.previous, selection))
      .toThrow(/lacks a matching Update Catalog URL/);
  });

  it("binds two consecutive synthetic tranches into one deterministic staging lock", () => {
    const inventories = trancheFixtures();
    const forward = buildMsrcWindowsLpeTrancheLock(inventories);
    const reversed = buildMsrcWindowsLpeTrancheLock([...inventories].reverse());
    expect(reversed).toEqual(forward);
    expect(forward.lockId).toMatch(/^sha256:[a-f0-9]{64}$/);
    expect(forward.counts).toEqual({ tranches: 2, sourceDocuments: 3, stagedCandidateCves: 20, distinctPatchBoundaries: 2 });
    expect(forward.sourceDocuments.map((entry) => entry.release)).toEqual(["2025-Jan", "2025-Feb", "2025-Mar"]);
    expect(forward.tranches.map((entry) => entry.selected)).toEqual([11, 9]);
    expect(new Set(forward.cases.map((entry) => entry.cve)).size).toBe(20);
    expect(JSON.stringify(forward)).not.toMatch(/positive|negative|claimable|exploit_payload|poc_source/i);
    expect(forward.policy).toEqual({
      stagingOnly: true, benchmarkEligible: false, bountyClaimEligible: false,
      weaponization: false, promotable: false, containsExploitMaterial: false,
    });
  });

  it("fails the tranche lock closed on mismatched shared evidence, duplicates, and stale policy", () => {
    const inventories = trancheFixtures();
    const mismatch = structuredClone(inventories);
    mismatch[1].sourceDocuments.previous.rawBytesSha256 = "0".repeat(64);
    expect(() => buildMsrcWindowsLpeTrancheLock(mismatch)).toThrow(/shared MSRC source descriptor mismatch/);

    const duplicate = structuredClone(inventories);
    duplicate[1].cases[0]!.cve = duplicate[0].cases[0]!.cve;
    expect(() => buildMsrcWindowsLpeTrancheLock(duplicate)).toThrow(/inconsistent product or selection evidence|20 unique staged CVEs/);

    const stale = structuredClone(inventories);
    stale[0].counts.selected = 10;
    expect(() => buildMsrcWindowsLpeTrancheLock(stale)).toThrow(/stale MSRC inventory counts/);

    const promoted = structuredClone(inventories);
    (promoted[0].cases[0]!.policy as { benchmarkEligible: boolean }).benchmarkEligible = true;
    expect(() => buildMsrcWindowsLpeTrancheLock(promoted)).toThrow(/not an unverified staging candidate/);

    const hiddenMaterial = structuredClone(inventories);
    (hiddenMaterial[0].cases[0] as unknown as Record<string, unknown>).exploit_payload = "forbidden";
    expect(() => buildMsrcWindowsLpeTrancheLock(hiddenMaterial)).toThrow(/unknown or missing fields/);

    const hiddenCountMaterial = structuredClone(inventories);
    (hiddenCountMaterial[0].counts as unknown as Record<string, unknown>).exploit_payload = "forbidden";
    expect(() => buildMsrcWindowsLpeTrancheLock(hiddenCountMaterial)).toThrow(/unknown or missing fields/);

    const wrongSource = structuredClone(inventories);
    wrongSource[0].sourceDocuments.previous.release = "1999-Jan";
    expect(() => buildMsrcWindowsLpeTrancheLock(wrongSource)).toThrow(/invalid inventory previous source descriptor/);

    const contradictoryCvss = structuredClone(inventories);
    contradictoryCvss[0].cases[0]!.cvss.vector = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H";
    expect(() => buildMsrcWindowsLpeTrancheLock(contradictoryCvss)).toThrow(/inconsistent product or selection evidence/);

    const contradictoryExploitability = structuredClone(inventories);
    contradictoryExploitability[0].cases[0]!.exploitability.raw = "Publicly Disclosed:Yes;Exploited:Yes";
    expect(() => buildMsrcWindowsLpeTrancheLock(contradictoryExploitability)).toThrow(/inconsistent product or selection evidence/);

    const contradictoryBoundary = structuredClone(inventories);
    contradictoryBoundary[0].cases[0]!.supersededBoundaryCandidate.updateBuildRevision = 999999;
    expect(() => buildMsrcWindowsLpeTrancheLock(contradictoryBoundary)).toThrow(/inconsistent boundary evidence/);
  });

  it("validates the frozen official-source observation lock without treating it as a vulnerability claim", () => {
    const raw = readFileSync(new URL("../fixtures/msrc-windows-lpe-safe-tranche-lock-v1.json", import.meta.url), "utf8");
    const lock = JSON.parse(raw) as unknown;
    expect(() => validateMsrcWindowsLpeTrancheLock(lock)).not.toThrow();
    expect(raw).toContain("sha256:c822b7eb75dcab043b669cc51b28554123b3f646918a0475f881cb6eb8b92a1d");
    expect(raw).not.toMatch(/claimable|exploit_payload|poc_source/i);

    const changed = structuredClone(lock) as { sourceDocuments: Array<{ rawBytesSha256: string }> };
    changed.sourceDocuments[1]!.rawBytesSha256 = "0".repeat(64);
    expect(() => validateMsrcWindowsLpeTrancheLock(changed)).toThrow(/commitment/);

    const forged = structuredClone(lock) as Record<string, unknown> & {
      sourceDocuments: Array<{ url: string }>;
      tranches: Array<{ selected: number }>;
    };
    forged.sourceDocuments[0]!.url = "https://evil.example/forged";
    forged.tranches[0]!.selected = 999;
    recommit(forged);
    expect(() => validateMsrcWindowsLpeTrancheLock(forged)).toThrow(/source descriptor|tranche descriptor/);
  });
});
