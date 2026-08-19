#!/usr/bin/env node

import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { assertNoDuplicateWindowsLpeJsonKeys } from "./windows-lpe-paired-corpus.js";

export const MSRC_WINDOWS_LPE_INVENTORY_SCHEMA = "0sec.msrc-windows-lpe-inventory/v1" as const;
const MSRC_API_ORIGIN = "https://api.msrc.microsoft.com";
const MSRC_ADVISORY_ORIGIN = "https://msrc.microsoft.com";
const RELEASE = /^[0-9]{4}-(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$/;
const CVE = /^CVE-[12][0-9]{3}-[0-9]{4,}$/;
const KB = /^[0-9]{7}$/;

export interface MsrcInventorySelection {
  currentRelease: string;
  previousRelease: string;
  productName: string;
  architecture: "x64" | "arm64";
  currentBuildNumber: string;
}

export interface MsrcWindowsLpeInventoryCase {
  caseId: string;
  cve: string;
  title: string;
  cwes: Array<{ id: string | null; name: string }>;
  advisoryUrl: string;
  product: {
    productId: string;
    name: string;
    cpe: string;
    cpeBuild: string;
    architecture: "x64" | "arm64";
  };
  affectedStatus: { type: 3; productId: string };
  impact: { type: 0; value: "Elevation of Privilege"; productId: string };
  cvss: {
    baseScore: number;
    vector: string;
    attackVector: "local";
  };
  exploitability: {
    publiclyDisclosed: "no";
    exploited: "no";
    raw: string;
  };
  supersededBoundaryCandidate: {
    release: string;
    productCpe: string;
    kb: string;
    build: string;
    updateBuildRevision: number;
    catalogUrl: string;
  };
  fixedBoundary: {
    release: string;
    kb: string;
    build: string;
    updateBuildRevision: number;
    catalogUrl: string;
  };
  empiricalStatus: "unverified-candidate-boundary";
  promotion: {
    artifactBindingRequired: true;
    scopeBindingRequired: true;
    evaluatorLabelsRequired: true;
    ready: false;
  };
  policy: {
    stagingOnly: true;
    benchmarkEligible: false;
    bountyClaimEligible: false;
    weaponization: false;
  };
}

export interface MsrcWindowsLpeInventory {
  schemaVersion: typeof MSRC_WINDOWS_LPE_INVENTORY_SCHEMA;
  sourceDocuments: {
    current: MsrcSourceDocument;
    previous: MsrcSourceDocument;
  };
  selection: MsrcInventorySelection;
  selectionPolicy: {
    affectedProductStatusRequired: true;
    impact: "Elevation of Privilege";
    attackVector: "local";
    userInteraction: "none";
    publiclyDisclosed: "no";
    exploited: "no";
  };
  counts: {
    selected: number;
    unresolvedPatchBoundary: number;
    excludedBySafeLocalProfile: number;
    distinctPatchBoundaries: number;
    distinctTitles: number;
    distinctCwes: number;
  };
  cases: MsrcWindowsLpeInventoryCase[];
  policy: {
    stagingOnly: true;
    containsExploitMaterial: false;
    promotableWithoutArtifactBindings: false;
  };
}

interface MsrcSourceDocument {
  release: string;
  url: string;
  rawBytesSha256: string;
  initialReleaseDate: string;
  currentReleaseDate: string;
  trackingVersion: string;
  trackingStatus: number;
  revisionNumber: string;
}

export const MSRC_WINDOWS_LPE_TRANCHE_LOCK_SCHEMA = "0sec.msrc-windows-lpe-tranche-lock/v1" as const;

export interface MsrcWindowsLpeTrancheLock {
  schemaVersion: typeof MSRC_WINDOWS_LPE_TRANCHE_LOCK_SCHEMA;
  lockId: string;
  profile: "staging";
  product: { productId: string; name: string; architecture: "x64" | "arm64"; currentBuildNumber: string };
  sourceDocuments: MsrcSourceDocument[];
  tranches: Array<{
    trancheId: string;
    previousRelease: string;
    currentRelease: string;
    inventorySha256: string;
    previousRawBytesSha256: string;
    currentRawBytesSha256: string;
    selected: number;
  }>;
  cases: Array<{ caseId: string; cve: string; currentRelease: string }>;
  counts: { tranches: 2; sourceDocuments: 3; stagedCandidateCves: 20; distinctPatchBoundaries: number };
  policy: {
    stagingOnly: true;
    benchmarkEligible: false;
    bountyClaimEligible: false;
    weaponization: false;
    promotable: false;
    containsExploitMaterial: false;
  };
}

type JsonRecord = Record<string, unknown>;

function record(value: unknown, name: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as JsonRecord;
}

function array(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function text(value: unknown, name: string, maximum = 1000): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum || value.trim() !== value) {
    throw new Error(`${name} must be non-empty bounded text`);
  }
  return value;
}

function optionalText(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function documentUrl(release: string): string {
  return `${MSRC_API_ORIGIN}/cvrf/v3.0/cvrf/${release}`;
}

function parseDocument(raw: Uint8Array, expectedRelease: string): { root: JsonRecord; source: MsrcSourceDocument } {
  if (!RELEASE.test(expectedRelease)) throw new Error(`invalid MSRC release: ${expectedRelease}`);
  if (raw.byteLength > 64 * 1024 * 1024) throw new Error("MSRC CVRF document exceeds 64 MiB");
  const decoded = new TextDecoder("utf-8", { fatal: true }).decode(raw);
  assertNoDuplicateWindowsLpeJsonKeys(decoded);
  const root = record(JSON.parse(decoded) as unknown, "MSRC CVRF document");
  const tracking = record(root.DocumentTracking, "DocumentTracking");
  const identification = record(tracking.Identification, "DocumentTracking.Identification");
  const id = record(identification.ID, "DocumentTracking.Identification.ID");
  if (id.Value !== expectedRelease) throw new Error(`MSRC document release mismatch: expected ${expectedRelease}`);
  const revisions = array(tracking.RevisionHistory).map((value) => record(value, "DocumentTracking.RevisionHistory[]"));
  if (revisions.length === 0) throw new Error("MSRC document has no revision history");
  const numberedRevisions = revisions.map((revision) => ({ revision, number: Number(revision.Number) }));
  if (numberedRevisions.some((entry) => !Number.isSafeInteger(entry.number) || entry.number < 0)) {
    throw new Error("MSRC document has an invalid revision number");
  }
  const latestRevision = numberedRevisions.sort((a, b) => b.number - a.number)[0]!.revision;
  if (!Number.isSafeInteger(tracking.Status)) throw new Error("MSRC document has an invalid tracking status");
  return {
    root,
    source: {
      release: expectedRelease,
      url: documentUrl(expectedRelease),
      rawBytesSha256: createHash("sha256").update(raw).digest("hex"),
      initialReleaseDate: text(tracking.InitialReleaseDate, "DocumentTracking.InitialReleaseDate", 64),
      currentReleaseDate: text(tracking.CurrentReleaseDate, "DocumentTracking.CurrentReleaseDate", 64),
      trackingVersion: text(tracking.Version, "DocumentTracking.Version", 64),
      trackingStatus: Number(tracking.Status),
      revisionNumber: text(latestRevision.Number, "DocumentTracking.RevisionHistory.Number", 64),
    },
  };
}

function product(root: JsonRecord, productName: string, architecture: "x64" | "arm64", currentBuildNumber: string): {
  productId: string;
  name: string;
  cpe: string;
  cpeBuild: string;
  architecture: "x64" | "arm64";
} {
  const tree = record(root.ProductTree, "ProductTree");
  const matches = array(tree.FullProductName).map((value, index) => record(value, `FullProductName[${index}]`))
    .filter((value) => value.Value === productName);
  if (matches.length !== 1) throw new Error(`expected exactly one MSRC product named ${productName}`);
  const match = matches[0]!;
  const cpe = text(match.CPE, "product.CPE");
  const cpeParts = cpe.split(":");
  if (cpeParts.length !== 13 || cpeParts[0] !== "cpe" || cpeParts[1] !== "2.3" || cpeParts[11]?.toLowerCase() !== architecture) {
    throw new Error(`MSRC product CPE does not match ${architecture}`);
  }
  const cpeBuild = cpeParts[5];
  if (!cpeBuild || !cpeBuild.startsWith(`10.0.${currentBuildNumber}.`)) {
    throw new Error(`MSRC product CPE build does not match ${currentBuildNumber}`);
  }
  return { productId: text(match.ProductID, "product.ProductID", 64), name: productName, cpe, cpeBuild, architecture };
}

interface Boundary {
  kb: string;
  build: string;
  updateBuildRevision: number;
  catalogUrl: string;
  supersededKb: string | null;
}

function parseBoundary(value: JsonRecord, currentBuildNumber: string): Boundary {
  const description = record(value.Description, "remediation.Description");
  const kb = text(description.Value, "remediation KB", 16);
  if (!KB.test(kb)) throw new Error(`invalid MSRC remediation KB: ${kb}`);
  const build = text(value.FixedBuild, "remediation.FixedBuild", 64);
  const match = /^10\.0\.([0-9]{4,6})\.([0-9]+)$/.exec(build);
  if (!match || match[1] !== currentBuildNumber) throw new Error(`MSRC remediation build ${build} does not match ${currentBuildNumber}`);
  const catalogUrl = text(value.URL, "remediation.URL");
  const url = new URL(catalogUrl);
  const queries = url.searchParams.getAll("q");
  if (url.protocol !== "https:" || url.hostname !== "catalog.update.microsoft.com"
    || queries.length !== 1 || queries[0]!.toUpperCase() !== `KB${kb}`) {
    throw new Error(`MSRC remediation ${kb} lacks a matching Update Catalog URL`);
  }
  const supersededKb = optionalText(value.Supercedence);
  if (supersededKb !== null && !KB.test(supersededKb)) throw new Error(`invalid superseded KB: ${supersededKb}`);
  return { kb, build, updateBuildRevision: Number(match[2]), catalogUrl, supersededKb };
}

function remediationCandidates(root: JsonRecord, productId: string, currentBuildNumber: string): Boundary[] {
  const results: Boundary[] = [];
  for (const vulnerability of array(root.Vulnerability)) {
    const row = record(vulnerability, "Vulnerability[]");
    for (const remediation of array(row.Remediations)) {
      const value = record(remediation, "Remediations[]");
      if (value.Type !== 2 || value.SubType !== "Security Update") continue;
      if (!array(value.ProductID).includes(productId)) continue;
      results.push(parseBoundary(value, currentBuildNumber));
    }
  }
  return results;
}

function uniqueBoundary(values: Boundary[], name: string): Boundary | null {
  const unique = new Map(values.map((value) => [
    `${value.kb}\u0000${value.build}\u0000${value.catalogUrl}\u0000${value.supersededKb ?? ""}`,
    value,
  ]));
  if (unique.size === 0) return null;
  if (unique.size !== 1) throw new Error(`conflicting MSRC ${name} boundaries`);
  return [...unique.values()][0]!;
}

function valueText(value: unknown): string | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  return optionalText((value as JsonRecord).Value);
}

function includesProduct(value: unknown, productId: string): boolean {
  return array(value).includes(productId);
}

function safeLocalCvssVector(vector: string): boolean {
  const segments = vector.split("/");
  if (segments.shift() !== "CVSS:3.1") throw new Error("selected MSRC CVSS record must use CVSS 3.1");
  const metrics = new Map<string, string>();
  for (const segment of segments) {
    const separator = segment.indexOf(":");
    if (separator <= 0 || separator === segment.length - 1 || segment.indexOf(":", separator + 1) !== -1) {
      throw new Error("invalid MSRC CVSS metric");
    }
    const key = segment.slice(0, separator);
    const value = segment.slice(separator + 1);
    if (metrics.has(key)) throw new Error(`duplicate MSRC CVSS metric: ${key}`);
    metrics.set(key, value);
  }
  return metrics.get("AV") === "L" && metrics.get("UI") === "N";
}

function localCvss(vulnerability: JsonRecord, productId: string): { baseScore: number; vector: string } | null {
  const matches = array(vulnerability.CVSSScoreSets).map((value) => record(value, "CVSSScoreSets[]"))
    .filter((value) => includesProduct(value.ProductID, productId));
  const unique = new Map(matches.map((value) => [`${value.BaseScore}\u0000${value.Vector}`, value]));
  if (unique.size === 0) return null;
  if (unique.size !== 1) throw new Error("conflicting CVSS records for selected product");
  const match = [...unique.values()][0]!;
  if (typeof match.BaseScore !== "number" || !Number.isFinite(match.BaseScore)) throw new Error("invalid MSRC CVSS base score");
  const vector = text(match.Vector, "CVSS vector", 256);
  if (!safeLocalCvssVector(vector)) return null;
  return { baseScore: match.BaseScore, vector };
}

function hasElevationImpact(vulnerability: JsonRecord, productId: string): boolean {
  const relevant = array(vulnerability.Threats).map((value) => record(value, "Threats[]"))
    .filter((threat) => threat.Type === 0 && includesProduct(threat.ProductID, productId));
  const values = relevant.map((threat) => valueText(threat.Description));
  if (values.some((value) => value === null)) throw new Error("malformed impact record for selected product");
  const unique = new Set(values.map((value) => value!.toLowerCase()));
  if (unique.size > 1) throw new Error("conflicting impact records for selected product");
  return unique.size === 1 && /^elevation of privilege(?:s)?$/.test([...unique][0]!);
}

function hasAffectedStatus(vulnerability: JsonRecord, productId: string): boolean {
  const types = array(vulnerability.ProductStatuses).map((value) => record(value, "ProductStatuses[]"))
    .filter((status) => includesProduct(status.ProductID, productId)).map((status) => status.Type);
  const unique = new Set(types);
  if (unique.size > 1) throw new Error("conflicting affected-status records for selected product");
  return unique.size === 1 && [...unique][0] === 3;
}

function safeExploitabilityText(raw: string): boolean {
  const fields = new Map<string, string>();
  for (const segment of raw.split(";")) {
    const separator = segment.indexOf(":");
    if (separator <= 0 || separator === segment.length - 1) throw new Error("invalid MSRC exploitability field");
    const key = segment.slice(0, separator).trim();
    const value = segment.slice(separator + 1).trim();
    if (fields.has(key)) throw new Error(`duplicate MSRC exploitability field: ${key}`);
    fields.set(key, value);
  }
  return fields.get("Publicly Disclosed") === "No" && fields.get("Exploited") === "No";
}

function safeExploitability(vulnerability: JsonRecord): string | null {
  const values = array(vulnerability.Threats).map((value) => record(value, "Threats[]"))
    .filter((threat) => threat.Type === 1).map((threat) => valueText(threat.Description)).filter((value): value is string => value !== null);
  const unique = [...new Set(values)];
  if (unique.length === 0) return null;
  if (unique.length !== 1) throw new Error("conflicting MSRC exploitability records");
  const raw = unique[0]!;
  return safeExploitabilityText(raw) ? raw : null;
}

function cwes(vulnerability: JsonRecord): Array<{ id: string | null; name: string }> {
  const values = array(vulnerability.CWE).map((value) => record(value, "CWE[]")).map((value) => ({
    id: optionalText(value.ID),
    name: text(value.Value, "CWE.Value", 256),
  }));
  const unique = new Map(values.map((value) => [`${value.id ?? ""}\u0000${value.name}`, value]));
  return [...unique.values()].sort((a, b) => `${a.id ?? ""}:${a.name}`.localeCompare(`${b.id ?? ""}:${b.name}`));
}

export function buildMsrcWindowsLpeInventory(
  currentRaw: Uint8Array,
  previousRaw: Uint8Array,
  selection: MsrcInventorySelection,
): MsrcWindowsLpeInventory {
  if (!RELEASE.test(selection.currentRelease) || !RELEASE.test(selection.previousRelease)
    || selection.currentRelease === selection.previousRelease) throw new Error("current and previous MSRC releases must be distinct YYYY-Mmm values");
  if (!/^[0-9]{4,6}$/.test(selection.currentBuildNumber)) throw new Error("currentBuildNumber must be decimal text");
  const current = parseDocument(currentRaw, selection.currentRelease);
  const previous = parseDocument(previousRaw, selection.previousRelease);
  const selectedProduct = product(current.root, selection.productName, selection.architecture, selection.currentBuildNumber);
  const previousProduct = product(previous.root, selection.productName, selection.architecture, selection.currentBuildNumber);
  if (selectedProduct.productId !== previousProduct.productId) throw new Error("MSRC product ID changed across selected releases");
  const previousBoundaries = remediationCandidates(previous.root, selectedProduct.productId, selection.currentBuildNumber);
  const cases: MsrcWindowsLpeInventoryCase[] = [];
  let unresolvedPatchBoundary = 0;
  let excludedBySafeLocalProfile = 0;
  for (const [index, rawVulnerability] of array(current.root.Vulnerability).entries()) {
    const vulnerability = record(rawVulnerability, `Vulnerability[${index}]`);
    const cve = optionalText(vulnerability.CVE);
    const title = valueText(vulnerability.Title);
    if (!cve || !CVE.test(cve) || !title) continue;
    if (!hasAffectedStatus(vulnerability, selectedProduct.productId)
      || !hasElevationImpact(vulnerability, selectedProduct.productId)) continue;
    const cvss = localCvss(vulnerability, selectedProduct.productId);
    const exploitability = safeExploitability(vulnerability);
    if (!cvss || !exploitability) {
      excludedBySafeLocalProfile += 1;
      continue;
    }
    const fixedCandidates = array(vulnerability.Remediations).map((value) => record(value, "Remediations[]"))
      .filter((value) => value.Type === 2 && value.SubType === "Security Update"
        && includesProduct(value.ProductID, selectedProduct.productId))
      .map((value) => parseBoundary(value, selection.currentBuildNumber));
    const fixed = uniqueBoundary(fixedCandidates, `${cve} fixed`);
    if (!fixed?.supersededKb) {
      unresolvedPatchBoundary += 1;
      continue;
    }
    const vulnerable = uniqueBoundary(previousBoundaries.filter((value) => value.kb === fixed.supersededKb), `${cve} vulnerable`);
    if (!vulnerable || vulnerable.updateBuildRevision >= fixed.updateBuildRevision) {
      unresolvedPatchBoundary += 1;
      continue;
    }
    if (fixed.build !== selectedProduct.cpeBuild || vulnerable.build !== previousProduct.cpeBuild) {
      throw new Error(`${cve} remediation boundary does not match the selected product CPE builds`);
    }
    cases.push({
      caseId: `msrc-${cve.toLowerCase()}-${selectedProduct.productId}-${selectedProduct.architecture}`,
      cve,
      title,
      cwes: cwes(vulnerability),
      advisoryUrl: `${MSRC_ADVISORY_ORIGIN}/update-guide/vulnerability/${cve}`,
      product: selectedProduct,
      affectedStatus: { type: 3, productId: selectedProduct.productId },
      impact: { type: 0, value: "Elevation of Privilege", productId: selectedProduct.productId },
      cvss: { ...cvss, attackVector: "local" },
      exploitability: { publiclyDisclosed: "no", exploited: "no", raw: exploitability },
      supersededBoundaryCandidate: {
        release: selection.previousRelease, productCpe: previousProduct.cpe, kb: vulnerable.kb, build: vulnerable.build,
        updateBuildRevision: vulnerable.updateBuildRevision, catalogUrl: vulnerable.catalogUrl,
      },
      fixedBoundary: {
        release: selection.currentRelease, kb: fixed.kb, build: fixed.build,
        updateBuildRevision: fixed.updateBuildRevision, catalogUrl: fixed.catalogUrl,
      },
      empiricalStatus: "unverified-candidate-boundary",
      promotion: { artifactBindingRequired: true, scopeBindingRequired: true, evaluatorLabelsRequired: true, ready: false },
      policy: { stagingOnly: true, benchmarkEligible: false, bountyClaimEligible: false, weaponization: false },
    });
  }
  cases.sort((a, b) => a.cve.localeCompare(b.cve));
  if (cases.length === 0) throw new Error("MSRC selection produced no resolved local LPE patch boundaries");
  if (new Set(cases.map((entry) => entry.cve)).size !== cases.length) throw new Error("duplicate CVE in MSRC staging inventory");
  const patchBoundaries = new Set(cases.map((entry) =>
    `${entry.supersededBoundaryCandidate.kb}->${entry.fixedBoundary.kb}`));
  const titles = new Set(cases.map((entry) => entry.title));
  const cweNames = new Set(cases.flatMap((entry) => entry.cwes.map((value) => `${value.id ?? ""}:${value.name}`)));
  return {
    schemaVersion: MSRC_WINDOWS_LPE_INVENTORY_SCHEMA,
    sourceDocuments: { current: current.source, previous: previous.source },
    selection,
    selectionPolicy: {
      affectedProductStatusRequired: true,
      impact: "Elevation of Privilege",
      attackVector: "local",
      userInteraction: "none",
      publiclyDisclosed: "no",
      exploited: "no",
    },
    counts: {
      selected: cases.length,
      unresolvedPatchBoundary,
      excludedBySafeLocalProfile,
      distinctPatchBoundaries: patchBoundaries.size,
      distinctTitles: titles.size,
      distinctCwes: cweNames.size,
    },
    cases,
    policy: { stagingOnly: true, containsExploitMaterial: false, promotableWithoutArtifactBindings: false },
  };
}

function releaseOrdinal(release: string): number {
  const match = /^([0-9]{4})-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$/.exec(release);
  if (!match) throw new Error(`invalid MSRC release: ${release}`);
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  return Number(match[1]) * 12 + months.indexOf(match[2]!);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const object = value as JsonRecord;
  return `{${Object.keys(object).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(object[key])}`).join(",")}}`;
}

function sha256Canonical(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function assertInventoryLockable(inventory: MsrcWindowsLpeInventory): void {
  exactKeys(inventory as unknown as JsonRecord, ["cases", "counts", "policy", "schemaVersion", "selection", "selectionPolicy", "sourceDocuments"], "MSRC inventory");
  if (inventory.schemaVersion !== MSRC_WINDOWS_LPE_INVENTORY_SCHEMA || inventory.cases.length === 0) {
    throw new Error("tranche lock requires non-empty v1 MSRC inventories");
  }
  exactKeys(inventory.selection as unknown as JsonRecord,
    ["architecture", "currentBuildNumber", "currentRelease", "previousRelease", "productName"], "inventory selection");
  if (!RELEASE.test(inventory.selection.currentRelease) || !RELEASE.test(inventory.selection.previousRelease)
    || !(inventory.selection.architecture === "x64" || inventory.selection.architecture === "arm64")
    || !/^[0-9]{4,6}$/.test(inventory.selection.currentBuildNumber)) throw new Error("invalid inventory selection");
  exactKeys(inventory.sourceDocuments as unknown as JsonRecord, ["current", "previous"], "inventory sourceDocuments");
  for (const [role, source, expectedRelease] of [
    ["previous", inventory.sourceDocuments.previous, inventory.selection.previousRelease],
    ["current", inventory.sourceDocuments.current, inventory.selection.currentRelease],
  ] as const) {
    exactKeys(source as unknown as JsonRecord,
      ["currentReleaseDate", "initialReleaseDate", "rawBytesSha256", "release", "revisionNumber", "trackingStatus", "trackingVersion", "url"],
      `inventory ${role} source`);
    if (source.release !== expectedRelease || source.url !== documentUrl(expectedRelease)
      || !/^[a-f0-9]{64}$/.test(source.rawBytesSha256) || !Number.isSafeInteger(source.trackingStatus)
      || !/^[0-9]+$/.test(source.revisionNumber)) throw new Error(`invalid inventory ${role} source descriptor`);
  }
  const expectedSelectionPolicy: MsrcWindowsLpeInventory["selectionPolicy"] = {
    affectedProductStatusRequired: true, impact: "Elevation of Privilege", attackVector: "local",
    userInteraction: "none", publiclyDisclosed: "no", exploited: "no",
  };
  if (canonicalJson(inventory.selectionPolicy) !== canonicalJson(expectedSelectionPolicy)
    || canonicalJson(inventory.policy) !== canonicalJson({
      stagingOnly: true, containsExploitMaterial: false, promotableWithoutArtifactBindings: false,
    })) throw new Error("tranche lock requires the safe staging policy");
  const boundaries = new Set<string>();
  const titles = new Set<string>();
  const cweNames = new Set<string>();
  exactKeys(inventory.counts as unknown as JsonRecord,
    ["distinctCwes", "distinctPatchBoundaries", "distinctTitles", "excludedBySafeLocalProfile", "selected", "unresolvedPatchBoundary"],
    "inventory counts");
  if (Object.values(inventory.counts).some((value) => !Number.isSafeInteger(value) || value < 0)) {
    throw new Error("invalid MSRC inventory counts");
  }
  const firstProduct = inventory.cases[0]!.product;
  for (const entry of inventory.cases) {
    exactKeys(entry as unknown as JsonRecord, ["advisoryUrl", "affectedStatus", "caseId", "cve", "cvss", "cwes", "empiricalStatus", "exploitability", "fixedBoundary", "impact", "policy", "product", "promotion", "supersededBoundaryCandidate", "title"], `case ${entry.caseId}`);
    exactKeys(entry.product as unknown as JsonRecord, ["architecture", "cpe", "cpeBuild", "name", "productId"], `case ${entry.caseId} product`);
    exactKeys(entry.affectedStatus as unknown as JsonRecord, ["productId", "type"], `case ${entry.caseId} affectedStatus`);
    exactKeys(entry.impact as unknown as JsonRecord, ["productId", "type", "value"], `case ${entry.caseId} impact`);
    exactKeys(entry.cvss as unknown as JsonRecord, ["attackVector", "baseScore", "vector"], `case ${entry.caseId} cvss`);
    exactKeys(entry.exploitability as unknown as JsonRecord, ["exploited", "publiclyDisclosed", "raw"], `case ${entry.caseId} exploitability`);
    exactKeys(entry.supersededBoundaryCandidate as unknown as JsonRecord,
      ["build", "catalogUrl", "kb", "productCpe", "release", "updateBuildRevision"], `case ${entry.caseId} candidate boundary`);
    exactKeys(entry.fixedBoundary as unknown as JsonRecord,
      ["build", "catalogUrl", "kb", "release", "updateBuildRevision"], `case ${entry.caseId} fixed boundary`);
    exactKeys(entry.promotion as unknown as JsonRecord,
      ["artifactBindingRequired", "evaluatorLabelsRequired", "ready", "scopeBindingRequired"], `case ${entry.caseId} promotion`);
    exactKeys(entry.policy as unknown as JsonRecord,
      ["benchmarkEligible", "bountyClaimEligible", "stagingOnly", "weaponization"], `case ${entry.caseId} policy`);
    for (const value of entry.cwes) exactKeys(value as unknown as JsonRecord, ["id", "name"], `case ${entry.caseId} CWE`);
    if (entry.cve !== entry.cve.toUpperCase() || !CVE.test(entry.cve)
      || entry.caseId !== `msrc-${entry.cve.toLowerCase()}-${entry.product.productId}-${entry.product.architecture}`
      || entry.advisoryUrl !== `${MSRC_ADVISORY_ORIGIN}/update-guide/vulnerability/${entry.cve}`
      || canonicalJson(entry.product) !== canonicalJson(firstProduct)
      || entry.product.name !== inventory.selection.productName
      || entry.product.architecture !== inventory.selection.architecture
      || entry.affectedStatus.type !== 3 || entry.affectedStatus.productId !== entry.product.productId
      || entry.impact.type !== 0 || entry.impact.value !== "Elevation of Privilege" || entry.impact.productId !== entry.product.productId
      || entry.cvss.attackVector !== "local" || !Number.isFinite(entry.cvss.baseScore) || !safeLocalCvssVector(entry.cvss.vector)
      || entry.exploitability.publiclyDisclosed !== "no" || entry.exploitability.exploited !== "no"
      || !safeExploitabilityText(entry.exploitability.raw)) {
      throw new Error(`case ${entry.caseId} has inconsistent product or selection evidence`);
    }
    if (entry.empiricalStatus !== "unverified-candidate-boundary"
      || entry.supersededBoundaryCandidate.release !== inventory.selection.previousRelease
      || entry.fixedBoundary.release !== inventory.selection.currentRelease
      || canonicalJson(entry.promotion) !== canonicalJson({
        artifactBindingRequired: true, scopeBindingRequired: true, evaluatorLabelsRequired: true, ready: false,
      }) || canonicalJson(entry.policy) !== canonicalJson({
        stagingOnly: true, benchmarkEligible: false, bountyClaimEligible: false, weaponization: false,
      })) throw new Error(`case ${entry.caseId} is not an unverified staging candidate`);
    const fixedCpe = entry.product.cpe.split(":");
    const candidateCpe = entry.supersededBoundaryCandidate.productCpe.split(":");
    const fixedCatalog = new URL(entry.fixedBoundary.catalogUrl);
    const candidateCatalog = new URL(entry.supersededBoundaryCandidate.catalogUrl);
    const fixedBuild = /^10\.0\.([0-9]{4,6})\.([0-9]+)$/.exec(entry.fixedBoundary.build);
    const candidateBuild = /^10\.0\.([0-9]{4,6})\.([0-9]+)$/.exec(entry.supersededBoundaryCandidate.build);
    if (entry.product.cpeBuild !== entry.fixedBoundary.build || !fixedBuild || !candidateBuild || fixedCpe.length !== 13
      || fixedCpe[11]?.toLowerCase() !== entry.product.architecture || fixedCpe[5] !== entry.fixedBoundary.build
      || candidateCpe.length !== 13 || candidateCpe[11]?.toLowerCase() !== entry.product.architecture
      || candidateCpe[5] !== entry.supersededBoundaryCandidate.build
      || !KB.test(entry.fixedBoundary.kb) || !KB.test(entry.supersededBoundaryCandidate.kb)
      || fixedCatalog.origin !== "https://catalog.update.microsoft.com"
      || fixedCatalog.searchParams.getAll("q").length !== 1
      || fixedCatalog.searchParams.get("q")?.toUpperCase() !== `KB${entry.fixedBoundary.kb}`
      || candidateCatalog.origin !== "https://catalog.update.microsoft.com"
      || candidateCatalog.searchParams.getAll("q").length !== 1
      || candidateCatalog.searchParams.get("q")?.toUpperCase() !== `KB${entry.supersededBoundaryCandidate.kb}`
      || !Number.isSafeInteger(entry.fixedBoundary.updateBuildRevision)
      || !Number.isSafeInteger(entry.supersededBoundaryCandidate.updateBuildRevision)
      || Number(fixedBuild[2]) !== entry.fixedBoundary.updateBuildRevision
      || Number(candidateBuild[2]) !== entry.supersededBoundaryCandidate.updateBuildRevision
      || entry.supersededBoundaryCandidate.updateBuildRevision >= entry.fixedBoundary.updateBuildRevision) {
      throw new Error(`case ${entry.caseId} has inconsistent boundary evidence`);
    }
    boundaries.add(`${entry.supersededBoundaryCandidate.kb}->${entry.fixedBoundary.kb}`);
    titles.add(entry.title);
    for (const value of entry.cwes) cweNames.add(`${value.id ?? ""}:${value.name}`);
  }
  if (inventory.counts.selected !== inventory.cases.length
    || inventory.counts.distinctPatchBoundaries !== boundaries.size
    || inventory.counts.distinctTitles !== titles.size || inventory.counts.distinctCwes !== cweNames.size) {
    throw new Error("stale MSRC inventory counts");
  }
}

export function buildMsrcWindowsLpeTrancheLock(
  input: readonly MsrcWindowsLpeInventory[],
): MsrcWindowsLpeTrancheLock {
  if (input.length !== 2) throw new Error("tranche lock requires exactly two inventories");
  const inventories = [...input].sort((a, b) => releaseOrdinal(a.selection.currentRelease) - releaseOrdinal(b.selection.currentRelease));
  inventories.forEach(assertInventoryLockable);
  const [earlier, later] = inventories as [MsrcWindowsLpeInventory, MsrcWindowsLpeInventory];
  if (earlier.selection.currentRelease !== later.selection.previousRelease
    || releaseOrdinal(earlier.selection.previousRelease) + 1 !== releaseOrdinal(earlier.selection.currentRelease)
    || releaseOrdinal(earlier.selection.currentRelease) + 1 !== releaseOrdinal(later.selection.currentRelease)) {
    throw new Error("tranche inventories must form a consecutive three-release chain");
  }
  const sharedEarlier = earlier.sourceDocuments.current;
  const sharedLater = later.sourceDocuments.previous;
  if (canonicalJson(sharedEarlier) !== canonicalJson(sharedLater)) throw new Error("shared MSRC source descriptor mismatch");
  const identity = (inventory: MsrcWindowsLpeInventory) => ({
    productId: inventory.cases[0]!.product.productId,
    name: inventory.selection.productName,
    architecture: inventory.selection.architecture,
    currentBuildNumber: inventory.selection.currentBuildNumber,
  });
  const productIdentity = identity(earlier);
  if (canonicalJson(productIdentity) !== canonicalJson(identity(later))
    || canonicalJson(earlier.selectionPolicy) !== canonicalJson(later.selectionPolicy)) {
    throw new Error("tranche product or selection policy mismatch");
  }
  const sourceMap = new Map<string, MsrcSourceDocument>();
  for (const inventory of inventories) {
    for (const source of [inventory.sourceDocuments.previous, inventory.sourceDocuments.current]) {
      if (!/^[a-f0-9]{64}$/.test(source.rawBytesSha256)) throw new Error("invalid MSRC raw-byte digest");
      const existing = sourceMap.get(source.release);
      if (existing && canonicalJson(existing) !== canonicalJson(source)) throw new Error("conflicting MSRC source descriptor");
      sourceMap.set(source.release, source);
    }
  }
  if (sourceMap.size !== 3) throw new Error("tranche lock requires exactly three source documents");
  const cases = inventories.flatMap((inventory) => inventory.cases.map((entry) => ({
    caseId: entry.caseId, cve: entry.cve, currentRelease: inventory.selection.currentRelease,
  }))).sort((a, b) => a.cve.localeCompare(b.cve) || a.caseId.localeCompare(b.caseId));
  if (cases.length !== 20 || new Set(cases.map((entry) => entry.cve)).size !== 20
    || new Set(cases.map((entry) => entry.caseId)).size !== 20) {
    throw new Error("tranche lock requires exactly 20 unique staged CVEs and case IDs");
  }
  const tranches = inventories.map((inventory) => ({
    trancheId: `${inventory.selection.previousRelease}--${inventory.selection.currentRelease}`,
    previousRelease: inventory.selection.previousRelease,
    currentRelease: inventory.selection.currentRelease,
    inventorySha256: sha256Canonical(inventory),
    previousRawBytesSha256: inventory.sourceDocuments.previous.rawBytesSha256,
    currentRawBytesSha256: inventory.sourceDocuments.current.rawBytesSha256,
    selected: inventory.cases.length,
  }));
  const distinctPatchBoundaries = new Set(inventories.flatMap((inventory) => inventory.cases.map((entry) =>
    `${entry.supersededBoundaryCandidate.kb}->${entry.fixedBoundary.kb}`))).size;
  const body = {
    schemaVersion: MSRC_WINDOWS_LPE_TRANCHE_LOCK_SCHEMA,
    profile: "staging" as const,
    product: productIdentity,
    sourceDocuments: [...sourceMap.values()].sort((a, b) => releaseOrdinal(a.release) - releaseOrdinal(b.release)),
    tranches,
    cases,
    counts: { tranches: 2 as const, sourceDocuments: 3 as const, stagedCandidateCves: 20 as const, distinctPatchBoundaries },
    policy: {
      stagingOnly: true as const, benchmarkEligible: false as const, bountyClaimEligible: false as const,
      weaponization: false as const, promotable: false as const, containsExploitMaterial: false as const,
    },
  };
  return { ...body, lockId: `sha256:${sha256Canonical(body)}` };
}

function exactKeys(value: JsonRecord, keys: string[], name: string): void {
  if (canonicalJson(Object.keys(value).sort()) !== canonicalJson([...keys].sort())) {
    throw new Error(`${name} has unknown or missing fields`);
  }
}

export function validateMsrcWindowsLpeTrancheLock(
  value: unknown,
  boundInventories?: readonly MsrcWindowsLpeInventory[],
): asserts value is MsrcWindowsLpeTrancheLock {
  const lock = record(value, "MSRC tranche lock");
  exactKeys(lock, ["cases", "counts", "lockId", "policy", "product", "profile", "schemaVersion", "sourceDocuments", "tranches"], "MSRC tranche lock");
  const lockId = text(lock.lockId, "tranche lock ID", 80);
  const { lockId: ignored, ...body } = lock;
  void ignored;
  if (lock.schemaVersion !== MSRC_WINDOWS_LPE_TRANCHE_LOCK_SCHEMA || lock.profile !== "staging"
    || lockId !== `sha256:${sha256Canonical(body)}`) throw new Error("invalid MSRC tranche lock commitment");
  const productValue = record(lock.product, "product");
  exactKeys(productValue, ["architecture", "currentBuildNumber", "name", "productId"], "product");
  const productId = text(productValue.productId, "product.productId", 64);
  text(productValue.name, "product.name", 256);
  if (!(productValue.architecture === "x64" || productValue.architecture === "arm64")
    || typeof productValue.currentBuildNumber !== "string" || !/^[0-9]{4,6}$/.test(productValue.currentBuildNumber)) {
    throw new Error("invalid MSRC tranche lock product");
  }
  const sources = array(lock.sourceDocuments).map((entry) => {
    const source = record(entry, "sourceDocuments[]");
    exactKeys(source, ["currentReleaseDate", "initialReleaseDate", "rawBytesSha256", "release", "revisionNumber", "trackingStatus", "trackingVersion", "url"], "sourceDocuments[]");
    const release = text(source.release, "source release", 16);
    if (!RELEASE.test(release) || source.url !== documentUrl(release)
      || typeof source.rawBytesSha256 !== "string" || !/^[a-f0-9]{64}$/.test(source.rawBytesSha256)
      || !Number.isSafeInteger(source.trackingStatus)
      || typeof source.revisionNumber !== "string" || !/^[0-9]+$/.test(source.revisionNumber)) {
      throw new Error("invalid MSRC tranche lock source descriptor");
    }
    text(source.initialReleaseDate, "source initial release date", 64);
    text(source.currentReleaseDate, "source current release date", 64);
    text(source.trackingVersion, "source tracking version", 64);
    return source;
  });
  const tranches = array(lock.tranches).map((entry) => {
    const tranche = record(entry, "tranches[]");
    exactKeys(tranche, ["currentRawBytesSha256", "currentRelease", "inventorySha256", "previousRawBytesSha256", "previousRelease", "selected", "trancheId"], "tranches[]");
    const previousRelease = text(tranche.previousRelease, "tranche previous release", 16);
    const currentRelease = text(tranche.currentRelease, "tranche current release", 16);
    if (tranche.trancheId !== `${previousRelease}--${currentRelease}`
      || releaseOrdinal(previousRelease) + 1 !== releaseOrdinal(currentRelease)
      || typeof tranche.inventorySha256 !== "string" || !/^[a-f0-9]{64}$/.test(tranche.inventorySha256)
      || typeof tranche.previousRawBytesSha256 !== "string" || !/^[a-f0-9]{64}$/.test(tranche.previousRawBytesSha256)
      || typeof tranche.currentRawBytesSha256 !== "string" || !/^[a-f0-9]{64}$/.test(tranche.currentRawBytesSha256)
      || !Number.isSafeInteger(tranche.selected) || Number(tranche.selected) <= 0) {
      throw new Error("invalid MSRC tranche descriptor");
    }
    return tranche;
  });
  const cases = array(lock.cases).map((entry) => {
    const candidate = record(entry, "cases[]");
    exactKeys(candidate, ["caseId", "currentRelease", "cve"], "cases[]");
    const cve = text(candidate.cve, "case CVE", 32);
    const currentRelease = text(candidate.currentRelease, "case current release", 16);
    const expectedCaseId = `msrc-${cve.toLowerCase()}-${productId}-${productValue.architecture}`;
    if (!CVE.test(cve) || candidate.caseId !== expectedCaseId || !RELEASE.test(currentRelease)) {
      throw new Error("invalid MSRC tranche lock case");
    }
    return candidate;
  });
  if (sources.length !== 3 || tranches.length !== 2 || cases.length !== 20
    || new Set(sources.map((entry) => entry.release)).size !== 3
    || new Set(cases.map((entry) => entry.cve)).size !== 20
    || new Set(cases.map((entry) => entry.caseId)).size !== 20) throw new Error("invalid MSRC tranche lock cardinality");
  const sortedReleases = sources.map((entry) => text(entry.release, "source release", 16));
  if (sortedReleases.some((release, index) => index > 0 && releaseOrdinal(sortedReleases[index - 1]!) + 1 !== releaseOrdinal(release))) {
    throw new Error("MSRC tranche lock sources are not canonical");
  }
  if (tranches[0]!.previousRelease !== sortedReleases[0] || tranches[0]!.currentRelease !== sortedReleases[1]
    || tranches[1]!.previousRelease !== sortedReleases[1] || tranches[1]!.currentRelease !== sortedReleases[2]
    || tranches[0]!.currentRawBytesSha256 !== tranches[1]!.previousRawBytesSha256) {
    throw new Error("MSRC tranche lock does not bind its shared source");
  }
  for (const [index, tranche] of tranches.entries()) {
    if (tranche.previousRawBytesSha256 !== sources[index]!.rawBytesSha256
      || tranche.currentRawBytesSha256 !== sources[index + 1]!.rawBytesSha256
      || cases.filter((entry) => entry.currentRelease === tranche.currentRelease).length !== tranche.selected) {
      throw new Error("MSRC tranche does not match its sources or cases");
    }
  }
  const canonicalCases = [...cases].sort((a, b) => String(a.cve).localeCompare(String(b.cve)) || String(a.caseId).localeCompare(String(b.caseId)));
  if (canonicalJson(cases) !== canonicalJson(canonicalCases)
    || cases.some((entry) => !tranches.some((tranche) => tranche.currentRelease === entry.currentRelease))) {
    throw new Error("MSRC tranche cases are not canonical or do not belong to a tranche");
  }
  const counts = record(lock.counts, "counts");
  exactKeys(counts, ["distinctPatchBoundaries", "sourceDocuments", "stagedCandidateCves", "tranches"], "counts");
  if (counts.tranches !== 2 || counts.sourceDocuments !== 3 || counts.stagedCandidateCves !== 20
    || !Number.isSafeInteger(counts.distinctPatchBoundaries) || Number(counts.distinctPatchBoundaries) < 1
    || Number(counts.distinctPatchBoundaries) > 20 || tranches.reduce((sum, tranche) => sum + Number(tranche.selected), 0) !== 20) {
    throw new Error("invalid MSRC tranche lock counts");
  }
  const policy = record(lock.policy, "policy");
  exactKeys(policy, ["benchmarkEligible", "bountyClaimEligible", "containsExploitMaterial", "promotable", "stagingOnly", "weaponization"], "policy");
  if (canonicalJson(policy) !== canonicalJson({
    stagingOnly: true, benchmarkEligible: false, bountyClaimEligible: false,
    weaponization: false, promotable: false, containsExploitMaterial: false,
  })) throw new Error("invalid MSRC tranche lock policy");
  if (boundInventories && canonicalJson(buildMsrcWindowsLpeTrancheLock(boundInventories)) !== canonicalJson(lock)) {
    throw new Error("MSRC tranche lock does not match bound inventories");
  }
}

async function fetchDocument(release: string): Promise<Uint8Array> {
  if (!RELEASE.test(release)) throw new Error(`invalid MSRC release: ${release}`);
  const expectedPath = `/cvrf/v3.0/cvrf/${release}`;
  const url = new URL(expectedPath, `${MSRC_API_ORIGIN}/`);
  if (url.origin !== MSRC_API_ORIGIN || url.pathname !== expectedPath || url.search || url.hash) {
    throw new Error("MSRC CVRF URL failed the outbound allowlist");
  }
  // The exact origin/path guard above is the sanitizer; this structural rule does not model it.
  const response = await fetch(url.href, { // foxguard: ignore[js/no-ssrf]
    headers: { accept: "application/json" }, signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`MSRC CVRF request failed: HTTP ${response.status}`);
  if (response.url !== url.href) throw new Error("MSRC CVRF request was redirected away from the allowlisted URL");
  const contentType = response.headers.get("content-type") ?? "";
  if (!/^application\/(?:json|[^;]+\+json)(?:;|$)/i.test(contentType)) throw new Error(`MSRC CVRF response is not JSON: ${contentType || "missing content-type"}`);
  const contentLength = Number(response.headers.get("content-length") ?? "0");
  if (contentLength > 64 * 1024 * 1024) throw new Error("MSRC CVRF response exceeds 64 MiB");
  const raw = new Uint8Array(await response.arrayBuffer());
  if (raw.byteLength > 64 * 1024 * 1024) throw new Error("MSRC CVRF response exceeds 64 MiB");
  return raw;
}

function option(argv: string[], name: string): string | undefined {
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : undefined;
}

async function main(argv = process.argv.slice(2)): Promise<void> {
  const currentRelease = option(argv, "--current-release");
  const previousRelease = option(argv, "--previous-release");
  const productName = option(argv, "--product-name") ?? "Windows 11 Version 24H2 for x64-based Systems";
  const architecture = option(argv, "--architecture") ?? "x64";
  const currentBuildNumber = option(argv, "--current-build-number") ?? "26100";
  if (!currentRelease || !previousRelease || !(architecture === "x64" || architecture === "arm64")) {
    throw new Error("usage: msrc-windows-lpe-inventory --current-release YYYY-Mmm --previous-release YYYY-Mmm [--product-name name] [--architecture x64|arm64] [--current-build-number N]");
  }
  const [currentRaw, previousRaw] = await Promise.all([fetchDocument(currentRelease), fetchDocument(previousRelease)]);
  const inventory = buildMsrcWindowsLpeInventory(currentRaw, previousRaw, {
    currentRelease, previousRelease, productName, architecture, currentBuildNumber,
  });
  process.stdout.write(`${JSON.stringify(inventory, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
