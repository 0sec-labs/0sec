import type {
  IntelGraphEdge,
  IntelGraphNode,
  IntelReference,
  IntelSeverity,
  IntelSource,
  VulnerabilityIntel,
} from "./types.js";

export function normalizeSeverity(value: unknown): IntelSeverity {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (normalized === "critical") return "critical";
  if (normalized === "high") return "high";
  if (normalized === "moderate" || normalized === "medium") return "medium";
  if (normalized === "low") return "low";
  return "info";
}

export function uniqueStrings(values: Array<string | undefined | null>): string[] {
  return [...new Set(values.filter((v): v is string => typeof v === "string" && v.trim().length > 0).map((v) => v.trim()))];
}

export function uniqueReferences(refs: IntelReference[]): IntelReference[] {
  const seen = new Set<string>();
  const out: IntelReference[] = [];
  for (const ref of refs) {
    if (!ref.url || seen.has(ref.url)) continue;
    seen.add(ref.url);
    out.push(ref);
  }
  return out;
}

export function primaryId(ids: string[], fallback: string): string {
  const cve = ids.find((id) => /^CVE-\d{4}-\d{4,}$/i.test(id));
  if (cve) return cve.toUpperCase();
  const ghsa = ids.find((id) => /^GHSA-/i.test(id));
  if (ghsa) return ghsa.toUpperCase();
  const osv = ids.find(Boolean);
  return osv ?? fallback;
}

export function normalizeCveId(cveId: string): string {
  const normalized = cveId.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(normalized)) {
    throw new Error(`invalid CVE id: ${cveId}`);
  }
  return normalized;
}

export function parseCvssVectorSeverity(vector: string | undefined): IntelSeverity | undefined {
  if (!vector) return undefined;
  if (vector.trim().toUpperCase().startsWith("CVSS:")) return undefined;
  return normalizeSeverity(vector);
}

export function mergeIntel(intels: VulnerabilityIntel[]): VulnerabilityIntel[] {
  const byKey = new Map<string, VulnerabilityIntel>();
  for (const intel of intels) {
    const allIds = uniqueStrings([intel.id, ...intel.aliases]).map((id) => id.toUpperCase());
    const existingKey = allIds.find((id) => byKey.has(id));
    if (!existingKey) {
      const copy = {
        ...intel,
        aliases: uniqueStrings([intel.id, ...intel.aliases]).map((id) => id.toUpperCase()),
        sources: uniqueStrings(intel.sources) as IntelSource[],
        references: uniqueReferences(intel.references),
        cwes: uniqueStrings(intel.cwes).map((cwe) => cwe.toUpperCase()),
        affectedRanges: uniqueStrings(intel.affectedRanges),
        fixedVersions: uniqueStrings(intel.fixedVersions),
      };
      for (const id of allIds) byKey.set(id, copy);
      continue;
    }
    const existing = byKey.get(existingKey)!;
    const merged: VulnerabilityIntel = {
      ...existing,
      summary: existing.summary ?? intel.summary,
      details: existing.details ?? intel.details,
      package: existing.package ?? intel.package,
      aliases: uniqueStrings([existing.id, ...existing.aliases, intel.id, ...intel.aliases]).map((id) => id.toUpperCase()),
      sources: uniqueStrings([...existing.sources, ...intel.sources]) as IntelSource[],
      affectedRanges: uniqueStrings([...existing.affectedRanges, ...intel.affectedRanges]),
      fixedVersions: uniqueStrings([...existing.fixedVersions, ...intel.fixedVersions]),
      severity: higherSeverity(existing.severity, intel.severity),
      cvss: existing.cvss?.score && (!intel.cvss?.score || existing.cvss.score >= intel.cvss.score)
        ? existing.cvss
        : intel.cvss ?? existing.cvss,
      cwes: uniqueStrings([...existing.cwes, ...intel.cwes]).map((cwe) => cwe.toUpperCase()),
      references: uniqueReferences([...existing.references, ...intel.references]),
      kev: existing.kev ?? intel.kev,
      publishedAt: existing.publishedAt ?? intel.publishedAt,
      modifiedAt: existing.modifiedAt ?? intel.modifiedAt,
      fetchedAt: existing.fetchedAt > intel.fetchedAt ? existing.fetchedAt : intel.fetchedAt,
    };
    for (const id of merged.aliases) byKey.set(id, merged);
    byKey.set(merged.id.toUpperCase(), merged);
  }
  return [...new Set(byKey.values())];
}

function severityRank(severity: IntelSeverity): number {
  return { info: 1, low: 2, medium: 3, high: 4, critical: 5 }[severity];
}

function higherSeverity(a: IntelSeverity, b: IntelSeverity): IntelSeverity {
  return severityRank(a) >= severityRank(b) ? a : b;
}

export function toGraphSnapshot(intels: VulnerabilityIntel[]) {
  const nodes = new Map<string, IntelGraphNode>();
  const edges: IntelGraphEdge[] = [];
  const addNode = (node: IntelGraphNode) => {
    if (!nodes.has(node.id)) nodes.set(node.id, node);
  };
  const addEdge = (edge: IntelGraphEdge) => {
    edges.push(edge);
  };

  for (const intel of intels) {
    const advisoryId = `advisory:${intel.id}`;
    addNode({
      id: advisoryId,
      kind: "advisory",
      key: intel.id,
      title: intel.summary ?? intel.id,
      data: {
        severity: intel.severity,
        sources: intel.sources,
        publishedAt: intel.publishedAt,
        modifiedAt: intel.modifiedAt,
      },
    });

    for (const alias of intel.aliases) {
      if (alias === intel.id) continue;
      const aliasId = `advisory:${alias}`;
      addNode({ id: aliasId, kind: "advisory", key: alias });
      addEdge({ from: advisoryId, to: aliasId, kind: "HAS_ALIAS" });
    }

    if (intel.package) {
      const pkgId = `package:${intel.package.ecosystem}:${intel.package.name}`;
      addNode({
        id: pkgId,
        kind: "package",
        key: `${intel.package.ecosystem}:${intel.package.name}`,
        title: intel.package.name,
      });
      addEdge({ from: advisoryId, to: pkgId, kind: "AFFECTS_PACKAGE" });
    }

    for (const fixed of intel.fixedVersions) {
      const versionId = `version:${intel.package?.ecosystem ?? "unknown"}:${intel.package?.name ?? "unknown"}:${fixed}`;
      addNode({ id: versionId, kind: "version", key: fixed });
      addEdge({ from: advisoryId, to: versionId, kind: "FIXED_IN" });
    }

    for (const cwe of intel.cwes) {
      const cweId = `cwe:${cwe}`;
      addNode({ id: cweId, kind: "cwe", key: cwe });
      addEdge({ from: advisoryId, to: cweId, kind: "MAPS_TO_CWE" });
    }

    for (const ref of intel.references) {
      const refId = `reference:${ref.url}`;
      addNode({ id: refId, kind: "reference", key: ref.url, title: ref.kind });
      addEdge({ from: advisoryId, to: refId, kind: "REFERENCES", data: { kind: ref.kind, source: ref.source } });
    }

    if (intel.kev?.knownExploited) {
      const kevId = `kev:${intel.id}`;
      addNode({ id: kevId, kind: "kev", key: intel.id, title: intel.kev.vulnerabilityName });
      addEdge({ from: advisoryId, to: kevId, kind: "KNOWN_EXPLOITED" });
    }
  }

  return { nodes: [...nodes.values()], edges };
}
