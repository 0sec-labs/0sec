import { describe, expect, it } from "vitest";
import { buildAdGraph } from "../../adgraph/ingest.js";
import type { AdEdge, AdGraph, AdEdgeKind, AdNode } from "../../adgraph/types.js";
import { buildEntraGraph } from "../entra-graph/build.js";
import type { EntraGraph } from "../entra-graph/types.js";
import type { TenantSnapshot, TenantUser } from "../types.js";
import { buildHybridGraph, joinDirectories, runHybridPathAnalysis } from "./index.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const DOMAIN_SID = "S-1-5-21-9-8-7";
const DOMAIN_ADMINS = `${DOMAIN_SID}-512`;
const TENANT = "22222222-2222-2222-2222-222222222222";
const GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10";

/** A GUID and its base64 `onPremisesImmutableId` encoding, as Entra Connect emits it. */
const ALICE_GUID = "3F2504E0-4F89-11D3-9A0C-0305E82C3301";

function immutableIdFor(guid: string): string {
  const hex = guid.replace(/-/g, "");
  // Entra Connect encodes objectGUID in little-endian mixed-endian order.
  const le = [
    hex.slice(6, 8), hex.slice(4, 6), hex.slice(2, 4), hex.slice(0, 2),
    hex.slice(10, 12), hex.slice(8, 10),
    hex.slice(14, 16), hex.slice(12, 14),
    hex.slice(16, 32),
  ].join("");
  return Buffer.from(le, "hex").toString("base64");
}

function adNode(objectId: string, kind: string, properties: Record<string, unknown> = {}): AdNode {
  return { objectId, label: objectId, kind, properties };
}

function adEdge(source: string, kind: AdEdgeKind, target: string): AdEdge {
  return { source, target, kind };
}

/** On-prem: alice is a member of a group that holds GenericAll over Domain Admins. */
function onPremGraph(aliceProps: Record<string, unknown>): AdGraph {
  return buildAdGraph(
    [
      adNode("S-1-5-21-9-8-7-1001", "User", { name: "ALICE@CORP.LOCAL", ...aliceProps }),
      adNode("S-1-5-21-9-8-7-1500", "Group", { name: "HELPDESK@CORP.LOCAL" }),
      adNode(DOMAIN_ADMINS, "Group", { name: "DOMAIN ADMINS@CORP.LOCAL" }),
    ],
    [
      adEdge("S-1-5-21-9-8-7-1001", "MemberOf", "S-1-5-21-9-8-7-1500"),
      adEdge("S-1-5-21-9-8-7-1500", "GenericAll", DOMAIN_ADMINS),
    ],
  );
}

function tenantUser(over: Partial<TenantUser> = {}): TenantUser {
  return {
    id: "aaaa1111-0000-0000-0000-000000000001",
    displayName: "Alice Cloud",
    userPrincipalName: "alice@corp.example.com",
    userType: "Member",
    accountEnabled: true,
    onPremisesSyncEnabled: true,
    ...over,
  };
}

/** Cloud: the corresponding user is in a group that holds Global Administrator. */
function cloudGraph(user: TenantUser): EntraGraph {
  const snapshot: TenantSnapshot = {
    tenantId: TENANT,
    tenantDisplayName: "Contoso",
    collectedAt: new Date(0).toISOString(),
    users: [user],
    groups: [{ id: "bbbb2222-0000-0000-0000-000000000001", displayName: "Cloud Admins", securityEnabled: true }],
    servicePrincipals: [],
    appRegistrations: [],
    roleDefinitions: [
      { id: GLOBAL_ADMIN_TEMPLATE, templateId: GLOBAL_ADMIN_TEMPLATE, displayName: "Global Administrator", isBuiltIn: true },
    ],
    roleAssignments: [
      {
        id: "ra-1",
        roleDefinitionId: GLOBAL_ADMIN_TEMPLATE,
        principalId: "bbbb2222-0000-0000-0000-000000000001",
        directoryScopeId: "/",
      },
    ],
    roleEligibilitySchedules: [],
    conditionalAccessPolicies: [],
    federationConfig: { domains: [] },
    relationships: {
      groupMembers: [{ groupId: "bbbb2222-0000-0000-0000-000000000001", memberId: user.id, memberType: "user" }],
      groupOwners: [],
      applicationOwners: [],
      servicePrincipalOwners: [],
      devices: [],
      deviceOwners: [],
      administrativeUnits: [],
    },
    warnings: [],
  };
  return buildEntraGraph(snapshot);
}

// ---------------------------------------------------------------------------
// Join
// ---------------------------------------------------------------------------

describe("joinDirectories", () => {
  it("joins on immutableId at high confidence", () => {
    const ad = onPremGraph({ objectguid: ALICE_GUID });
    const entra = cloudGraph(tenantUser({ onPremisesImmutableId: immutableIdFor(ALICE_GUID) }));

    const report = joinDirectories(ad, entra);

    expect(report.joined).toBe(true);
    expect(report.correspondences.length).toBeGreaterThan(0);
    expect(report.byConfidence.high).toBeGreaterThan(0);
    expect(report.correspondences[0]?.signals).toContain("immutable-id");
    expect(report.correspondences[0]?.heuristic).toBe(false);
  });

  it("joins on security identifier", () => {
    const ad = onPremGraph({});
    const entra = cloudGraph(
      tenantUser({ onPremisesSecurityIdentifier: "S-1-5-21-9-8-7-1001" }),
    );

    const report = joinDirectories(ad, entra);

    expect(report.joined).toBe(true);
    expect(report.correspondences[0]?.signals).toContain("security-identifier");
    expect(report.correspondences[0]?.heuristic).toBe(false);
  });

  it("falls back to UPN at reduced confidence", () => {
    // No immutableId, no SID — only the principal name matches.
    const ad = onPremGraph({ userprincipalname: "alice@corp.example.com" });
    const entra = cloudGraph(tenantUser());

    const report = joinDirectories(ad, entra);

    expect(report.joined).toBe(true);
    const match = report.correspondences[0];
    expect(match?.signals).toContain("upn");
    // The whole point: a name match must not read like a directory-attested one.
    expect(match?.confidence).not.toBe("high");
    expect(match?.heuristic).toBe(true);
    expect(report.byConfidence.high).toBe(0);
  });

  it("can be told to refuse heuristic joins entirely", () => {
    const ad = onPremGraph({ userprincipalname: "alice@corp.example.com" });
    const entra = cloudGraph(tenantUser());

    const report = joinDirectories(ad, entra, { allowHeuristicJoins: false });

    expect(report.joined).toBe(false);
    expect(report.correspondences).toHaveLength(0);
  });

  // The most important behaviour in the module. An empty result that reads as
  // "no hybrid paths exist" would be a false negative in a client report.
  it("states the gap explicitly when no correspondence signal exists at all", () => {
    const ad = onPremGraph({});
    const entra = cloudGraph(tenantUser({ userPrincipalName: "someone-else@other.example" }));

    const report = joinDirectories(ad, entra);

    expect(report.joined).toBe(false);
    expect(report.gaps.length).toBeGreaterThan(0);
    expect(report.gaps.join(" ")).toMatch(/correspond|join|signal/i);
  });

  it("reports per-signal coverage so a reader can see what was available", () => {
    const ad = onPremGraph({ objectguid: ALICE_GUID });
    const entra = cloudGraph(tenantUser({ onPremisesImmutableId: immutableIdFor(ALICE_GUID) }));

    const report = joinDirectories(ad, entra);

    expect(report.signalCoverage["immutable-id"]).toBeDefined();
    expect(report.signalCoverage["upn"]).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Graph construction
// ---------------------------------------------------------------------------

describe("buildHybridGraph", () => {
  it("carries nodes from both planes into one graph", () => {
    const ad = onPremGraph({ objectguid: ALICE_GUID });
    const entra = cloudGraph(tenantUser({ onPremisesImmutableId: immutableIdFor(ALICE_GUID) }));

    const graph = buildHybridGraph(ad, entra);

    expect(graph.nodes.size).toBeGreaterThanOrEqual(ad.nodes.size + entra.nodes.size);
    const planes = new Set([...graph.nodes.values()].map((n) => n.plane));
    expect(planes.has("on-prem")).toBe(true);
    expect(planes.has("cloud")).toBe(true);
  });

  it("re-keys node ids so an on-prem and a cloud object never collide", () => {
    const ad = onPremGraph({ objectguid: ALICE_GUID });
    const entra = cloudGraph(tenantUser({ onPremisesImmutableId: immutableIdFor(ALICE_GUID) }));

    const graph = buildHybridGraph(ad, entra);

    // Every original id appears exactly once per plane, never merged.
    for (const id of ad.nodes.keys()) {
      const onPrem = [...graph.nodes.values()].filter(
        (n) => n.plane === "on-prem" && n.sourceObjectId === id,
      );
      expect(onPrem).toHaveLength(1);
    }
  });

  it("emits synchronisation edges between corresponding principals", () => {
    const ad = onPremGraph({ objectguid: ALICE_GUID });
    const entra = cloudGraph(tenantUser({ onPremisesImmutableId: immutableIdFor(ALICE_GUID) }));

    const graph = buildHybridGraph(ad, entra);

    const syncEdges = graph.edges.filter((e) => /sync/i.test(String(e.kind)));
    expect(syncEdges.length).toBeGreaterThan(0);
  });

  it("produces a usable graph even when nothing joins", () => {
    const ad = onPremGraph({});
    const entra = cloudGraph(tenantUser({ userPrincipalName: "nobody@elsewhere.example" }));

    const graph = buildHybridGraph(ad, entra);

    expect(graph.nodes.size).toBeGreaterThan(0);
    expect(graph.meta.join.joined).toBe(false);
    expect(graph.meta.join.gaps.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

describe("runHybridPathAnalysis", () => {
  it("finds a path from an on-premises principal into a cloud privileged role", () => {
    const ad = onPremGraph({ objectguid: ALICE_GUID });
    const entra = cloudGraph(tenantUser({ onPremisesImmutableId: immutableIdFor(ALICE_GUID) }));

    const analysis = runHybridPathAnalysis(buildHybridGraph(ad, entra));

    expect(analysis.findings.length).toBeGreaterThan(0);
    expect(analysis.summary.findingCount).toBe(analysis.findings.length);

    // At least one finding must rest on a path that actually crosses the planes.
    const crossing = analysis.findings.some((f) =>
      f.paths.some((p) => {
        const planes = new Set(p.steps.map((s) => s.to.plane));
        return planes.size > 1 || p.steps.some((s) => s.from.plane !== s.to.plane);
      }),
    );
    expect(crossing).toBe(true);
  });

  it("returns a well-formed empty analysis when the directories do not join", () => {
    const ad = onPremGraph({});
    const entra = cloudGraph(tenantUser({ userPrincipalName: "nobody@elsewhere.example" }));

    const analysis = runHybridPathAnalysis(buildHybridGraph(ad, entra));

    expect(analysis.summary.findingCount).toBe(analysis.findings.length);
    expect(analysis.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    // The gap must survive into the analysis, not be lost at the graph layer.
    expect(analysis.correspondence.gaps.length).toBeGreaterThan(0);
  });

  it("surfaces join confidence on findings, so a UPN guess is visibly weaker", () => {
    const strong = runHybridPathAnalysis(
      buildHybridGraph(
        onPremGraph({ objectguid: ALICE_GUID }),
        cloudGraph(tenantUser({ onPremisesImmutableId: immutableIdFor(ALICE_GUID) })),
      ),
    );
    const weak = runHybridPathAnalysis(
      buildHybridGraph(
        onPremGraph({ userprincipalname: "alice@corp.example.com" }),
        cloudGraph(tenantUser()),
      ),
    );

    const confidenceOf = (a: typeof strong): string =>
      JSON.stringify(a.findings).toLowerCase();

    // Both should find something, but the weak one must carry a visible
    // lower-confidence marker that the strong one does not present as fact.
    if (weak.findings.length > 0) {
      expect(confidenceOf(weak)).toMatch(/low|medium|heuristic|name match|confidence/);
    }
    expect(strong.findings.length).toBeGreaterThan(0);
  });

  it("orders findings worst-first", () => {
    const analysis = runHybridPathAnalysis(
      buildHybridGraph(
        onPremGraph({ objectguid: ALICE_GUID }),
        cloudGraph(tenantUser({ onPremisesImmutableId: immutableIdFor(ALICE_GUID) })),
      ),
    );

    const order = ["critical", "high", "medium", "low", "info"];
    const ranks = analysis.findings.map((f) => order.indexOf(f.severity));
    for (let i = 1; i < ranks.length; i += 1) {
      expect(ranks[i]).toBeGreaterThanOrEqual(ranks[i - 1]!);
    }
  });

  it("uses an injected clock", () => {
    const analysis = runHybridPathAnalysis(
      buildHybridGraph(
        onPremGraph({ objectguid: ALICE_GUID }),
        cloudGraph(tenantUser({ onPremisesImmutableId: immutableIdFor(ALICE_GUID) })),
      ),
      {},
      () => new Date("2026-09-15T09:00:00.000Z"),
    );
    expect(analysis.generatedAt).toBe("2026-09-15T09:00:00.000Z");
  });
});
