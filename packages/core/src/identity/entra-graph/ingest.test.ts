import { describe, expect, it } from "vitest";
import { buildEntraGraphFromAzureHound, ingestAzureHound } from "./ingest.js";
import { runEntraPathAnalysis } from "./index.js";

// AzureHound writes one document per collection. These fixtures use the modern
// `{ kind, data }` item shape; `flat item` cases below cover the older one.
const doc = (type: string, items: unknown[]): unknown => ({
  data: items,
  meta: { type, count: items.length, version: 5 },
});

const kinded = (kind: string, data: Record<string, unknown>): unknown => ({ kind, data });

const GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10";
const TENANT = "11111111-1111-1111-1111-111111111111";

/** A guest who is a member of a group that holds Global Administrator. */
function guestToGlobalAdminExport(): unknown[] {
  return [
    doc("aztenants", [kinded("AZTenant", { id: TENANT, tenantId: TENANT, displayName: "Contoso" })]),
    doc("azusers", [
      kinded("AZUser", {
        id: "aaaaaaaa-0000-0000-0000-000000000001",
        displayName: "Guest Auditor",
        userPrincipalName: "guest_auditor#EXT#@contoso.onmicrosoft.com",
        userType: "Guest",
        accountEnabled: true,
        tenantId: TENANT,
      }),
    ]),
    doc("azgroups", [
      kinded("AZGroup", {
        id: "bbbbbbbb-0000-0000-0000-000000000001",
        displayName: "Legacy Admins",
        securityEnabled: true,
        tenantId: TENANT,
      }),
    ]),
    doc("azgroupmembers", [
      kinded("AZGroupMember", {
        groupId: "bbbbbbbb-0000-0000-0000-000000000001",
        member: {
          id: "aaaaaaaa-0000-0000-0000-000000000001",
          "@odata.type": "#microsoft.graph.user",
          displayName: "Guest Auditor",
        },
      }),
    ]),
    doc("azroles", [
      kinded("AZRole", {
        id: GLOBAL_ADMIN_TEMPLATE,
        templateId: GLOBAL_ADMIN_TEMPLATE,
        displayName: "Global Administrator",
        isBuiltIn: true,
      }),
    ]),
    doc("azroleassignments", [
      kinded("AZRoleAssignment", {
        id: "ra-1",
        roleDefinitionId: GLOBAL_ADMIN_TEMPLATE,
        principalId: "bbbbbbbb-0000-0000-0000-000000000001",
        directoryScopeId: "/",
      }),
    ]),
  ];
}

describe("ingestAzureHound", () => {
  it("reconstructs a snapshot from a complete export", () => {
    const { snapshot, collections } = ingestAzureHound(guestToGlobalAdminExport());

    expect(snapshot.tenantId).toBe(TENANT);
    expect(snapshot.tenantDisplayName).toBe("Contoso");
    expect(snapshot.users).toHaveLength(1);
    expect(snapshot.groups).toHaveLength(1);
    expect(snapshot.roleAssignments).toHaveLength(1);
    expect(snapshot.relationships?.groupMembers).toHaveLength(1);
    expect(collections).toContain("azusers");
    expect(collections).toContain("azgroupmembers");
  });

  it("accepts the older flat item shape without a kind wrapper", () => {
    const { snapshot } = ingestAzureHound([
      doc("azusers", [{ id: "aaaa", displayName: "Flat User", userType: "Member" }]),
    ]);
    expect(snapshot.users).toHaveLength(1);
    expect(snapshot.users[0]?.displayName).toBe("Flat User");
  });

  it("normalises casing differences across collector versions", () => {
    const { snapshot } = ingestAzureHound([
      doc("azusers", [kinded("AZUser", { Id: "AAAA-BBBB", DisplayName: "Upper Case" })]),
    ]);
    expect(snapshot.users[0]?.id).toBe("AAAA-BBBB");
    expect(snapshot.users[0]?.displayName).toBe("Upper Case");
  });

  it("distinguishes 'relationships not collected' from 'no relationships exist'", () => {
    // Users and groups only — the collector was never asked for membership.
    const { snapshot, warnings } = ingestAzureHound([
      doc("azusers", [kinded("AZUser", { id: "u1" })]),
      doc("azgroups", [kinded("AZGroup", { id: "g1" })]),
    ]);

    expect(snapshot.relationships).toBeUndefined();
    expect(warnings.some((w) => w.includes("not evidence that none exist"))).toBe(true);
  });

  it("records relationships as collected when any relationship collection is present", () => {
    const { snapshot } = ingestAzureHound([
      doc("azgroupmembers", [kinded("AZGroupMember", { groupId: "g1", member: { id: "u1" } })]),
    ]);
    expect(snapshot.relationships).toBeDefined();
    expect(snapshot.relationships?.groupMembers).toHaveLength(1);
  });

  it("routes owner collections to their own buckets", () => {
    const { snapshot } = ingestAzureHound([
      doc("azappowners", [kinded("AZAppOwner", { objectId: "app1", owner: { id: "u1" } })]),
      doc("azserviceprincipalowners", [kinded("AZServicePrincipalOwner", { objectId: "sp1", owner: { id: "u2" } })]),
    ]);
    expect(snapshot.relationships?.applicationOwners).toHaveLength(1);
    expect(snapshot.relationships?.servicePrincipalOwners).toHaveLength(1);
    expect(snapshot.relationships?.applicationOwners[0]?.ownerId).toBe("u1");
    expect(snapshot.relationships?.servicePrincipalOwners[0]?.ownerId).toBe("u2");
  });

  it("drops self-referential membership and ownership rows", () => {
    const { snapshot } = ingestAzureHound([
      doc("azgroupmembers", [kinded("AZGroupMember", { groupId: "same", member: { id: "same" } })]),
      doc("azappowners", [kinded("AZAppOwner", { objectId: "same2", owner: { id: "same2" } })]),
    ]);
    expect(snapshot.relationships?.groupMembers).toHaveLength(0);
    expect(snapshot.relationships?.applicationOwners).toHaveLength(0);
  });

  it("warns rather than throwing on a malformed document", () => {
    const { snapshot, warnings } = ingestAzureHound([
      "not an object",
      { data: "not an array" },
      null,
      doc("azusers", [kinded("AZUser", { id: "u1" })]),
    ]);
    expect(snapshot.users).toHaveLength(1);
    expect(warnings.some((w) => w.includes("expected an array"))).toBe(true);
  });

  it("warns on items with no recognisable collection", () => {
    const { warnings } = ingestAzureHound([doc("azsubscriptions", [kinded("AZSubscription", { id: "s1" })])]);
    expect(warnings.some((w) => w.includes("no recognised AzureHound kind"))).toBe(true);
  });

  it("always states that posture collections are absent from an AzureHound export", () => {
    const { warnings, snapshot } = ingestAzureHound(guestToGlobalAdminExport());
    expect(snapshot.conditionalAccessPolicies).toHaveLength(0);
    expect(snapshot.federationConfig.domains).toHaveLength(0);
    expect(warnings.some((w) => w.includes("conditional-access"))).toBe(true);
  });

  it("reports an unknown tenant rather than inventing one", () => {
    const { snapshot, warnings } = ingestAzureHound([doc("azusers", [kinded("AZUser", { id: "u1" })])]);
    expect(snapshot.tenantId).toBe("unknown");
    expect(warnings.some((w) => w.includes("no tenant id"))).toBe(true);
  });

  it("tolerates an entirely empty input", () => {
    const { snapshot, collections } = ingestAzureHound([]);
    expect(snapshot.users).toHaveLength(0);
    expect(collections).toHaveLength(0);
  });
});

describe("buildEntraGraphFromAzureHound", () => {
  it("tags the graph as an offline reconstruction, not a live collection", () => {
    const { graph } = buildEntraGraphFromAzureHound(guestToGlobalAdminExport());
    expect(graph.meta.origin).toBe("azurehound");
    expect(graph.meta.relationshipsCollected).toBe(true);
    expect(graph.meta.tenantId).toBe(TENANT.toLowerCase());
  });

  it("records the collections present as the graph's source types", () => {
    const { graph } = buildEntraGraphFromAzureHound(guestToGlobalAdminExport());
    expect(graph.meta.sourceTypes).toContain("azusers");
    expect(graph.meta.sourceTypes).toContain("azroleassignments");
  });

  it("carries relationshipsCollected=false through to the graph when absent", () => {
    const { graph } = buildEntraGraphFromAzureHound([doc("azusers", [kinded("AZUser", { id: "u1" })])]);
    expect(graph.meta.relationshipsCollected).toBe(false);
  });

  it("builds nodes for every collected object type", () => {
    const { graph } = buildEntraGraphFromAzureHound(guestToGlobalAdminExport());
    expect(graph.meta.counts.users).toBe(1);
    expect(graph.meta.counts.groups).toBe(1);
    expect(graph.nodes.size).toBeGreaterThan(0);
  });
});

describe("runEntraPathAnalysis over an AzureHound export", () => {
  it("finds a guest's path to Global Administrator through group membership", () => {
    const { graph } = buildEntraGraphFromAzureHound(guestToGlobalAdminExport());
    const analysis = runEntraPathAnalysis(graph);

    expect(analysis.findings.length).toBeGreaterThan(0);
    expect(analysis.summary.findingCount).toBe(analysis.findings.length);
    expect(analysis.summary.pathCount).toBeGreaterThan(0);
    expect(analysis.graph.origin).toBe("azurehound");
  });

  it("returns an empty, well-formed analysis when there is no path", () => {
    // A lone disabled user, no groups, no roles.
    const { graph } = buildEntraGraphFromAzureHound([
      doc("azusers", [kinded("AZUser", { id: "u1", accountEnabled: false })]),
    ]);
    const analysis = runEntraPathAnalysis(graph);

    expect(analysis.findings).toHaveLength(0);
    expect(analysis.summary.findingCount).toBe(0);
    expect(analysis.summary.pathCount).toBe(0);
    expect(analysis.summary.topSeverity).toBe("info");
    expect(analysis.summary.shortestPathLength).toBeUndefined();
    expect(analysis.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("respects a maxDepth ceiling", () => {
    const { graph } = buildEntraGraphFromAzureHound(guestToGlobalAdminExport());
    const deep = runEntraPathAnalysis(graph, { maxDepth: 8 });
    const shallow = runEntraPathAnalysis(graph, { maxDepth: 1 });

    for (const f of shallow.findings) {
      for (const p of f.paths) expect(p.length).toBeLessThanOrEqual(1);
    }
    expect(shallow.summary.pathCount).toBeLessThanOrEqual(deep.summary.pathCount);
  });

  it("orders findings worst-first", () => {
    const { graph } = buildEntraGraphFromAzureHound(guestToGlobalAdminExport());
    const order = ["critical", "high", "medium", "low", "info"];
    const seen = runEntraPathAnalysis(graph).findings.map((f) => order.indexOf(f.severity));
    for (let i = 1; i < seen.length; i += 1) {
      expect(seen[i]).toBeGreaterThanOrEqual(seen[i - 1]!);
    }
  });

  it("uses an injected clock for generatedAt", () => {
    const { graph } = buildEntraGraphFromAzureHound(guestToGlobalAdminExport());
    const analysis = runEntraPathAnalysis(graph, {}, () => new Date("2026-09-15T09:00:00.000Z"));
    expect(analysis.generatedAt).toBe("2026-09-15T09:00:00.000Z");
  });
});
