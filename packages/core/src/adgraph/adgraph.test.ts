import { describe, expect, it } from "vitest";
import {
  buildAdGraph,
  domainAdminGroupIds,
  findAclAbuseChains,
  findAdcsEscalation,
  findDcsyncPrincipals,
  findKerberoastablePaths,
  findPathsToDomainAdmin,
  findUnconstrainedDelegation,
  highValueTargetIds,
  ingestBloodHoundFiles,
  ingestBloodHoundJson,
  parseBloodHoundFile,
  reachableFrom,
  reachableTo,
  runAdGraphAnalysis,
  shortestPaths,
} from "./index.js";
import type { AdEdge, AdEdgeKind, AdGraph, AdNode, AttackPath } from "./types.js";

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

const DOMAIN_SID = "S-1-5-21-1-2-3";
const DOMAIN_ADMINS = `${DOMAIN_SID}-512`;
const ENTERPRISE_ADMINS = `${DOMAIN_SID}-519`;
const DOMAIN_CONTROLLERS = `${DOMAIN_SID}-516`;

function node(objectId: string, kind: string, properties: Record<string, unknown> = {}): AdNode {
  return { objectId, label: objectId, kind, properties };
}

function edge(source: string, kind: AdEdgeKind, target: string): AdEdge {
  return { source, target, kind };
}

function graphOf(nodes: AdNode[], edges: AdEdge[]): AdGraph {
  return buildAdGraph(nodes, edges);
}

/** `A -MemberOf-> B -GenericAll-> C` rendered as `"A -MemberOf-> B -GenericAll-> C"`. */
function renderPath(path: AttackPath): string {
  return (
    path.steps[0]!.from.objectId +
    path.steps.map((step) => ` -${step.edge.kind}-> ${step.to.objectId}`).join("")
  );
}

/**
 * Traversal fixture with two competing routes A -> D and a cycle back to the
 * start. Hop counts and costs are known by construction:
 *
 *   A -AdminTo-> E -GenericAll-> D                     2 hops
 *   A -MemberOf-> B -GenericWrite-> C -AddMember-> D   3 hops
 *   D -Owns-> A                                        closes the cycle
 *   F <-> G                                            isolated 2-cycle
 *   H                                                  isolated
 */
function twoRouteGraph(): AdGraph {
  return graphOf(
    ["A", "B", "C", "D", "E", "F", "G", "H"].map((id) => node(id, "Base")),
    [
      edge("A", "AdminTo", "E"),
      edge("E", "GenericAll", "D"),
      edge("A", "MemberOf", "B"),
      edge("B", "GenericWrite", "C"),
      edge("C", "AddMember", "D"),
      edge("D", "Owns", "A"),
      edge("F", "MemberOf", "G"),
      edge("G", "MemberOf", "F"),
    ],
  );
}

// ---------------------------------------------------------------------------
// shortestPaths
// ---------------------------------------------------------------------------

describe("shortestPaths", () => {
  it("returns the genuinely shortest of two competing routes", () => {
    const paths = shortestPaths(twoRouteGraph(), ["A"], ["D"]);

    expect(paths).toHaveLength(1);
    expect(paths[0]!.length).toBe(2);
    expect(paths[0]!.cost).toBe(2);
    expect(renderPath(paths[0]!)).toBe("A -AdminTo-> E -GenericAll-> D");
    expect(paths[0]!.technique).toBe("AdminTo -> GenericAll");
    expect(paths[0]!.sourceId).toBe("A");
    expect(paths[0]!.targetId).toBe("D");
  });

  it("falls back to the longer route when the short one is filtered out", () => {
    const paths = shortestPaths(twoRouteGraph(), ["A"], ["D"], { deniedEdgeKinds: ["AdminTo"] });

    expect(paths).toHaveLength(1);
    expect(renderPath(paths[0]!)).toBe("A -MemberOf-> B -GenericWrite-> C -AddMember-> D");
    expect(paths[0]!.length).toBe(3);
  });

  it("respects edge direction and does not walk edges backwards", () => {
    const graph = graphOf([node("X", "User"), node("Y", "Group")], [edge("X", "MemberOf", "Y")]);

    expect(shortestPaths(graph, ["X"], ["Y"])).toHaveLength(1);
    expect(shortestPaths(graph, ["Y"], ["X"])).toHaveLength(0);
  });

  it("terminates on a cycle instead of looping forever", () => {
    // C1 -> C2 -> C3 -> C1 is a closed loop; only C3 leaves it.
    const graph = graphOf(
      ["C1", "C2", "C3", "T"].map((id) => node(id, "Base")),
      [
        edge("C1", "MemberOf", "C2"),
        edge("C2", "MemberOf", "C3"),
        edge("C3", "MemberOf", "C1"),
        edge("C3", "GenericAll", "T"),
      ],
    );

    const paths = shortestPaths(graph, ["C1"], ["T"], { maxDepth: 20 });
    expect(paths).toHaveLength(1);
    expect(paths[0]!.length).toBe(3);
    expect(renderPath(paths[0]!)).toBe("C1 -MemberOf-> C2 -MemberOf-> C3 -GenericAll-> T");
    // No node repeats: a looping search would have produced a longer walk.
    const visited = paths[0]!.steps.map((step) => step.to.objectId);
    expect(new Set(visited).size).toBe(visited.length);
  });

  it("terminates when the target is unreachable from inside a cycle", () => {
    const graph = graphOf(
      ["F", "G", "H"].map((id) => node(id, "Base")),
      [edge("F", "MemberOf", "G"), edge("G", "MemberOf", "F")],
    );

    expect(shortestPaths(graph, ["F"], ["H"], { maxDepth: 50 })).toEqual([]);
  });

  it("honors maxDepth", () => {
    const graph = twoRouteGraph();

    expect(shortestPaths(graph, ["A"], ["D"], { maxDepth: 1 })).toEqual([]);
    expect(shortestPaths(graph, ["A"], ["D"], { maxDepth: 2 })).toHaveLength(1);
  });

  it("honors maxResults", () => {
    const graph = graphOf(
      [node("S", "User"), ...["T1", "T2", "T3", "T4", "T5"].map((id) => node(id, "Group"))],
      ["T1", "T2", "T3", "T4", "T5"].map((id) => edge("S", "MemberOf", id)),
    );

    expect(shortestPaths(graph, ["S"], ["T1", "T2", "T3", "T4", "T5"])).toHaveLength(5);
    expect(shortestPaths(graph, ["S"], ["T1", "T2", "T3", "T4", "T5"], { maxResults: 2 })).toHaveLength(2);
  });

  it("honors the maxExpansions budget", () => {
    // One relaxation is not enough to cross two hops.
    expect(shortestPaths(twoRouteGraph(), ["A"], ["D"], { maxExpansions: 1 })).toEqual([]);
  });

  it("minimises cost, not hop count, when edges are weighted", () => {
    const graph = twoRouteGraph();
    // Make the 2-hop route expensive (10 + 10) and the 3-hop route cheap (1+1+1).
    const edgeCost = (e: AdEdge) => (e.kind === "AdminTo" || e.kind === "GenericAll" ? 10 : 1);

    const paths = shortestPaths(graph, ["A"], ["D"], { edgeCost });
    expect(paths).toHaveLength(1);
    expect(paths[0]!.length).toBe(3);
    expect(paths[0]!.cost).toBe(3);
    expect(renderPath(paths[0]!)).toBe("A -MemberOf-> B -GenericWrite-> C -AddMember-> D");
  });

  it("still returns the cheapest path that fits inside maxDepth", () => {
    // The cheap route needs 3 hops; capping at 2 must fall back to the
    // expensive-but-short one rather than returning nothing. This is the
    // bi-criteria (cost, depth) label behaviour — plain Dijkstra would miss it.
    const graph = twoRouteGraph();
    const edgeCost = (e: AdEdge) => (e.kind === "AdminTo" || e.kind === "GenericAll" ? 10 : 1);

    const paths = shortestPaths(graph, ["A"], ["D"], { edgeCost, maxDepth: 2 });
    expect(paths).toHaveLength(1);
    expect(paths[0]!.length).toBe(2);
    expect(paths[0]!.cost).toBe(20);
    expect(renderPath(paths[0]!)).toBe("A -AdminTo-> E -GenericAll-> D");
  });

  it("searches from many sources at once and reports the reaching source", () => {
    const graph = graphOf(
      [node("P1", "User"), node("P2", "User"), node("MID", "Group"), node("GOAL", "Group")],
      [edge("P1", "MemberOf", "MID"), edge("MID", "MemberOf", "GOAL"), edge("P2", "MemberOf", "GOAL")],
    );

    const paths = shortestPaths(graph, ["P1", "P2"], ["GOAL"]);
    expect(paths).toHaveLength(1);
    // P2 is one hop away, P1 is two — the cheaper source wins.
    expect(paths[0]!.sourceId).toBe("P2");
    expect(paths[0]!.length).toBe(1);
  });

  it("sorts results cheapest first", () => {
    const graph = graphOf(
      [node("S", "User"), node("NEAR", "Group"), node("MID", "Group"), node("FAR", "Group")],
      [edge("S", "MemberOf", "NEAR"), edge("NEAR", "MemberOf", "MID"), edge("MID", "MemberOf", "FAR")],
    );

    const paths = shortestPaths(graph, ["S"], ["FAR", "NEAR", "MID"]);
    expect(paths.map((path) => path.targetId)).toEqual(["NEAR", "MID", "FAR"]);
    expect(paths.map((path) => path.length)).toEqual([1, 2, 3]);
  });

  it("returns nothing for unknown sources or targets", () => {
    const graph = twoRouteGraph();
    expect(shortestPaths(graph, ["nope"], ["D"])).toEqual([]);
    expect(shortestPaths(graph, ["A"], ["nope"])).toEqual([]);
    expect(shortestPaths(graph, [], ["D"])).toEqual([]);
  });

  it("does not report a zero-length path when a source is also a target", () => {
    expect(shortestPaths(twoRouteGraph(), ["A"], ["A"])).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// reachableFrom / reachableTo
// ---------------------------------------------------------------------------

describe("reachability", () => {
  it("maps forward reachability to minimum hop distance", () => {
    const reached = reachableFrom(twoRouteGraph(), ["A"], 10);

    expect(reached.get("A")).toBe(0);
    expect(reached.get("B")).toBe(1);
    expect(reached.get("E")).toBe(1);
    expect(reached.get("C")).toBe(2);
    expect(reached.get("D")).toBe(2); // via A -> E -> D, not the 3-hop route
    expect(reached.has("F")).toBe(false);
    expect(reached.has("H")).toBe(false);
  });

  it("terminates on cycles", () => {
    const graph = graphOf(
      ["C1", "C2", "C3"].map((id) => node(id, "Base")),
      [edge("C1", "MemberOf", "C2"), edge("C2", "MemberOf", "C3"), edge("C3", "MemberOf", "C1")],
    );

    const reached = reachableFrom(graph, ["C1"], 1000);
    expect([...reached.keys()].sort()).toEqual(["C1", "C2", "C3"]);
    expect(reached.get("C1")).toBe(0);
  });

  it("honors maxDepth", () => {
    const reached = reachableFrom(twoRouteGraph(), ["A"], 1);
    expect([...reached.keys()].sort()).toEqual(["A", "B", "E"]);
  });

  it("walks edges backwards for reachableTo", () => {
    const reached = reachableTo(twoRouteGraph(), ["D"], 10);

    expect(reached.get("D")).toBe(0);
    expect(reached.get("E")).toBe(1);
    expect(reached.get("C")).toBe(1);
    expect(reached.get("A")).toBe(2); // A -AdminTo-> E -GenericAll-> D
    expect(reached.get("B")).toBe(2);
    expect(reached.has("H")).toBe(false);
  });

  it("filters edge kinds, which is how group membership is expanded", () => {
    const graph = graphOf(
      [node("U", "User"), node("G", "Group"), node("O", "User")],
      [edge("U", "MemberOf", "G"), edge("O", "GenericAll", "G")],
    );

    const members = reachableTo(graph, ["G"], 5, { allowedEdgeKinds: ["MemberOf"] });
    expect(members.has("U")).toBe(true);
    expect(members.has("O")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// ingest
// ---------------------------------------------------------------------------

const USERS_FILE = {
  data: [
    {
      ObjectIdentifier: `${DOMAIN_SID}-1105`,
      Properties: {
        name: "SVC_SQL@LAB.LOCAL",
        domain: "LAB.LOCAL",
        domainsid: DOMAIN_SID,
        hasspn: true,
        enabled: true,
        AdminCount: false,
        serviceprincipalnames: ["MSSQLSvc/db01.lab.local:1433"],
      },
      PrimaryGroupSID: `${DOMAIN_SID}-513`,
      Aces: [
        {
          PrincipalSID: `${DOMAIN_SID}-1106`,
          PrincipalType: "User",
          RightName: "GenericAll",
          IsInherited: false,
        },
      ],
      SPNTargets: [{ ComputerSID: `${DOMAIN_SID}-1001`, Port: 1433, Service: "SQLAdmin" }],
      HasSIDHistory: [],
      IsDeleted: false,
    },
    {
      ObjectIdentifier: `${DOMAIN_SID}-1106`,
      Properties: { name: "ALICE@LAB.LOCAL", enabled: true },
      PrimaryGroupSID: `${DOMAIN_SID}-513`,
      Aces: [],
    },
    null,
    { Properties: { name: "NO-ID@LAB.LOCAL" } },
  ],
  meta: { methods: 5, type: "users", count: 4, version: 6 },
};

const GROUPS_FILE = {
  data: [
    {
      ObjectIdentifier: DOMAIN_ADMINS,
      Properties: { name: "DOMAIN ADMINS@LAB.LOCAL", admincount: true, highvalue: true },
      Members: [
        { ObjectIdentifier: `${DOMAIN_SID}-500`, ObjectType: "User" },
        { ObjectIdentifier: `${DOMAIN_SID}-1107`, ObjectType: "User" },
      ],
      Aces: [{ PrincipalSID: `${DOMAIN_SID}-1106`, PrincipalType: "User", RightName: "WriteDacl" }],
    },
  ],
  meta: { type: "groups", count: 1, version: 6 },
};

const COMPUTERS_FILE = {
  data: [
    {
      ObjectIdentifier: `${DOMAIN_SID}-1001`,
      Properties: {
        name: "DB01.LAB.LOCAL",
        UnconstrainedDelegation: true,
        enabled: true,
        operatingsystem: "Windows Server 2019 Standard",
      },
      PrimaryGroupSID: `${DOMAIN_SID}-515`,
      LocalAdmins: {
        Collected: true,
        FailureReason: null,
        Results: [{ ObjectIdentifier: `${DOMAIN_SID}-1106`, ObjectType: "User" }],
      },
      Sessions: {
        Collected: true,
        Results: [{ UserSID: `${DOMAIN_SID}-1107`, ComputerSID: `${DOMAIN_SID}-1001` }],
      },
      // Bare-array form of a collection that newer collectors wrap in Results.
      RemoteDesktopUsers: [{ ObjectIdentifier: `${DOMAIN_SID}-1105`, ObjectType: "User" }],
      AllowedToDelegate: [],
      Aces: [],
    },
  ],
  meta: { type: "computers", count: 1, version: 6 },
};

const DOMAINS_FILE = {
  data: [
    {
      ObjectIdentifier: DOMAIN_SID,
      Properties: { name: "LAB.LOCAL", domain: "LAB.LOCAL" },
      Aces: [
        { PrincipalSID: `${DOMAIN_SID}-1106`, PrincipalType: "User", RightName: "GetChanges" },
        { PrincipalSID: `${DOMAIN_SID}-1106`, PrincipalType: "User", RightName: "GetChangesAll" },
        // Legacy alias that must normalise to Owns.
        { PrincipalSID: DOMAIN_ADMINS, PrincipalType: "Group", RightName: "Owner" },
        // Unknown right: kept verbatim, never dropped.
        { PrincipalSID: `${DOMAIN_SID}-1106`, PrincipalType: "User", RightName: "SomeFutureRight" },
        { PrincipalType: "User", RightName: "GenericAll" }, // malformed, no principal
      ],
      Trusts: [
        {
          TargetDomainSid: "S-1-5-21-9-9-9",
          TargetDomainName: "PARTNER.LOCAL",
          TrustDirection: 1,
          TrustType: "Forest",
          IsTransitive: true,
          SidFilteringEnabled: false,
        },
      ],
      ChildObjects: [{ ObjectIdentifier: `${DOMAIN_SID}-1105`, ObjectType: "User" }],
      Links: [{ IsEnforced: false, Guid: "11111111-1111-1111-1111-111111111111" }],
    },
  ],
  meta: { type: "domains", count: 1, version: 6 },
};

/** A CE graph export — the only source of post-processed ADCS ESC edges. */
const GRAPH_EXPORT_FILE = {
  data: {
    nodes: {
      "42": { objectId: `${DOMAIN_SID}-1106`, label: "ALICE@LAB.LOCAL", kind: "User", properties: {} },
      "43": { objectId: "CERT-TEMPLATE-GUID", label: "VULNTEMPLATE@LAB.LOCAL", kind: "CertTemplate", properties: {} },
    },
    edges: [
      { source: "42", target: "43", kind: "ADCSESC1" },
      { source: "42", kind: "ADCSESC1" }, // malformed: no target
    ],
  },
  meta: { type: "graph-export", count: 2 },
};

describe("ingestBloodHoundFiles", () => {
  const graph = ingestBloodHoundFiles([USERS_FILE, GROUPS_FILE, COMPUTERS_FILE, DOMAINS_FILE, GRAPH_EXPORT_FILE]);

  const hasEdge = (source: string, kind: string, target: string): boolean =>
    graph.edges.some((e) => e.source === source && e.kind === kind && e.target === target);

  it("assigns node kinds from meta.type", () => {
    expect(graph.nodes.get(`${DOMAIN_SID}-1105`)?.kind).toBe("User");
    expect(graph.nodes.get(DOMAIN_ADMINS)?.kind).toBe("Group");
    expect(graph.nodes.get(`${DOMAIN_SID}-1001`)?.kind).toBe("Computer");
    expect(graph.nodes.get(DOMAIN_SID)?.kind).toBe("Domain");
    expect(graph.nodes.get("CERT-TEMPLATE-GUID")?.kind).toBe("CertTemplate");
  });

  it("lower-cases property keys so analyzers can rely on them", () => {
    const computer = graph.nodes.get(`${DOMAIN_SID}-1001`)!;
    expect(computer.properties.unconstraineddelegation).toBe(true);
    expect(computer.properties.UnconstrainedDelegation).toBeUndefined();
    expect(graph.nodes.get(`${DOMAIN_SID}-1105`)!.properties.admincount).toBe(false);
  });

  it("points ACE edges from the principal to the object it controls", () => {
    // Alice holds GenericAll over the service account, not the other way round.
    expect(hasEdge(`${DOMAIN_SID}-1106`, "GenericAll", `${DOMAIN_SID}-1105`)).toBe(true);
    expect(hasEdge(`${DOMAIN_SID}-1105`, "GenericAll", `${DOMAIN_SID}-1106`)).toBe(false);
    expect(hasEdge(`${DOMAIN_SID}-1106`, "WriteDacl", DOMAIN_ADMINS)).toBe(true);
  });

  it("points MemberOf from the member to the group", () => {
    expect(hasEdge(`${DOMAIN_SID}-1107`, "MemberOf", DOMAIN_ADMINS)).toBe(true);
    expect(hasEdge(DOMAIN_ADMINS, "MemberOf", `${DOMAIN_SID}-1107`)).toBe(false);
    // PrimaryGroupSID is a membership too.
    expect(hasEdge(`${DOMAIN_SID}-1105`, "MemberOf", `${DOMAIN_SID}-513`)).toBe(true);
  });

  it("points computer-scoped rights the right way round", () => {
    expect(hasEdge(`${DOMAIN_SID}-1106`, "AdminTo", `${DOMAIN_SID}-1001`)).toBe(true);
    expect(hasEdge(`${DOMAIN_SID}-1105`, "CanRDP", `${DOMAIN_SID}-1001`)).toBe(true);
    // Sessions run computer -> user: the host holds the user's credentials.
    expect(hasEdge(`${DOMAIN_SID}-1001`, "HasSession", `${DOMAIN_SID}-1107`)).toBe(true);
    expect(hasEdge(`${DOMAIN_SID}-1105`, "SQLAdmin", `${DOMAIN_SID}-1001`)).toBe(true);
  });

  it("derives containment, GPO links and trusts", () => {
    expect(hasEdge(DOMAIN_SID, "Contains", `${DOMAIN_SID}-1105`)).toBe(true);
    // The GPO is the abuse origin, so the edge is emitted GPO -> container.
    expect(hasEdge("11111111-1111-1111-1111-111111111111", "GPLink", DOMAIN_SID)).toBe(true);
    // Inbound trust: the target domain trusts us, so we can traverse into it.
    expect(hasEdge(DOMAIN_SID, "TrustedBy", "S-1-5-21-9-9-9")).toBe(true);
    expect(hasEdge("S-1-5-21-9-9-9", "TrustedBy", DOMAIN_SID)).toBe(false);
  });

  it("normalises legacy right names but keeps unknown ones verbatim", () => {
    expect(hasEdge(DOMAIN_ADMINS, "Owns", DOMAIN_SID)).toBe(true);
    expect(hasEdge(`${DOMAIN_SID}-1106`, "SomeFutureRight", DOMAIN_SID)).toBe(true);
    expect(graph.edgesByKind.has("SomeFutureRight")).toBe(true);
  });

  it("ingests post-processed edges from a graph export", () => {
    expect(hasEdge(`${DOMAIN_SID}-1106`, "ADCSESC1", "CERT-TEMPLATE-GUID")).toBe(true);
  });

  it("creates stubs for referenced but uncollected principals", () => {
    const stub = graph.nodes.get(`${DOMAIN_SID}-500`);
    expect(stub).toBeDefined();
    expect(stub!.stub).toBe(true);
    expect(stub!.kind).toBe("User");
    // A fully collected object is never a stub.
    expect(graph.nodes.get(`${DOMAIN_SID}-1106`)!.stub).toBeUndefined();
  });

  it("builds a consistent adjacency index", () => {
    expect(graph.meta.nodeCount).toBe(graph.nodes.size);
    expect(graph.meta.edgeCount).toBe(graph.edges.length);
    for (const [nodeId, edgeIndices] of graph.outbound) {
      for (const index of edgeIndices) expect(graph.edges[index]!.source).toBe(nodeId);
    }
    for (const [nodeId, edgeIndices] of graph.inbound) {
      for (const index of edgeIndices) expect(graph.edges[index]!.target).toBe(nodeId);
    }
    for (const [kind, edgeIndices] of graph.edgesByKind) {
      for (const index of edgeIndices) expect(graph.edges[index]!.kind).toBe(kind);
    }
    // Every edge endpoint resolves to a node — no dangling adjacency.
    for (const e of graph.edges) {
      expect(graph.nodes.has(e.source)).toBe(true);
      expect(graph.nodes.has(e.target)).toBe(true);
    }
  });

  it("records warnings for malformed records instead of throwing", () => {
    expect(graph.meta.warnings.length).toBeGreaterThan(0);
    expect(graph.meta.warnings.some((w) => w.includes("missing ObjectIdentifier"))).toBe(true);
    expect(graph.meta.warnings.some((w) => w.includes("not an object"))).toBe(true);
    expect(graph.meta.warnings.some((w) => w.includes("PrincipalSID"))).toBe(true);
  });

  it("tracks collector provenance", () => {
    expect(graph.meta.sourceTypes).toContain("users");
    expect(graph.meta.sourceTypes).toContain("domains");
    expect(graph.meta.collectorVersion).toBe(6);
    expect(graph.meta.ingestedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("is traversable end to end", () => {
    // Alice -WriteDacl-> Domain Admins is a real one-hop escalation here.
    const paths = shortestPaths(graph, [`${DOMAIN_SID}-1106`], [DOMAIN_ADMINS]);
    expect(paths).toHaveLength(1);
    expect(paths[0]!.steps[0]!.edge.kind).toBe("WriteDacl");
  });
});

describe("parseBloodHoundFile resilience", () => {
  it("never throws on junk input", () => {
    for (const junk of [null, undefined, 42, "string", [], {}, { data: 5 }, { data: [1, 2, 3] }]) {
      expect(() => parseBloodHoundFile(junk)).not.toThrow();
    }
    expect(parseBloodHoundFile({ data: "not-an-array" }).warnings.length).toBeGreaterThan(0);
  });

  it("keeps records from an unknown collection type", () => {
    const chunk = parseBloodHoundFile({
      data: [{ ObjectIdentifier: "S-1-5-21-7-7-7-1000", ObjectType: "Something", Properties: { name: "X" } }],
      meta: { type: "somethings", count: 1 },
    });

    expect(chunk.nodes).toHaveLength(1);
    expect(chunk.nodes[0]!.kind).toBe("Something");
    expect(chunk.warnings.some((w) => w.includes("unknown collector type"))).toBe(true);
  });

  it("upper-cases object identifiers so SID casing never splits a node", () => {
    const graph = ingestBloodHoundFiles([
      {
        data: [
          { ObjectIdentifier: "s-1-5-21-4-4-4-1000", Properties: { name: "LOWER" } },
          { ObjectIdentifier: "S-1-5-21-4-4-4-1000", Properties: { name: "UPPER" } },
        ],
        meta: { type: "users", count: 2 },
      },
    ]);

    expect(graph.nodes.size).toBe(1);
    expect(graph.nodes.has("S-1-5-21-4-4-4-1000")).toBe(true);
  });

  it("collapses duplicate edges", () => {
    const graph = ingestBloodHoundFiles([
      {
        data: [
          {
            ObjectIdentifier: "S-1-5-21-4-4-4-2000",
            Properties: { name: "G" },
            Members: [
              { ObjectIdentifier: "S-1-5-21-4-4-4-2001", ObjectType: "User" },
              { ObjectIdentifier: "S-1-5-21-4-4-4-2001", ObjectType: "User" },
            ],
          },
        ],
        meta: { type: "groups", count: 1 },
      },
    ]);

    expect(graph.edges.filter((e) => e.kind === "MemberOf")).toHaveLength(1);
  });
});

describe("ingestBloodHoundJson", () => {
  it("survives an unparseable file and still ingests the rest", () => {
    const graph = ingestBloodHoundJson([JSON.stringify(GROUPS_FILE), "{ truncated", JSON.stringify(USERS_FILE)]);

    expect(graph.nodes.has(DOMAIN_ADMINS)).toBe(true);
    expect(graph.nodes.has(`${DOMAIN_SID}-1105`)).toBe(true);
    expect(graph.meta.warnings.some((w) => w.includes("invalid JSON"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Analyzers
// ---------------------------------------------------------------------------

const CLEAN_GRAPH = (): AdGraph =>
  graphOf(
    [
      node(DOMAIN_SID, "Domain"),
      node(DOMAIN_ADMINS, "Group", { name: "DOMAIN ADMINS" }),
      node(`${DOMAIN_SID}-1201`, "User", { name: "BOB", enabled: true }),
      node(`${DOMAIN_SID}-1202`, "Computer", { name: "WS01", enabled: true }),
      node(`${DOMAIN_SID}-1300`, "Group", { name: "HELPDESK" }),
    ],
    [
      edge(`${DOMAIN_SID}-1201`, "MemberOf", `${DOMAIN_SID}-1300`),
      edge(`${DOMAIN_SID}-1201`, "CanRDP", `${DOMAIN_SID}-1202`),
    ],
  );

describe("target selection", () => {
  it("finds Domain Admins, Enterprise Admins and BUILTIN\\Administrators", () => {
    const graph = graphOf(
      [
        node(DOMAIN_ADMINS, "Group"),
        node(ENTERPRISE_ADMINS, "Group"),
        node("S-1-5-32-544", "Group"),
        node(`${DOMAIN_SID}-1300`, "Group"),
        node(`${DOMAIN_SID}-1201`, "User"),
      ],
      [],
    );

    expect(domainAdminGroupIds(graph).sort()).toEqual([DOMAIN_ADMINS, ENTERPRISE_ADMINS, "S-1-5-32-544"].sort());
  });

  it("treats Tier-0 groups, domains and flagged objects as high value", () => {
    const graph = graphOf(
      [
        node(DOMAIN_SID, "Domain"),
        node(DOMAIN_CONTROLLERS, "Group"),
        node(`${DOMAIN_SID}-1300`, "Group"),
        node(`${DOMAIN_SID}-1400`, "User", { highvalue: true }),
      ],
      [],
    );
    const highValue = highValueTargetIds(graph);

    expect(highValue.has(DOMAIN_SID)).toBe(true);
    expect(highValue.has(DOMAIN_CONTROLLERS)).toBe(true);
    expect(highValue.has(`${DOMAIN_SID}-1400`)).toBe(true);
    expect(highValue.has(`${DOMAIN_SID}-1300`)).toBe(false);
  });
});

describe("findPathsToDomainAdmin", () => {
  it("raises a finding with the correct path", () => {
    const graph = graphOf(
      [
        node(DOMAIN_ADMINS, "Group", { name: "DOMAIN ADMINS" }),
        node(`${DOMAIN_SID}-1300`, "Group", { name: "HELPDESK" }),
        node(`${DOMAIN_SID}-1201`, "User", { name: "BOB", enabled: true }),
      ],
      [
        edge(`${DOMAIN_SID}-1201`, "MemberOf", `${DOMAIN_SID}-1300`),
        edge(`${DOMAIN_SID}-1300`, "GenericAll", DOMAIN_ADMINS),
      ],
    );

    const findings = findPathsToDomainAdmin(graph);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.analyzer).toBe("paths-to-domain-admin");
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.affectedPrincipals).toContain(`${DOMAIN_SID}-1201`);
    expect(findings[0]!.paths).toHaveLength(1);
    expect(renderPath(findings[0]!.paths[0]!)).toBe(
      `${DOMAIN_SID}-1201 -MemberOf-> ${DOMAIN_SID}-1300 -GenericAll-> ${DOMAIN_ADMINS}`,
    );
    expect(findings[0]!.evidence!.shortestPathLength).toBe(2);
  });

  it("returns nothing on a clean graph", () => {
    expect(findPathsToDomainAdmin(CLEAN_GRAPH())).toEqual([]);
  });

  it("returns nothing when the only reachable principal is already Tier 0", () => {
    const graph = graphOf(
      [node(DOMAIN_ADMINS, "Group"), node(`${DOMAIN_SID}-1500`, "User", { admincount: true, enabled: true })],
      [edge(`${DOMAIN_SID}-1500`, "MemberOf", DOMAIN_ADMINS)],
    );

    expect(findPathsToDomainAdmin(graph)).toEqual([]);
  });

  it("scopes the search to operator-owned principals when given", () => {
    const graph = graphOf(
      [
        node(DOMAIN_ADMINS, "Group"),
        node(`${DOMAIN_SID}-1201`, "User", { enabled: true }),
        node(`${DOMAIN_SID}-1202`, "User", { enabled: true }),
      ],
      [
        edge(`${DOMAIN_SID}-1201`, "GenericAll", DOMAIN_ADMINS),
        edge(`${DOMAIN_SID}-1202`, "GenericAll", DOMAIN_ADMINS),
      ],
    );

    const scoped = findPathsToDomainAdmin(graph, { ownedPrincipalIds: [`${DOMAIN_SID}-1202`] });
    expect(scoped).toHaveLength(1);
    expect(scoped[0]!.affectedPrincipals).toEqual([`${DOMAIN_SID}-1202`]);
    expect(scoped[0]!.evidence!.reachingPrincipalCount).toBe(1);
  });

  it("honors maxDepth", () => {
    const graph = graphOf(
      [
        node(DOMAIN_ADMINS, "Group"),
        node(`${DOMAIN_SID}-1300`, "Group"),
        node(`${DOMAIN_SID}-1201`, "User", { enabled: true }),
      ],
      [
        edge(`${DOMAIN_SID}-1201`, "MemberOf", `${DOMAIN_SID}-1300`),
        edge(`${DOMAIN_SID}-1300`, "GenericAll", DOMAIN_ADMINS),
      ],
    );

    expect(findPathsToDomainAdmin(graph, { maxDepth: 1 })).toEqual([]);
    expect(findPathsToDomainAdmin(graph, { maxDepth: 2 })).toHaveLength(1);
  });
});

describe("findKerberoastablePaths", () => {
  it("raises a finding for an SPN account with a path to Tier 0", () => {
    const graph = graphOf(
      [
        node(DOMAIN_ADMINS, "Group"),
        node(`${DOMAIN_SID}-1105`, "User", { name: "SVC_SQL", hasspn: true, enabled: true }),
      ],
      [edge(`${DOMAIN_SID}-1105`, "AddMember", DOMAIN_ADMINS)],
    );

    const findings = findKerberoastablePaths(graph);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.affectedPrincipals).toEqual([`${DOMAIN_SID}-1105`]);
    expect(renderPath(findings[0]!.paths[0]!)).toBe(`${DOMAIN_SID}-1105 -AddMember-> ${DOMAIN_ADMINS}`);
  });

  it("escalates when the SPN account is itself Tier 0", () => {
    const graph = graphOf(
      [node(DOMAIN_ADMINS, "Group"), node(`${DOMAIN_SID}-1105`, "User", { hasspn: true, admincount: true, enabled: true })],
      [],
    );

    const findings = findKerberoastablePaths(graph);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.paths).toEqual([]);
    expect(findings[0]!.evidence!.alreadyPrivileged).toBe(true);
  });

  it("ignores SPN accounts with no path to privilege", () => {
    const graph = graphOf(
      [
        node(DOMAIN_ADMINS, "Group"),
        node(`${DOMAIN_SID}-1105`, "User", { hasspn: true, enabled: true }),
        node(`${DOMAIN_SID}-1300`, "Group"),
      ],
      [edge(`${DOMAIN_SID}-1105`, "MemberOf", `${DOMAIN_SID}-1300`)],
    );

    expect(findKerberoastablePaths(graph)).toEqual([]);
  });

  it("ignores disabled accounts and returns nothing on a clean graph", () => {
    const disabled = graphOf(
      [node(DOMAIN_ADMINS, "Group"), node(`${DOMAIN_SID}-1105`, "User", { hasspn: true, enabled: false })],
      [edge(`${DOMAIN_SID}-1105`, "AddMember", DOMAIN_ADMINS)],
    );

    expect(findKerberoastablePaths(disabled)).toEqual([]);
    expect(findKerberoastablePaths(CLEAN_GRAPH())).toEqual([]);
  });
});

describe("findUnconstrainedDelegation", () => {
  it("raises a finding for a non-DC host and names its controllers", () => {
    const graph = graphOf(
      [
        node(`${DOMAIN_SID}-1001`, "Computer", { name: "DB01", unconstraineddelegation: true, enabled: true }),
        node(`${DOMAIN_SID}-1201`, "User", { enabled: true }),
      ],
      [edge(`${DOMAIN_SID}-1201`, "AdminTo", `${DOMAIN_SID}-1001`)],
    );

    const findings = findUnconstrainedDelegation(graph);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.affectedPrincipals).toContain(`${DOMAIN_SID}-1001`);
    expect(findings[0]!.affectedPrincipals).toContain(`${DOMAIN_SID}-1201`);
    expect(findings[0]!.evidence!.directControllerCount).toBe(1);
    expect(renderPath(findings[0]!.paths[0]!)).toBe(`${DOMAIN_SID}-1201 -AdminTo-> ${DOMAIN_SID}-1001`);
  });

  it("excludes domain controllers, which are unconstrained by design", () => {
    const byMembership = graphOf(
      [
        node(`${DOMAIN_SID}-1002`, "Computer", { name: "DC01", unconstraineddelegation: true, enabled: true }),
        node(DOMAIN_CONTROLLERS, "Group"),
      ],
      [edge(`${DOMAIN_SID}-1002`, "MemberOf", DOMAIN_CONTROLLERS)],
    );
    const byDn = graphOf(
      [
        node(`${DOMAIN_SID}-1003`, "Computer", {
          unconstraineddelegation: true,
          enabled: true,
          distinguishedname: "CN=DC02,OU=DOMAIN CONTROLLERS,DC=LAB,DC=LOCAL",
        }),
      ],
      [],
    );

    expect(findUnconstrainedDelegation(byMembership)).toEqual([]);
    expect(findUnconstrainedDelegation(byDn)).toEqual([]);
  });

  it("returns nothing on a clean graph", () => {
    expect(findUnconstrainedDelegation(CLEAN_GRAPH())).toEqual([]);
  });
});

describe("findDcsyncPrincipals", () => {
  it("raises a finding when a principal holds both replication rights", () => {
    const graph = graphOf(
      [
        node(DOMAIN_SID, "Domain", { name: "LAB.LOCAL" }),
        node(`${DOMAIN_SID}-1300`, "Group", { name: "HELPDESK" }),
        node(`${DOMAIN_SID}-1201`, "User", { enabled: true }),
      ],
      [
        edge(`${DOMAIN_SID}-1300`, "GetChanges", DOMAIN_SID),
        edge(`${DOMAIN_SID}-1300`, "GetChangesAll", DOMAIN_SID),
        edge(`${DOMAIN_SID}-1201`, "MemberOf", `${DOMAIN_SID}-1300`),
      ],
    );

    const findings = findDcsyncPrincipals(graph);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.paths).toHaveLength(2);
    // Group membership propagates the right to the member.
    expect(findings[0]!.affectedPrincipals).toContain(`${DOMAIN_SID}-1201`);
    expect(findings[0]!.evidence!.inheritedByCount).toBe(1);
    expect(findings[0]!.evidence!.grantedBy).toEqual(["GetChanges", "GetChangesAll"]);
  });

  it("accepts a pre-computed DCSync edge", () => {
    const graph = graphOf(
      [node(DOMAIN_SID, "Domain"), node(`${DOMAIN_SID}-1201`, "User")],
      [edge(`${DOMAIN_SID}-1201`, "DCSync", DOMAIN_SID)],
    );

    expect(findDcsyncPrincipals(graph)).toHaveLength(1);
  });

  it("does not fire on half the replication rights", () => {
    const graph = graphOf(
      [node(DOMAIN_SID, "Domain"), node(`${DOMAIN_SID}-1201`, "User")],
      [edge(`${DOMAIN_SID}-1201`, "GetChanges", DOMAIN_SID)],
    );

    expect(findDcsyncPrincipals(graph)).toEqual([]);
  });

  it("suppresses default holders unless asked for them", () => {
    const graph = graphOf(
      [node(DOMAIN_SID, "Domain"), node(DOMAIN_ADMINS, "Group")],
      [edge(DOMAIN_ADMINS, "DCSync", DOMAIN_SID)],
    );

    expect(findDcsyncPrincipals(graph)).toEqual([]);
    expect(findDcsyncPrincipals(graph, { includeDefaultPrivileged: true })).toHaveLength(1);
  });

  it("returns nothing on a clean graph", () => {
    expect(findDcsyncPrincipals(CLEAN_GRAPH())).toEqual([]);
  });
});

describe("findAclAbuseChains", () => {
  it("raises a finding for a non-Tier-0 principal controlling a Tier-0 object", () => {
    const graph = graphOf(
      [
        node(DOMAIN_ADMINS, "Group"),
        node(DOMAIN_SID, "Domain"),
        node(`${DOMAIN_SID}-1300`, "Group", { name: "HELPDESK" }),
        node(`${DOMAIN_SID}-1201`, "User", { enabled: true }),
      ],
      [
        edge(`${DOMAIN_SID}-1300`, "WriteDacl", DOMAIN_ADMINS),
        edge(`${DOMAIN_SID}-1300`, "WriteOwner", DOMAIN_SID),
        edge(`${DOMAIN_SID}-1201`, "MemberOf", `${DOMAIN_SID}-1300`),
      ],
    );

    const findings = findAclAbuseChains(graph);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("high");
    expect(findings[0]!.paths).toHaveLength(2);
    expect(findings[0]!.evidence!.rightKinds).toEqual(expect.arrayContaining(["WriteDacl", "WriteOwner"]));
    expect(findings[0]!.affectedPrincipals).toContain(`${DOMAIN_SID}-1201`);
  });

  it("ignores Tier-0 principals controlling Tier-0 objects", () => {
    const graph = graphOf(
      [node(DOMAIN_ADMINS, "Group"), node(DOMAIN_SID, "Domain")],
      [edge(DOMAIN_ADMINS, "GenericAll", DOMAIN_SID)],
    );

    expect(findAclAbuseChains(graph)).toEqual([]);
  });

  it("ignores dangerous ACLs over ordinary objects", () => {
    const graph = graphOf(
      [
        node(DOMAIN_ADMINS, "Group"),
        node(`${DOMAIN_SID}-1300`, "Group"),
        node(`${DOMAIN_SID}-1201`, "User"),
      ],
      [edge(`${DOMAIN_SID}-1201`, "GenericAll", `${DOMAIN_SID}-1300`)],
    );

    expect(findAclAbuseChains(graph)).toEqual([]);
  });

  it("returns nothing on a clean graph", () => {
    expect(findAclAbuseChains(CLEAN_GRAPH())).toEqual([]);
  });
});

describe("findAdcsEscalation", () => {
  it("raises one finding per ESC edge kind present", () => {
    const graph = graphOf(
      [
        node(`${DOMAIN_SID}-1201`, "User"),
        node(`${DOMAIN_SID}-1202`, "User"),
        node("TEMPLATE-1", "CertTemplate"),
        node("CA-1", "EnterpriseCA"),
      ],
      [
        edge(`${DOMAIN_SID}-1201`, "ADCSESC1", "TEMPLATE-1"),
        edge(`${DOMAIN_SID}-1202`, "ADCSESC1", "TEMPLATE-1"),
        edge(`${DOMAIN_SID}-1201`, "ManageCA", "CA-1"),
      ],
    );

    const findings = findAdcsEscalation(graph);
    expect(findings.map((f) => f.evidence!.edgeKind)).toEqual(["ADCSESC1", "ManageCA"]);
    expect(findings[0]!.severity).toBe("critical");
    expect(findings[0]!.evidence!.edgeCount).toBe(2);
    expect(findings[0]!.affectedPrincipals.sort()).toEqual([`${DOMAIN_SID}-1201`, `${DOMAIN_SID}-1202`]);
    expect(findings[1]!.severity).toBe("high");
  });

  it("detects an ESC kind it has never seen before", () => {
    const graph = graphOf(
      [node(`${DOMAIN_SID}-1201`, "User"), node("TEMPLATE-1", "CertTemplate")],
      [edge(`${DOMAIN_SID}-1201`, "ADCSESC99z", "TEMPLATE-1")],
    );

    const findings = findAdcsEscalation(graph);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("critical");
  });

  it("returns nothing on a clean graph", () => {
    expect(findAdcsEscalation(CLEAN_GRAPH())).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// runAdGraphAnalysis
// ---------------------------------------------------------------------------

describe("runAdGraphAnalysis", () => {
  const richGraph = (): AdGraph =>
    graphOf(
      [
        node(DOMAIN_SID, "Domain", { name: "LAB.LOCAL" }),
        node(DOMAIN_ADMINS, "Group", { name: "DOMAIN ADMINS" }),
        node(`${DOMAIN_SID}-1300`, "Group", { name: "HELPDESK" }),
        node(`${DOMAIN_SID}-1201`, "User", { name: "BOB", enabled: true }),
        node(`${DOMAIN_SID}-1105`, "User", { name: "SVC_SQL", hasspn: true, enabled: true }),
        node(`${DOMAIN_SID}-1001`, "Computer", { name: "DB01", unconstraineddelegation: true, enabled: true }),
        node("TEMPLATE-1", "CertTemplate", { name: "VULNTEMPLATE" }),
      ],
      [
        edge(`${DOMAIN_SID}-1201`, "MemberOf", `${DOMAIN_SID}-1300`),
        edge(`${DOMAIN_SID}-1300`, "WriteDacl", DOMAIN_ADMINS),
        edge(`${DOMAIN_SID}-1105`, "AdminTo", `${DOMAIN_SID}-1001`),
        edge(`${DOMAIN_SID}-1105`, "GetChanges", DOMAIN_SID),
        edge(`${DOMAIN_SID}-1105`, "GetChangesAll", DOMAIN_SID),
        edge(`${DOMAIN_SID}-1201`, "ADCSESC1", "TEMPLATE-1"),
      ],
    );

  it("runs every analyzer and summarises the result", () => {
    const analysis = runAdGraphAnalysis(richGraph());
    const fired = new Set(analysis.summary.analyzersFired);

    expect(fired).toContain("paths-to-domain-admin");
    expect(fired).toContain("dcsync-principals");
    expect(fired).toContain("unconstrained-delegation");
    expect(fired).toContain("adcs-escalation");
    expect(fired).toContain("acl-abuse-chains");
    expect(fired).toContain("kerberoastable-paths");
    expect(analysis.summary.findingCount).toBe(analysis.findings.length);
    expect(analysis.summary.criticalCount).toBeGreaterThan(0);
    expect(analysis.summary.topSeverity).toBe("critical");
    expect(analysis.summary.affectedPrincipalCount).toBeGreaterThan(0);
    expect(analysis.generatedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("sorts findings by severity, then by shortest path", () => {
    const findings = runAdGraphAnalysis(richGraph()).findings;
    const rank = { critical: 5, high: 4, medium: 3, low: 2, info: 1 } as const;

    for (let i = 1; i < findings.length; i += 1) {
      expect(rank[findings[i - 1]!.severity]).toBeGreaterThanOrEqual(rank[findings[i]!.severity]);
    }
  });

  it("emits unique, stable finding ids", () => {
    const first = runAdGraphAnalysis(richGraph()).findings.map((f) => f.id);
    const second = runAdGraphAnalysis(richGraph()).findings.map((f) => f.id);

    expect(new Set(first).size).toBe(first.length);
    expect(first).toEqual(second);
    for (const id of first) expect(id.startsWith("adgraph:")).toBe(true);
  });

  it("is pure — the same graph always yields the same findings", () => {
    const graph = richGraph();
    const strip = (analysis: ReturnType<typeof runAdGraphAnalysis>) =>
      JSON.stringify(analysis.findings, (key, value) => (key === "properties" ? undefined : value));

    expect(strip(runAdGraphAnalysis(graph))).toEqual(strip(runAdGraphAnalysis(graph)));
    // The graph itself is never mutated.
    expect(graph.nodes.size).toBe(7);
    expect(graph.edges).toHaveLength(6);
  });

  it("produces no findings on a clean graph", () => {
    const analysis = runAdGraphAnalysis(CLEAN_GRAPH());

    expect(analysis.findings).toEqual([]);
    expect(analysis.summary.findingCount).toBe(0);
    expect(analysis.summary.topSeverity).toBe("info");
    expect(analysis.summary.analyzersFired).toEqual([]);
  });

  it("handles an empty graph", () => {
    const analysis = runAdGraphAnalysis(buildAdGraph([], []));

    expect(analysis.findings).toEqual([]);
    expect(analysis.graph.nodeCount).toBe(0);
  });

  it("analyses a graph that came straight out of ingest", () => {
    const graph = ingestBloodHoundFiles([USERS_FILE, GROUPS_FILE, COMPUTERS_FILE, DOMAINS_FILE, GRAPH_EXPORT_FILE]);
    const analysis = runAdGraphAnalysis(graph);

    expect(analysis.findings.length).toBeGreaterThan(0);
    // Alice holds both replication rights on the domain head.
    expect(analysis.findings.some((f) => f.analyzer === "dcsync-principals")).toBe(true);
    // DB01 is unconstrained and is not a DC.
    expect(analysis.findings.some((f) => f.analyzer === "unconstrained-delegation")).toBe(true);
    // The ESC1 edge arrived via the graph export.
    expect(analysis.findings.some((f) => f.analyzer === "adcs-escalation")).toBe(true);
    // Ingest warnings are carried into the report.
    expect(analysis.graph.warnings.length).toBeGreaterThan(0);
  });
});
