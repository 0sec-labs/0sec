import { buildAttackPath, reachableTo, shortestPaths } from "./paths.js";
import type { TraversalOptions } from "./paths.js";
import type {
  AdAnalyzerId,
  AdEdgeKind,
  AdFinding,
  AdGraph,
  AdNode,
  AdSeverity,
  AttackPath,
} from "./types.js";

// ---------------------------------------------------------------------------
// Well-known principals
//
// SIDs are upper-cased at ingest. Domain groups are `<domain SID>-<RID>`;
// BUILTIN groups are absolute and identical in every domain.
// ---------------------------------------------------------------------------

/** RIDs of the domain groups that own Tier 0. */
const TIER0_DOMAIN_RIDS = ["512", "516", "518", "519", "521", "526", "527"];

/** Domain Admins / Enterprise Admins — the canonical "game over" groups. */
const DOMAIN_ADMIN_RIDS = ["512", "519"];

const BUILTIN_ADMINISTRATORS = "S-1-5-32-544";

/** BUILTIN groups whose members can trivially escalate to domain compromise. */
const TIER0_BUILTIN_SIDS = [
  BUILTIN_ADMINISTRATORS,
  "S-1-5-32-548", // Account Operators
  "S-1-5-32-549", // Server Operators
  "S-1-5-32-550", // Print Operators
  "S-1-5-32-551", // Backup Operators
];

/** Principals that hold replication rights by design; noise unless asked for. */
const DEFAULT_REPLICATION_HOLDER_SIDS = new Set(["S-1-5-9", "S-1-5-32-544"]);
const DEFAULT_REPLICATION_HOLDER_RIDS = ["512", "516", "518", "519", "498", "521"];

/** RIDs of groups whose membership makes a computer a domain controller. */
const DOMAIN_CONTROLLER_RIDS = ["516", "521"];

const DANGEROUS_ACL_EDGES: AdEdgeKind[] = [
  "GenericAll",
  "GenericWrite",
  "WriteDacl",
  "WriteOwner",
  "Owns",
  "AllExtendedRights",
  "ForceChangePassword",
  "AddMember",
  "AddSelf",
  "AddKeyCredentialLink",
  "WriteSPN",
  "WriteAccountRestrictions",
  "WriteGPLink",
];

/** Non-`ADCSESC*` edges that still represent a certificate-services takeover. */
const ADCS_ABUSE_EDGES: AdEdgeKind[] = [
  "GoldenCert",
  "ManageCA",
  "ManageCertificates",
  "WritePKIEnrollmentFlag",
  "WritePKINameFlag",
  "CanAbuseUPNCertMapping",
  "CanAbuseWeakCertBinding",
];

export interface AdAnalyzerOptions {
  /**
   * Principals already under operator control. When supplied these become the
   * path sources; otherwise every enabled, non-Tier-0 user is a candidate.
   */
  ownedPrincipalIds?: Iterable<string>;
  /** Extra objectIds to treat as high-value targets. */
  highValueIds?: Iterable<string>;
  /** Hop ceiling for every traversal this analyzer performs. Default 6. */
  maxDepth?: number;
  /** Attack paths attached to a single finding. Default 5. */
  maxPathsPerFinding?: number;
  /** Findings a single analyzer may emit. Default 25. */
  maxFindingsPerAnalyzer?: number;
  /** Report principals that hold a right by default (DCs, EA, ...). Default false. */
  includeDefaultPrivileged?: boolean;
  /** Passed through to the traversal layer (edge filters, costs, budgets). */
  traversal?: TraversalOptions;
}

interface ResolvedOptions {
  maxDepth: number;
  maxPathsPerFinding: number;
  maxFindingsPerAnalyzer: number;
  includeDefaultPrivileged: boolean;
  traversal: TraversalOptions;
}

function resolveOptions(opts: AdAnalyzerOptions): ResolvedOptions {
  const maxDepth = Math.max(1, opts.maxDepth ?? 6);
  return {
    maxDepth,
    maxPathsPerFinding: Math.max(1, opts.maxPathsPerFinding ?? 5),
    maxFindingsPerAnalyzer: Math.max(1, opts.maxFindingsPerAnalyzer ?? 25),
    includeDefaultPrivileged: opts.includeDefaultPrivileged ?? false,
    traversal: { maxDepth, ...opts.traversal },
  };
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

function slug(...parts: string[]): string {
  return parts
    .map((part) => part.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "x")
    .join(":");
}

function hasRid(objectId: string, rids: string[]): boolean {
  return rids.some((rid) => objectId.endsWith(`-${rid}`));
}

function isTrue(value: unknown): boolean {
  return value === true || value === "true" || value === "True";
}

/** Absent `enabled` means "collector did not say"; treat as enabled. */
function isEnabled(node: AdNode): boolean {
  return node.properties.enabled !== false;
}

function nodesOfKind(graph: AdGraph, kind: string): AdNode[] {
  const ids = graph.nodesByKind.get(kind) ?? [];
  const out: AdNode[] = [];
  for (const id of ids) {
    const node = graph.nodes.get(id);
    if (node) out.push(node);
  }
  return out;
}

/** Turn individual edges into one-hop attack paths, capped. */
function singleEdgePaths(graph: AdGraph, edgeIndices: number[], cap: number): AttackPath[] {
  const paths: AttackPath[] = [];
  for (const edgeIndex of edgeIndices.slice(0, cap)) {
    const path = buildAttackPath(graph, [edgeIndex]);
    if (path) paths.push(path);
  }
  return paths;
}

function finding(
  analyzer: AdAnalyzerId,
  id: string,
  severity: AdSeverity,
  title: string,
  description: string,
  remediation: string,
  paths: AttackPath[],
  affectedPrincipals: string[],
  evidence?: Record<string, unknown>,
): AdFinding {
  return {
    id: `adgraph:${analyzer}:${id}`,
    analyzer,
    title,
    severity,
    description,
    paths,
    affectedPrincipals: [...new Set(affectedPrincipals)],
    remediation,
    ...(evidence ? { evidence } : {}),
  };
}

// ---------------------------------------------------------------------------
// Target selection
// ---------------------------------------------------------------------------

/** Domain Admins, Enterprise Admins and BUILTIN\Administrators, if collected. */
export function domainAdminGroupIds(graph: AdGraph): string[] {
  const out: string[] = [];
  for (const node of nodesOfKind(graph, "Group")) {
    if (hasRid(node.objectId, DOMAIN_ADMIN_RIDS) || node.objectId === BUILTIN_ADMINISTRATORS) {
      out.push(node.objectId);
    }
  }
  return out;
}

/**
 * Everything a compromise of which means domain compromise: Tier-0 groups, the
 * domain objects themselves, and anything the collector or caller flagged.
 */
export function highValueTargetIds(graph: AdGraph, extra?: Iterable<string>): Set<string> {
  const out = new Set<string>(extra ?? []);
  for (const node of nodesOfKind(graph, "Group")) {
    if (hasRid(node.objectId, TIER0_DOMAIN_RIDS) || TIER0_BUILTIN_SIDS.includes(node.objectId)) {
      out.add(node.objectId);
    }
  }
  for (const node of nodesOfKind(graph, "Domain")) out.add(node.objectId);
  for (const node of graph.nodes.values()) {
    if (isTrue(node.properties.highvalue)) out.add(node.objectId);
  }
  return out;
}

/** Is this computer a domain controller? DCs legitimately hold Tier-0 rights. */
function isDomainController(graph: AdGraph, node: AdNode): boolean {
  if (isTrue(node.properties.isdc)) return true;
  const dn = String(node.properties.distinguishedname ?? "").toUpperCase();
  if (dn.includes("OU=DOMAIN CONTROLLERS")) return true;
  for (const edgeIndex of graph.outbound.get(node.objectId) ?? []) {
    const edge = graph.edges[edgeIndex]!;
    if (edge.kind === "MemberOf" && hasRid(edge.target, DOMAIN_CONTROLLER_RIDS)) return true;
  }
  return false;
}

/**
 * Candidate path origins: caller-supplied owned principals, else every enabled
 * user that is not already inside the Tier-0 blast radius.
 */
function candidateSources(graph: AdGraph, opts: AdAnalyzerOptions, highValue: Set<string>): string[] {
  if (opts.ownedPrincipalIds) {
    return [...opts.ownedPrincipalIds].filter((id) => graph.nodes.has(id));
  }
  return nodesOfKind(graph, "User")
    .filter((node) => isEnabled(node) && !highValue.has(node.objectId) && !isTrue(node.properties.admincount))
    .map((node) => node.objectId);
}

// ---------------------------------------------------------------------------
// Analyzer 1 — paths to Domain Admin
// ---------------------------------------------------------------------------

/**
 * Shortest paths from low-privileged (or operator-owned) principals to the
 * Domain Admins / Enterprise Admins / BUILTIN\Administrators groups.
 *
 * One reverse BFS narrows the candidate set before any path search runs, so
 * cost is O(V + E) plus a bounded number of path searches — not
 * O(sources x targets).
 */
export function findPathsToDomainAdmin(graph: AdGraph, opts: AdAnalyzerOptions = {}): AdFinding[] {
  const resolved = resolveOptions(opts);
  const targets = domainAdminGroupIds(graph);
  if (targets.length === 0) return [];

  const highValue = highValueTargetIds(graph, opts.highValueIds);
  const sources = candidateSources(graph, opts, highValue);
  if (sources.length === 0) return [];

  const findings: AdFinding[] = [];
  for (const targetId of targets) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    const target = graph.nodes.get(targetId)!;

    // Reverse BFS from this one target: everything that can reach it, and how
    // far away it is. Sorting by that distance gives the shortest paths first
    // without searching from every source.
    const distances = reachableTo(graph, [targetId], resolved.maxDepth, resolved.traversal);
    const reaching = sources
      .filter((id) => id !== targetId && distances.has(id))
      .sort((a, b) => distances.get(a)! - distances.get(b)! || a.localeCompare(b));
    if (reaching.length === 0) continue;

    const paths: AttackPath[] = [];
    for (const sourceId of reaching.slice(0, resolved.maxPathsPerFinding)) {
      const [path] = shortestPaths(graph, [sourceId], [targetId], {
        ...resolved.traversal,
        maxResults: 1,
      });
      if (path) paths.push(path);
    }
    if (paths.length === 0) continue;

    findings.push(
      finding(
        "paths-to-domain-admin",
        slug(targetId),
        "critical",
        `Attack path from unprivileged principals to ${target.label}`,
        `${reaching.length} unprivileged principal(s) can reach ${target.label} within ` +
          `${resolved.maxDepth} hops. The shortest path takes ${paths[0]!.length} hop(s): ` +
          `${paths[0]!.technique}.`,
        `Break the shortest hop first — it is usually a single over-broad ACL or a stale ` +
          `local-admin membership. Move ${target.label} into a Tier-0 admin tier, remove ` +
          `standing membership in favour of just-in-time elevation, and re-run collection to confirm the path is gone.`,
        paths,
        reaching.slice(0, 100),
        {
          targetId,
          reachingPrincipalCount: reaching.length,
          shortestPathLength: paths[0]!.length,
        },
      ),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 2 — kerberoastable principals with a path to privilege
// ---------------------------------------------------------------------------

/**
 * Accounts with a Service Principal Name, whose password hash any domain user
 * can request and crack offline, that also sit on a path to Tier 0.
 */
export function findKerberoastablePaths(graph: AdGraph, opts: AdAnalyzerOptions = {}): AdFinding[] {
  const resolved = resolveOptions(opts);
  const highValue = highValueTargetIds(graph, opts.highValueIds);
  const roastable = nodesOfKind(graph, "User").filter(
    (node) => isTrue(node.properties.hasspn) && isEnabled(node),
  );
  if (roastable.length === 0) return [];

  // One reverse BFS covers every high-value target at once.
  const distances = reachableTo(graph, highValue, resolved.maxDepth, resolved.traversal);
  const findings: AdFinding[] = [];

  for (const node of roastable) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    const alreadyPrivileged = highValue.has(node.objectId) || isTrue(node.properties.admincount);

    if (!alreadyPrivileged && !distances.has(node.objectId)) continue;

    const paths = alreadyPrivileged
      ? []
      : shortestPaths(graph, [node.objectId], highValue, {
          ...resolved.traversal,
          maxResults: resolved.maxPathsPerFinding,
        });
    if (!alreadyPrivileged && paths.length === 0) continue;

    const description = alreadyPrivileged
      ? `${node.label} has an SPN and is itself a Tier-0 principal. Any domain user can request ` +
        `a service ticket for it and crack the hash offline, yielding privileged access directly.`
      : `${node.label} has an SPN and reaches ${paths.length} high-value target(s) within ` +
        `${resolved.maxDepth} hops. Cracking its password gives an attacker the whole path: ${paths[0]!.technique}.`;

    findings.push(
      finding(
        "kerberoastable-paths",
        slug(node.objectId),
        alreadyPrivileged ? "critical" : "high",
        `Kerberoastable account with a path to privilege: ${node.label}`,
        description,
        `Move ${node.label} to a group Managed Service Account so the password is machine-generated ` +
          `and rotated automatically. If that is not possible, set a 25+ character random password and ` +
          `remove the account's privileged group memberships.`,
        paths,
        [node.objectId],
        {
          hasSpn: true,
          alreadyPrivileged,
          servicePrincipalNames: node.properties.serviceprincipalnames,
          pwdLastSet: node.properties.pwdlastset,
        },
      ),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 3 — unconstrained delegation
// ---------------------------------------------------------------------------

/**
 * Non-DC hosts trusted for unconstrained delegation. Any account that
 * authenticates to such a host leaves a usable TGT in its LSA cache, and an
 * attacker who controls the host can coerce a domain controller into
 * authenticating (PrinterBug / PetitPotam) to capture the DC's own TGT — which
 * is DCSync, and therefore full domain compromise.
 */
export function findUnconstrainedDelegation(graph: AdGraph, opts: AdAnalyzerOptions = {}): AdFinding[] {
  const resolved = resolveOptions(opts);
  const findings: AdFinding[] = [];
  const candidates = [...nodesOfKind(graph, "Computer"), ...nodesOfKind(graph, "User")];

  for (const node of candidates) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    if (!isTrue(node.properties.unconstraineddelegation)) continue;
    if (!isEnabled(node)) continue;
    // Domain controllers are unconstrained by design — flagging them is noise.
    if (node.kind === "Computer" && isDomainController(graph, node)) continue;

    // Whoever already controls this host inherits the coercion primitive.
    const controlEdges: number[] = [];
    const controllers: string[] = [];
    for (const edgeIndex of graph.inbound.get(node.objectId) ?? []) {
      const edge = graph.edges[edgeIndex]!;
      if (edge.kind === "MemberOf" || edge.kind === "Contains") continue;
      controlEdges.push(edgeIndex);
      controllers.push(edge.source);
    }

    findings.push(
      finding(
        "unconstrained-delegation",
        slug(node.objectId),
        "critical",
        `Unconstrained delegation on ${node.label}`,
        `${node.label} is trusted for unconstrained delegation and is not a domain controller. ` +
          `An attacker controlling this host can coerce a DC into authenticating to it, capture the ` +
          `DC's TGT from memory, and replay it to replicate domain secrets. ` +
          `${controllers.length} principal(s) already hold a direct relationship over it.`,
        `Clear the TRUSTED_FOR_DELEGATION flag on ${node.label} and switch the service to ` +
          `resource-based constrained delegation. Add Tier-0 accounts to the Protected Users group and ` +
          `mark them "sensitive and cannot be delegated" so their tickets are never cacheable here.`,
        singleEdgePaths(graph, controlEdges, resolved.maxPathsPerFinding),
        [node.objectId, ...controllers],
        {
          objectId: node.objectId,
          kind: node.kind,
          operatingSystem: node.properties.operatingsystem,
          directControllerCount: controllers.length,
        },
      ),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 4 — DCSync
// ---------------------------------------------------------------------------

/**
 * Principals that can replicate the directory. BloodHound may pre-compute a
 * `DCSync` edge; when it has not, holding both `GetChanges` and `GetChangesAll`
 * on the same domain is equivalent, so both forms are detected.
 */
export function findDcsyncPrincipals(graph: AdGraph, opts: AdAnalyzerOptions = {}): AdFinding[] {
  const resolved = resolveOptions(opts);
  const findings: AdFinding[] = [];

  for (const domain of nodesOfKind(graph, "Domain")) {
    // principal -> the replication edges it holds on this domain
    const rights = new Map<string, { kinds: Set<AdEdgeKind>; edges: number[] }>();
    for (const edgeIndex of graph.inbound.get(domain.objectId) ?? []) {
      const edge = graph.edges[edgeIndex]!;
      if (edge.kind !== "DCSync" && edge.kind !== "GetChanges" && edge.kind !== "GetChangesAll") continue;
      let entry = rights.get(edge.source);
      if (!entry) {
        entry = { kinds: new Set(), edges: [] };
        rights.set(edge.source, entry);
      }
      entry.kinds.add(edge.kind);
      entry.edges.push(edgeIndex);
    }

    for (const [principalId, entry] of rights) {
      if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
      const viaDcsyncEdge = entry.kinds.has("DCSync");
      const viaReplicationPair = entry.kinds.has("GetChanges") && entry.kinds.has("GetChangesAll");
      if (!viaDcsyncEdge && !viaReplicationPair) continue;

      const isDefault =
        DEFAULT_REPLICATION_HOLDER_SIDS.has(principalId) || hasRid(principalId, DEFAULT_REPLICATION_HOLDER_RIDS);
      if (isDefault && !resolved.includeDefaultPrivileged) continue;

      const principal = graph.nodes.get(principalId);
      if (!principal) continue;
      if (principal.kind === "Computer" && isDomainController(graph, principal) && !resolved.includeDefaultPrivileged) {
        continue;
      }

      // A group holding DCSync hands it to every transitive member.
      const inherited = [...reachableTo(graph, [principalId], resolved.maxDepth, {
        ...resolved.traversal,
        allowedEdgeKinds: ["MemberOf"],
      }).keys()].filter((id) => id !== principalId);

      findings.push(
        finding(
          "dcsync-principals",
          slug(domain.objectId, principalId),
          "critical",
          `${principal.label} can DCSync ${domain.label}`,
          `${principal.label} holds ${viaDcsyncEdge ? "a DCSync right" : "both GetChanges and GetChangesAll"} ` +
            `on ${domain.label} and is not a domain controller or a default replication holder. ` +
            `That is enough to replicate every credential in the domain, including the krbtgt hash, ` +
            `which enables Golden Ticket forgery. ${inherited.length} principal(s) inherit this through group membership.`,
          `Remove the DS-Replication-Get-Changes and DS-Replication-Get-Changes-All ACEs for ` +
            `${principal.label} from the domain head. Replication rights belong to domain controllers and ` +
            `to directory-sync service accounts that are managed as Tier 0.`,
          singleEdgePaths(graph, entry.edges, resolved.maxPathsPerFinding),
          [principalId, ...inherited.slice(0, 100)],
          {
            domainId: domain.objectId,
            grantedBy: [...entry.kinds],
            inheritedByCount: inherited.length,
          },
        ),
      );
    }
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 5 — ACL abuse chains
// ---------------------------------------------------------------------------

/**
 * Object-control ACEs (`GenericAll`, `WriteDacl`, `WriteOwner`, ...) held by
 * non-Tier-0 principals over Tier-0 objects. Each one is a single-hop
 * escalation, and each is grouped by the holding principal so remediation has
 * one owner per finding.
 *
 * Only the relevant edge-kind buckets are scanned, never the whole edge list.
 */
export function findAclAbuseChains(graph: AdGraph, opts: AdAnalyzerOptions = {}): AdFinding[] {
  const resolved = resolveOptions(opts);
  const highValue = highValueTargetIds(graph, opts.highValueIds);
  if (highValue.size === 0) return [];

  // principal -> the dangerous ACEs it holds over high-value objects
  const bySource = new Map<string, number[]>();
  for (const kind of DANGEROUS_ACL_EDGES) {
    for (const edgeIndex of graph.edgesByKind.get(kind) ?? []) {
      const edge = graph.edges[edgeIndex]!;
      if (!highValue.has(edge.target)) continue;
      if (highValue.has(edge.source)) continue; // Tier 0 controlling Tier 0 is expected
      const source = graph.nodes.get(edge.source);
      if (!source) continue;
      if (!resolved.includeDefaultPrivileged && hasRid(edge.source, TIER0_DOMAIN_RIDS)) continue;
      const bucket = bySource.get(edge.source);
      if (bucket) bucket.push(edgeIndex);
      else bySource.set(edge.source, [edgeIndex]);
    }
  }

  const findings: AdFinding[] = [];
  for (const [sourceId, edgeIndices] of bySource) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    const source = graph.nodes.get(sourceId)!;
    const kinds = [...new Set(edgeIndices.map((index) => graph.edges[index]!.kind))];
    const targets = [...new Set(edgeIndices.map((index) => graph.edges[index]!.target))];
    const inherited = [...reachableTo(graph, [sourceId], resolved.maxDepth, {
      ...resolved.traversal,
      allowedEdgeKinds: ["MemberOf"],
    }).keys()].filter((id) => id !== sourceId);

    findings.push(
      finding(
        "acl-abuse-chains",
        slug(sourceId),
        "high",
        `${source.label} holds ${kinds.join("/")} over ${targets.length} Tier-0 object(s)`,
        `${source.label} is not a Tier-0 principal yet holds ${kinds.join(", ")} over ` +
          `${targets.length} high-value object(s). Any of these rights can be converted into ` +
          `membership or control of the target in a single step, so compromising ${source.label} ` +
          `is equivalent to compromising Tier 0. ${inherited.length} principal(s) inherit these ` +
          `rights through group membership.`,
        `Remove the ACEs granting ${source.label} control over Tier-0 objects, or promote and ` +
          `manage it as a Tier-0 principal itself. Enable AdminSDHolder protection on the affected ` +
          `objects so the ACL is restored automatically if it is loosened again.`,
        singleEdgePaths(graph, edgeIndices, resolved.maxPathsPerFinding),
        [sourceId, ...inherited.slice(0, 100)],
        {
          rightKinds: kinds,
          targetIds: targets.slice(0, 50),
          inheritedByCount: inherited.length,
        },
      ),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 6 — ADCS escalation
// ---------------------------------------------------------------------------

/**
 * Certificate-services escalation edges present in the graph.
 *
 * These are computed by BloodHound CE's post-processing, not by the collector,
 * so they only appear when the ingested data came from a graph export. Findings
 * are grouped per escalation kind, which is how the fix is scoped in practice —
 * one template or CA misconfiguration explains all of its edges.
 */
export function findAdcsEscalation(graph: AdGraph, opts: AdAnalyzerOptions = {}): AdFinding[] {
  const resolved = resolveOptions(opts);
  const findings: AdFinding[] = [];

  const relevantKinds: AdEdgeKind[] = [];
  for (const kind of graph.edgesByKind.keys()) {
    if (/^ADCSESC/i.test(kind) || ADCS_ABUSE_EDGES.includes(kind)) relevantKinds.push(kind);
  }
  relevantKinds.sort();

  for (const kind of relevantKinds) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    const edgeIndices = graph.edgesByKind.get(kind) ?? [];
    if (edgeIndices.length === 0) continue;

    const principals = [...new Set(edgeIndices.map((index) => graph.edges[index]!.source))];
    const targets = [...new Set(edgeIndices.map((index) => graph.edges[index]!.target))];
    const isEsc = /^ADCSESC/i.test(kind);

    findings.push(
      finding(
        "adcs-escalation",
        slug(kind),
        isEsc || kind === "GoldenCert" ? "critical" : "high",
        `ADCS escalation available: ${kind}`,
        `${principals.length} principal(s) hold the ${kind} relationship over ` +
          `${targets.length} certificate-services object(s). This lets an attacker obtain a ` +
          `certificate that authenticates as a higher-privileged principal, which survives a ` +
          `password reset and is usable until the certificate expires or is revoked.`,
        `Audit the affected certificate templates and CAs. Remove caller-supplied subject names ` +
          `(CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT), require manager approval or authorised signatures for ` +
          `client-authentication templates, restrict enrollment rights to the principals that need them, ` +
          `and clear EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA. Revoke certificates already issued under ` +
          `the vulnerable configuration.`,
        singleEdgePaths(graph, edgeIndices, resolved.maxPathsPerFinding),
        principals.slice(0, 100),
        {
          edgeKind: kind,
          edgeCount: edgeIndices.length,
          targetIds: targets.slice(0, 50),
        },
      ),
    );
  }
  return findings;
}

/** Every analyzer in this module, in reporting order. */
export const AD_ANALYZERS: ReadonlyArray<(graph: AdGraph, opts?: AdAnalyzerOptions) => AdFinding[]> = [
  findPathsToDomainAdmin,
  findDcsyncPrincipals,
  findUnconstrainedDelegation,
  findAdcsEscalation,
  findAclAbuseChains,
  findKerberoastablePaths,
];
