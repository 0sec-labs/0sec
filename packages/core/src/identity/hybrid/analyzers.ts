// Hybrid identity attack-path analyzers — the seam between on-premises Active
// Directory and Microsoft Entra ID.
//
// Offline: every function here is pure over two already-built in-memory graphs.
// This module never touches a network, never runs a collector, and never
// authenticates to a domain or a tenant. Same scope boundary as
// `../../adgraph/types.ts` and `../entra-graph/ingest.ts`, for the same reason.
//
// Structural mirror of `../entra-graph/analyzers.ts` and `../../adgraph/analyzers.ts`:
// each analyzer is a pure `(graph, options?) => HybridPathFinding[]`, narrows its
// candidate set with one reverse BFS before it runs a path search, and attaches
// the supporting paths as the finding's evidence. The traversal engine is
// `../../adgraph/paths.ts`, unmodified — there is no third path-finder in this
// codebase.
//
// Two things are specific to this module and load-bearing:
//
//   1. JOIN CONFIDENCE REACHES THE FINDING. Every boundary edge carries the
//      confidence of the correspondence that produced it (see `./build.ts`), so
//      a finding can report the weakest join any of its evidence rests on. A
//      path resting on a user-principal-name guess is rendered visibly weaker
//      than one resting on the directory-synchronisation anchor, and a finding
//      with no anchored evidence at all is severity-downgraded. A false join
//      invents an attack path that does not exist, which is a worse outcome in a
//      client report than missing one.
//
//   2. AN EMPTY RESULT IS NEVER LEFT TO SPEAK FOR ITSELF.
//      `findHybridCorrespondenceGaps` turns `HybridJoinReport.gaps` into
//      first-class findings, so "we could not join the two directories" is
//      stated rather than rendered as "no hybrid attack paths exist".

import { highValueTargetIds } from "../../adgraph/analyzers.js";
import { reachableTo, shortestPaths, type TraversalOptions } from "../../adgraph/paths.js";
import type { AffectedPrincipal, IdentityPrincipalType, IdentitySeverity } from "../types.js";
import { boundaryCrossings } from "./build.js";
import { describeHybridEdge } from "./edges.js";
import { writebackEnabled } from "./sync.js";
import type {
  HybridAttackPath,
  HybridEdge,
  HybridGraph,
  HybridJoinConfidence,
  HybridNode,
  HybridPathAnalyzerId,
  HybridPathFinding,
  HybridSyncAccount,
} from "./types.js";

/**
 * BUILTIN groups whose members escalate to domain compromise trivially.
 * `highValueTargetIds` matches these by exact object id, which the `ad:` prefix
 * this module adds defeats — they are recovered by suffix here rather than by
 * forking the upstream constant.
 */
const BUILTIN_TIER0_SIDS = [
  "S-1-5-32-544", // Administrators
  "S-1-5-32-548", // Account Operators
  "S-1-5-32-549", // Server Operators
  "S-1-5-32-550", // Print Operators
  "S-1-5-32-551", // Backup Operators
];

export interface HybridPathAnalyzerOptions {
  /**
   * Principals already under operator control, as prefixed hybrid node ids
   * (`ad:<sid>` / `aad:<guid>`). When supplied these become the path sources;
   * otherwise every enabled, non-privileged principal is a candidate.
   */
  ownedPrincipalIds?: Iterable<string>;
  /** Extra prefixed node ids to treat as high-value targets, either plane. */
  highValueIds?: Iterable<string>;
  /**
   * Hop ceiling for every traversal. Default 8 — one higher than the Entra
   * module's, because a hybrid path spends at least one hop on the boundary
   * itself before it has done anything in the second directory.
   */
  maxDepth?: number;
  /** Attack paths attached to a single finding. Default 5. */
  maxPathsPerFinding?: number;
  /** Findings a single analyzer may emit. Default 25. */
  maxFindingsPerAnalyzer?: number;
  /** Passed through to the traversal layer (edge filters, costs, budgets). */
  traversal?: TraversalOptions<HybridEdge>;
}

interface ResolvedOptions {
  maxDepth: number;
  maxPathsPerFinding: number;
  maxFindingsPerAnalyzer: number;
  /** True when a writeback direction justifies traversing `SyncedFrom`. */
  writeback: boolean;
  traversal: TraversalOptions<HybridEdge>;
}

function resolveOptions(graph: HybridGraph, opts: HybridPathAnalyzerOptions): ResolvedOptions {
  const maxDepth = Math.max(1, opts.maxDepth ?? 8);
  const writeback = writebackEnabled(graph.meta.writeback);
  return {
    maxDepth,
    maxPathsPerFinding: Math.max(1, opts.maxPathsPerFinding ?? 5),
    maxFindingsPerAnalyzer: Math.max(1, opts.maxFindingsPerAnalyzer ?? 25),
    writeback,
    traversal: {
      maxDepth,
      // Without this every cloud hop renders with the generic on-premises
      // wording — see the dispatch rationale in `./edges.ts`.
      describeEdge: describeHybridEdge,
      // Rule 1 in `./build.ts`: the correspondence is not symmetric. Holding a
      // cloud account does not hand you the on-premises one unless writeback is
      // configured, so `SyncedFrom` is denied by default. Traversing it
      // unconditionally would manufacture cloud-to-on-premises paths that do not
      // work, in every hybrid estate.
      ...(writeback ? {} : { deniedEdgeKinds: ["SyncedFrom"] }),
      ...opts.traversal,
    },
  };
}

// ---------------------------------------------------------------------------
// Target and source selection
// ---------------------------------------------------------------------------

function nodesOfKind(graph: HybridGraph, kind: string): HybridNode[] {
  const out: HybridNode[] = [];
  for (const id of graph.nodesByKind.get(kind) ?? []) {
    const node = graph.nodes.get(id);
    if (node) out.push(node);
  }
  return out;
}

/**
 * Cloud objects whose compromise is tenant compromise: unscoped Tier-0 directory
 * roles and the tenant node itself. Administrative-unit-scoped role nodes are
 * excluded exactly as in `../entra-graph/analyzers.ts` — a scoped admin does not
 * inherit the tenant-wide role's abuse edges.
 */
export function hybridCloudTier0Ids(graph: HybridGraph, extra?: Iterable<string>): Set<string> {
  const out = new Set<string>();
  for (const id of extra ?? []) {
    if (graph.nodes.get(id)?.plane === "cloud") out.add(id);
  }
  for (const node of nodesOfKind(graph, "AZRole")) {
    if ((node as { scopeId?: string }).scopeId) continue;
    if (node.properties.tier0 === true) out.add(node.objectId);
  }
  for (const node of nodesOfKind(graph, "AZTenant")) out.add(node.objectId);
  return out;
}

/** Every cloud role node treated as privileged, administrative-unit scopes included. */
export function hybridCloudPrivilegedRoleIds(graph: HybridGraph): Set<string> {
  const out = new Set<string>();
  for (const node of nodesOfKind(graph, "AZRole")) {
    if (node.properties.privileged === true) out.add(node.objectId);
  }
  return out;
}

/**
 * On-premises objects whose compromise is domain compromise. Delegates to
 * `../../adgraph/analyzers.ts` so "Tier-0 on-premises" has one definition in this
 * codebase, then filters to the on-premises plane — the upstream helper also
 * returns the cloud sync identity, which `./build.ts` flags `highvalue`.
 */
export function hybridOnPremHighValueIds(graph: HybridGraph, extra?: Iterable<string>): Set<string> {
  const out = new Set<string>();
  for (const id of highValueTargetIds(graph, extra)) {
    if (graph.nodes.get(id)?.plane === "on-prem") out.add(id);
  }
  for (const node of nodesOfKind(graph, "Group")) {
    if (node.plane !== "on-prem") continue;
    if (BUILTIN_TIER0_SIDS.some((sid) => node.sourceObjectId.toUpperCase().endsWith(sid))) {
      out.add(node.objectId);
    }
  }
  return out;
}

function isEnabled(node: HybridNode): boolean {
  return node.properties.enabled !== false && node.properties.accountenabled !== false;
}

/**
 * Candidate path origins on one plane: caller-supplied owned principals, else
 * every enabled principal that is not already inside the blast radius it would
 * be escalating into.
 */
function candidateSources(
  graph: HybridGraph,
  opts: HybridPathAnalyzerOptions,
  plane: HybridNode["plane"],
  excluded: Set<string>,
): string[] {
  if (opts.ownedPrincipalIds) {
    return [...opts.ownedPrincipalIds].filter((id) => graph.nodes.get(id)?.plane === plane);
  }
  const kinds = plane === "on-prem" ? ["User", "Computer"] : ["AZUser", "AZServicePrincipal"];
  return kinds
    .flatMap((kind) => nodesOfKind(graph, kind))
    .filter(
      (node) =>
        node.plane === plane &&
        isEnabled(node) &&
        !excluded.has(node.objectId) &&
        node.properties.admincount !== true,
    )
    .map((node) => node.objectId);
}

// ---------------------------------------------------------------------------
// Join confidence
// ---------------------------------------------------------------------------

const CONFIDENCE_RANK: Record<HybridJoinConfidence, number> = { high: 3, medium: 2, low: 1 };

/**
 * The weakest correspondence a single path depends on, or `undefined` when the
 * path crosses no correspondence edge at all (a `SyncAccountFor` or
 * `SeamlessSsoForge` hop is a capability of the sync plane, not an inferred
 * identity match, so it carries no join confidence).
 */
export function pathJoinConfidence(path: HybridAttackPath): HybridJoinConfidence | undefined {
  let weakest: HybridJoinConfidence | undefined;
  for (const step of path.steps) {
    const raw = step.edge.properties?.confidence;
    if (raw !== "high" && raw !== "medium" && raw !== "low") continue;
    if (weakest === undefined || CONFIDENCE_RANK[raw] < CONFIDENCE_RANK[weakest]) weakest = raw;
  }
  return weakest;
}

/** The weakest join across every supporting path — what `HybridPathFinding.joinConfidence` means. */
function findingJoinConfidence(paths: readonly HybridAttackPath[]): HybridJoinConfidence | undefined {
  let weakest: HybridJoinConfidence | undefined;
  for (const path of paths) {
    const confidence = pathJoinConfidence(path);
    if (confidence === undefined) continue;
    if (weakest === undefined || CONFIDENCE_RANK[confidence] < CONFIDENCE_RANK[weakest]) weakest = confidence;
  }
  return weakest;
}

/**
 * True when the finding has no anchored evidence at all — every supporting path
 * that crosses the boundary does so on a user-principal-name or mail guess.
 *
 * This, not the weakest-path rule, is what drives a severity downgrade. One
 * heuristic path alongside three anchored ones does not make the finding wrong;
 * a finding whose *entire* evidence base is unanchored might not describe a real
 * attack path at all.
 */
function whollyHeuristic(paths: readonly HybridAttackPath[]): boolean {
  const crossing = paths.map(pathJoinConfidence).filter((c): c is HybridJoinConfidence => c !== undefined);
  return crossing.length > 0 && crossing.every((c) => c === "low");
}

const SEVERITY_DOWNGRADE: Record<IdentitySeverity, IdentitySeverity> = {
  critical: "high",
  high: "medium",
  medium: "low",
  low: "info",
  info: "info",
};

/**
 * The sentence appended to any finding whose evidence rests on an unanchored
 * join. It is deliberately part of the description rather than a separate field:
 * a renderer that only prints `description` still shows the caveat.
 */
const HEURISTIC_CAVEAT =
  " CONFIDENCE CAVEAT: the on-premises-to-cloud correspondence behind this path was matched on user principal " +
  "name or mail address alone, with no directory-synchronisation anchor to confirm it. If those two accounts are " +
  "unrelated — a user-principal-name collision across a forest boundary is the common case — this path does not " +
  "exist. Verify the correspondence against the Entra Connect metaverse before acting on it.";

const MEDIUM_CAVEAT =
  " The correspondence behind this path was matched on the on-premises distinguished name rather than the " +
  "synchronisation anchor Entra Connect keys on; it is authoritative in practice but goes stale after an object " +
  "move.";

function caveatFor(confidence: HybridJoinConfidence | undefined, wholly: boolean): string {
  if (confidence === "low") return wholly ? HEURISTIC_CAVEAT : HEURISTIC_CAVEAT + " Other paths below are anchored.";
  if (confidence === "medium") return MEDIUM_CAVEAT;
  return "";
}

/**
 * Order supporting paths strongest-evidence first, then cheapest.
 *
 * This deliberately differs from `../entra-graph/analyzers.ts`, which orders on
 * cost alone. Here the leading path is the one quoted in the description, and
 * quoting an unanchored guess ahead of a confirmed synchronisation would put the
 * weakest sentence in the most prominent position.
 */
function orderPaths(paths: HybridAttackPath[]): HybridAttackPath[] {
  return [...paths].sort((a, b) => {
    const aRank = CONFIDENCE_RANK[pathJoinConfidence(a) ?? "high"];
    const bRank = CONFIDENCE_RANK[pathJoinConfidence(b) ?? "high"];
    return bRank - aRank || a.cost - b.cost || a.length - b.length;
  });
}

// ---------------------------------------------------------------------------
// Finding construction
// ---------------------------------------------------------------------------

function slug(...parts: string[]): string {
  return parts
    .map((part) => part.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "x")
    .join(":");
}

const NODE_KIND_TO_PRINCIPAL_TYPE: Record<string, IdentityPrincipalType> = {
  User: "user",
  Group: "group",
  Domain: "domain",
  AZUser: "user",
  AZGroup: "group",
  AZServicePrincipal: "servicePrincipal",
  AZApp: "application",
  AZTenant: "domain",
};

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

/**
 * Render a hybrid node as the same `AffectedPrincipal` the 27 posture checks and
 * the two other path modules use, so a report merges all three without a second
 * principal vocabulary.
 *
 * `id` is the prefixed hybrid id. An AD SID and an Entra GUID cannot collide
 * today, but a consumer deduping principals across a merged report needs the
 * plane to be unambiguous in the key itself.
 */
export function hybridPrincipalOf(graph: HybridGraph, nodeId: string): AffectedPrincipal {
  const node = graph.nodes.get(nodeId);
  if (!node) return { id: nodeId, type: "unknown" };
  const upn = asString(node.properties.userprincipalname);
  const appId = asString(node.properties.appid);
  return {
    id: node.objectId,
    type: NODE_KIND_TO_PRINCIPAL_TYPE[node.kind] ?? "unknown",
    displayName: asString(node.properties.displayname) ?? node.label,
    ...(upn ? { userPrincipalName: upn } : {}),
    ...(appId ? { appId } : {}),
  };
}

interface FindingInput {
  analyzer: HybridPathAnalyzerId;
  id: string;
  severity: IdentitySeverity;
  title: string;
  description: string;
  remediation: string;
  paths: HybridAttackPath[];
  affectedPrincipals: AffectedPrincipal[];
  evidence?: Record<string, unknown>;
}

/**
 * Assemble a finding, applying the confidence rules in one place so no analyzer
 * can forget them: paths ordered strongest-first, `joinConfidence` and
 * `boundaryCrossings` derived from the evidence, the caveat spliced into the
 * description, and the severity downgraded when nothing is anchored.
 */
function finding(input: FindingInput): HybridPathFinding {
  const paths = orderPaths(input.paths);
  const confidence = findingJoinConfidence(paths);
  const wholly = whollyHeuristic(paths);
  const shortest = paths.reduce<HybridAttackPath | undefined>(
    (best, path) => (best === undefined || path.length < best.length ? path : best),
    undefined,
  );
  const seen = new Set<string>();
  return {
    id: `hybrid:${input.analyzer}:${input.id}`,
    analyzer: input.analyzer,
    title: input.title,
    severity: wholly ? SEVERITY_DOWNGRADE[input.severity] : input.severity,
    description: input.description + caveatFor(confidence, wholly),
    paths,
    affectedPrincipals: input.affectedPrincipals.filter((p) => (seen.has(p.id) ? false : (seen.add(p.id), true))),
    remediation: input.remediation,
    ...(confidence ? { joinConfidence: confidence } : {}),
    ...(shortest ? { boundaryCrossings: boundaryCrossings(shortest.steps) } : {}),
    ...(input.evidence ? { evidence: input.evidence } : {}),
  };
}

/** Shortest path from each of `sources` to `targets`, cheapest first, capped. */
function pathsFrom(
  graph: HybridGraph,
  sources: string[],
  targets: Iterable<string>,
  resolved: ResolvedOptions,
  traversal: TraversalOptions<HybridEdge> = resolved.traversal,
): HybridAttackPath[] {
  const paths: HybridAttackPath[] = [];
  for (const sourceId of sources.slice(0, resolved.maxPathsPerFinding)) {
    const [path] = shortestPaths(graph, [sourceId], targets, { ...traversal, maxResults: 1 });
    if (path) paths.push(path);
  }
  return paths.sort((a, b) => a.cost - b.cost || a.length - b.length);
}

// ---------------------------------------------------------------------------
// Analyzer 1 — on-premises principal reaches a cloud privileged role
// ---------------------------------------------------------------------------

/**
 * The headline finding: an on-premises account that reaches a privileged Entra
 * directory role or the tenant itself.
 *
 * This is the class of path a single-directory assessment structurally cannot
 * report. The on-premises engagement sees an ordinary user with no interesting
 * rights; the tenant assessment sees a cloud account whose privilege looks
 * correctly assigned. Only the join says the two are the same identity, and that
 * the domain credential therefore authenticates as the cloud administrator.
 */
export function findHybridOnPremToCloudAdmin(
  graph: HybridGraph,
  opts: HybridPathAnalyzerOptions = {},
): HybridPathFinding[] {
  const resolved = resolveOptions(graph, opts);
  const tier0 = hybridCloudTier0Ids(graph, opts.highValueIds);
  const privilegedRoles = hybridCloudPrivilegedRoleIds(graph);
  const targets = [...new Set([...tier0, ...privilegedRoles])].sort();
  if (targets.length === 0) return [];

  const sources = candidateSources(graph, opts, "on-prem", hybridOnPremHighValueIds(graph, opts.highValueIds));
  if (sources.length === 0) return [];

  const findings: HybridPathFinding[] = [];
  for (const targetId of targets) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    const target = graph.nodes.get(targetId);
    if (!target) continue;

    // One reverse BFS per target narrows the candidate set before any path
    // search runs — the same prefilter the other two modules use.
    const distances = reachableTo(graph, [targetId], resolved.maxDepth, resolved.traversal);
    const reaching = sources
      .filter((id) => id !== targetId && distances.has(id))
      .sort((a, b) => distances.get(a)! - distances.get(b)! || a.localeCompare(b));
    if (reaching.length === 0) continue;

    const paths = pathsFrom(graph, reaching, [targetId], resolved).filter(
      // Defensive: a target on the cloud plane is only reachable from an
      // on-premises source across the boundary, but an operator-supplied
      // `highValueIds` entry could name an on-premises object.
      (path) => boundaryCrossings(path.steps) > 0,
    );
    if (paths.length === 0) continue;

    const lead = orderPaths(paths)[0]!;
    findings.push(
      finding({
        analyzer: "hybrid-onprem-to-cloud-admin",
        id: slug(targetId),
        severity: tier0.has(targetId) ? "critical" : "high",
        title: `On-premises principals reach cloud role ${target.label} across the hybrid boundary`,
        description:
          `${reaching.length} on-premises principal(s) reach ${target.label} in the Entra tenant within ` +
          `${resolved.maxDepth} hops. The path crosses the on-premises/cloud boundary, so a domain credential ` +
          `is a tenant credential here: whoever compromises the on-premises account authenticates as the ` +
          `synchronised cloud identity and inherits everything it holds. Neither an Active Directory assessment ` +
          `nor a tenant assessment reports this on its own — the on-premises side sees an unremarkable user and ` +
          `the cloud side sees a correctly-assigned role. Leading path (${lead.length} hop(s), ` +
          `${boundaryCrossings(lead.steps)} boundary crossing(s)): ${lead.technique}.`,
        remediation:
          `Break the boundary hop, not the cloud hop. A privileged Entra role must not be held by an identity ` +
          `whose credential is mastered on-premises: move ${target.label} onto a cloud-only administrative ` +
          `account with phishing-resistant MFA and PIM-eligible activation, and leave the synchronised account ` +
          `unprivileged. Where the synchronised account must keep the role, exclude it from password-hash ` +
          `synchronisation and require conditional access that the on-premises credential alone cannot satisfy.`,
        paths,
        affectedPrincipals: [
          hybridPrincipalOf(graph, targetId),
          ...reaching.slice(0, 100).map((id) => hybridPrincipalOf(graph, id)),
        ],
        evidence: {
          targetId,
          targetLabel: target.label,
          targetPlane: target.plane,
          tier0: tier0.has(targetId),
          reachingPrincipalCount: reaching.length,
          shortestPathLength: paths[0]!.length,
        },
      }),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 2 — cloud principal reaches an on-premises resource via writeback
// ---------------------------------------------------------------------------

/**
 * The reverse direction, which is only real where writeback is configured.
 *
 * `./build.ts` emits `SyncedFrom` for every correspondence but the default
 * traversal profile denies it, because compromising a cloud account does not by
 * itself hand you the on-premises one. Password, group and device writeback each
 * turn that edge into a genuine capability, and `detectWriteback` establishes
 * which are on from collected attributes. This analyzer returns nothing at all
 * when none are — silence here is the conservative answer, and the writeback
 * state is reported on `graph.meta.writeback` either way.
 */
export function findHybridCloudToOnPremWriteback(
  graph: HybridGraph,
  opts: HybridPathAnalyzerOptions = {},
): HybridPathFinding[] {
  const resolved = resolveOptions(graph, opts);
  if (!resolved.writeback) return [];

  const targets = hybridOnPremHighValueIds(graph, opts.highValueIds);
  if (targets.size === 0) return [];

  const sources = candidateSources(graph, opts, "cloud", hybridCloudTier0Ids(graph, opts.highValueIds));
  if (sources.length === 0) return [];

  const directions = [
    graph.meta.writeback.password ? "password" : "",
    graph.meta.writeback.group ? "group" : "",
    graph.meta.writeback.device ? "device" : "",
  ].filter(Boolean);

  const findings: HybridPathFinding[] = [];
  for (const targetId of [...targets].sort()) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    const target = graph.nodes.get(targetId);
    if (!target) continue;

    const distances = reachableTo(graph, [targetId], resolved.maxDepth, resolved.traversal);
    const reaching = sources
      .filter((id) => id !== targetId && distances.has(id))
      .sort((a, b) => distances.get(a)! - distances.get(b)! || a.localeCompare(b));
    if (reaching.length === 0) continue;

    const paths = pathsFrom(graph, reaching, [targetId], resolved).filter(
      (path) => boundaryCrossings(path.steps) > 0,
    );
    if (paths.length === 0) continue;

    const lead = orderPaths(paths)[0]!;
    findings.push(
      finding({
        analyzer: "hybrid-cloud-to-onprem-writeback",
        id: slug(targetId),
        severity: "critical",
        title: `Cloud principals reach on-premises ${target.label} through configured writeback`,
        description:
          `${directions.join("/")} writeback is configured in this estate, which makes the cloud-to-on-premises ` +
          `direction of the identity correspondence a real capability rather than a reporting artefact. ` +
          `${reaching.length} cloud principal(s) reach on-premises Tier-0 object ${target.label} within ` +
          `${resolved.maxDepth} hops. Entra ID is normally treated as downstream of Active Directory; with ` +
          `writeback enabled the trust runs both ways, and a tenant compromise becomes a domain compromise. ` +
          `Leading path (${lead.length} hop(s), ${boundaryCrossings(lead.steps)} boundary crossing(s)): ` +
          `${lead.technique}. Writeback evidence: ${graph.meta.writeback.evidence.join("; ") || "operator-supplied"}.`,
        remediation:
          `Scope the writeback delegation down. The Entra Connect connector account should hold password-reset ` +
          `rights only over the organisational units that actually need self-service password reset, never over ` +
          `Tier-0 containers, and group writeback should be restricted to a dedicated OU that contains no ` +
          `privileged group. Where the capability is not in use, disable the writeback feature in Entra Connect ` +
          `and remove the delegation from Active Directory — leaving the ACL in place after turning the feature ` +
          `off keeps the attack path and loses the functionality.`,
        paths,
        affectedPrincipals: [
          hybridPrincipalOf(graph, targetId),
          ...reaching.slice(0, 100).map((id) => hybridPrincipalOf(graph, id)),
        ],
        evidence: {
          targetId,
          targetLabel: target.label,
          writebackDirections: directions,
          writebackEvidence: graph.meta.writeback.evidence,
          reachingPrincipalCount: reaching.length,
          shortestPathLength: paths[0]!.length,
        },
      }),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 3 — sync-account compromise
// ---------------------------------------------------------------------------

const SYNC_ROLE_DESCRIPTION: Record<HybridSyncAccount["role"], string> = {
  "ad-connector":
    "the on-premises Entra Connect AD DS connector account. It is delegated directory-replication rights so it " +
    "can read every password hash in the domain, which is DCSync by design, and the credential it uses to " +
    "authenticate to the tenant is stored on the Connect server where it can be recovered",
  "cloud-sync-identity":
    "the cloud identity Entra Connect authenticates to the tenant as. It holds the Directory Synchronization " +
    "Accounts role, which carries directory-write across the whole tenant and is excluded from most privileged " +
    "access reviews because it is not a conventional administrative role",
  "seamless-sso":
    "the AZUREADSSOACC$ computer account, whose Kerberos key signs seamless single-sign-on service tickets. The " +
    "key is not rotated by default, and whoever holds it forges cloud authentication for any synchronised user",
};

/**
 * The sync plane, reported as the single most valuable target in a hybrid estate.
 *
 * This analyzer emits a finding for a sync account even when no path is found in
 * either direction. That is deliberate: the account's privilege is a property of
 * what Entra Connect is, not of what the collection happened to capture, and a
 * report that stays silent about it because the tenant half was not collected
 * would understate the estate's worst exposure.
 */
export function findHybridSyncAccountCompromise(
  graph: HybridGraph,
  opts: HybridPathAnalyzerOptions = {},
): HybridPathFinding[] {
  const resolved = resolveOptions(graph, opts);
  const accounts = graph.meta.syncAccounts;
  if (accounts.length === 0) return [];

  const downstreamTargets = new Set([
    ...hybridCloudTier0Ids(graph, opts.highValueIds),
    ...hybridOnPremHighValueIds(graph, opts.highValueIds),
  ]);

  const findings: HybridPathFinding[] = [];
  for (const account of accounts) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    const node = graph.nodes.get(account.nodeId);
    if (!node) continue;

    // What a compromise of this account yields.
    const downstream = shortestPaths(
      graph,
      [account.nodeId],
      [...downstreamTargets].filter((id) => id !== account.nodeId),
      { ...resolved.traversal, maxResults: resolved.maxPathsPerFinding },
    );

    // Who can seize it. One reverse BFS, then a bounded number of searches.
    const excluded = new Set([
      ...hybridCloudTier0Ids(graph, opts.highValueIds),
      ...hybridOnPremHighValueIds(graph, opts.highValueIds),
      ...accounts.map((a) => a.nodeId),
    ]);
    const candidates = [
      ...candidateSources(graph, opts, "on-prem", excluded),
      ...candidateSources(graph, opts, "cloud", excluded),
    ];
    const distances = reachableTo(graph, [account.nodeId], resolved.maxDepth, resolved.traversal);
    const reaching = candidates
      .filter((id) => id !== account.nodeId && distances.has(id))
      .sort((a, b) => distances.get(a)! - distances.get(b)! || a.localeCompare(b));
    const upstream = pathsFrom(graph, reaching, [account.nodeId], resolved);

    findings.push(
      finding({
        analyzer: "hybrid-sync-account-compromise",
        id: slug(account.nodeId),
        // The naming convention alone is a weak signal — a renamed connector is
        // missed and an account called `MSOL_decoy` is a false positive — so a
        // name-only classification does not carry a critical rating on its own.
        severity: account.nameOnly ? "high" : "critical",
        title: `Entra Connect sync account ${account.label} is a tenant-wide single point of compromise`,
        description:
          `${account.label} is ${SYNC_ROLE_DESCRIPTION[account.role]}. Compromise of this one account is ` +
          `equivalent to compromise of both directories at once, which is why it is modelled as high-value on ` +
          `both planes rather than left to the generic privilege checks. ` +
          (downstream.length > 0
            ? `It reaches ${downstream.length} Tier-0 target(s) across the estate within ${resolved.maxDepth} ` +
              `hops; the shortest is ${downstream[0]!.length} hop(s): ${downstream[0]!.technique}. `
            : `No onward path was computed from it — either the second directory was not collected or the ` +
              `traversal depth was too shallow, and that absence is NOT evidence that this account is contained. `) +
          (reaching.length > 0
            ? `${reaching.length} principal(s) with no privilege of their own can reach it, so the account is ` +
              `not only powerful but also exposed.`
            : `No unprivileged principal was found with a path to it in this collection.`) +
          ` Classification evidence: ${account.evidence.join("; ")}.` +
          (account.nameOnly
            ? ` This classification rests on the account naming convention alone: nothing else corroborated it, ` +
              `so confirm the account is genuinely the Connect connector before treating this as a live finding.`
            : ""),
        remediation:
          `Treat the Connect server and both sync accounts as Tier-0 assets. Put the Connect server in the same ` +
          `administrative tier as a domain controller, restrict interactive logon to it, exclude the cloud sync ` +
          `identity from every conditional-access exclusion it does not strictly need, and monitor for its use ` +
          `from anywhere other than the Connect server's own address. Remove any delegation the connector holds ` +
          `beyond what the enabled synchronisation features actually require, and rotate the ` +
          `AZUREADSSOACC$ Kerberos key on a schedule — it is never rotated automatically.`,
        paths: [...downstream, ...upstream].slice(0, resolved.maxPathsPerFinding * 2),
        affectedPrincipals: [
          hybridPrincipalOf(graph, account.nodeId),
          ...reaching.slice(0, 100).map((id) => hybridPrincipalOf(graph, id)),
        ],
        evidence: {
          syncAccountId: account.nodeId,
          plane: account.plane,
          role: account.role,
          nameOnly: account.nameOnly,
          classificationEvidence: account.evidence,
          reachableTier0TargetCount: downstream.length,
          reachingPrincipalCount: reaching.length,
        },
      }),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 4 — paths that cross the boundary more than once
// ---------------------------------------------------------------------------

/**
 * Join two paths that meet at a pivot node into one.
 *
 * Not a third path-finder: both halves come from `shortestPaths`, and this only
 * concatenates their steps. A composition that revisits a node is discarded —
 * two individually-valid shortest paths can share an intermediate node, and the
 * concatenation would then describe a route no attacker would take.
 */
function concatPaths(a: HybridAttackPath, b: HybridAttackPath): HybridAttackPath | undefined {
  if (a.targetId !== b.sourceId) return undefined;
  const steps = [...a.steps, ...b.steps];
  const seen = new Set<string>([steps[0]!.from.objectId]);
  for (const step of steps) {
    if (seen.has(step.to.objectId)) return undefined;
    seen.add(step.to.objectId);
  }
  return {
    sourceId: a.sourceId,
    targetId: b.targetId,
    steps,
    length: steps.length,
    cost: a.cost + b.cost,
    technique: steps.map((step) => step.edge.kind).join(" -> "),
  };
}

/**
 * Paths that cross the on-premises/cloud boundary more than once.
 *
 * This is the strongest argument the module exists. A single-directory
 * assessment cannot find a route that leaves its directory and comes back — the
 * on-premises engagement loses the trail at the sync boundary and the tenant
 * engagement never sees where the identity came from. Only a joined graph shows
 * that an ordinary domain user reaches a cloud group, that the group is written
 * back on-premises, and that the written-back group is privileged in the domain.
 *
 * Every path with two or more crossings contains at least one `SyncedFrom` hop
 * (crossings alternate planes, and `SyncedFrom` is the only cloud-to-on-premises
 * edge kind), so this analyzer necessarily returns nothing when writeback is not
 * configured. That is a property of the estate, not a limitation of the search.
 *
 * The search itself is a two-stage composition over the existing traversal:
 * `source -> pivot` and `pivot -> target`, where the pivots are the endpoints of
 * the boundary edges. Asking `shortestPaths` for `source -> target` directly
 * would find the cheapest route, which by construction is the one that does NOT
 * detour through the second directory.
 */
export function findHybridMultiBoundaryCrossings(
  graph: HybridGraph,
  opts: HybridPathAnalyzerOptions = {},
): HybridPathFinding[] {
  const resolved = resolveOptions(graph, opts);
  if (!resolved.writeback) return [];

  const targets = new Set([
    ...hybridCloudTier0Ids(graph, opts.highValueIds),
    ...hybridOnPremHighValueIds(graph, opts.highValueIds),
  ]);
  if (targets.size === 0) return [];

  const excluded = new Set(targets);
  const sources = new Set([
    ...candidateSources(graph, opts, "on-prem", excluded),
    ...candidateSources(graph, opts, "cloud", excluded),
  ]);
  if (sources.size === 0) return [];

  // Both endpoints of every writeback edge are pivots: a path may cross out and
  // back (on-prem -> cloud -> on-prem) or in and out (cloud -> on-prem -> cloud).
  const pivots = new Set<string>();
  for (const edgeIndex of graph.edgesByKind.get("SyncedFrom") ?? []) {
    const edge = graph.edges[edgeIndex]!;
    pivots.add(edge.source);
    pivots.add(edge.target);
  }
  if (pivots.size === 0) return [];

  const findings: HybridPathFinding[] = [];
  for (const pivotId of [...pivots].sort()) {
    if (findings.length >= resolved.maxFindingsPerAnalyzer) break;
    const pivot = graph.nodes.get(pivotId);
    if (!pivot) continue;

    const onward = shortestPaths(graph, [pivotId], [...targets].filter((id) => id !== pivotId), {
      ...resolved.traversal,
      maxResults: resolved.maxPathsPerFinding,
    });
    if (onward.length === 0) continue;

    const distances = reachableTo(graph, [pivotId], resolved.maxDepth, resolved.traversal);
    const reaching = [...sources]
      .filter((id) => id !== pivotId && distances.has(id))
      .sort((a, b) => distances.get(a)! - distances.get(b)! || a.localeCompare(b));
    if (reaching.length === 0) continue;

    const inbound = pathsFrom(graph, reaching, [pivotId], resolved);

    const composed: HybridAttackPath[] = [];
    for (const first of inbound) {
      for (const second of onward) {
        const path = concatPaths(first, second);
        if (path && boundaryCrossings(path.steps) >= 2) composed.push(path);
        if (composed.length >= resolved.maxPathsPerFinding) break;
      }
      if (composed.length >= resolved.maxPathsPerFinding) break;
    }
    if (composed.length === 0) continue;

    const lead = orderPaths(composed)[0]!;
    const crossings = boundaryCrossings(lead.steps);
    const target = graph.nodes.get(lead.targetId);
    findings.push(
      finding({
        analyzer: "hybrid-multi-boundary-crossing",
        id: slug(pivotId),
        severity: "critical",
        title: `Attack path crosses the on-premises/cloud boundary ${crossings} times through ${pivot.label}`,
        description:
          `A route from ${graph.nodes.get(lead.sourceId)?.label ?? lead.sourceId} to ` +
          `${target?.label ?? lead.targetId} leaves one directory, traverses the other, and comes back — ` +
          `${crossings} boundary crossings in ${lead.length} hops, pivoting through ${pivot.label}. ` +
          `No single-directory assessment can produce this finding. The Active Directory engagement loses the ` +
          `trail at the synchronisation boundary; the tenant engagement never sees where the identity came from ` +
          `or where it goes back to. Each half looks like an accepted risk in isolation, and together they are a ` +
          `path to Tier-0. Full route: ${lead.technique}.`,
        remediation:
          `Cut the path at the crossing that is easiest to defend, which is usually the writeback hop rather ` +
          `than either directory's internal permissions. Confirm the pivot object ${pivot.label} genuinely needs ` +
          `to exist on both planes at all: a group that is synchronised out and written back is almost always a ` +
          `configuration nobody intended, and removing one direction of its correspondence removes every path ` +
          `like this one. Then re-run this analysis to confirm the crossing count drops.`,
        paths: composed,
        affectedPrincipals: [
          hybridPrincipalOf(graph, pivotId),
          ...composed.map((path) => hybridPrincipalOf(graph, path.sourceId)),
          ...(target ? [hybridPrincipalOf(graph, target.objectId)] : []),
        ],
        evidence: {
          pivotId,
          pivotLabel: pivot.label,
          pivotPlane: pivot.plane,
          maxBoundaryCrossings: Math.max(...composed.map((path) => boundaryCrossings(path.steps))),
          composedPathCount: composed.length,
          reachingPrincipalCount: reaching.length,
        },
      }),
    );
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Analyzer 5 — correspondence gaps
// ---------------------------------------------------------------------------

/**
 * Turn what the join could NOT do into findings.
 *
 * The most important analyzer in this file, and the reason it exists at all: the
 * four analyzers above return an empty array when no correspondence could be
 * established, and an empty hybrid section in a client report reads as "this
 * estate has no on-premises-to-cloud attack paths". That is an assertion nobody
 * has evidence for. `joinDirectories` already writes the honest sentences into
 * `HybridJoinReport.gaps`; this promotes them into the finding list so a
 * consumer that renders only `findings` still sees them.
 *
 * Severity is `info` deliberately. These are statements about collection
 * coverage, not attack paths, and inflating them would corrupt the severity
 * vocabulary shared with the posture checks. `HybridPathAnalysis.correspondence`
 * carries the same report at the top level for consumers that sort on severity.
 */
export function findHybridCorrespondenceGaps(
  graph: HybridGraph,
  _opts: HybridPathAnalyzerOptions = {},
): HybridPathFinding[] {
  const join = graph.meta.join;
  const findings: HybridPathFinding[] = [];

  if (!join.joined) {
    findings.push(
      finding({
        analyzer: "hybrid-correspondence-gap",
        id: "no-correspondence",
        severity: "info",
        title: "No identity correspondence could be established between the two directories",
        description:
          `The on-premises graph (${graph.meta.counts.onPremNodes} node(s)) and the Entra graph ` +
          `(${graph.meta.counts.cloudNodes} node(s)) were merged, but no object in one could be matched to an ` +
          `object in the other, so zero boundary edges exist and no hybrid attack path could be computed. ` +
          `THE ABSENCE OF HYBRID FINDINGS BELOW IS A LIMIT OF THE INPUT, NOT A RESULT. Do not read it as ` +
          `evidence that the two directories are unconnected. ` +
          join.gaps.join(" "),
        remediation:
          `Re-collect the cloud side with a token that carries directory read scope so ` +
          `\`onPremisesImmutableId\`, \`onPremisesSecurityIdentifier\` and \`onPremisesDistinguishedName\` are ` +
          `present — an AzureHound export does not contain them and Microsoft Graph drops them silently when the ` +
          `scope is missing. Failing that, export the correspondence from the Entra Connect metaverse and pass ` +
          `it to \`buildHybridGraph\` as \`knownCorrespondences\`.`,
        paths: [],
        affectedPrincipals: [],
        evidence: {
          onPremNodes: graph.meta.counts.onPremNodes,
          cloudNodes: graph.meta.counts.cloudNodes,
          bridgeEdges: graph.meta.counts.bridgeEdges,
          signalCoverage: join.signalCoverage,
          gaps: join.gaps,
          conflictCount: join.conflicts.length,
        },
      }),
    );
    return findings;
  }

  // Joined, but partially. Say what is missing from the picture.
  if (join.gaps.length > 0 || join.conflicts.length > 0) {
    const heuristic = join.correspondences.filter((c) => c.heuristic).length;
    findings.push(
      finding({
        analyzer: "hybrid-correspondence-gap",
        id: "partial-correspondence",
        severity: "info",
        title: `Hybrid correspondence is incomplete — ${join.correspondences.length} join(s), ${join.conflicts.length} rejected as ambiguous`,
        description:
          `${join.correspondences.length} identity correspondence(s) were established ` +
          `(${join.byConfidence.high} anchored, ${join.byConfidence.medium} matched on distinguished name, ` +
          `${join.byConfidence.low} heuristic). ${join.conflicts.length} candidate correspondence(s) were ` +
          `rejected as ambiguous rather than guessed at, and any hybrid path through those identities is ` +
          `therefore missing from this report. ` +
          (heuristic > 0
            ? `${heuristic} correspondence(s) rest on a user-principal-name or mail match with no ` +
              `synchronisation anchor; findings built on them are marked \`low\` join confidence. `
            : "") +
          join.gaps.join(" "),
        remediation:
          `Resolve the ambiguous correspondences from the Entra Connect metaverse and re-run with ` +
          `\`knownCorrespondences\` so the paths through them become visible. Where the ambiguity is a genuine ` +
          `duplicate — two cloud accounts matching one on-premises user — the duplicate is itself worth ` +
          `investigating before it is dismissed as a collection artefact.`,
        paths: [],
        affectedPrincipals: [],
        evidence: {
          correspondenceCount: join.correspondences.length,
          byConfidence: join.byConfidence,
          heuristicCount: heuristic,
          conflicts: join.conflicts,
          gaps: join.gaps,
          warnings: join.warnings,
        },
      }),
    );
  }

  return findings;
}

// ---------------------------------------------------------------------------
// Composition
// ---------------------------------------------------------------------------

/** Every analyzer in this module, in reporting order. */
export const HYBRID_PATH_ANALYZERS: ReadonlyArray<
  (graph: HybridGraph, opts?: HybridPathAnalyzerOptions) => HybridPathFinding[]
> = [
  findHybridOnPremToCloudAdmin,
  findHybridMultiBoundaryCrossings,
  findHybridSyncAccountCompromise,
  findHybridCloudToOnPremWriteback,
  findHybridCorrespondenceGaps,
];

export const HYBRID_PATH_ANALYZERS_BY_ID: Record<
  HybridPathAnalyzerId,
  (graph: HybridGraph, opts?: HybridPathAnalyzerOptions) => HybridPathFinding[]
> = {
  "hybrid-onprem-to-cloud-admin": findHybridOnPremToCloudAdmin,
  "hybrid-cloud-to-onprem-writeback": findHybridCloudToOnPremWriteback,
  "hybrid-sync-account-compromise": findHybridSyncAccountCompromise,
  "hybrid-multi-boundary-crossing": findHybridMultiBoundaryCrossings,
  "hybrid-correspondence-gap": findHybridCorrespondenceGaps,
};
