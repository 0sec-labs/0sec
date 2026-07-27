import type { AdEdge, AdEdgeKind, AdGraph, AdNode, AttackPath, AttackPathStep } from "./types.js";

/**
 * How each edge kind is abused, one line per hop. Used to build the human
 * readable `technique` on every {@link AttackPathStep}. Unknown kinds fall back
 * to the raw kind name so a new BloodHound edge still renders sensibly.
 */
export const AD_EDGE_TECHNIQUES: Record<string, string> = {
  MemberOf: "inherits the group's rights through membership",
  Contains: "controls the child object via the containing OU/container",
  GPLink: "applies policy to every object under the linked container",
  TrustedBy: "crosses the domain trust into the trusting domain",
  HasSIDHistory: "carries the target's SID in SID history, inheriting its access",
  AdminTo: "has local administrator rights on the host",
  HasSession: "can dump the logged-on user's credentials from LSASS",
  CanRDP: "can log on interactively over RDP",
  CanPSRemote: "can execute code over PowerShell Remoting (WinRM)",
  ExecuteDCOM: "can execute code through DCOM activation",
  SQLAdmin: "is a SQL sysadmin and can execute OS commands via xp_cmdshell",
  GenericAll: "holds full control and can reset the password or add itself",
  GenericWrite: "can write attributes, e.g. set an SPN or a logon script",
  WriteDacl: "can rewrite the DACL and grant itself full control",
  WriteOwner: "can take ownership and then rewrite the DACL",
  Owns: "owns the object and can grant itself full control",
  WriteSPN: "can set an SPN and then kerberoast the account",
  AllExtendedRights: "holds all extended rights, including password reset",
  ForceChangePassword: "can reset the account password without knowing the old one",
  AddMember: "can add any principal to the group",
  AddSelf: "can add itself to the group",
  AddKeyCredentialLink: "can shadow-credential the account and request a TGT",
  WriteAccountRestrictions: "can set delegation attributes on the account",
  WriteGPLink: "can link a malicious GPO to the container",
  ReadLAPSPassword: "can read the LAPS-managed local administrator password",
  ReadGMSAPassword: "can read the gMSA password blob and derive its keys",
  SyncLAPSPassword: "can sync the LAPS password via directory replication",
  DumpSMSAPassword: "can dump the sMSA password from the host",
  AllowedToDelegate: "can impersonate any user to the target service (constrained delegation)",
  AllowedToAct: "is trusted for resource-based constrained delegation to the host",
  AddAllowedToAct: "can configure RBCD on the target and then impersonate any user",
  DCSync: "can replicate directory secrets, including the krbtgt hash",
  GetChanges: "holds one half of the replication rights needed for DCSync",
  GetChangesAll: "holds the second half of the replication rights needed for DCSync",
  GetChangesInFilteredSet: "can replicate the filtered attribute set (LAPS)",
  ADCSESC1: "enrolls in a template allowing a caller-supplied SAN (ESC1)",
  ADCSESC3: "abuses an enrollment-agent template to enrol on behalf of others (ESC3)",
  ADCSESC4: "has write access over the certificate template itself (ESC4)",
  ADCSESC5: "controls a PKI object the CA depends on (ESC5)",
  ADCSESC6a: "abuses EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA (ESC6)",
  ADCSESC6b: "abuses EDITF_ATTRIBUTESUBJECTALTNAME2 with weak binding (ESC6)",
  ADCSESC7: "holds ManageCA/ManageCertificates on the CA (ESC7)",
  ADCSESC9a: "abuses a template with CT_FLAG_NO_SECURITY_EXTENSION (ESC9)",
  ADCSESC9b: "abuses no-security-extension against a machine account (ESC9)",
  ADCSESC10a: "abuses weak certificate mapping on the DC (ESC10)",
  ADCSESC10b: "abuses UPN certificate mapping on the DC (ESC10)",
  ADCSESC13: "abuses an issuance policy linked to a privileged group (ESC13)",
  GoldenCert: "can steal the CA private key and forge certificates for any principal",
  ManageCA: "is a CA administrator and can enable a vulnerable configuration",
  ManageCertificates: "is a certificate manager and can approve pending requests",
  Enroll: "may request a certificate from the template",
  WritePKIEnrollmentFlag: "can set the enrollment flags on the template",
  WritePKINameFlag: "can enable caller-supplied subject names on the template",
  CoerceToTGT: "can coerce the target into authenticating and capture its TGT",
  CoerceAndRelayNTLMToADCS: "can coerce authentication and relay it to ADCS web enrollment",
  CoerceAndRelayNTLMToLDAP: "can coerce authentication and relay it to LDAP",
  CoerceAndRelayNTLMToLDAPS: "can coerce authentication and relay it to LDAPS",
  CoerceAndRelayNTLMToSMB: "can coerce authentication and relay it to SMB",
};

export function describeEdgeTechnique(kind: AdEdgeKind): string {
  return AD_EDGE_TECHNIQUES[kind] ?? `holds the ${kind} relationship over the target`;
}

export interface TraversalOptions {
  /** Maximum hop count. Default 8 — deeper paths are rarely actionable. */
  maxDepth?: number;
  /** Maximum paths returned. Default 25. */
  maxResults?: number;
  /** If set, only these edge kinds are traversable. */
  allowedEdgeKinds?: Iterable<AdEdgeKind>;
  /** Edge kinds to skip. Applied after `allowedEdgeKinds`. */
  deniedEdgeKinds?: Iterable<AdEdgeKind>;
  /**
   * Per-edge weight. Negative and non-finite values are clamped — a negative
   * weight would break the label-setting invariant this search relies on.
   * Default: every edge costs 1, so cost equals hop count.
   */
  edgeCost?: (edge: AdEdge) => number;
  /**
   * Hard ceiling on relaxations, as a runaway guard on very large graphs.
   * Default 500_000. Hitting it truncates results rather than throwing.
   */
  maxExpansions?: number;
}

const DEFAULT_MAX_DEPTH = 8;
const DEFAULT_MAX_RESULTS = 25;
const DEFAULT_MAX_EXPANSIONS = 500_000;

function resolveEdgeFilter(opts: TraversalOptions): (edge: AdEdge) => boolean {
  const allowed = opts.allowedEdgeKinds ? new Set(opts.allowedEdgeKinds) : undefined;
  const denied = opts.deniedEdgeKinds ? new Set(opts.deniedEdgeKinds) : undefined;
  if (!allowed && !denied) return () => true;
  return (edge) => {
    if (allowed && !allowed.has(edge.kind)) return false;
    if (denied && denied.has(edge.kind)) return false;
    return true;
  };
}

function resolveEdgeCost(opts: TraversalOptions): (edge: AdEdge) => number {
  const fn = opts.edgeCost;
  if (!fn) return () => 1;
  return (edge) => {
    const cost = fn(edge);
    return Number.isFinite(cost) && cost > 0 ? cost : 0;
  };
}

// ---------------------------------------------------------------------------
// Binary min-heap over label indices, ordered by (cost, depth)
// ---------------------------------------------------------------------------

class LabelHeap {
  private readonly items: number[] = [];

  constructor(
    private readonly cost: number[],
    private readonly depth: number[],
  ) {}

  get size(): number {
    return this.items.length;
  }

  private before(a: number, b: number): boolean {
    if (this.cost[a] !== this.cost[b]) return this.cost[a]! < this.cost[b]!;
    return this.depth[a]! < this.depth[b]!;
  }

  push(label: number): void {
    const items = this.items;
    items.push(label);
    let i = items.length - 1;
    while (i > 0) {
      const parent = (i - 1) >> 1;
      if (!this.before(items[i]!, items[parent]!)) break;
      [items[i], items[parent]] = [items[parent]!, items[i]!];
      i = parent;
    }
  }

  pop(): number | undefined {
    const items = this.items;
    if (items.length === 0) return undefined;
    const top = items[0]!;
    const last = items.pop()!;
    if (items.length === 0) return top;
    items[0] = last;
    let i = 0;
    for (;;) {
      const left = 2 * i + 1;
      const right = left + 1;
      let smallest = i;
      if (left < items.length && this.before(items[left]!, items[smallest]!)) smallest = left;
      if (right < items.length && this.before(items[right]!, items[smallest]!)) smallest = right;
      if (smallest === i) break;
      [items[i], items[smallest]] = [items[smallest]!, items[i]!];
      i = smallest;
    }
    return top;
  }
}

// ---------------------------------------------------------------------------
// Path construction
// ---------------------------------------------------------------------------

/** Materialise an ordered edge-index list into an {@link AttackPath}. */
export function buildAttackPath(
  graph: AdGraph,
  edgeIndices: number[],
  edgeCost: (edge: AdEdge) => number = () => 1,
): AttackPath | undefined {
  if (edgeIndices.length === 0) return undefined;
  const steps: AttackPathStep[] = [];
  let cost = 0;
  for (const edgeIndex of edgeIndices) {
    const edge = graph.edges[edgeIndex];
    if (!edge) return undefined;
    const from = graph.nodes.get(edge.source);
    const to = graph.nodes.get(edge.target);
    if (!from || !to) return undefined;
    cost += edgeCost(edge);
    steps.push({ from, edge, to, technique: `${from.label} ${describeEdgeTechnique(edge.kind)}` });
  }
  return {
    sourceId: steps[0]!.from.objectId,
    targetId: steps[steps.length - 1]!.to.objectId,
    steps,
    length: steps.length,
    cost,
    technique: steps.map((step) => step.edge.kind).join(" -> "),
  };
}

// ---------------------------------------------------------------------------
// Shortest paths
// ---------------------------------------------------------------------------

/**
 * Minimum-cost path from any node in `sourceIds` to each node in `targetIds`.
 *
 * Multi-source, multi-target label-setting search (Dijkstra generalised to a
 * bi-criteria `(cost, depth)` label). Returns at most one path per reached
 * target — the cheapest, ties broken by fewest hops — sorted cheapest first and
 * truncated to `maxResults`.
 *
 * **Termination.** Each node keeps `bestCostByDepth[d]` = the cheapest cost seen
 * reaching it in `<= d` hops, a non-increasing array. A label is only expanded
 * when it strictly beats that array, so a cycle can never be re-entered: a
 * zero-cost cycle raises depth (and is cut off by `maxDepth`), and a positive
 * cost cycle raises cost. That bounds accepted labels at `maxDepth + 1` per
 * node, independent of how many cycles the graph contains.
 *
 * **Complexity.** O(E * maxDepth * log V) worst case, O(E log V) in practice,
 * with `maxExpansions` as a hard backstop.
 *
 * Traversal is directional — `source -> target` only.
 */
export function shortestPaths(
  graph: AdGraph,
  sourceIds: Iterable<string>,
  targetIds: Iterable<string>,
  opts: TraversalOptions = {},
): AttackPath[] {
  const maxDepth = Math.max(1, opts.maxDepth ?? DEFAULT_MAX_DEPTH);
  const maxResults = Math.max(1, opts.maxResults ?? DEFAULT_MAX_RESULTS);
  const maxExpansions = Math.max(1, opts.maxExpansions ?? DEFAULT_MAX_EXPANSIONS);
  const passesFilter = resolveEdgeFilter(opts);
  const edgeCost = resolveEdgeCost(opts);

  const targets = new Set<string>();
  for (const id of targetIds) if (graph.nodes.has(id)) targets.add(id);
  if (targets.size === 0) return [];

  // Parallel arrays instead of objects: one label per relaxation, and these
  // graphs generate a lot of labels.
  const labelNode: string[] = [];
  const labelCost: number[] = [];
  const labelDepth: number[] = [];
  const labelEdge: number[] = [];
  const labelPrev: number[] = [];
  const heap = new LabelHeap(labelCost, labelDepth);

  /** node -> cheapest cost reaching it in `<= index` hops. Non-increasing. */
  const bestCostByDepth = new Map<string, number[]>();

  const admit = (node: string, cost: number, depth: number, edgeIndex: number, prev: number): boolean => {
    let frontier = bestCostByDepth.get(node);
    if (!frontier) {
      frontier = new Array<number>(maxDepth + 1).fill(Number.POSITIVE_INFINITY);
      bestCostByDepth.set(node, frontier);
    }
    if (cost >= frontier[depth]!) return false;
    for (let d = depth; d <= maxDepth; d += 1) {
      if (frontier[d]! <= cost) break;
      frontier[d] = cost;
    }
    const label = labelNode.length;
    labelNode.push(node);
    labelCost.push(cost);
    labelDepth.push(depth);
    labelEdge.push(edgeIndex);
    labelPrev.push(prev);
    heap.push(label);
    return true;
  };

  let seeded = false;
  for (const id of sourceIds) {
    if (!graph.nodes.has(id)) continue;
    // A source that is already a target is a zero-length path, not a finding.
    if (admit(id, 0, 0, -1, -1)) seeded = true;
  }
  if (!seeded) return [];

  const bestLabelByTarget = new Map<string, number>();
  let expansions = 0;

  while (heap.size > 0 && bestLabelByTarget.size < targets.size && expansions < maxExpansions) {
    const label = heap.pop()!;
    const node = labelNode[label]!;
    const cost = labelCost[label]!;
    const depth = labelDepth[label]!;

    // Stale label: a strictly better one for this node was admitted after it
    // was queued. Cheap to skip, and avoids a decrease-key implementation.
    if (cost > bestCostByDepth.get(node)![depth]!) continue;

    if (depth > 0 && targets.has(node) && !bestLabelByTarget.has(node)) {
      // First pop wins: the heap orders by (cost, depth), so this is the
      // cheapest, shortest label for this target. The search deliberately keeps
      // expanding *through* it — a target can sit on the path to another
      // target, and stopping here would silently hide the ones behind it.
      bestLabelByTarget.set(node, label);
    }

    if (depth >= maxDepth) continue;

    for (const edgeIndex of graph.outbound.get(node) ?? []) {
      const edge = graph.edges[edgeIndex]!;
      if (!passesFilter(edge)) continue;
      expansions += 1;
      if (expansions >= maxExpansions) break;
      admit(edge.target, cost + edgeCost(edge), depth + 1, edgeIndex, label);
    }
  }

  const paths: AttackPath[] = [];
  for (const label of bestLabelByTarget.values()) {
    const edgeIndices: number[] = [];
    for (let cursor = label; cursor !== -1; cursor = labelPrev[cursor]!) {
      const edgeIndex = labelEdge[cursor]!;
      if (edgeIndex !== -1) edgeIndices.push(edgeIndex);
    }
    edgeIndices.reverse();
    const path = buildAttackPath(graph, edgeIndices, edgeCost);
    if (path) paths.push(path);
  }

  paths.sort((a, b) => a.cost - b.cost || a.length - b.length || a.targetId.localeCompare(b.targetId));
  return paths.slice(0, maxResults);
}

// ---------------------------------------------------------------------------
// Reachability
// ---------------------------------------------------------------------------

function bfs(
  graph: AdGraph,
  startIds: Iterable<string>,
  maxDepth: number,
  index: Map<string, number[]>,
  step: (edge: AdEdge) => string,
  opts: TraversalOptions,
): Map<string, number> {
  const passesFilter = resolveEdgeFilter(opts);
  const maxExpansions = Math.max(1, opts.maxExpansions ?? DEFAULT_MAX_EXPANSIONS);
  const depths = new Map<string, number>();
  let frontier: string[] = [];

  for (const id of startIds) {
    if (!graph.nodes.has(id) || depths.has(id)) continue;
    depths.set(id, 0);
    frontier.push(id);
  }

  let expansions = 0;
  for (let depth = 0; depth < Math.max(0, maxDepth) && frontier.length > 0; depth += 1) {
    const next: string[] = [];
    for (const node of frontier) {
      for (const edgeIndex of index.get(node) ?? []) {
        const edge = graph.edges[edgeIndex]!;
        if (!passesFilter(edge)) continue;
        if (++expansions >= maxExpansions) return depths;
        const neighbour = step(edge);
        // The `has` check is what makes cycles terminate: every node is
        // enqueued at most once, at its minimum depth.
        if (depths.has(neighbour)) continue;
        depths.set(neighbour, depth + 1);
        next.push(neighbour);
      }
    }
    frontier = next;
  }
  return depths;
}

/**
 * Every node reachable by following edges forward from `sourceIds`, mapped to
 * its minimum hop distance. Sources are included at depth 0. O(V + E).
 */
export function reachableFrom(
  graph: AdGraph,
  sourceIds: Iterable<string>,
  maxDepth = DEFAULT_MAX_DEPTH,
  opts: TraversalOptions = {},
): Map<string, number> {
  return bfs(graph, sourceIds, maxDepth, graph.outbound, (edge) => edge.target, opts);
}

/**
 * The inverse of {@link reachableFrom}: every node that can reach `targetIds`
 * by following edges forward, mapped to its minimum hop distance.
 *
 * This is the cheap prefilter that keeps the analyzers off O(sources x targets)
 * path searches — narrow the candidate set with one reverse BFS, then run
 * {@link shortestPaths} only for the survivors.
 */
export function reachableTo(
  graph: AdGraph,
  targetIds: Iterable<string>,
  maxDepth = DEFAULT_MAX_DEPTH,
  opts: TraversalOptions = {},
): Map<string, number> {
  return bfs(graph, targetIds, maxDepth, graph.inbound, (edge) => edge.source, opts);
}

/** Node lookup that never returns undefined, for rendering partial graphs. */
export function nodeOrStub(graph: AdGraph, objectId: string): AdNode {
  return graph.nodes.get(objectId) ?? { objectId, label: objectId, kind: "Base", properties: {}, stub: true };
}
