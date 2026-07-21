/**
 * Graph-slice finder stage (Phase 0/1 of the graph-native LPE harness) —
 * `docs/operations/graph-native-lpe-harness-2026-07-21.md`.
 *
 * The flat-text finder (`agentic-scanner.ts`) gets flat file text + a prose
 * hint and CANNOT see multi-step interprocedural chains (alloc-in-A / free-in-B
 * / use-in-C across files). A/B proof (bench:/root/graph-lpe/, 2026-07-21):
 * given the SAME model + hint, a compact interprocedural reachability SLICE
 * surfaced the exact cross-file alloc (`unix_prepare_fpl` → `kvmalloc_array` in
 * garbage.c) and free (`unix_destroy_fpl` → `kvfree`) sites that flat-text
 * called "not visible" — at 5.5x FEWER prompt chars (16,696 vs 92,333).
 *
 * This module is the deterministic slicer that produces that context. It is the
 * TS port of the proven python reference (bench:/root/graph-lpe/{graphlib,slice}.py):
 *
 *   Joern CPG export (graphson JSON) ─▶ {@link loadCpg}
 *     ─▶ interprocedural call graph + intra-procedural DDG (REACHING_DEF)
 *     ─▶ {@link injectOps} (Phase 1: synthesize the ops-struct indirect-call
 *        edges Joern leaves as dead-ends — pre-harvested edge list)
 *     ─▶ {@link buildSlice} (BFS N hops caller/callee, surfacing lifetime sinks)
 *     ─▶ {@link renderSlice} (compact markdown: edges + path lines only)
 *
 * MVP SCOPE: the slice walk runs over a PRE-EXPORTED CPG JSON (produced by
 * `packages/core/scripts/provision-cpg.sh` — Joern c2cpg + joern-export). Joern
 * itself (a Java tool) is NOT bundled: the stage loads the exported JSON and
 * degrades gracefully to the flat-text finder when no CPG is available for the
 * target (see {@link ./graph-slice-hunt-context.ts}). Bundling the Joern
 * provisioning into the cloud sandbox is an explicit follow-up.
 *
 * Pure + IO-free except {@link loadCpg} (reads/parses the JSON) — the walk and
 * render are unit-testable over a synthetic fixture CPG.
 */

import { readFileSync } from "node:fs";

// ── Graphson value unwrapping ──────────────────────────────────────────────────

/**
 * Unwrap one Joern graphson vertex-property value. The shape is
 * `{ "@value": { "@value": [ <el> ] } }` where `<el>` is either a plain scalar
 * (strings) or a typed wrapper `{ "@type": "g:Int32", "@value": 42 }` (numbers).
 * Returns the first list element's underlying value, or undefined.
 */
function flatProp(propval: unknown): string | number | boolean | undefined {
  if (!propval || typeof propval !== "object") return undefined;
  const inner = (propval as Record<string, unknown>)["@value"];
  if (!inner || typeof inner !== "object") return undefined;
  const list = (inner as Record<string, unknown>)["@value"];
  if (!Array.isArray(list) || list.length === 0) return undefined;
  const el = list[0];
  if (el && typeof el === "object" && "@value" in (el as Record<string, unknown>)) {
    const v = (el as Record<string, unknown>)["@value"];
    return typeof v === "string" || typeof v === "number" || typeof v === "boolean" ? v : undefined;
  }
  return typeof el === "string" || typeof el === "number" || typeof el === "boolean" ? el : undefined;
}

/** Unwrap a graphson `{ "@value": <n> }` id/ref to its number. */
function flatId(idval: unknown): number | undefined {
  if (idval && typeof idval === "object" && "@value" in (idval as Record<string, unknown>)) {
    const v = (idval as Record<string, unknown>)["@value"];
    return typeof v === "number" ? v : undefined;
  }
  return typeof idval === "number" ? idval : undefined;
}

// ── CPG model ──────────────────────────────────────────────────────────────────

/** One CPG node: its label and unwrapped property bag. */
export interface CpgNode {
  label: string;
  props: Record<string, string | number | boolean | undefined>;
}

/** A resolved (or Phase-1 synthesized) call edge: caller method → callee method via a call-site node. */
export type CallEdge = readonly [callerMid: number, calleeMid: number, callNode: number, kind: "call" | "ops"];

/** A pre-harvested ops-struct indirect-call edge (from `ops_harvest.py --out ops_map.json`). */
export interface OpsSynthEdge {
  caller_mid: number;
  callee: string;
  callnode?: number;
  field?: string;
  site_code?: string;
  site_line?: number;
}

/** The `ops_map.json` produced by the tree-sitter ops harvester. */
export interface OpsMap {
  synth_edges?: OpsSynthEdge[];
  [k: string]: unknown;
}

/**
 * A loaded Joern CPG: normalized nodes + the interprocedural call graph and
 * intra-procedural DDG indexes needed for slicing. Faithful port of the python
 * `graphlib.CPG` class.
 */
export class Cpg {
  readonly nodes = new Map<number, CpgNode>();
  /** edges grouped by label → list of [outV, inV]. */
  readonly edges = new Map<string, Array<[number, number]>>();

  /** node → enclosing METHOD id (from METHOD --CONTAINS--> node). */
  readonly enclosing = new Map<number, number>();
  readonly methods = new Map<number, CpgNode>();
  readonly methodByName = new Map<string, number[]>();
  readonly methodByFullName = new Map<string, number>();

  /** resolved call graph: method → [(callee_method, call_node)]. */
  readonly callees = new Map<number, Array<[number, number]>>();
  readonly callers = new Map<number, Array<[number, number]>>();
  /** Phase-1 injected ops-struct edges (kept separate so a plain load is untouched). */
  readonly synthCallees = new Map<number, Array<[number, number]>>();
  readonly synthCallers = new Map<number, Array<[number, number]>>();

  /** DDG adjacency (REACHING_DEF), intra-procedural. */
  readonly ddg = new Map<number, number[]>();
  readonly ddgRev = new Map<number, number[]>();

  private pushEdge(map: Map<number, Array<[number, number]>>, key: number, val: [number, number]): void {
    const cur = map.get(key);
    if (cur) cur.push(val);
    else map.set(key, [val]);
  }

  private buildIndexes(): void {
    // enclosing method for every contained node
    for (const [out, inn] of this.edges.get("CONTAINS") ?? []) {
      if (this.nodes.get(out)?.label === "METHOD") this.enclosing.set(inn, out);
    }
    for (const [nid, n] of this.nodes) {
      if (n.label !== "METHOD") continue;
      this.methods.set(nid, n);
      const nm = n.props.NAME;
      const fn = n.props.FULL_NAME;
      if (typeof nm === "string") {
        const cur = this.methodByName.get(nm);
        if (cur) cur.push(nid);
        else this.methodByName.set(nm, [nid]);
      }
      if (typeof fn === "string") this.methodByFullName.set(fn, nid);
    }
    // call graph from resolved CALL edges: CALL-node --CALL--> callee METHOD
    for (const [callNode, callee] of this.edges.get("CALL") ?? []) {
      if (this.nodes.get(callee)?.label !== "METHOD") continue;
      const caller = this.enclosing.get(callNode);
      if (caller === undefined) continue;
      this.pushEdge(this.callees, caller, [callee, callNode]);
      this.pushEdge(this.callers, callee, [caller, callNode]);
    }
    // DDG adjacency
    for (const [out, inn] of this.edges.get("REACHING_DEF") ?? []) {
      const a = this.ddg.get(out);
      if (a) a.push(inn);
      else this.ddg.set(out, [inn]);
      const b = this.ddgRev.get(inn);
      if (b) b.push(out);
      else this.ddgRev.set(inn, [out]);
    }
  }

  /** Build a CPG from a parsed graphson export object (`{ "@value": { vertices, edges } }`). */
  static fromGraphson(doc: unknown): Cpg {
    const cpg = new Cpg();
    const g = (doc as Record<string, unknown>)?.["@value"] as Record<string, unknown> | undefined;
    const vertices = (g?.vertices as unknown[]) ?? [];
    const edges = (g?.edges as unknown[]) ?? [];
    for (const raw of vertices) {
      const v = raw as Record<string, unknown>;
      const nid = flatId(v.id);
      if (nid === undefined) continue;
      const props: CpgNode["props"] = {};
      const rawProps = (v.properties as Record<string, unknown>) ?? {};
      for (const [k, pv] of Object.entries(rawProps)) props[k] = flatProp(pv);
      cpg.nodes.set(nid, { label: String(v.label), props });
    }
    for (const raw of edges) {
      const e = raw as Record<string, unknown>;
      const out = flatId(e.outV);
      const inn = flatId(e.inV);
      const label = String(e.label);
      if (out === undefined || inn === undefined) continue;
      const cur = cpg.edges.get(label);
      if (cur) cur.push([out, inn]);
      else cpg.edges.set(label, [[out, inn]]);
    }
    cpg.buildIndexes();
    return cpg;
  }

  // ── convenience accessors (mirror graphlib.CPG) ──
  mname(mid: number): string {
    const v = this.nodes.get(mid)?.props.NAME;
    return typeof v === "string" ? v : "?";
  }
  mfile(mid: number): string {
    const v = this.nodes.get(mid)?.props.FILENAME;
    return typeof v === "string" ? v : "?";
  }
  mlines(mid: number): [number | undefined, number | undefined] {
    const p = this.nodes.get(mid)?.props ?? {};
    const a = p.LINE_NUMBER;
    const b = p.LINE_NUMBER_END;
    return [typeof a === "number" ? a : undefined, typeof b === "number" ? b : undefined];
  }
  isExternal(mid: number): boolean {
    return Boolean(this.nodes.get(mid)?.props.IS_EXTERNAL);
  }
  nodeLine(nid: number): number | undefined {
    const v = this.nodes.get(nid)?.props.LINE_NUMBER;
    return typeof v === "number" ? v : undefined;
  }
  nodeCode(nid: number): string | undefined {
    const v = this.nodes.get(nid)?.props.CODE;
    return typeof v === "string" ? v : undefined;
  }
  /** resolved + Phase-1 synthesized callees. */
  allCallees(mid: number): Array<[number, number]> {
    return [...(this.callees.get(mid) ?? []), ...(this.synthCallees.get(mid) ?? [])];
  }
  allCallers(mid: number): Array<[number, number]> {
    return [...(this.callers.get(mid) ?? []), ...(this.synthCallers.get(mid) ?? [])];
  }
}

/** Read + parse a graphson JSON export into a {@link Cpg}. Throws on unreadable/invalid JSON. */
export function loadCpg(jsonPath: string): Cpg {
  const doc = JSON.parse(readFileSync(jsonPath, "utf8"));
  return Cpg.fromGraphson(doc);
}

// ── Slicing ────────────────────────────────────────────────────────────────────

/**
 * Calls that mark a memory-lifetime event — always surfaced in the slice even
 * when they are external stubs (so the alloc/free sites of an interprocedural
 * object lifetime appear in the compact slice). Mirrors slice.py `LIFETIME`.
 */
export const LIFETIME_SINKS: ReadonlySet<string> = new Set([
  "kmalloc", "kzalloc", "kcalloc", "kvmalloc", "kvmalloc_array", "kvzalloc",
  "kmalloc_array", "vmalloc", "krealloc", "kmem_cache_alloc",
  "kfree", "kvfree", "vfree", "kfree_rcu", "kmem_cache_free", "call_rcu",
  "kfree_skb", "consume_skb", "sock_wfree", "sock_rfree",
]);

/**
 * Phase 1: add synthesized call edges from a pre-harvested ops map (produced by
 * `ops_harvest.py`). Resolves the kernel's ops-struct indirect dispatch
 * (`sk->sk_prot->close(...)`) that Joern leaves as unresolved dead-ends into
 * concrete caller→callee edges. Returns the number of edges added.
 *
 * MVP loads a PRE-COMPUTED edge list (mirrors python `inject_ops`); harvesting
 * the `.field = fn` initializers in-process via the existing tree-sitter infra
 * (`c-dataflow.ts` `parseC`) is a documented follow-up.
 */
export function injectOps(cpg: Cpg, ops: OpsMap): number {
  let added = 0;
  for (const e of ops.synth_edges ?? []) {
    const caller = e.caller_mid;
    for (const callee of cpg.methodByName.get(e.callee) ?? []) {
      if (cpg.isExternal(callee)) continue;
      const cn = e.callnode ?? -1;
      const scallees = cpg.synthCallees.get(caller);
      if (scallees) scallees.push([callee, cn]);
      else cpg.synthCallees.set(caller, [[callee, cn]]);
      const scallers = cpg.synthCallers.get(callee);
      if (scallers) scallers.push([caller, cn]);
      else cpg.synthCallers.set(callee, [[caller, cn]]);
      added++;
    }
  }
  return added;
}

/**
 * Resolve a target spec — either a bare function `NAME` or `file:line` — to the
 * internal (non-external) method ids it names. Mirrors slice.py `find_targets`.
 */
export function findTargets(cpg: Cpg, spec: string): number[] {
  const colon = spec.lastIndexOf(":");
  const tail = colon >= 0 ? spec.slice(colon + 1) : "";
  if (colon >= 0 && /^\d+$/.test(tail)) {
    const fname = spec.slice(0, colon);
    const line = parseInt(tail, 10);
    const base = fname.slice(fname.lastIndexOf("/") + 1);
    const hits: number[] = [];
    for (const mid of cpg.methods.keys()) {
      if (cpg.isExternal(mid)) continue;
      const mf = cpg.mfile(mid);
      if (mf.slice(mf.lastIndexOf("/") + 1) !== base) continue;
      const [a, b] = cpg.mlines(mid);
      if (a !== undefined && b !== undefined && a <= line && line <= b) hits.push(mid);
    }
    return hits;
  }
  return (cpg.methodByName.get(spec) ?? []).filter((m) => !cpg.isExternal(m));
}

export interface SliceResult {
  /** method id → BFS hop distance from the nearest target. */
  dist: Map<number, number>;
  /** internal call edges within the slice. */
  callEdges: CallEdge[];
}

/**
 * BFS over the call graph from the target methods, up to `hops` hops in BOTH
 * directions (caller/callee, including Phase-1 synthesized ops edges). External
 * stubs are skipped UNLESS they are lifetime primitives (so alloc/free sinks
 * enter the slice). Mirrors slice.py `build_slice`. Returns the reached method
 * set (with distances) and the internal call edges between them.
 */
export function buildSlice(cpg: Cpg, targetMids: number[], hops: number): SliceResult {
  const dist = new Map<number, number>();
  const q: number[] = [];
  for (const t of targetMids) {
    dist.set(t, 0);
    q.push(t);
  }
  let head = 0;
  while (head < q.length) {
    const m = q[head++];
    const d = dist.get(m)!;
    if (d >= hops) continue;
    const neigh: number[] = [];
    for (const [callee] of cpg.allCallees(m)) neigh.push(callee);
    for (const [caller] of cpg.allCallers(m)) neigh.push(caller);
    for (const nb of neigh) {
      if (cpg.isExternal(nb) && !LIFETIME_SINKS.has(cpg.mname(nb))) continue;
      if (!dist.has(nb)) {
        dist.set(nb, d + 1);
        q.push(nb);
      }
    }
  }
  const sliceMids = new Set(dist.keys());
  const callEdges: CallEdge[] = [];
  for (const m of sliceMids) {
    for (const [callee, cn] of cpg.allCallees(m)) {
      if (sliceMids.has(callee)) callEdges.push([m, callee, cn, "call"]);
    }
  }
  return { dist, callEdges };
}

/** Which source lines of `mid` to surface: signature + linking call-sites + lifetime calls. */
function relevantLines(cpg: Cpg, mid: number, callEdgesByCaller: Map<number, CallEdge[]>): number[] {
  const [a] = cpg.mlines(mid);
  const lines = new Set<number>();
  if (a !== undefined) lines.add(a); // signature
  for (const [, , cn] of callEdgesByCaller.get(mid) ?? []) {
    const ln = cpg.nodeLine(cn);
    if (ln !== undefined) lines.add(ln);
  }
  for (const [callee, cn] of cpg.allCallees(mid)) {
    if (LIFETIME_SINKS.has(cpg.mname(callee))) {
      const ln = cpg.nodeLine(cn);
      if (ln !== undefined) lines.add(ln);
    }
  }
  return [...lines].sort((x, y) => x - y);
}

/** Loads the source lines of a repo-relative filename, or null when unavailable. */
export type SourceLoader = (filename: string) => string[] | null;

export interface SliceRenderStats {
  functions: number;
  files: string[];
  callEdges: number;
  chars: number;
}

/**
 * Render the slice as ONE compact markdown block: the interprocedural call
 * edges, then for each function only the path-relevant source lines (signature,
 * linking call-sites, lifetime calls). Falls back to node CODE for call-sites
 * when a source loader is absent or a file is unavailable. Mirrors slice.py
 * `render`. Pure given `loadSource`.
 */
export function renderSlice(
  cpg: Cpg,
  slice: SliceResult,
  loadSource?: SourceLoader,
  opsNote?: string,
): { text: string; stats: SliceRenderStats } {
  const { dist, callEdges } = slice;
  const sliceMids = [...dist.keys()];
  const internal = sliceMids.filter((m) => !cpg.isExternal(m));
  const files = [...new Set(internal.map((m) => cpg.mfile(m)))].sort();
  const callEdgesByCaller = new Map<number, CallEdge[]>();
  for (const e of callEdges) {
    const cur = callEdgesByCaller.get(e[0]);
    if (cur) cur.push(e);
    else callEdgesByCaller.set(e[0], [e]);
  }

  const out: string[] = [];
  out.push("# Reachability slice");
  out.push(`functions: ${internal.length}  files: ${files.length} (${files.join(", ")})`);
  if (opsNote) out.push(opsNote);
  out.push("");
  out.push("## Call/dataflow edges (interprocedural)");
  const seen = new Set<string>();
  const sortedEdges = [...callEdges].sort((x, y) => {
    const fx = cpg.mfile(x[0]);
    const fy = cpg.mfile(y[0]);
    if (fx !== fy) return fx < fy ? -1 : 1;
    return (cpg.nodeLine(x[2]) ?? 0) - (cpg.nodeLine(y[2]) ?? 0);
  });
  for (const [caller, callee, cn, kind] of sortedEdges) {
    const ln = cpg.nodeLine(cn);
    const key = `${cpg.mname(caller)}|${cpg.mname(callee)}|${ln}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const tag = kind === "ops" ? " [ops-synth]" : "";
    out.push(
      `  ${cpg.mname(caller)} (${cpg.mfile(caller)}:${ln}) -> ${cpg.mname(callee)} ` +
        `(${cpg.mfile(callee)}:${cpg.mlines(callee)[0]})${tag}`,
    );
  }
  out.push("");
  out.push("## Function source (path lines only)");
  const srcCache = new Map<string, string[] | null>();
  const order = [...internal].sort((x, y) => dist.get(x)! - dist.get(y)!);
  for (const m of order) {
    const fn = cpg.mfile(m);
    const [a, b] = cpg.mlines(m);
    out.push(`\n### ${cpg.mname(m)}  (${fn}:${a}-${b})  [hop ${dist.get(m)}]`);
    let rendered = false;
    if (loadSource) {
      if (!srcCache.has(fn)) srcCache.set(fn, loadSource(fn));
      const src = srcCache.get(fn);
      if (src) {
        for (const ln of relevantLines(cpg, m, callEdgesByCaller)) {
          if (ln >= 1 && ln <= src.length) out.push(`  ${ln}: ${src[ln - 1].replace(/\s+$/, "")}`);
        }
        rendered = true;
      }
    }
    if (!rendered) {
      for (const [, , cn] of callEdgesByCaller.get(m) ?? []) {
        out.push(`  ${cpg.nodeLine(cn)}: ${cpg.nodeCode(cn)}`);
      }
    }
  }
  const text = out.join("\n");
  return {
    text,
    stats: { functions: internal.length, files, callEdges: seen.size, chars: text.length },
  };
}

/**
 * High-level convenience: resolve `specs` to targets, slice `hops` deep, and
 * render. Returns null when NO spec resolves to a method in the CPG (the caller
 * degrades to the flat-text finder).
 */
export function sliceAroundTargets(
  cpg: Cpg,
  specs: string[],
  opts: { hops?: number; loadSource?: SourceLoader; opsNote?: string } = {},
): { text: string; stats: SliceRenderStats; targetCount: number } | null {
  const targets = new Set<number>();
  for (const spec of specs) for (const mid of findTargets(cpg, spec)) targets.add(mid);
  if (targets.size === 0) return null;
  const slice = buildSlice(cpg, [...targets], opts.hops ?? 3);
  const { text, stats } = renderSlice(cpg, slice, opts.loadSource, opts.opsNote);
  return { text, stats, targetCount: targets.size };
}
