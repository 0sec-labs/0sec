/**
 * Static sink → syscall reachability ranking (technique #5).
 *
 * Goal: when an LLM (or foxguard) flags a *sink* in the kernel — a specific
 * `file:line` / function we suspect is vulnerable — the repro/fuzzing prompt
 * needs to know *which userspace syscalls can actually reach it* so it can
 * target the right entry points instead of fuzzing blind.
 *
 * This module builds a bounded, backwards breadth-first search over a static
 * call graph extracted from the kernel source tree, starting at the sink
 * function and walking *up* the caller chain until it hits a known syscall
 * entry point (from `scanSyscallBoundary`). Candidate entry syscalls are then
 * ranked by shortest path length, then by edge confidence.
 *
 * Inspiration: FuzzingBrain's SVF-backed value-flow ranking and Trail of Bits'
 * Buttercup, which uses a Kythe call graph to direct fuzzing at reachable
 * sinks. We deliberately do NOT reimplement SVF/Kythe — this is a cheap,
 * regex-extracted call graph that runs without compiling the kernel.
 *
 * ────────────────────────────────────────────────────────────────────────────
 * HONESTY / PRECISION CAVEAT — READ THIS.
 *
 * Kernel control flow is dominated by *indirect* calls: syscall tables, struct
 * file_operations / net_proto_family / genl_ops function pointers, BPF
 * dispatch, etc. A purely syntactic call graph (this one) CANNOT resolve those
 * edges — it only sees direct `foo(...)` call sites. Consequences:
 *
 *   - FALSE NEGATIVES: a sink reached only through a function pointer (the
 *     common case for ioctl/netlink handlers) will look unreachable. We attach
 *     entry points that live in the *same file* as a fallback so the ranker
 *     still emits a hint rather than nothing — but flagged as low confidence.
 *   - FALSE POSITIVES / over-broad: a directly-called helper shared by many
 *     paths will appear reachable from many syscalls.
 *
 * Therefore the output is RANKED HINTS, not a soundness claim. Treat the top
 * candidate as "most plausible syscall to start fuzzing", never as proof.
 * A consumer should always fall back to broad fuzzing if the hints don't pan
 * out. Optional SARIF call edges (from foxguard / CodeQL) can be supplied to
 * recover some indirect edges with higher confidence.
 *
 * Planned consumer: `kernel-prompts.ts` (separate PR) will call
 * `rankSinkReachability` and inject the top-N syscalls into the repro prompt.
 * This PR only exports the function + types; it does not rewire the prompt.
 */

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { scanSyscallBoundary, type EntryPoint } from "./syscall-boundary-map.js";

// ── Types ────────────────────────────────────────────────────────────────────

/** A sink the caller wants to know the reaching syscalls for. */
export interface SinkLocation {
  /** Path to the sink, relative to the kernel tree root (e.g. "fs/foo.c"). */
  file: string;
  /** 1-based line number of the suspected vulnerable line. */
  line: number;
  /**
   * Optional explicit enclosing function name. If omitted, we infer it from
   * the call graph by finding the function whose body contains `line`.
   */
  function?: string;
}

/** Confidence in a single call-graph edge. */
export type EdgeConfidence = "direct" | "sarif" | "same-file-fallback";

/** A directed caller → callee edge in the static call graph. */
export interface CallEdge {
  caller: string;
  callee: string;
  /** File the call site was found in (relative to tree root). */
  file: string;
  /** 1-based line of the call site (0 for synthetic/fallback edges). */
  line: number;
  confidence: EdgeConfidence;
}

/** A ranked candidate entry syscall that can (plausibly) reach the sink. */
export interface ReachabilityCandidate {
  /** The syscall entry point. */
  entry: EntryPoint;
  /** Number of call-graph hops from the entry to the sink (1 = direct call). */
  pathLength: number;
  /**
   * The function chain from entry down to the sink function, inclusive of both
   * endpoints, e.g. ["vuln_open", "vuln_dispatch", "vuln_copy_payload"].
   */
  path: string[];
  /** Weakest edge confidence along the path (the path is only as good as its weakest link). */
  confidence: EdgeConfidence;
  /**
   * Heuristic score in [0,1]. Higher = more plausible. Used for ordering; not
   * a probability. Combines path length and edge confidence.
   */
  score: number;
}

export interface RankSinkReachabilityResult {
  /** The sink that was queried. */
  sink: SinkLocation;
  /** Resolved enclosing function of the sink (best effort). */
  sinkFunction?: string;
  /** Candidates, best first. */
  candidates: ReachabilityCandidate[];
  /** Number of edges in the extracted call graph (for debugging/telemetry). */
  edgeCount: number;
  /** Non-fatal warnings (e.g. sink function could not be resolved). */
  warnings: string[];
}

export interface RankSinkReachabilityOptions {
  /**
   * Maximum BFS depth (caller hops) to walk back from the sink. Indirect-call
   * blindness makes deep walks low-value, so this is bounded. Default 8.
   */
  maxDepth?: number;
  /** Maximum number of ranked candidates to return. Default 10. */
  maxCandidates?: number;
  /** Maximum source files to read when extracting the call graph. Default 5000. */
  maxFiles?: number;
  /**
   * Optional externally-supplied call edges (e.g. from foxguard / CodeQL SARIF
   * call-graph output). These recover *indirect* edges the regex extractor
   * cannot see and are treated as higher-confidence than same-file fallbacks.
   */
  extraEdges?: CallEdge[];
  /**
   * Pre-computed syscall entry points. If omitted, `scanSyscallBoundary` is run
   * against the tree. Supplying this avoids a redundant scan when the caller
   * already has a boundary map.
   */
  entryPoints?: EntryPoint[];
}

// ── Call-graph extraction (regex, no compilation) ────────────────────────────

/**
 * Matches a C function *definition* opening line of the common kernel form:
 *   static int foo(struct bar *b)
 *   long sys_foo(void)
 * plus the SYSCALL_DEFINEn(name, ...) macro form. Deliberately conservative —
 * we only need enough structure to map line ranges to function names.
 */
const FUNC_DEF_RE =
  /^[A-Za-z_][\w\s*]*?\b([A-Za-z_]\w*)\s*\([^;{]*$/;
const SYSCALL_DEF_RE = /^\s*(?:COMPAT_)?SYSCALL_DEFINE\d+\(\s*(\w+)/;

/** Call sites: `identifier(` not preceded by a `.`/`->` (skip struct fields). */
const CALL_SITE_RE = /(?<![.\w>])([A-Za-z_]\w*)\s*\(/g;

/**
 * C keywords / macros that look like calls but are not functions we want as
 * call-graph nodes.
 */
const CALL_NOISE = new Set([
  "if", "for", "while", "switch", "return", "sizeof", "do", "else",
  "case", "defined", "typeof", "__attribute__", "static_assert",
  "BUG_ON", "WARN_ON", "likely", "unlikely",
]);

interface FuncSpan {
  name: string;
  file: string;
  startLine: number;
  endLine: number;
}

/**
 * Extract function spans (name + line range) from a single C source file by
 * tracking brace depth. Returns the spans plus the raw lines for call-site
 * scanning.
 */
function extractFuncSpans(content: string, file: string): FuncSpan[] {
  const lines = content.split("\n");
  const spans: FuncSpan[] = [];

  let i = 0;
  while (i < lines.length) {
    const line = lines[i]!;
    const trimmed = line.trim();

    // Find a definition opener. SYSCALL_DEFINE takes priority (the macro name
    // is the real symbol).
    let name: string | undefined;
    const sysMatch = trimmed.match(SYSCALL_DEF_RE);
    if (sysMatch) {
      name = sysMatch[1];
    } else if (
      !trimmed.startsWith("*") &&
      !trimmed.startsWith("//") &&
      !trimmed.startsWith("#")
    ) {
      const m = trimmed.match(FUNC_DEF_RE);
      if (m && !CALL_NOISE.has(m[1]!)) {
        // Heuristic: a real definition's opener is followed (within a few
        // lines) by an opening brace at column 0 or end-of-signature `{`.
        name = m[1];
      }
    }

    if (!name) {
      i++;
      continue;
    }

    // Walk forward to the opening brace, then track depth to the matching close.
    let j = i;
    let sawOpen = false;
    let depth = 0;
    let guard = 0;
    while (j < lines.length && guard < 20000) {
      const text = lines[j]!;
      for (const ch of text) {
        if (ch === "{") {
          depth++;
          sawOpen = true;
        } else if (ch === "}") {
          depth--;
        }
      }
      // A definition we never opened a brace for within ~10 lines is a
      // prototype / false match — bail.
      if (!sawOpen && j - i > 10) break;
      if (sawOpen && depth <= 0) {
        spans.push({ name, file, startLine: i + 1, endLine: j + 1 });
        i = j;
        break;
      }
      j++;
      guard++;
    }
    i++;
  }

  return spans;
}

/** Find the function span enclosing a 1-based line in a file. */
function functionAtLine(spans: FuncSpan[], line: number): FuncSpan | undefined {
  // Prefer the innermost (smallest) span that contains the line.
  let best: FuncSpan | undefined;
  for (const s of spans) {
    if (line >= s.startLine && line <= s.endLine) {
      if (!best || s.endLine - s.startLine < best.endLine - best.startLine) {
        best = s;
      }
    }
  }
  return best;
}

/** Recursively collect .c/.h files under a path, bounded by maxFiles. */
function collectSourceFiles(root: string, maxFiles: number): string[] {
  const out: string[] = [];
  const stack: string[] = [root];
  while (stack.length > 0 && out.length < maxFiles) {
    const dir = stack.pop()!;
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (out.length >= maxFiles) break;
      const full = join(dir, entry);
      let s;
      try {
        s = statSync(full);
      } catch {
        continue;
      }
      if (s.isDirectory()) {
        stack.push(full);
      } else if (entry.endsWith(".c") || entry.endsWith(".h")) {
        out.push(full);
      }
    }
  }
  return out;
}

interface CallGraph {
  /** callee name → set of caller names that directly call it. */
  callersOf: Map<string, Set<string>>;
  /** All function spans keyed by file. */
  spansByFile: Map<string, FuncSpan[]>;
  /** edge metadata, keyed by `caller->callee`. */
  edges: Map<string, CallEdge>;
}

/**
 * Build a static call graph from a kernel tree. Direct call sites only; see the
 * module-level caveat about indirect calls.
 */
function buildCallGraph(
  tree: string,
  maxFiles: number,
  extraEdges: CallEdge[],
): CallGraph {
  const callersOf = new Map<string, Set<string>>();
  const spansByFile = new Map<string, FuncSpan[]>();
  const edges = new Map<string, CallEdge>();

  const addEdge = (edge: CallEdge) => {
    let set = callersOf.get(edge.callee);
    if (!set) {
      set = new Set();
      callersOf.set(edge.callee, set);
    }
    set.add(edge.caller);
    const key = `${edge.caller}->${edge.callee}`;
    const existing = edges.get(key);
    // Keep the highest-confidence record for a given edge.
    if (!existing || confidenceRank(edge.confidence) > confidenceRank(existing.confidence)) {
      edges.set(key, edge);
    }
  };

  for (const file of collectSourceFiles(tree, maxFiles)) {
    let content: string;
    try {
      content = readFileSync(file, "utf8");
    } catch {
      continue;
    }
    const rel = relative(tree, file);
    const spans = extractFuncSpans(content, rel);
    spansByFile.set(rel, spans);

    const lines = content.split("\n");
    for (const span of spans) {
      // Scan the body (between signature and end) for call sites.
      for (let ln = span.startLine; ln <= span.endLine; ln++) {
        const text = lines[ln - 1] ?? "";
        const trimmed = text.trim();
        if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
        CALL_SITE_RE.lastIndex = 0;
        let m: RegExpExecArray | null;
        while ((m = CALL_SITE_RE.exec(text)) !== null) {
          const callee = m[1]!;
          if (callee === span.name) continue; // ignore the definition opener itself
          if (CALL_NOISE.has(callee)) continue;
          addEdge({
            caller: span.name,
            callee,
            file: rel,
            line: ln,
            confidence: "direct",
          });
        }
      }
    }
  }

  for (const edge of extraEdges) {
    addEdge(edge);
  }

  return { callersOf, spansByFile, edges };
}

function confidenceRank(c: EdgeConfidence): number {
  switch (c) {
    case "direct":
      return 3;
    case "sarif":
      return 2;
    case "same-file-fallback":
      return 1;
  }
}

// ── Ranking ──────────────────────────────────────────────────────────────────

/**
 * Rank the userspace syscalls that can (plausibly) reach a flagged kernel sink.
 *
 * Output is RANKED HINTS to direct a fuzzer/repro prompt — NOT a soundness
 * claim. See the module-level honesty caveat: indirect calls (function
 * pointers, syscall tables) are invisible to the static extractor, so missing
 * candidates are expected. Supply `opts.extraEdges` (from SARIF call graphs) to
 * recover indirect edges.
 */
export async function rankSinkReachability(
  sink: SinkLocation,
  treeRoot: string,
  opts: RankSinkReachabilityOptions = {},
): Promise<RankSinkReachabilityResult> {
  const maxDepth = opts.maxDepth ?? 8;
  const maxCandidates = opts.maxCandidates ?? 10;
  const maxFiles = opts.maxFiles ?? 5000;
  const warnings: string[] = [];

  if (!existsSync(treeRoot)) {
    throw new Error(`Kernel tree not found: ${treeRoot}`);
  }

  const graph = buildCallGraph(treeRoot, maxFiles, opts.extraEdges ?? []);

  // Resolve the enclosing function of the sink.
  let sinkFunction = sink.function;
  if (!sinkFunction) {
    const spans = graph.spansByFile.get(sink.file);
    const enclosing = spans ? functionAtLine(spans, sink.line) : undefined;
    sinkFunction = enclosing?.name;
  }
  if (!sinkFunction) {
    warnings.push(
      `Could not resolve a function enclosing ${sink.file}:${sink.line}. ` +
        `Reachability cannot be computed; returning no candidates.`,
    );
    return { sink, candidates: [], edgeCount: graph.edges.size, warnings };
  }

  // Syscall entry points: name → EntryPoint.
  const entryList =
    opts.entryPoints ??
    (await scanSyscallBoundary({ tree: treeRoot })).entryPoints.filter(
      (e) => e.type === "syscall",
    );
  const syscallEntries = entryList.filter((e) => e.type === "syscall");
  const entryByName = new Map<string, EntryPoint>();
  for (const e of syscallEntries) {
    entryByName.set(e.name, e);
    // SYSCALL_DEFINE(foo) often implies the in-tree symbol is also `foo`; the
    // boundary map already strips the macro, so name === function name here.
  }

  // Backwards BFS from the sink function up the caller chain.
  // Each queue item carries the path from the *current* node down to the sink.
  interface QueueItem {
    fn: string;
    path: string[];
    minConfidence: EdgeConfidence;
  }
  const best = new Map<string, ReachabilityCandidate>();
  const visited = new Set<string>([sinkFunction]);
  let queue: QueueItem[] = [
    { fn: sinkFunction, path: [sinkFunction], minConfidence: "direct" },
  ];

  for (let depth = 0; depth < maxDepth && queue.length > 0; depth++) {
    const next: QueueItem[] = [];
    for (const item of queue) {
      const callers = graph.callersOf.get(item.fn);
      if (!callers) continue;
      for (const caller of callers) {
        if (visited.has(caller)) continue;
        visited.add(caller);

        const edge = graph.edges.get(`${caller}->${item.fn}`);
        const edgeConf = edge?.confidence ?? "same-file-fallback";
        const minConfidence = weakerConfidence(item.minConfidence, edgeConf);
        const path = [caller, ...item.path];

        const entry = entryByName.get(caller);
        if (entry) {
          const pathLength = path.length - 1;
          const candidate = makeCandidate(entry, pathLength, path, minConfidence);
          const prev = best.get(entry.name);
          if (!prev || candidate.score > prev.score) {
            best.set(entry.name, candidate);
          }
          // A syscall is a terminal entry; do not walk above it.
          continue;
        }

        next.push({ fn: caller, path, minConfidence });
      }
    }
    queue = next;
  }

  // Same-file fallback: if a syscall lives in the same file as the sink but the
  // (indirect-call-blind) graph never connected them, emit it as a low-
  // confidence hint rather than nothing.
  for (const entry of syscallEntries) {
    if (best.has(entry.name)) continue;
    if (entry.file === sink.file) {
      const candidate = makeCandidate(
        entry,
        Number.POSITIVE_INFINITY,
        [entry.name, "…", sinkFunction],
        "same-file-fallback",
      );
      best.set(entry.name, candidate);
    }
  }

  if (best.size === 0) {
    warnings.push(
      `No syscall reaches ${sinkFunction} via the static (direct-call) graph. ` +
        `This is expected when the path goes through a function pointer ` +
        `(ioctl/netlink/file_operations dispatch). Consider broad fuzzing or ` +
        `supplying SARIF call edges via opts.extraEdges.`,
    );
  }

  const candidates = Array.from(best.values())
    .sort(
      (a, b) =>
        b.score - a.score ||
        a.pathLength - b.pathLength ||
        a.entry.name.localeCompare(b.entry.name),
    )
    .slice(0, maxCandidates);

  return {
    sink,
    sinkFunction,
    candidates,
    edgeCount: graph.edges.size,
    warnings,
  };
}

function makeCandidate(
  entry: EntryPoint,
  pathLength: number,
  path: string[],
  confidence: EdgeConfidence,
): ReachabilityCandidate {
  return {
    entry,
    pathLength,
    path,
    confidence,
    score: scoreCandidate(pathLength, confidence),
  };
}

/**
 * Heuristic score: shorter paths and stronger edges rank higher. Confidence
 * dominates length (a direct 4-hop path beats a same-file fallback).
 */
function scoreCandidate(pathLength: number, confidence: EdgeConfidence): number {
  const confWeight =
    confidence === "direct" ? 1.0 : confidence === "sarif" ? 0.8 : 0.3;
  // length component decays toward 0 as the path grows; Infinity → 0.
  const lengthComponent = Number.isFinite(pathLength)
    ? 1 / (1 + pathLength)
    : 0;
  return Number((confWeight * (0.5 + 0.5 * lengthComponent)).toFixed(4));
}

function weakerConfidence(a: EdgeConfidence, b: EdgeConfidence): EdgeConfidence {
  return confidenceRank(a) <= confidenceRank(b) ? a : b;
}
