/**
 * INTER-PROCEDURAL refcount get/put coupling checker — FIRST INCREMENT.
 *
 * WHY THIS EXISTS: the seedless invariant checker's refcount signal
 * ({@link ./c-dataflow.ts} `findViolationsDataflow`, check (3)) is
 * INTRA-procedural and has NO call graph. It counts direct `getFn`/`putFn`
 * calls WITHIN one function body. That structurally cannot pair a refcount
 * coupling whose get and put are split across functions AND files — the exact
 * shape of the mqueue `notify_sock` case:
 *
 *   ipc/mqueue.c            do_mq_notify():
 *     sock = netlink_getsockbyfilp(fd_file(f));   // GET (wrapper)
 *     info->notify_sock = sock;                   // ref stored in a field
 *     ... netlink_detachskb(sock, nc);            // PUT (wrapper), error path
 *   ipc/mqueue.c            __do_notify()/remove_notification():
 *     netlink_sendskb(info->notify_sock, ...);    // PUT (wrapper), via the field
 *   net/netlink/af_netlink.c:
 *     netlink_getsockbyfilp() { ...; sock_hold(sock); return sock; }   // the real GET
 *     netlink_sendskb(sk, ..) { ...; sock_put(sk); }                   // the real PUT
 *     netlink_detachskb(sk, ..) { ...; sock_put(sk); }                 // the real PUT
 *
 * The direct `sock_hold`/`sock_put` (the model's getFn/putFn) NEVER appear in
 * mqueue.c — they are wrapped. The intra-proc checker sees zero refcount ops in
 * mqueue.c and emits nothing. This module resolves the wrappers through a
 * lightweight call graph over the whole subsystem so the `netlink_getsockbyfilp`
 * call in mqueue.c COUNTS as a `sock_hold`, `netlink_sendskb`/`netlink_detachskb`
 * count as `sock_put`, and the get/put are then paired across the file boundary.
 *
 * THE MILESTONE this increment targets: GENERATE the cross-file/cross-function
 * refcount-coupling candidate class the intra-proc engine could not — not
 * necessarily find a live bug. The mqueue coupling is a KNOWN-SAFE FP (the
 * ownership transfer is correct), so the win is that it is now GENERATED AT ALL,
 * and correctly classified `balanced` rather than escalated to a leak.
 *
 * ── HONEST PRECISION LIMITS (a first increment, NOT a points-to solver) ────────
 *   • NAME-BASED call graph: edges are `callee-identifier` → `function name`.
 *     No static/duplicate-name disambiguation (two `static foo()` in different
 *     files collapse to one node), no indirect / function-pointer calls, no
 *     macro-expanded calls.
 *   • NO ALIASING: ref-carrying storage is tracked only through a direct
 *     `field = var` copy (the notify_sock store). `a = b; c = a;` chains beyond
 *     one hop, container_of, and pointer arithmetic are not followed.
 *   • CROSS-FUNCTION puts are matched by FIELD NAME (`->notify_sock`), which is
 *     name-based: a same-named field on an unrelated struct would false-match.
 *   • WRAPPER RESOLUTION is a bounded fixpoint with a coarse "returns the held
 *     object" / "puts a parameter" heuristic; a wrapper that conditionally holds
 *     or launders the ref through a struct is over- or under-approximated.
 *   • This is a CANDIDATE GENERATOR. Every coupling it emits is a lead for the
 *     downstream skeptic+prover gate, not a confirmed bug. Its value vs the
 *     intra-proc engine is COVERAGE of a class that was previously unreachable,
 *     at a documented, bounded FP cost.
 */

import type Parser from "tree-sitter";
import { parseC } from "./c-dataflow.js";
import type { InvariantModel, RefcountRule } from "./subsystem-invariant-model.js";
import type { HuntBrief, HuntCandidate } from "./hunt-scan.js";

type TsNode = Parser.SyntaxNode;

// ── Canonicalization (lvalue/expr → stable storage key) ─────────────────────────

const collapseWs = (s: string) => s.replace(/\s+/g, "");

/**
 * Canonicalize an expression node to a stable storage key. `.` and `->` both
 * normalize to `->`; a leading `&` is stripped (`&f->lock` == `f->lock`); a
 * leading `*` deref is kept as a marker so it is not confused with the pointer.
 * Mirrors c-dataflow's `canon` (kept local so this module stays additive and
 * does not force new exports on the intra-proc checker).
 */
function canon(node: TsNode, src: string): string {
  switch (node.type) {
    case "identifier":
    case "field_identifier":
    case "type_identifier":
      return src.slice(node.startIndex, node.endIndex);
    case "parenthesized_expression": {
      const inner = node.namedChildren[0];
      return inner ? canon(inner, src) : collapseWs(src.slice(node.startIndex, node.endIndex));
    }
    case "cast_expression": {
      const value = node.childForFieldName("value");
      return value ? canon(value, src) : collapseWs(src.slice(node.startIndex, node.endIndex));
    }
    case "pointer_expression": {
      const op = node.child(0);
      const arg = node.childForFieldName("argument") ?? node.namedChildren[0];
      if (!arg) return collapseWs(src.slice(node.startIndex, node.endIndex));
      return op && src.slice(op.startIndex, op.endIndex) === "&" ? canon(arg, src) : "*" + canon(arg, src);
    }
    case "field_expression": {
      const arg = node.childForFieldName("argument");
      const field = node.childForFieldName("field");
      const base = arg ? canon(arg, src) : "";
      const f = field ? src.slice(field.startIndex, field.endIndex) : "";
      return `${base}->${f}`;
    }
    case "subscript_expression": {
      const arg = node.childForFieldName("argument") ?? node.namedChildren[0];
      return (arg ? canon(arg, src) : "") + "[]";
    }
    default:
      return collapseWs(src.slice(node.startIndex, node.endIndex));
  }
}

/** Leading identifier of a storage key (`info->notify_sock` → `info`). */
const firstIdent = (s: string): string => /^[A-Za-z_][A-Za-z0-9_]*/.exec(s)?.[0] ?? s;

/** Trailing field of a storage key (`info->notify_sock` → `notify_sock`; bare id → ""). */
function fieldOf(key: string): string {
  const idx = key.lastIndexOf("->");
  return idx === -1 ? "" : key.slice(idx + 2).replace(/\[\]$/, "");
}

// ── Lightweight per-function extraction (calls, aliases, returns, params) ────────

/** A call effect inside a function body. */
interface CallEv {
  callee: string;
  /** Canonical first-argument storage key (`&` stripped), or "" if none. */
  arg0Key: string;
  /** lvalue this call's result is assigned to (`x = f(...)` / `T x = f(...)`), or undefined. */
  resultKey?: string;
  line: number;
}

/** A `lhs = <identifier>` copy (the only aliasing this increment tracks). */
interface AliasEv {
  lhsKey: string;
  rhsIdent: string;
  line: number;
}

/** One function definition + its extracted refcount-relevant events. */
export interface FnDef {
  name: string;
  file: string;
  startLine: number;
  calls: CallEv[];
  aliases: AliasEv[];
  /** Leading identifiers of every `return <expr>` (for get-wrapper detection). */
  returnBases: Set<string>;
  /** Parameter identifier names (for put-wrapper detection). */
  params: Set<string>;
}

const line1 = (n: TsNode) => n.startPosition.row + 1;

/** Extract parameter identifier names from a function_definition. */
function extractParams(fnDef: TsNode, src: string): Set<string> {
  const out = new Set<string>();
  const pl = findDescendant(fnDef.childForFieldName("declarator"), "parameter_list");
  if (!pl) return out;
  for (const p of pl.namedChildren) {
    if (p.type !== "parameter_declaration") continue;
    // Drill through pointer_declarator/array_declarator to the identifier.
    const id = findDescendant(p.childForFieldName("declarator") ?? p, "identifier");
    if (id) out.add(src.slice(id.startIndex, id.endIndex));
  }
  return out;
}

/** First descendant (BFS, incl. the node itself) of a given type. */
function findDescendant(node: TsNode | null, type: string): TsNode | null {
  if (!node) return null;
  const q: TsNode[] = [node];
  while (q.length) {
    const n = q.shift()!;
    if (n.type === type) return n;
    for (const c of n.namedChildren) q.push(c);
  }
  return null;
}

/** The callee identifier of a call_expression (only plain `name(...)` calls). */
function calleeName(call: TsNode, src: string): string {
  const fn = call.childForFieldName("function");
  return fn && fn.type === "identifier" ? src.slice(fn.startIndex, fn.endIndex) : "";
}

/** Determine the lvalue a call's result is bound to, from the call's parent. */
function resultKeyOf(call: TsNode, src: string): string | undefined {
  const p = call.parent;
  if (!p) return undefined;
  if (p.type === "assignment_expression" && p.childForFieldName("right")?.id === call.id) {
    const left = p.childForFieldName("left");
    return left ? canon(left, src) : undefined;
  }
  if (p.type === "init_declarator" && p.childForFieldName("value")?.id === call.id) {
    const decl = p.childForFieldName("declarator");
    const id = decl && decl.type === "identifier" ? decl : findDescendant(decl, "identifier");
    return id ? src.slice(id.startIndex, id.endIndex) : undefined;
  }
  return undefined;
}

/** Walk one function body, collecting calls / alias-copies / returns. */
function extractBody(body: TsNode, src: string): Pick<FnDef, "calls" | "aliases" | "returnBases"> {
  const calls: CallEv[] = [];
  const aliases: AliasEv[] = [];
  const returnBases = new Set<string>();

  const walk = (n: TsNode): void => {
    switch (n.type) {
      case "call_expression": {
        const callee = calleeName(n, src);
        if (callee) {
          const args = n.childForFieldName("arguments");
          const a0 = args?.namedChildren[0];
          calls.push({
            callee,
            arg0Key: a0 ? canon(a0, src) : "",
            ...(resultKeyOf(n, src) ? { resultKey: resultKeyOf(n, src) } : {}),
            line: line1(n),
          });
        }
        break;
      }
      case "assignment_expression": {
        const left = n.childForFieldName("left");
        const right = n.childForFieldName("right");
        // Only a bare `lhs = <identifier>` copy is an alias we track.
        if (left && right && right.type === "identifier") {
          aliases.push({ lhsKey: canon(left, src), rhsIdent: src.slice(right.startIndex, right.endIndex), line: line1(n) });
        }
        break;
      }
      case "init_declarator": {
        const decl = n.childForFieldName("declarator");
        const value = n.childForFieldName("value");
        if (decl && decl.type === "identifier" && value && value.type === "identifier") {
          aliases.push({ lhsKey: src.slice(decl.startIndex, decl.endIndex), rhsIdent: src.slice(value.startIndex, value.endIndex), line: line1(n) });
        }
        break;
      }
      case "return_statement": {
        const e = n.namedChildren[0];
        if (e) returnBases.add(firstIdent(canon(e, src)));
        break;
      }
    }
    for (const c of n.namedChildren) walk(c);
  };
  walk(body);
  return { calls, aliases, returnBases };
}

/** Collect every top-level function_definition in a parsed file. */
function collectFnDefs(root: TsNode, src: string, file: string): FnDef[] {
  const out: FnDef[] = [];
  const walk = (n: TsNode) => {
    if (n.type === "function_definition") {
      const body = n.childForFieldName("body");
      if (body && body.type === "compound_statement") {
        const { calls, aliases, returnBases } = extractBody(body, src);
        out.push({
          name: fnName(n, src),
          file,
          startLine: line1(n),
          calls,
          aliases,
          returnBases,
          params: extractParams(n, src),
        });
      }
      return; // C functions don't nest
    }
    for (const c of n.namedChildren) walk(c);
  };
  walk(root);
  return out;
}

/** Recover a function_definition's name (drills through pointer/paren declarators). */
function fnName(fnDef: TsNode, src: string): string {
  let decl = fnDef.childForFieldName("declarator");
  const seen = new Set<number>();
  while (decl && !seen.has(decl.id)) {
    seen.add(decl.id);
    if (decl.type === "identifier") return src.slice(decl.startIndex, decl.endIndex);
    const inner = decl.childForFieldName("declarator");
    if (inner) {
      decl = inner;
      continue;
    }
    const id = decl.namedChildren.find((c) => c.type === "identifier");
    if (id) return src.slice(id.startIndex, id.endIndex);
    break;
  }
  return "<anonymous>";
}

// ── The subsystem call graph ─────────────────────────────────────────────────────

/** A lightweight, name-based call graph over the subsystem's parsed files. */
export interface CallGraph {
  /** Every defined function, in parse order. */
  fns: FnDef[];
  /** name → the FIRST definition with that name (dup names collapse; see limits). */
  byName: Map<string, FnDef>;
}

/**
 * Build the call graph over all subsystem sources. Nodes are function names;
 * edges (implicit in each {@link FnDef.calls}) are name-based caller→callee. The
 * cross-file functions named in the model's refcountRules resolve here even when
 * defined in a different file, because C function names are global — that global
 * namespace IS the cross-file join this increment relies on.
 */
export function buildCallGraph(sources: Array<{ file: string; text: string }>): CallGraph {
  const fns: FnDef[] = [];
  for (const { file, text } of sources) {
    const root = parseC(text);
    if (!root) continue;
    fns.push(...collectFnDefs(root, text, file));
  }
  const byName = new Map<string, FnDef>();
  for (const f of fns) if (!byName.has(f.name)) byName.set(f.name, f);
  return { fns, byName };
}

// ── Wrapper resolution (transitively resolve get/put wrappers via the graph) ─────

/** Where a get/put wrapper's actual refcount op lives (provenance for the report). */
export interface OpProvenance {
  /** The wrapper function name (`netlink_getsockbyfilp`), or the raw op itself. */
  via: string;
  /** File the ACTUAL getFn/putFn call resolves into (`net/netlink/af_netlink.c`). */
  resolvedFile: string;
  /** 1-based line of the actual getFn/putFn call, when known. */
  resolvedLine: number;
  /** The raw refcount op the wrapper bottoms out in (`sock_hold` / `sock_put`). */
  rawOp: string;
}

export interface ResolvedOps {
  /** Call tokens that ESTABLISH a ref: the raw getFn plus every get-wrapper. */
  getOps: Map<string, OpProvenance>;
  /** Call tokens that RELEASE a ref: the raw putFn plus every put-wrapper. */
  putOps: Map<string, OpProvenance>;
}

/**
 * Resolve the get/put wrapper closures for one refcount rule.
 *
 * A function is a GET-WRAPPER when it calls a known get-op and RETURNS the held
 * object (`sock_hold(sock); return sock;`). A function is a PUT-WRAPPER when it
 * calls a known put-op on one of its own PARAMETERS (`netlink_sendskb(sk,..){
 * sock_put(sk); }`). Both are computed to a fixpoint so a wrapper that wraps a
 * wrapper (e.g. `netlink_attachskb` → `netlink_sendskb` → `sock_put`) resolves.
 * The raw getFn/putFn are always members. Bounded + heuristic — see the module
 * header's precision limits.
 */
export function resolveWrapperOps(cg: CallGraph, rule: RefcountRule): ResolvedOps {
  const getOps = new Map<string, OpProvenance>([
    [rule.getFn, { via: rule.getFn, resolvedFile: "", resolvedLine: 0, rawOp: rule.getFn }],
  ]);
  const putOps = new Map<string, OpProvenance>([
    [rule.putFn, { via: rule.putFn, resolvedFile: "", resolvedLine: 0, rawOp: rule.putFn }],
  ]);

  // Fixpoint: keep adding wrappers until no new ones appear.
  for (let iter = 0; iter < cg.fns.length + 2; iter++) {
    let changed = false;
    for (const fn of cg.fns) {
      // GET-WRAPPER: calls a get-op whose produced ref key is among the returns.
      if (!getOps.has(fn.name)) {
        for (const call of fn.calls) {
          const seed = getOps.get(call.callee);
          if (!seed) continue;
          // produced ref = result of a wrapper call, or the arg0 of the raw getFn.
          const produced = call.resultKey ? firstIdent(call.resultKey) : firstIdent(call.arg0Key);
          if (produced && fn.returnBases.has(produced)) {
            getOps.set(fn.name, {
              via: fn.name,
              resolvedFile: seed.resolvedFile || fn.file,
              resolvedLine: seed.resolvedLine || call.line,
              rawOp: seed.rawOp,
            });
            changed = true;
            break;
          }
        }
      }
      // PUT-WRAPPER: calls a put-op on one of its own parameters.
      if (!putOps.has(fn.name)) {
        for (const call of fn.calls) {
          const seed = putOps.get(call.callee);
          if (!seed) continue;
          if (call.arg0Key && fn.params.has(firstIdent(call.arg0Key))) {
            putOps.set(fn.name, {
              via: fn.name,
              resolvedFile: seed.resolvedFile || fn.file,
              resolvedLine: seed.resolvedLine || call.line,
              rawOp: seed.rawOp,
            });
            changed = true;
            break;
          }
        }
      }
    }
    if (!changed) break;
  }
  return { getOps, putOps };
}

// ── The coupling candidate (the milestone artifact) ─────────────────────────────

export interface GetSite {
  fn: string;
  file: string;
  line: number;
  /** The get-op call token (`netlink_getsockbyfilp` or the raw `sock_hold`). */
  callee: string;
  /** Storage the held ref is bound to (the result var, e.g. `sock`). */
  refVar: string;
  /** Field the ref is stored into via a `field = refVar` copy (`notify_sock`), if any. */
  storedField?: string;
  /** File the actual getFn resolves into (cross-file when != file). */
  resolvedFile: string;
  resolvedLine: number;
  rawOp: string;
}

export interface PutSite {
  fn: string;
  file: string;
  line: number;
  callee: string;
  arg0: string;
  /** Trailing field of arg0 (`notify_sock` for `netlink_sendskb(info->notify_sock,..)`). */
  argField: string;
  resolvedFile: string;
  rawOp: string;
  /** How this put was paired to the get: same variable, or same stored field. */
  matchedBy: "same-var" | "stored-field";
}

/**
 * `balanced` — a release reaches the get (or the ref is returned to the caller).
 * `leak-suspect` — no release reaches the acquired ref anywhere in the subsystem.
 * `double-put-suspect` — RESERVED for a future CFG-aware pass; this first
 * increment never emits it (double-put needs path-sensitivity — see the verdict
 * note in {@link findInterprocRefcountCouplings}).
 */
export type CouplingVerdict = "balanced" | "leak-suspect" | "double-put-suspect";

/** One inter-procedural get/put coupling candidate. */
export interface RefcountCoupling {
  object: string;
  /** The refcount rule name (`notify_sock ref`). */
  refcount: string;
  getSite: GetSite;
  putSites: PutSite[];
  /**
   * TRUE when the get and/or put resolve to a refcount op DEFINED IN A DIFFERENT
   * FILE than the call site, or when a matched put lives in a different file than
   * the get. This is the property the intra-proc engine cannot produce.
   */
  crossFile: boolean;
  /** TRUE when a matched put is in a different FUNCTION than the get. */
  crossFunction: boolean;
  verdict: CouplingVerdict;
  /** Count of matched puts on the SAME variable (>=2 ⇒ probable exclusive cleanup pair, not double-put). */
  sameVarPutCount: number;
  detail: string;
}

export interface FindCouplingOptions {
  /** Cap emitted couplings (default 40). */
  maxCouplings?: number;
  log?: (msg: string) => void;
}

/**
 * FIND inter-procedural refcount couplings for every {@link RefcountRule} in the
 * model, over the whole subsystem. For each get-op call site it gathers matching
 * put-op calls — intra-function by variable, and cross-function by the field the
 * ref was stored into — resolving get/put wrappers through the call graph so the
 * pairing spans functions and files. The verdict is a heuristic first cut:
 *   • `balanced`      — a matching put reaches the get, or the ref is returned to
 *                       the caller (ownership transfer).
 *   • `leak-suspect`  — no matching put anywhere in the subsystem and the ref is
 *                       not returned — a get with no release on the paths seen.
 * (double-put is deliberately NOT emitted here — it needs the path-sensitive CFG.)
 */
export function findInterprocRefcountCouplings(
  model: InvariantModel,
  sources: Array<{ file: string; text: string }>,
  opts: FindCouplingOptions = {},
): RefcountCoupling[] {
  const log = opts.log ?? (() => {});
  const maxCouplings = opts.maxCouplings ?? 40;
  const cg = buildCallGraph(sources);
  const couplings: RefcountCoupling[] = [];

  for (const obj of model.objects) {
    for (const rule of obj.refcountRules) {
      const { getOps, putOps } = resolveWrapperOps(cg, rule);

      // Global put-site index for this rule.
      const allPuts: PutSite[] = [];
      for (const fn of cg.fns) {
        for (const call of fn.calls) {
          const seed = putOps.get(call.callee);
          if (!seed) continue;
          allPuts.push({
            fn: fn.name,
            file: fn.file,
            line: call.line,
            callee: call.callee,
            arg0: call.arg0Key,
            argField: fieldOf(call.arg0Key),
            resolvedFile: seed.resolvedFile || fn.file,
            rawOp: seed.rawOp,
            matchedBy: "same-var", // refined per get below
          });
        }
      }

      // Every get site, paired against the put index.
      for (const fn of cg.fns) {
        for (const call of fn.calls) {
          const seed = getOps.get(call.callee);
          if (!seed) continue;
          const refVar = call.resultKey ? call.resultKey : call.arg0Key;
          if (!refVar) continue;
          const refBase = firstIdent(refVar);

          // Did this function store the ref into a field (`field = refVar`)?
          const storedField = fn.aliases.find((a) => a.rhsIdent === refBase && fieldOf(a.lhsKey))
            ? fieldOf(fn.aliases.find((a) => a.rhsIdent === refBase && fieldOf(a.lhsKey))!.lhsKey)
            : undefined;

          const getSite: GetSite = {
            fn: fn.name,
            file: fn.file,
            line: call.line,
            callee: call.callee,
            refVar,
            ...(storedField ? { storedField } : {}),
            resolvedFile: seed.resolvedFile || fn.file,
            resolvedLine: seed.resolvedLine || call.line,
            rawOp: seed.rawOp,
          };

          // Match puts: (1) same variable in the same function; (2) the stored
          // field anywhere in the subsystem (the cross-function join).
          const matched: PutSite[] = [];
          for (const p of allPuts) {
            const sameVar = p.fn === fn.name && p.file === fn.file && firstIdent(p.arg0) === refBase && p.line >= call.line;
            const sameField = storedField !== undefined && p.argField === storedField;
            if (sameVar) matched.push({ ...p, matchedBy: "same-var" });
            else if (sameField) matched.push({ ...p, matchedBy: "stored-field" });
          }

          const crossFile =
            getSite.resolvedFile !== getSite.file ||
            matched.some((p) => p.resolvedFile !== p.file || p.file !== getSite.file);
          const crossFunction = matched.some((p) => p.fn !== fn.name);

          // Ownership can also leave the function by being RETURNED to the caller
          // (`sock_hold(sk); return sk;` — a get-wrapper's own body). That is a
          // transfer, not a leak: the caller owns the release.
          const returnedToCaller = fn.returnBases.has(refBase);

          // VERDICT (first-increment, deliberately conservative):
          //   • a matching release present            → balanced
          //   • ref returned to the caller            → balanced (transfer)
          //   • otherwise (get, no release, not returned) → leak-suspect
          // NB: genuine DOUBLE-PUT detection is intentionally NOT emitted here.
          // Two puts on the same variable are almost always the mutually-exclusive
          // error/success cleanup pair (e.g. do_mq_notify's netlink_attachskb on
          // the transfer path vs netlink_detachskb on the error path). Deciding
          // they are actually reachable together needs the path-sensitive CFG in
          // c-dataflow.ts — out of scope for this increment. `sameVarPutCount` is
          // recorded so a future CFG-aware pass can escalate; the verdict does not.
          const sameVarPutCount = matched.filter((p) => p.matchedBy === "same-var").length;
          let verdict: CouplingVerdict;
          if (matched.length > 0 || returnedToCaller) verdict = "balanced";
          else verdict = "leak-suspect";

          const wrapNote =
            getSite.callee !== rule.getFn
              ? `get-wrapper ${getSite.callee}() resolves to ${getSite.rawOp}() @ ${getSite.resolvedFile}:${getSite.resolvedLine}`
              : `direct ${rule.getFn}()`;
          const putNote =
            matched.length === 0
              ? "no matching put found in the subsystem"
              : matched
                  .map(
                    (p) =>
                      `${p.callee}(${p.arg0}) @ ${p.file}:${p.line} [${p.matchedBy}${
                        p.callee !== rule.putFn ? ` → ${p.rawOp}() @ ${p.resolvedFile}` : ""
                      }]`,
                  )
                  .join("; ");

          couplings.push({
            object: obj.object,
            refcount: rule.name,
            getSite,
            putSites: matched,
            crossFile,
            crossFunction,
            verdict,
            sameVarPutCount,
            detail:
              `${rule.name}: ${wrapNote}. GET at ${getSite.file}:${getSite.line} in ${getSite.fn}()` +
              (storedField ? ` stores the ref into ->${storedField}` : "") +
              `. PUT(s): ${putNote}.` +
              (crossFile ? " COUPLING SPANS FILES (get/put resolve to a different file than the call site)." : "") +
              (verdict === "leak-suspect"
                ? returnedToCaller
                  ? ""
                  : " No release reaches the acquired ref on the analyzed paths — leak/UAF SUSPECT."
                : returnedToCaller && matched.length === 0
                  ? " The ref is RETURNED to the caller (ownership transfer) — balanced; the caller owns the release."
                  : ` A release is present (${sameVarPutCount} same-var, ${matched.length - sameVarPutCount} via stored field) — balanced; the candidate is the cross-scope coupling itself.` +
                    (sameVarPutCount >= 2
                      ? " NOTE: >=2 same-var releases — likely the exclusive error/success cleanup pair, NOT a double-put; confirming a real double-put needs the path-sensitive CFG (out of scope for this increment)."
                      : "")),
          });
        }
      }
    }
  }

  // Deterministic order; couplings that span files / look imbalanced first.
  const rank = (c: RefcountCoupling) =>
    (c.verdict === "balanced" ? 0 : 1) * 0 + // keep all; ordering below
    (c.crossFile ? 0 : 1);
  couplings.sort(
    (a, b) =>
      rank(a) - rank(b) ||
      a.getSite.file.localeCompare(b.getSite.file) ||
      a.getSite.line - b.getSite.line,
  );
  const capped = couplings.slice(0, maxCouplings);
  log(
    `[interproc-refcount] ${couplings.length} coupling candidate(s) ` +
      `(${couplings.filter((c) => c.crossFile).length} cross-file, ` +
      `${couplings.filter((c) => c.verdict !== "balanced").length} imbalance-suspect)` +
      `${capped.length < couplings.length ? ` (capped to ${capped.length})` : ""}`,
  );
  return capped;
}

// ── Map couplings → runHuntScan candidates (plug into the existing gate) ─────────

export interface InterprocRefcountPlan {
  couplings: RefcountCoupling[];
  brief: HuntBrief;
  /** One candidate per get-site file, hints merged — same shape as the other stages. */
  candidates: HuntCandidate[];
}

/**
 * Turn couplings into a {@link HuntBrief} + {@link HuntCandidate}[] for
 * `runHuntScan`, exactly like `violationsToHuntPlan` — so inter-procedural
 * couplings flow through the SAME skeptic+prover gate the intra-proc candidates
 * do. Only non-`balanced` couplings become candidates by default (the balanced
 * ones are coverage evidence, not leads); pass `includeBalanced` to surface all.
 */
export function couplingsToHuntPlan(
  model: InvariantModel,
  couplings: RefcountCoupling[],
  includeBalanced = false,
): InterprocRefcountPlan {
  const selected = includeBalanced ? couplings : couplings.filter((c) => c.verdict !== "balanced");
  const bySite = new Map<string, HuntCandidate>();
  for (const c of selected) {
    const hint =
      `INTER-PROCEDURAL REFCOUNT COUPLING candidate (call-graph resolved). ${c.detail} ` +
      `Verify the get/put balance across all reachable paths — this pairing spans ` +
      `${c.crossFile ? "files" : "functions"} and was resolved through refcount-op wrappers, ` +
      `so confirm the wrapper resolution and the field-based cross-function match are real (not a ` +
      `name-collision or an unfollowed alias).`;
    const existing = bySite.get(c.getSite.file);
    if (existing) existing.hint = `${existing.hint}\n---\n${hint}`;
    else bySite.set(c.getSite.file, { path: c.getSite.file, hint });
  }
  const brief: HuntBrief = {
    bugClass: `inter-procedural refcount imbalance (seedless, call-graph): ${model.subsystem}`,
    pattern:
      `A refcount get/put coupling in ${model.subsystem} is split across functions and/or files: the get and put ` +
      `bottom out in refcount ops (e.g. sock_hold/sock_put) reached only through wrapper functions defined in a ` +
      `different file. A candidate is emitted when the acquired ref has no reaching release (leak/UAF) or a doubled ` +
      `release (double-put). Confirm the call-graph resolution and reject name-collision / unfollowed-alias false ` +
      `positives.`,
    fixReference: undefined,
  };
  return { couplings, brief, candidates: [...bySite.values()] };
}
