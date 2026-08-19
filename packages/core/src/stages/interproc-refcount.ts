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

// ── Refinement 3: rule-quality filter (reject non-refcount pairs) ────────────────

/**
 * Function tokens that are NOT symmetric object-refcount get/put pairs — the LLM
 * model-build injected these as `refcountRules` and they generated pure FP noise.
 * A rule whose get OR put token is on this list is rejected before the checker
 * runs. Grouped by why they are not a refcount coupling:
 *   • plain atomic counters (`atomic_t`, not `refcount_t`) — a bare inc/dec is a
 *     counter, not an object-lifetime refcount, so "no put reaches it" is noise;
 *   • allocation pairs — `kzalloc`/`kfree` etc. are ownership by allocation, a
 *     different (and separately-modeled) discipline, not a get/put refcount;
 *   • page refs and module refs — real refcounts, but on `struct page` / a module,
 *     never the modeled subsystem object, so they false-couple everything;
 *   • `sk_msg_alloc` and friends — buffer allocation, not a refcount.
 * NB: `refcount_inc`/`refcount_dec` (the real refcount_t API) and named object
 * gets/puts (`sock_hold`/`sock_put`, `get_pid`/`put_pid`, …) are deliberately NOT
 * here — they are exactly what the checker exists to pair.
 */
const NON_REFCOUNT_TOKENS = new Set<string>([
  // plain atomic counters
  "atomic_inc", "atomic_dec", "atomic_add", "atomic_sub", "atomic_inc_return",
  "atomic_dec_return", "atomic_dec_and_test", "atomic_add_return", "atomic64_inc",
  "atomic64_dec", "atomic_long_inc", "atomic_long_dec", "atomic_fetch_inc", "atomic_fetch_dec",
  // allocation pairs (ownership-by-alloc, not a get/put refcount)
  "kzalloc", "kmalloc", "kcalloc", "kvzalloc", "kvmalloc", "vmalloc", "vzalloc",
  "kfree", "kvfree", "vfree", "kmem_cache_alloc", "kmem_cache_zalloc", "kmem_cache_free",
  "alloc_skb", "alloc_skb_with_frags", "kfree_skb", "consume_skb", "skb_free",
  "sk_msg_alloc", "sk_msg_free", "sk_msg_free_nocharge", "napi_alloc_skb",
  // page refs (never the modeled object)
  "get_page", "put_page", "__free_page", "__free_pages", "free_page", "free_pages",
  "get_user_pages", "put_user_page",
  // module refs (never the modeled object)
  "try_module_get", "__module_get", "module_put",
]);

const GET_TOKENS = ["get", "hold", "grab", "_inc", "acquire", "pin", "_ref", "take"];
const PUT_TOKENS = ["put", "_free", "release", "_dec", "drop", "unref", "unpin", "destroy", "kill"];

const looksIdentifier = (s: string): boolean => /^[A-Za-z_][A-Za-z0-9_]*$/.test(s);

/**
 * Refinement 3. TRUE when `rule` is a plausible symmetric object-refcount get/put
 * pair — a named get with a matching named put on the same object type. Rejects:
 *   • parse junk (`fn=void`, `fn=pf`, empty, non-identifier tokens);
 *   • get === put;
 *   • either side on {@link NON_REFCOUNT_TOKENS} (atomic counters, alloc pairs,
 *     page/module refs, `sk_msg_alloc`);
 *   • pairs whose get does not read like a get and whose put does not read like a
 *     put AND which share no object stem — i.e. not a symmetric acquire/release.
 * This runs BEFORE wrapper resolution, so the noise never reaches the call graph.
 */
export function isRefcountLikeRule(rule: RefcountRule): boolean {
  const g = (rule.getFn ?? "").trim();
  const p = (rule.putFn ?? "").trim();
  if (!g || !p || !looksIdentifier(g) || !looksIdentifier(p)) return false;
  if (g === p) return false;
  const gl = g.toLowerCase();
  const pl = p.toLowerCase();
  if (NON_REFCOUNT_TOKENS.has(gl) || NON_REFCOUNT_TOKENS.has(pl)) return false;
  const gLooksGet = GET_TOKENS.some((t) => gl.includes(t));
  const pLooksPut = PUT_TOKENS.some((t) => pl.includes(t));
  if (gLooksGet && pLooksPut) return true;
  // Fallback: a shared object stem (>=4 chars) with at least one side reading as
  // an acquire/release still counts (`foo_ref`/`foo_unref` where a token is fuzzy).
  const stem = (s: string) => s.replace(/^(__|_)+/, "").split("_")[0] ?? "";
  const shareStem = stem(gl).length >= 4 && stem(gl) === stem(pl);
  return shareStem && (gLooksGet || pLooksPut);
}

// ── Destructor-family recognition (refinement 1) ─────────────────────────────────

/**
 * TRUE when a function name reads as an object destructor / free / release / put /
 * evict path. Refinement 1 treats a put-op inside such a function as a genuine
 * release of the freed object's fields — the #1 FP was a get stored into
 * `obj->field` (`sk->sk_peer_pid = get_pid(...)`) whose only release lives in the
 * object's destructor (`__sk_destruct`: `put_pid(sk->sk_peer_pid)`), a different
 * function the pairing has to reach.
 */
export function isDestructorFamily(name: string): boolean {
  return /(?:_|^)(?:destruct(?:or)?|dtor|free|release|evict|reclaim|destroy|put|dealloc|cleanup|teardown|drop|kill)(?:_|$)/i.test(
    name,
  );
}

// ── Lightweight per-function extraction (calls, aliases, returns, params) ────────

/** A call effect inside a function body. */
interface CallEv {
  callee: string;
  /** Canonical first-argument storage key (`&` stripped), or "" if none. */
  arg0Key: string;
  /** lvalue this call's result is assigned to (`x = f(...)` / `T x = f(...)`), or undefined. */
  resultKey?: string;
  /**
   * TRUE when this call expression is itself the returned value
   * (`return f(...)`, through parens/casts) — the call's result (an acquired
   * ref, for a get-op) is handed straight to the caller. Multi-hop
   * return-ownership (refinement 2) relies on this: the 1-hop `x = f(); return x`
   * shape was already tracked via {@link resultKey} + returnBases, but the inline
   * `return f(...)` shape produced NO resultKey and was mis-scored as a leak.
   */
  returnedInline: boolean;
  line: number;
}

/** A `lhs = <identifier>` copy (the only aliasing this increment tracks). */
interface AliasEv {
  lhsKey: string;
  rhsIdent: string;
  line: number;
}

/** A `local = base->field` copy — lets a later `put(local)` resolve to the field. */
interface FieldAliasEv {
  /** The plain local identifier the field was copied into. */
  local: string;
  /** The trailing field name the local aliases (`sk_peer_pid`). */
  field: string;
}

/** One function definition + its extracted refcount-relevant events. */
export interface FnDef {
  name: string;
  file: string;
  startLine: number;
  calls: CallEv[];
  aliases: AliasEv[];
  /** `local = base->field` copies (so `put(local)` resolves to `->field`). */
  fieldAliases: FieldAliasEv[];
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

/**
 * TRUE when `call` is the value of an enclosing `return` (`return f(...)`,
 * looking through parenthesized/cast wrappers). Used for inline
 * return-ownership: `return get(x);` transfers the acquired ref to the caller.
 */
function isReturnedInline(call: TsNode): boolean {
  let n: TsNode = call;
  for (;;) {
    const parent: TsNode | null = n.parent;
    if (!parent) return false;
    if (parent.type === "return_statement") return true;
    if (parent.type === "parenthesized_expression" || parent.type === "cast_expression") {
      n = parent;
      continue;
    }
    return false;
  }
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
function extractBody(body: TsNode, src: string): Pick<FnDef, "calls" | "aliases" | "fieldAliases" | "returnBases"> {
  const calls: CallEv[] = [];
  const aliases: AliasEv[] = [];
  const fieldAliases: FieldAliasEv[] = [];
  const returnBases = new Set<string>();

  // Record `local = <field expr>` so a later `put(local)` resolves to the field.
  // `local` may be a bare identifier (assignment) or wrapped in pointer/paren
  // declarators (`struct pid *pid = sk->field`) — drill to the plain identifier.
  const noteFieldAlias = (localName: string | null, valueNode: TsNode): void => {
    if (!localName || valueNode.type !== "field_expression") return;
    const field = fieldOf(canon(valueNode, src));
    if (field) fieldAliases.push({ local: localName, field });
  };
  /** Plain local name of a declarator (drills pointer/paren declarators); null for array/fn. */
  const declLocalName = (decl: TsNode | null): string | null => {
    let d: TsNode | null = decl;
    const seen = new Set<number>();
    while (d && !seen.has(d.id)) {
      seen.add(d.id);
      if (d.type === "identifier") return src.slice(d.startIndex, d.endIndex);
      if (d.type === "pointer_declarator" || d.type === "parenthesized_declarator") {
        d = d.childForFieldName("declarator") ?? d.namedChildren.find((c) => c.type.endsWith("declarator") || c.type === "identifier") ?? null;
        continue;
      }
      return null; // array/function declarator — not a simple local
    }
    return null;
  };

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
            returnedInline: isReturnedInline(n),
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
        if (left && right) noteFieldAlias(left.type === "identifier" ? src.slice(left.startIndex, left.endIndex) : null, right);
        break;
      }
      case "init_declarator": {
        const decl = n.childForFieldName("declarator");
        const value = n.childForFieldName("value");
        if (decl && decl.type === "identifier" && value && value.type === "identifier") {
          aliases.push({ lhsKey: src.slice(decl.startIndex, decl.endIndex), rhsIdent: src.slice(value.startIndex, value.endIndex), line: line1(n) });
        }
        if (decl && value) noteFieldAlias(declLocalName(decl), value);
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
  return { calls, aliases, fieldAliases, returnBases };
}

/** Collect every top-level function_definition in a parsed file. */
function collectFnDefs(root: TsNode, src: string, file: string): FnDef[] {
  const out: FnDef[] = [];
  const walk = (n: TsNode) => {
    if (n.type === "function_definition") {
      const body = n.childForFieldName("body");
      if (body && body.type === "compound_statement") {
        const { calls, aliases, fieldAliases, returnBases } = extractBody(body, src);
        out.push({
          name: fnName(n, src),
          file,
          startLine: line1(n),
          calls,
          aliases,
          fieldAliases,
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
      // GET-WRAPPER: calls a get-op and RETURNS the acquired ref — either as a
      // named var (`x = get(); return x`) or inline (`return get(...)`). The
      // inline form is refinement 2's fix: it produced no result key, so the
      // fixpoint never promoted it and its callers were mis-scored as leaks.
      if (!getOps.has(fn.name)) {
        for (const call of fn.calls) {
          const seed = getOps.get(call.callee);
          if (!seed) continue;
          // produced ref = result of a wrapper call, or the arg0 of the raw getFn.
          const produced = call.resultKey ? firstIdent(call.resultKey) : firstIdent(call.arg0Key);
          const returnsAcquired = call.returnedInline || (!!produced && fn.returnBases.has(produced));
          if (returnsAcquired) {
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
  /** TRUE when this put lives in a destructor/free/release-family function. */
  fromDestructor: boolean;
  /** TRUE when `argField` was recovered from a `local = base->field` copy. */
  fieldViaAlias: boolean;
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

  let rejectedRules = 0;
  for (const obj of model.objects) {
    for (const rule of obj.refcountRules) {
      // Refinement 3: drop non-refcount pairs (atomic counters, alloc pairs,
      // page/module refs, parse junk) before they reach the call graph.
      if (!isRefcountLikeRule(rule)) {
        rejectedRules++;
        log(`[interproc-refcount] rejected non-refcount rule "${rule.name}" (${rule.getFn}/${rule.putFn})`);
        continue;
      }
      const { getOps, putOps } = resolveWrapperOps(cg, rule);

      // Global put-site index for this rule.
      const allPuts: PutSite[] = [];
      for (const fn of cg.fns) {
        const inDestructor = isDestructorFamily(fn.name);
        for (const call of fn.calls) {
          const seed = putOps.get(call.callee);
          if (!seed) continue;
          // Refinement 1: recover the field a plain-local put targets when the
          // local was copied from `base->field` (`pid = sk->sk_peer_pid;
          // put_pid(pid);`) — common in destructors.
          let argField = fieldOf(call.arg0Key);
          let fieldViaAlias = false;
          if (!argField) {
            const local = firstIdent(call.arg0Key);
            const fa = fn.fieldAliases.find((a) => a.local === local);
            if (fa) {
              argField = fa.field;
              fieldViaAlias = true;
            }
          }
          allPuts.push({
            fn: fn.name,
            file: fn.file,
            line: call.line,
            callee: call.callee,
            arg0: call.arg0Key,
            argField,
            resolvedFile: seed.resolvedFile || fn.file,
            rawOp: seed.rawOp,
            matchedBy: "same-var", // refined per get below
            fromDestructor: inDestructor,
            fieldViaAlias,
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

          // Where did the acquired ref get parked? Refinement 1 handles BOTH:
          //   (a) a separate `field = refVar` copy after the get; and
          //   (b) the get result assigned DIRECTLY into a field
          //       (`sk->sk_peer_pid = get_pid(...)`) — resultKey IS the field, so
          //       fieldOf(refVar) recovers it. Case (b) was the #1 FP: with no
          //       storedField the cross-function destructor put never matched.
          const aliasStore = fn.aliases.find((a) => a.rhsIdent === refBase && fieldOf(a.lhsKey));
          const storedField = aliasStore ? fieldOf(aliasStore.lhsKey) : fieldOf(refVar) || undefined;

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
          // transfer, not a leak: the caller owns the release. Refinement 2 adds
          // the inline form `return get(...)` (no result var) — the acquired ref
          // is the return value — which the 1-hop var check missed; combined with
          // inline-return wrapper promotion this makes return-ownership multi-hop.
          const returnedToCaller = fn.returnBases.has(refBase) || call.returnedInline;

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
                        p.fromDestructor ? " in destructor/free-path" : ""
                      }${p.fieldViaAlias ? " (field via local copy)" : ""}${
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
      `${rejectedRules ? `, ${rejectedRules} non-refcount rule(s) rejected` : ""}` +
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
