/**
 * Real intra-procedural C dataflow for the seedless invariant checker.
 *
 * This replaces the invariant checker's original token-level over-approximation
 * (a brace-splitter + "does the body mention lock L anywhere" regex) with an
 * actual analysis:
 *
 *   tree-sitter-c AST  ──▶  per-function basic-block CFG  ──▶  two forward
 *   dataflow fixpoints:
 *     • LOCK-SET (must-analysis, meet = intersection): the set of locks
 *       DEFINITELY held at each program point. A guarded field access is flagged
 *       ONLY when its guarding lock is not in the held-set *at that access point*
 *       — not "anywhere in the body". Locks are resolved to the STRUCT FIELD
 *       (receiver-expression + field), so `spin_lock(&f->lock)` guarding
 *       `f->state` and `spin_lock(&local->lock)` guarding `local->state` are the
 *       same rule regardless of the local variable name.
 *     • REACHING-FREE (may-analysis, meet = union): a `free(x)` fact reaches a
 *       later use of `x` on some path with no intervening re-assignment → UAF.
 *       Because the CFG has real return/goto edges, a `free` on an error branch
 *       that `return`s never reaches a use on the success branch (the classic
 *       false positive the token-level checker had).
 *
 * The refcount check stays a per-function heuristic (get/put call counting) — it
 * genuinely needs a call graph to be precise, which is out of intra-procedural
 * scope; it is documented as the weakest signal and is opt-out-able.
 *
 * HONEST RESIDUAL SCOPE: this is solid INTRA-procedural dataflow. It does NOT do
 * inter-procedural (a caller that holds the lock / owns the ref), and it does NOT
 * do points-to/alias analysis (two differently-named pointers to the same object,
 * or a lock reached through an aliased pointer, are treated as distinct). Both
 * surface as candidates the downstream skeptic+prover gate must still confirm —
 * but the FP volume is a fraction of the token-level checker's.
 */

import Parser from "tree-sitter";
// tree-sitter-c is a CommonJS native grammar with no types; import as unknown.
// eslint-disable-next-line @typescript-eslint/no-var-requires
import C from "tree-sitter-c";
import type { InvariantModel, InvariantViolation, ViolationKind } from "./subsystem-invariant-model.js";

// ── tree-sitter parser (singleton) ─────────────────────────────────────────────

let PARSER: Parser | null = null;
function parser(): Parser {
  if (!PARSER) {
    PARSER = new Parser();
    PARSER.setLanguage(C);
  }
  return PARSER;
}

type TsNode = Parser.SyntaxNode;

/** Parse a C translation unit; returns the root node (or null on failure). */
export function parseC(src: string): TsNode | null {
  try {
    return parser().parse(src).rootNode;
  } catch {
    return null;
  }
}

// ── Lock acquire/release vocabulary ─────────────────────────────────────────────

/** Default acquire-call tokens that count as "holding" a lock when a rule lists none. */
export const DEFAULT_ACQUIRE_FNS: readonly string[] = [
  "spin_lock", "spin_lock_bh", "spin_lock_irq", "spin_lock_irqsave", "spin_trylock",
  "raw_spin_lock", "raw_spin_lock_bh", "raw_spin_lock_irqsave",
  "mutex_lock", "mutex_lock_interruptible", "mutex_trylock",
  "read_lock", "read_lock_bh", "write_lock", "write_lock_bh",
  "down", "down_read", "down_write", "down_interruptible", "down_trylock",
];

/** Default release-call tokens that count as "dropping" a lock. */
export const DEFAULT_RELEASE_FNS: readonly string[] = [
  "spin_unlock", "spin_unlock_bh", "spin_unlock_irq", "spin_unlock_irqrestore",
  "raw_spin_unlock", "raw_spin_unlock_bh", "raw_spin_unlock_irqrestore",
  "mutex_unlock", "read_unlock", "read_unlock_bh", "write_unlock", "write_unlock_bh",
  "up", "up_read", "up_write",
];

/** Best-effort acquire→release mapping so a rule's custom acquireFns get matching releases. */
function releaseFnsFor(acquireFns: readonly string[]): string[] {
  const rel = new Set<string>(DEFAULT_RELEASE_FNS);
  for (const a of acquireFns) {
    if (a === "down" || a === "down_interruptible" || a === "down_trylock") rel.add("up");
    else if (a === "down_read") rel.add("up_read");
    else if (a === "down_write") rel.add("up_write");
    else if (a.includes("irqsave")) rel.add(a.replace("irqsave", "irqrestore").replace("_lock", "_unlock"));
    else if (a.includes("lock")) rel.add(a.replace("trylock", "unlock").replace("_lock", "_unlock"));
  }
  return [...rel];
}

// ── Canonicalization (resolve a lock/field to a stable storage key) ─────────────

const collapseWs = (s: string) => s.replace(/\s+/g, "");

/**
 * Canonicalize an lvalue/expression node to a stable storage key. `.` and `->`
 * both normalize to `->` so pointer- and value-access to the same field unify;
 * a leading `&` is stripped so `&f->lock` and `f->lock` are the same key.
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
    case "pointer_expression": {
      const op = node.child(0);
      const arg = node.childForFieldName("argument") ?? node.namedChildren[0];
      if (!arg) return collapseWs(src.slice(node.startIndex, node.endIndex));
      // `&x` → the storage x; `*x` → keep a deref marker so it isn't confused with x.
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

const firstIdent = (s: string): string => (/^[A-Za-z_][A-Za-z0-9_]*/.exec(s)?.[0] ?? s);

/** Normalize a model lock token (`f->lock`, `local->sockets.lock`, `sk->sk_lock.slock`, or a global). */
export function normalizeLockToken(token: string): { key: string; lockField: string; receiver: string; global: boolean } {
  const key = collapseWs(token.replace(/^&/, "").replace(/\./g, "->"));
  const idx = key.lastIndexOf("->");
  if (idx === -1) return { key, lockField: key, receiver: "", global: true };
  return { key, lockField: key.slice(idx + 2), receiver: key.slice(0, idx), global: false };
}

// ── Generic event stream (model-agnostic) ───────────────────────────────────────

type EvKind = "call" | "field" | "def" | "ref";
interface Ev {
  kind: EvKind;
  index: number; // ordering key within a block (source position of the EFFECT)
  line: number; // 1-based
  // call:
  callee?: string;
  arg0?: string; // canonical first-arg storage key (& stripped)
  // field:
  receiver?: string; // canonical receiver of a `recv->field`
  field?: string;
  canonStr?: string; // full canonical of the field/ref
  isAssignTarget?: boolean;
  // ref (identifier / deref / subscript used as a value):
  base?: string; // base identifier of the ref/field
  isDeref?: boolean;
}

interface Block {
  id: number;
  events: Ev[];
  succs: Set<number>;
}

const RECOGNIZED_CALL_SHAPE = new Set(["identifier"]);

/** Collect the generic event stream from an expression/statement subtree into `sink`. */
function collectEvents(node: TsNode, src: string, sink: Ev[]): void {
  const line = (n: TsNode) => n.startPosition.row + 1;

  const visit = (n: TsNode, assignTarget: boolean): void => {
    switch (n.type) {
      case "call_expression": {
        const callee = n.childForFieldName("function");
        const args = n.childForFieldName("arguments");
        const calleeName =
          callee && RECOGNIZED_CALL_SHAPE.has(callee.type) ? src.slice(callee.startIndex, callee.endIndex) : "";
        const arg0Node = args?.namedChildren[0];
        const arg0 = arg0Node ? canon(arg0Node, src) : "";
        // Emit the call EFFECT at endIndex so argument sub-expressions (evaluated
        // first) are ordered BEFORE it — this is what keeps `kfree(f)` from
        // reading as a use-after-free of its own argument.
        sink.push({ kind: "call", index: n.endIndex, line: line(n), callee: calleeName, arg0 });
        // Recurse into args for nested field/ref events, but NOT into arg0 — the
        // freed/locked storage itself is not a "use" of interest.
        if (args) {
          const kids = args.namedChildren;
          for (let i = 1; i < kids.length; i++) visit(kids[i], false);
        }
        return;
      }
      case "assignment_expression": {
        const left = n.childForFieldName("left");
        const right = n.childForFieldName("right");
        if (left) {
          sink.push({ kind: "def", index: left.startIndex, line: line(left), canonStr: canon(left, src), base: firstIdent(canon(left, src)) });
          // A write THROUGH a pointer/field is still an access of that field/base.
          visit(left, true);
        }
        if (right) visit(right, false);
        return;
      }
      case "init_declarator": {
        const decl = n.childForFieldName("declarator");
        const value = n.childForFieldName("value");
        if (decl && decl.type === "identifier") {
          const c = canon(decl, src);
          sink.push({ kind: "def", index: decl.startIndex, line: line(decl), canonStr: c, base: firstIdent(c) });
        }
        if (value) visit(value, false);
        return;
      }
      case "field_expression": {
        const arg = n.childForFieldName("argument");
        const field = n.childForFieldName("field");
        const receiver = arg ? canon(arg, src) : "";
        const fname = field ? src.slice(field.startIndex, field.endIndex) : "";
        const c = canon(n, src);
        sink.push({
          kind: "field",
          index: n.startIndex,
          line: line(n),
          receiver,
          field: fname,
          canonStr: c,
          isAssignTarget: assignTarget,
          base: firstIdent(c),
          isDeref: true,
        });
        // Recurse into the receiver so `a->b->c` records the inner access too.
        if (arg) visit(arg, false);
        return;
      }
      case "subscript_expression": {
        const arg = n.childForFieldName("argument") ?? n.namedChildren[0];
        const c = canon(n, src);
        sink.push({ kind: "ref", index: n.startIndex, line: line(n), canonStr: c, base: firstIdent(c), isDeref: true });
        if (arg) visit(arg, false);
        const idx = n.childForFieldName("index");
        if (idx) visit(idx, false);
        return;
      }
      case "pointer_expression": {
        const op = n.child(0);
        const arg = n.childForFieldName("argument") ?? n.namedChildren[0];
        if (op && src.slice(op.startIndex, op.endIndex) === "*" && arg) {
          const c = canon(arg, src);
          sink.push({ kind: "ref", index: n.startIndex, line: line(n), canonStr: c, base: firstIdent(c), isDeref: true });
        }
        if (arg) visit(arg, false);
        return;
      }
      case "identifier": {
        const c = src.slice(n.startIndex, n.endIndex);
        sink.push({ kind: "ref", index: n.startIndex, line: line(n), canonStr: c, base: c, isDeref: false });
        return;
      }
      default: {
        for (const k of n.namedChildren) visit(k, false);
        return;
      }
    }
  };

  visit(node, false);
}

// ── Per-function basic-block CFG ─────────────────────────────────────────────────

interface Cfg {
  blocks: Block[];
  entry: number;
  exit: number;
}

/**
 * Build a basic-block CFG for one function body (a `compound_statement`).
 * Structured recursion over the AST; handles sequencing, if/else, while/for/do,
 * switch, return, goto/label, break, continue.
 */
function buildCfg(body: TsNode, src: string): Cfg {
  const blocks: Block[] = [];
  const mk = (): number => {
    const id = blocks.length;
    blocks.push({ id, events: [], succs: new Set() });
    return id;
  };
  const edge = (a: number, b: number) => blocks[a].succs.add(b);

  const entry = mk();
  const exit = mk();
  let cur = entry;

  const breakStack: number[] = [];
  const continueStack: number[] = [];
  const labels = new Map<string, number>();
  const pendingGotos: Array<{ from: number; label: string }> = [];

  const emitInto = (block: number, node: TsNode) => collectEvents(node, src, blocks[block].events);

  const emit = (node: TsNode): void => {
    switch (node.type) {
      case "compound_statement": {
        for (const child of node.namedChildren) emit(child);
        return;
      }
      case "expression_statement":
      case "declaration": {
        emitInto(cur, node);
        return;
      }
      case "return_statement": {
        emitInto(cur, node);
        edge(cur, exit);
        cur = mk(); // dead-code continuation until a label re-enters
        return;
      }
      case "if_statement": {
        const cond = node.childForFieldName("condition");
        if (cond) emitInto(cur, cond);
        const condBlock = cur;
        const consequence = node.childForFieldName("consequence");
        const alternative = node.childForFieldName("alternative");

        const thenEntry = mk();
        edge(condBlock, thenEntry);
        cur = thenEntry;
        if (consequence) emit(consequence);
        const thenExit = cur;

        const merge = mk();
        edge(thenExit, merge);
        if (alternative) {
          const elseEntry = mk();
          edge(condBlock, elseEntry);
          cur = elseEntry;
          // `else if` arrives as an `else_clause`/if_statement; emit its child.
          const altStmt = alternative.type === "else_clause" ? alternative.namedChildren[0] ?? alternative : alternative;
          emit(altStmt);
          edge(cur, merge);
        } else {
          edge(condBlock, merge); // cond false → fall through
        }
        cur = merge;
        return;
      }
      case "while_statement":
      case "for_statement": {
        // for-init / while-cond events go into the pre-header (current block).
        const cond = node.childForFieldName("condition");
        const init = node.childForFieldName("initializer");
        const update = node.childForFieldName("update");
        if (init) emitInto(cur, init);
        const header = mk();
        edge(cur, header);
        if (cond) emitInto(header, cond);
        const bodyEntry = mk();
        const exitLoop = mk();
        edge(header, bodyEntry);
        edge(header, exitLoop);
        breakStack.push(exitLoop);
        continueStack.push(header);
        cur = bodyEntry;
        const bodyStmt = node.childForFieldName("body");
        if (bodyStmt) emit(bodyStmt);
        if (update) emitInto(cur, update);
        edge(cur, header); // back edge
        breakStack.pop();
        continueStack.pop();
        cur = exitLoop;
        return;
      }
      case "do_statement": {
        const bodyEntry = mk();
        edge(cur, bodyEntry);
        const exitLoop = mk();
        breakStack.push(exitLoop);
        continueStack.push(bodyEntry);
        cur = bodyEntry;
        const bodyStmt = node.childForFieldName("body");
        if (bodyStmt) emit(bodyStmt);
        const cond = node.childForFieldName("condition");
        if (cond) emitInto(cur, cond);
        edge(cur, bodyEntry); // back edge (do-while)
        edge(cur, exitLoop);
        breakStack.pop();
        continueStack.pop();
        cur = exitLoop;
        return;
      }
      case "switch_statement": {
        const cond = node.childForFieldName("condition");
        if (cond) emitInto(cur, cond);
        const switchBlock = cur;
        const exitSwitch = mk();
        breakStack.push(exitSwitch);
        const bodyStmt = node.childForFieldName("body");
        if (bodyStmt) {
          let prev: number | null = null;
          for (const caseNode of bodyStmt.namedChildren) {
            const caseEntry = mk();
            edge(switchBlock, caseEntry);
            if (prev !== null) edge(prev, caseEntry); // fall-through
            cur = caseEntry;
            for (const s of caseNode.namedChildren) {
              // skip the case label value node(s); emit statements
              if (s.type === "case_statement" || s.type === "default_statement") emit(s);
              else emit(s);
            }
            prev = cur;
          }
          if (prev !== null) edge(prev, exitSwitch);
        }
        edge(switchBlock, exitSwitch);
        breakStack.pop();
        cur = exitSwitch;
        return;
      }
      case "case_statement":
      case "default_statement": {
        for (const child of node.namedChildren) {
          if (child.type === "number_literal" || child.type === "identifier" || child.type === "char_literal") continue;
          emit(child);
        }
        return;
      }
      case "goto_statement": {
        const lbl = node.namedChildren.find((c) => c.type === "statement_identifier");
        if (lbl) pendingGotos.push({ from: cur, label: src.slice(lbl.startIndex, lbl.endIndex) });
        cur = mk(); // dead until a label
        return;
      }
      case "labeled_statement": {
        const lbl = node.namedChildren.find((c) => c.type === "statement_identifier");
        const labelBlock = mk();
        edge(cur, labelBlock); // fall-through into the label
        if (lbl) labels.set(src.slice(lbl.startIndex, lbl.endIndex), labelBlock);
        cur = labelBlock;
        const inner = node.namedChildren.find((c) => c.type !== "statement_identifier");
        if (inner) emit(inner);
        return;
      }
      case "break_statement": {
        if (breakStack.length) edge(cur, breakStack[breakStack.length - 1]);
        cur = mk();
        return;
      }
      case "continue_statement": {
        if (continueStack.length) edge(cur, continueStack[continueStack.length - 1]);
        cur = mk();
        return;
      }
      default: {
        emitInto(cur, node);
        return;
      }
    }
  };

  emit(body);
  edge(cur, exit); // fall off the end

  // Resolve goto edges now that all labels are known.
  for (const g of pendingGotos) {
    const target = labels.get(g.label);
    if (target !== undefined) edge(g.from, target);
  }

  // Sort each block's events by source position of their effect.
  for (const b of blocks) b.events.sort((a, c) => a.index - c.index);

  return { blocks, entry, exit };
}

function preds(cfg: Cfg): number[][] {
  const p: number[][] = cfg.blocks.map(() => []);
  for (const b of cfg.blocks) for (const s of b.succs) p[s].push(b.id);
  return p;
}

// ── Lock-set analysis (forward MUST, meet = intersection) ────────────────────────

interface RuleCtx {
  object: string;
  acquireFns: Set<string>;
  releaseFns: Set<string>;
  lockField: string;
  receiver: string;
  global: boolean;
  guardedFields: Set<string>;
  guardKey: string; // model token, for the message
}

/** Net gen/kill of held locks for a block (order matters within the block). */
function lockGenKill(block: Block, ctx: RuleCtx): { gen: Set<string>; kill: Set<string> } {
  const held = new Set<string>();
  const killed = new Set<string>();
  for (const ev of block.events) {
    if (ev.kind !== "call" || !ev.callee || !ev.arg0) continue;
    if (ctx.acquireFns.has(ev.callee)) {
      held.add(ev.arg0);
      killed.delete(ev.arg0);
    } else if (ctx.releaseFns.has(ev.callee)) {
      held.delete(ev.arg0);
      killed.add(ev.arg0);
    }
  }
  return { gen: held, kill: killed };
}

/** All lock keys acquired anywhere in the function (the must-analysis universe). */
function lockUniverse(cfg: Cfg, ctx: RuleCtx): Set<string> {
  const u = new Set<string>();
  for (const b of cfg.blocks) for (const ev of b.events) if (ev.kind === "call" && ev.callee && ctx.acquireFns.has(ev.callee) && ev.arg0) u.add(ev.arg0);
  return u;
}

/** Held-lock MUST-set at entry of every block (fixpoint). */
function lockSetIn(cfg: Cfg, ctx: RuleCtx): Map<number, Set<string>> {
  const P = preds(cfg);
  const universe = lockUniverse(cfg, ctx);
  const genKill = cfg.blocks.map((b) => lockGenKill(b, ctx));
  const IN = new Map<number, Set<string>>();
  const OUT = new Map<number, Set<string>>();
  for (const b of cfg.blocks) {
    IN.set(b.id, new Set(universe));
    OUT.set(b.id, new Set(universe));
  }
  IN.set(cfg.entry, new Set());
  const maxIter = cfg.blocks.length * 4 + 10;
  for (let iter = 0; iter < maxIter; iter++) {
    let changed = false;
    for (const b of cfg.blocks) {
      let inSet: Set<string>;
      if (b.id === cfg.entry) inSet = new Set();
      else if (P[b.id].length === 0) inSet = new Set();
      else {
        // intersection of predecessors' OUT
        inSet = new Set(OUT.get(P[b.id][0]));
        for (let i = 1; i < P[b.id].length; i++) {
          const po = OUT.get(P[b.id][i])!;
          for (const k of [...inSet]) if (!po.has(k)) inSet.delete(k);
        }
      }
      const { gen, kill } = genKill[b.id];
      const outSet = new Set<string>();
      for (const k of inSet) if (!kill.has(k)) outSet.add(k);
      for (const k of gen) outSet.add(k);
      if (!setEq(inSet, IN.get(b.id)!) || !setEq(outSet, OUT.get(b.id)!)) {
        changed = true;
        IN.set(b.id, inSet);
        OUT.set(b.id, outSet);
      }
    }
    if (!changed) break;
  }
  return IN;
}

function setEq(a: Set<string>, b: Set<string>): boolean {
  if (a.size !== b.size) return false;
  for (const k of a) if (!b.has(k)) return false;
  return true;
}

// ── Reaching-free analysis (forward MAY, meet = union) → UAF ─────────────────────

/** Freed-key gen/kill of a block (net). free(k) gens; `k = ...` kills. */
function freeGenKill(block: Block, freeFns: Set<string>): { gen: Set<string>; kill: Set<string> } {
  const gen = new Set<string>();
  const kill = new Set<string>();
  for (const ev of block.events) {
    if (ev.kind === "call" && ev.callee && freeFns.has(ev.callee) && ev.arg0) {
      gen.add(ev.arg0);
      kill.delete(ev.arg0);
    } else if (ev.kind === "def" && ev.canonStr) {
      // A re-assignment of the exact freed storage clears the danger.
      kill.add(ev.canonStr);
      gen.delete(ev.canonStr);
    }
  }
  return { gen, kill };
}

/** Freed-set (MAY) at entry of each block (fixpoint, union meet). */
function freeSetIn(cfg: Cfg, freeFns: Set<string>): Map<number, Set<string>> {
  const P = preds(cfg);
  const genKill = cfg.blocks.map((b) => freeGenKill(b, freeFns));
  const IN = new Map<number, Set<string>>();
  const OUT = new Map<number, Set<string>>();
  for (const b of cfg.blocks) {
    IN.set(b.id, new Set());
    OUT.set(b.id, new Set());
  }
  const maxIter = cfg.blocks.length * 4 + 10;
  for (let iter = 0; iter < maxIter; iter++) {
    let changed = false;
    for (const b of cfg.blocks) {
      const inSet = new Set<string>();
      for (const p of P[b.id]) for (const k of OUT.get(p)!) inSet.add(k);
      const { gen, kill } = genKill[b.id];
      const outSet = new Set<string>();
      for (const k of inSet) if (!kill.has(k)) outSet.add(k);
      for (const k of gen) outSet.add(k);
      if (!setEq(inSet, IN.get(b.id)!) || !setEq(outSet, OUT.get(b.id)!)) {
        changed = true;
        IN.set(b.id, inSet);
        OUT.set(b.id, outSet);
      }
    }
    if (!changed) break;
  }
  return IN;
}

// ── The finder: model + AST → InvariantViolation[] ───────────────────────────────

export interface DataflowFindOptions {
  maxViolations?: number;
  refcountCheck?: boolean;
  log?: (msg: string) => void;
}

interface FnInfo {
  name: string;
  body: TsNode;
  startLine: number;
}

/** Recursively collect every top-level function_definition (incl. inside preproc blocks). */
function collectFunctions(root: TsNode, src: string): FnInfo[] {
  const out: FnInfo[] = [];
  const walk = (n: TsNode) => {
    if (n.type === "function_definition") {
      const body = n.childForFieldName("body");
      if (body && body.type === "compound_statement") {
        out.push({ name: functionName(n, src), body, startLine: n.startPosition.row + 1 });
      }
      return; // functions don't nest in C
    }
    for (const c of n.namedChildren) walk(c);
  };
  walk(root);
  return out;
}

function functionName(fnDef: TsNode, src: string): string {
  let decl = fnDef.childForFieldName("declarator");
  // drill through pointer_declarator / parenthesized_declarator to function_declarator → identifier
  const seen = new Set<number>();
  while (decl && !seen.has(decl.id)) {
    seen.add(decl.id);
    if (decl.type === "identifier") return src.slice(decl.startIndex, decl.endIndex);
    const inner = decl.childForFieldName("declarator");
    if (inner) {
      decl = inner;
      continue;
    }
    // function_declarator's identifier may be a direct named child
    const idChild = decl.namedChildren.find((c) => c.type === "identifier");
    if (idChild) return src.slice(idChild.startIndex, idChild.endIndex);
    break;
  }
  return "<anonymous>";
}

/**
 * DETERMINISTIC violation finder backed by real intra-procedural dataflow.
 * Same output shape as the legacy token-level finder, but precise: lock-set at
 * the access point, path-sensitive reaching-free UAF.
 */
export function findViolationsDataflow(
  model: InvariantModel,
  sources: Array<{ file: string; text: string }>,
  opts: DataflowFindOptions = {},
): InvariantViolation[] {
  const log = opts.log ?? (() => {});
  const maxViolations = opts.maxViolations ?? 40;
  const refcountCheck = opts.refcountCheck ?? true;
  const violations: InvariantViolation[] = [];

  for (const { file, text } of sources) {
    const root = parseC(text);
    if (!root) {
      log(`[dataflow] parse failed for ${file}`);
      continue;
    }
    const fns = collectFunctions(root, text);

    for (const fn of fns) {
      const cfg = buildCfg(fn.body, text);

      for (const obj of model.objects) {
        // ── (1) unlocked-field-access via lock-set at the access point ──────────
        for (const rule of obj.lockRules) {
          const acquireFns = rule.acquireFns && rule.acquireFns.length > 0 ? [...rule.acquireFns] : [...DEFAULT_ACQUIRE_FNS];
          const norm = normalizeLockToken(rule.lock);
          const ctx: RuleCtx = {
            object: obj.object,
            acquireFns: new Set(acquireFns),
            releaseFns: new Set(releaseFnsFor(acquireFns)),
            lockField: norm.lockField,
            receiver: norm.receiver,
            global: norm.global,
            guardedFields: new Set(rule.guardedFields),
            guardKey: rule.lock,
          };
          // quick skip: does the function even touch a guarded field?
          const touches = cfg.blocks.some((b) => b.events.some((e) => e.kind === "field" && e.field && ctx.guardedFields.has(e.field)));
          if (!touches) continue;

          const IN = lockSetIn(cfg, ctx);
          // per (field) first unlocked access
          const flaggedField = new Set<string>();
          for (const b of cfg.blocks) {
            if (P0(cfg, b.id) && b.id !== cfg.entry) continue; // unreachable block: skip
            const held = new Set(IN.get(b.id));
            for (const ev of b.events) {
              if (ev.kind === "call" && ev.callee && ev.arg0) {
                if (ctx.acquireFns.has(ev.callee)) held.add(ev.arg0);
                else if (ctx.releaseFns.has(ev.callee)) held.delete(ev.arg0);
                continue;
              }
              if (ev.kind !== "field" || !ev.field || !ctx.guardedFields.has(ev.field)) continue;
              if (flaggedField.has(ev.field)) continue;
              const required = ctx.global ? norm.key : `${ev.receiver}->${ctx.lockField}`;
              if (held.has(required)) continue; // lock held AT this point → OK
              flaggedField.add(ev.field);
              violations.push({
                kind: "unlocked-field-access",
                object: obj.object,
                file,
                line: ev.line,
                functionName: fn.name,
                invariant: `field '${ev.field}' of ${obj.object} must only be accessed while holding ${ctx.guardKey}`,
                detail:
                  `${fn.name}() accesses ${ev.canonStr} at line ${ev.line} while ${ctx.guardKey} is NOT in the ` +
                  `held-lock set at that program point (lock-set dataflow over the function CFG). ` +
                  (ctx.global
                    ? `Global lock '${norm.key}' is not held on this path.`
                    : `Required lock '${required}' resolved from the access receiver; not held on this path (e.g. released on an earlier branch or never taken).`),
              });
            }
          }
        }

        // ── (2) use-after-free via reaching-free (path-sensitive) ───────────────
        for (const rule of obj.lifecycleRules) {
          const freeFns = new Set([rule.freeFn]);
          const IN = freeSetIn(cfg, freeFns);
          const flaggedKey = new Set<string>();
          for (const b of cfg.blocks) {
            if (P0(cfg, b.id) && b.id !== cfg.entry) continue;
            const freed = new Set(IN.get(b.id));
            for (const ev of b.events) {
              if (ev.kind === "call" && ev.callee && freeFns.has(ev.callee) && ev.arg0) {
                freed.add(ev.arg0);
                continue;
              }
              if (ev.kind === "def" && ev.canonStr) {
                freed.delete(ev.canonStr);
                continue;
              }
              // A use: a deref (field/subscript/*) or a pass-through of storage that
              // is currently freed on a reaching path.
              if ((ev.kind === "field" || ev.kind === "ref") && ev.base) {
                const baseFreed = freed.has(ev.base);
                const exactFreed = ev.canonStr !== undefined && freed.has(ev.canonStr);
                let isUAF: boolean;
                let freedThing: string;
                if (ev.isAssignTarget) {
                  // Writing THROUGH the pointer (`X->f = ...`) derefs X — a UAF only if
                  // the base pointer X itself is freed. Writing to a freed FIELD's slot
                  // while the base is live (`c->buf = NULL` cleanup) is legitimate and
                  // is handled as a kill by the def event, not a use.
                  isUAF = baseFreed && ev.base !== ev.canonStr;
                  freedThing = ev.base;
                } else {
                  isUAF = baseFreed || exactFreed;
                  freedThing = baseFreed ? ev.base : (ev.canonStr ?? ev.base);
                }
                if (!isUAF) continue;
                // Only a genuine dereference / pass-through use is dangerous.
                const isUse = ev.isDeref || ev.kind === "ref";
                if (!isUse) continue;
                if (flaggedKey.has(freedThing)) continue;
                flaggedKey.add(freedThing);
                violations.push({
                  kind: "use-after-free-order",
                  object: obj.object,
                  file,
                  line: ev.line,
                  functionName: fn.name,
                  invariant: `'${freedThing}' must not be used after ${rule.freeFn}() releases it`,
                  detail:
                    `${fn.name}() uses ${ev.canonStr} at line ${ev.line} on a path where ${rule.freeFn}(${freedThing}) ` +
                    `reaches it with no intervening re-assignment (reaching-free dataflow over the CFG — a free on a ` +
                    `returning error branch does NOT reach this use).`,
                });
              }
            }
          }
        }

        // ── (3) refcount-imbalance (per-function heuristic; weakest) ────────────
        if (refcountCheck) {
          for (const rule of obj.refcountRules) {
            let getCount = 0;
            let putCount = 0;
            let firstPutLine = 0;
            for (const b of cfg.blocks) {
              for (const ev of b.events) {
                if (ev.kind !== "call" || !ev.callee) continue;
                if (ev.callee === rule.getFn) getCount++;
                else if (ev.callee === rule.putFn) {
                  putCount++;
                  if (firstPutLine === 0) firstPutLine = ev.line;
                }
              }
            }
            if (putCount > 0 && getCount === 0 && firstPutLine > 0) {
              violations.push({
                kind: "refcount-imbalance",
                object: obj.object,
                file,
                line: firstPutLine,
                functionName: fn.name,
                invariant: `${rule.name}: every ${rule.putFn}() must be balanced by a prior ${rule.getFn}()`,
                detail:
                  `${fn.name}() calls ${rule.putFn}() (${putCount}x) but no ${rule.getFn}() — possible double-put / ` +
                  `underflow if the ref wasn't held on entry. WEAK signal (per-function heuristic): the get is often ` +
                  `legitimately in a caller (needs a call graph to resolve).`,
              });
            }
          }
        }
      }
    }
  }

  violations.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
  const capped = violations.slice(0, maxViolations);
  log(`[dataflow] ${violations.length} violation candidate(s)${capped.length < violations.length ? ` (capped to ${capped.length})` : ""}`);
  return capped;
}

/** True when block `id` has no predecessors (unreachable) — used to skip dead blocks. */
function P0(cfg: Cfg, id: number): boolean {
  for (const b of cfg.blocks) if (b.succs.has(id)) return false;
  return true;
}

// Types re-exported for tests.
export type { ViolationKind };
