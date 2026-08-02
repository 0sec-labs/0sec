/**
 * In-process tree-sitter ops-struct harvester — the TS-native follow-up to
 * `ops_harvest.py`. Extracts designated initializer assignments from C source
 * (e.g. `.recv_actor = unix_stream_read_actor` inside a struct initializer
 * block) so the graph-slice stage can synthesize indirect-call edges without
 * needing a pre-computed `ops_map.json` from a separate Python tool.
 *
 *   C source ──▶ tree-sitter-c parse (reuses {@link ../stages/c-dataflow.ts parseC})
 *           ──▶ walk declarations with struct initializers
 *           ──▶ collect (struct, field, fn) tuples
 *           ──▶ emit typed edges with file+line
 *
 * Pure — no I/O. The caller handles reading files and feeding source text.
 */

import type Parser from "tree-sitter";
import { parseC } from "../stages/c-dataflow.js";

type TsNode = Parser.SyntaxNode;


// ── Harvest model ──────────────────────────────────────────────────────────────

/** One ops-struct designated-initializer assignment extracted from source. */
export interface OpsHarvestEdge {
  /** The struct type name, e.g. "proto_ops" (without the "struct" keyword). */
  structName: string;
  /** The field being assigned, e.g. "recvmsg". */
  field: string;
  /** The function name assigned to the field, e.g. "unix_stream_recvmsg". */
  fnName: string;
  /** Source file path (caller-supplied; not extracted from C source). */
  file: string;
  /** 1-based line number of the assignment. */
  line: number;
}

// ── Extraction helpers ─────────────────────────────────────────────────────────

/**
 * Extract the struct name from a `struct_specifier` node.
 * For `struct proto_ops`, returns "proto_ops".
 */
function structNameFromSpecifier(node: TsNode, src: string): string | undefined {
  const nameNode = node.childForFieldName("name") ?? node.namedChildren.find((c) => c.type === "type_identifier");
  return nameNode ? src.slice(nameNode.startIndex, nameNode.endIndex) : undefined;
}

/**
 * Recursively walk an AST node, collecting every ops-struct designated
 * initializer assignment. `structName` is the enclosing struct type resolved
 * from the declaration; `file` is the caller-supplied path.
 */
function collectFromNode(node: TsNode, src: string, structName: string, file: string, sink: OpsHarvestEdge[]): void {
  // Direct designated initializer: the declaration IS the struct init.
  if (node.type === "init_declarator") {
    const initList = node.namedChildren.find((c) => c.type === "initializer_list");
    if (initList) {
      for (const pair of initList.namedChildren) {
        if (pair.type !== "initializer_pair") continue;
        const designator = pair.childForFieldName("designator") ?? pair.namedChildren.find((c) => c.type === "field_designator");
        if (!designator) continue;
        const fieldId = designator.namedChildren.find((c) => c.type === "field_identifier");
        if (!fieldId) continue;
        const fieldName = src.slice(fieldId.startIndex, fieldId.endIndex);

        const value = pair.childForFieldName("value") ?? pair.namedChildren.find((c) => c.type !== "field_designator");
        if (!value) continue;

        // Only collect function-pointer assignments: an `identifier` (bare fn
        // name) or a `parenthesized_expression` wrapping an identifier (cast
        // expressions like `(void *)fn` are NOT collected — they are non-call
        // data fields).
        let fnName: string | undefined;
        if (value.type === "identifier") {
          const raw = src.slice(value.startIndex, value.endIndex);
          if (!/^[A-Z][A-Z0-9_]*$/.test(raw)) fnName = raw;
        } else if (value.type === "parenthesized_expression") {
          // e.g. `(void *)fn` — unwrap to see if the inner is a plain identifier
          const inner = value.namedChildren[0];
          if (inner && inner.type === "identifier") {
            const raw = src.slice(inner.startIndex, inner.endIndex);
            if (!/^[A-Z][A-Z0-9_]*$/.test(raw)) fnName = raw;
          }
        }
        // Otherwise (string literal, number, field access, sizeof, arithmetic, etc.) — skip.

        if (!fnName) continue;

        sink.push({
          structName,
          field: fieldName,
          fnName,
          file,
          line: pair.startPosition.row + 1,
        });
      }
    }
    return;
  }

  // Recurse into children to handle nested scopes, preprocessor blocks, etc.
  for (const child of node.namedChildren) {
    collectFromNode(child, src, structName, file, sink);
  }
}

// ── Public API ─────────────────────────────────────────────────────────────────

/**
 * Harvest ops-struct designated-initializer assignments from C source text.
 * Returns every `(struct, field, fn)` assignment found in struct initializer
 * blocks across the file. Empty array on parse failure or no matches.
 *
 * Design: only returns CALLABLE function targets (plain identifiers / cast-
 * wrapped identifiers). String literals, numbers, sizeof, arithmetic, and
 * `NULL` / `THIS_MODULE` / macro references are excluded — they're data fields,
 * not indirect-call dispatch targets.
 */
export function harvestOps(source: string, file: string): OpsHarvestEdge[] {
  const root = parseC(source);
  if (!root) return [];

  const edges: OpsHarvestEdge[] = [];

  // Walk top-level declarations and declarations wrapped in preprocessor
  // branches: find every `struct X var = { ... }` pattern without treating
  // local declarations inside function bodies as dispatch tables.
  const pending = [...root.namedChildren];
  while (pending.length > 0) {
    const decl = pending.pop()!;
    if (decl.type.startsWith("preproc_")) {
      pending.push(...decl.namedChildren);
      continue;
    }
    if (decl.type !== "declaration") continue;

    // Find the struct_specifier to get the type name.
    const structSpec = decl.namedChildren.find(
      (child) => child.type === "struct_specifier" || child.type === "union_specifier",
    );
    if (!structSpec) continue;

    const structName = structNameFromSpecifier(structSpec, source);
    if (!structName) continue;

    // The init_declarator inside this declaration contains the initializer_list.
    const initDecl = decl.namedChildren.find((child) => child.type === "init_declarator");
    if (!initDecl) continue;

    collectFromNode(initDecl, source, structName, file, edges);
  }

  return edges;
}


export default harvestOps;
