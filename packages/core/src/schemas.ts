/**
 * Runtime validation schemas for `JSON.parse(...) as T` sites inside
 * `@0sec/core`. Mirrors the precedent set by `packages/cli/src/commands/
 * schemas.ts` (PR #300) but lives in core because the CLI depends on core,
 * not the other way around — we can't reach back into the CLI's schemas
 * file from here.
 *
 * Covers:
 *
 *   - `mcpRpcEnvelopeSchema` — guards `JSON.parse` of an external HTTP
 *     response body in `mcp.ts`. A malicious or broken MCP server can
 *     return arbitrary JSON; we validate the JSON-RPC envelope shape
 *     (jsonrpc/id/result/error) and leave the `result` payload as
 *     `unknown` since it varies per RPC method.
 *
 *   - `layerVerdictArraySchema` — guards `JSON.parse` of the
 *     `findings.layerVerdicts` DB column in `agentic-scanner.ts`. The
 *     verdict shape evolves (new TriageLayerName values, optional fields),
 *     so each element is `.passthrough()` and only the load-bearing
 *     `layer`/`verdict`/`reason` fields are enforced.
 *
 * Keep these schemas in lockstep with `packages/shared/src/types.ts`. If a
 * `LayerVerdictKind` or `TriageLayerName` variant is added there and core
 * code starts depending on it, mirror it here.
 */

import { z } from "zod";
import type { LayerVerdict } from "@0sec/shared";

// ── JSON-RPC envelope (used by mcp.ts) ──────────────────────────────────────
//
// JSON-RPC 2.0 envelopes wrap external HTTP responses from an MCP server.
// We intentionally don't pin `jsonrpc` to the literal "2.0" — some servers
// return "1.0" or omit the field entirely, and we want the validator to
// reject malformed shapes (e.g. an array, a number, a non-object error
// field) rather than spec violations. The `result` payload varies per
// method (tools/list returns `{ tools: [...] }`, tools/call returns
// `{ content: [...] }`, etc.) so we leave it as `unknown` and let each
// call site narrow further.

export const mcpRpcEnvelopeSchema = z
  .object({
    jsonrpc: z.string().optional(),
    id: z.union([z.string(), z.number()]).optional(),
    result: z.record(z.unknown()).optional(),
    error: z
      .object({
        code: z.number().optional(),
        message: z.string().optional(),
        data: z.unknown().optional(),
      })
      .passthrough()
      .optional(),
  })
  .passthrough();

// ── LayerVerdict (used by agentic-scanner.ts) ───────────────────────────────
//
// Mirrors `LayerVerdict` in `@0sec/shared`. The verdict surface is
// append-only telemetry (#112): new layers and verdict kinds get added over
// time, and old DB rows must keep round-tripping. So:
//
//   - Each verdict is `.passthrough()` — unknown fields survive.
//   - `layer` is a string (not a closed enum) because new TriageLayerName
//     values land regularly and historical rows reference older names.
//   - `verdict` is a closed enum: the kind set is small and stable.

const layerVerdictKindEnum = z.enum([
  "pass",
  "reject",
  "downgrade",
  "skip",
  "error",
]);

const severityEnum = z.enum(["critical", "high", "medium", "low", "info"]);

export const layerVerdictSchema = z
  .object({
    layer: z.string(),
    verdict: layerVerdictKindEnum,
    reason: z.string(),
    durationMs: z.number(),
    costUsd: z.number(),
    confidence: z.number().optional(),
    changedSeverity: z
      .object({ from: severityEnum, to: severityEnum })
      .optional(),
  })
  .passthrough();

export const layerVerdictArraySchema = z.array(layerVerdictSchema);

// ── Type-level sync check ───────────────────────────────────────────────────
//
// No-op assignment fails at compile time if the schema's inferred type
// drifts from the canonical TypeScript type for the load-bearing fields.

type _LayerVerdictSchemaShape = z.infer<typeof layerVerdictSchema>;
const _layerVerdictAssign: (x: _LayerVerdictSchemaShape) => Pick<
  LayerVerdict,
  "verdict" | "reason" | "durationMs" | "costUsd"
> = (x) => x;
void _layerVerdictAssign;

// ── Friendly error formatter ────────────────────────────────────────────────

/**
 * Turn a `ZodError` into a one-line, user-readable summary that names the
 * first failing field and its issue. Duplicates the helper in the CLI's
 * schemas.ts on purpose: the CLI depends on core, not the other way
 * around, so we can't reach into the CLI for the helper.
 */
export function formatZodError(err: z.ZodError, label: string): string {
  const issue = err.issues[0];
  if (!issue) return `${label} failed validation`;
  const path = issue.path.length > 0 ? issue.path.join(".") : "<root>";
  return `${label} failed validation at ${path}: ${issue.message}`;
}
