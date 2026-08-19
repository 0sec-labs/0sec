// Surface inventory for the file-review pipeline (deepsec repository-analysis
// phase): a read-only agent proposes what the codebase is, its auth shape,
// and a structured list of ingress surfaces; the output is validated,
// grounded against the real file universe, and feeds the coverage gate.
// Invalid output gets exactly one repair attempt (deepsec coordinator).

import { matchGlob, normalizeRelPath } from "./glob.js";
import type {
  ReviewInvoker,
  ReviewSurfaceExposure,
  ReviewSurfaceInventory,
  ReviewSurfaceInventoryItem,
  ReviewSurfaceKind,
} from "./types.js";
import { estimateCost } from "../agent/cost.js";

const SURFACE_KINDS: readonly ReviewSurfaceKind[] = [
  "http", "rpc", "queue", "cron", "cli", "webhook", "agent-tool", "other",
];
const SURFACE_EXPOSURES: readonly ReviewSurfaceExposure[] = [
  "public", "authenticated", "internal", "mixed", "unknown",
];
const ID_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const VALID_REGEX_FLAGS = /^[dgimsuvy]*$/;

const REQUIRED_INFO_SECTIONS = [
  "## What this codebase does",
  "## Auth shape",
  "## Threat model",
  "## Project-specific patterns to flag",
  "## Known false-positives",
] as const;

const MAX_INFO_LINES = 120;
const MAX_INFO_CHARS = 14_000;

const INVENTORY_PROMPT = `You are mapping the attack surface of a codebase for a security review. Read files; do not execute code or use the network.

Produce STRICT JSON only (no prose outside the JSON) with this shape:
{
  "infoMarkdown": "<markdown with EXACTLY these five headings: ${REQUIRED_INFO_SECTIONS.join(" / ")} — concise, ≤120 lines total>",
  "surfaces": [
    {
      "id": "kebab-case-id",
      "kind": "http|rpc|queue|cron|cli|webhook|agent-tool|other",
      "description": "one line",
      "fileGlobs": ["**/*.ts"],
      "representativeFiles": ["src/api/routes.ts"],
      "exposure": "public|authenticated|internal|mixed|unknown",
      "anchorPatterns": [{"source": "regex", "flags": "i"}],
      "expectedAuthPrimitives": ["session middleware"]
    }
  ],
  "inspectedPaths": ["src/", "package.json"]
}

Rules: surfaces are ingress points where untrusted input enters. Every
representativeFile and glob must exist relative to the repo root. Prefer
narrow, framework-specific globs. Cover every language present in the repo —
a dominant language with no surface is a gap. List at most 5 representative
files per surface.`;

/**
 * Validate untrusted inventory JSON without touching the filesystem
 * (deepsec validateSurfaceInventory). Returns issue strings; empty = valid.
 */
export function validateSurfaceInventory(raw: unknown): string[] {
  const issues: string[] = [];
  if (typeof raw !== "object" || raw === null) {
    return ["inventory must be a JSON object"];
  }
  const obj = raw as Record<string, unknown>;

  if (typeof obj.infoMarkdown !== "string" || obj.infoMarkdown.trim().length === 0) {
    issues.push("infoMarkdown missing");
  } else {
    const info = obj.infoMarkdown;
    for (const section of REQUIRED_INFO_SECTIONS) {
      if (!info.includes(section)) issues.push(`infoMarkdown missing heading: ${section}`);
    }
    if (info.split("\n").length > MAX_INFO_LINES) issues.push(`infoMarkdown exceeds ${MAX_INFO_LINES} lines`);
    if (info.length > MAX_INFO_CHARS) issues.push(`infoMarkdown exceeds ${MAX_INFO_CHARS} chars`);
  }

  if (!Array.isArray(obj.surfaces) || obj.surfaces.length === 0) {
    issues.push("surfaces must be a non-empty array");
    return issues;
  }

  const seenIds = new Set<string>();
  for (const [i, item] of (obj.surfaces as unknown[]).entries()) {
    const where = `surfaces[${i}]`;
    if (typeof item !== "object" || item === null) {
      issues.push(`${where}: not an object`);
      continue;
    }
    const s = item as Record<string, unknown>;
    if (typeof s.id !== "string" || !ID_RE.test(s.id)) {
      issues.push(`${where}: id must be kebab-case`);
    } else if (seenIds.has(s.id)) {
      issues.push(`${where}: duplicate id '${s.id}'`);
    } else {
      seenIds.add(s.id);
    }
    if (typeof s.kind !== "string" || !SURFACE_KINDS.includes(s.kind as ReviewSurfaceKind)) {
      issues.push(`${where}: invalid kind`);
    }
    if (typeof s.exposure !== "string" || !SURFACE_EXPOSURES.includes(s.exposure as ReviewSurfaceExposure)) {
      issues.push(`${where}: invalid exposure`);
    }
    if (!Array.isArray(s.fileGlobs) || s.fileGlobs.some((g) => typeof g !== "string")) {
      issues.push(`${where}: fileGlobs must be string[]`);
    }
    if (!Array.isArray(s.representativeFiles) || s.representativeFiles.length === 0 || s.representativeFiles.length > 5) {
      issues.push(`${where}: representativeFiles must have 1-5 entries`);
    }
    if (s.anchorPatterns !== undefined) {
      if (!Array.isArray(s.anchorPatterns)) {
        issues.push(`${where}: anchorPatterns must be an array`);
      } else {
        for (const ap of s.anchorPatterns) {
          if (typeof ap !== "object" || ap === null || typeof (ap as Record<string, unknown>).source !== "string") {
            issues.push(`${where}: anchorPattern needs a string source`);
            continue;
          }
          const flags = (ap as Record<string, unknown>).flags;
          if (flags !== undefined && (typeof flags !== "string" || !VALID_REGEX_FLAGS.test(flags))) {
            issues.push(`${where}: invalid anchor flags`);
          }
          try {
            new RegExp((ap as Record<string, string>).source);
          } catch {
            issues.push(`${where}: anchor source is not a valid regex`);
          }
        }
      }
    }
  }
  return issues;
}

/**
 * Ground model-produced globs/representatives against the actual file
 * universe: keep only paths that exist, and drop surfaces with zero real
 * files (deepsec groundSurfaceInventory). Pure — no I/O.
 */
export function groundSurfaceInventory(
  surfaces: ReviewSurfaceInventoryItem[],
  repositoryFiles: readonly string[],
): { items: ReviewSurfaceInventoryItem[]; dropped: string[] } {
  const universe = new Set(repositoryFiles.map(normalizeRelPath));
  const exists = (p: string): boolean => universe.has(normalizeRelPath(p));
  const items: ReviewSurfaceInventoryItem[] = [];
  const dropped: string[] = [];

  for (const surface of surfaces) {
    const reps = surface.representativeFiles.filter(exists);
    const globsHaveFiles = repositoryFiles.some((f) =>
      surface.fileGlobs.some((g) => matchGlob(normalizeRelPath(f), g)),
    );
    if (reps.length === 0 && !globsHaveFiles) {
      dropped.push(surface.id);
      continue;
    }
    items.push({
      ...surface,
      representativeFiles: reps.length > 0 ? reps : surface.representativeFiles.slice(0, 1),
    });
  }
  return { items, dropped };
}

/** Expand each surface's globs against the universe (pure). */
export function expandSurfaceInventory(
  surfaces: readonly ReviewSurfaceInventoryItem[],
  repositoryFiles: readonly string[],
): Record<string, string[]> {
  const expanded: Record<string, string[]> = {};
  for (const surface of surfaces) {
    expanded[surface.id] = repositoryFiles
      .filter((f) => surface.fileGlobs.some((g) => matchGlob(normalizeRelPath(f), g)))
      .map(normalizeRelPath)
      .sort();
  }
  return expanded;
}

export interface GenerateInventoryResult {
  /** INFO.md content (5 required sections). */
  infoMarkdown: string;
  inventory: ReviewSurfaceInventory;
  /** Repair attempt was needed. */
  repaired: boolean;
  /** Total model cost across initial generation and any repair attempt. */
  costUsd: number;
}

function extractJson(text: string): unknown {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = (fenced ?? [undefined, text])[1] ?? text;
  const start = candidate.indexOf("{");
  const end = candidate.lastIndexOf("}");
  if (start === -1 || end <= start) throw new Error("no JSON object in model output");
  return JSON.parse(candidate.slice(start, end + 1));
}

/**
 * Run the read-only repository-analysis agent to produce INFO.md + the
 * surface inventory. One repair attempt on validation failure.
 */
export async function generateSurfaceInventory(params: {
  rootPath: string;
  invoker: ReviewInvoker;
  /** The scannable file universe (relative paths) the inventory must ground against. */
  repositoryFiles: readonly string[];
  log?: (msg: string) => void;
}): Promise<GenerateInventoryResult> {
  const { invoker, repositoryFiles, log } = params;
  const context = `Repository root: ${params.rootPath}\nFile universe (${repositoryFiles.length} files):\n${repositoryFiles.slice(0, 2000).join("\n")}`;

  let attempt = 0;
  let lastError = "";
  let costUsd = 0;
  while (attempt < 2) {
    const prompt = attempt === 0
      ? `${INVENTORY_PROMPT}\n\n${context}`
      : `${INVENTORY_PROMPT}\n\n${context}\n\nThe previous output failed validation: ${lastError}. Return corrected JSON only.`;
    const invocation = await invoker(prompt, "inventory");
    costUsd += invocation.costUsd ?? (invocation.usage ? estimateCost(invocation.usage, invocation.model) : 0);
    try {
      const raw = extractJson(invocation.output);
      const issues = validateSurfaceInventory(raw);
      if (issues.length === 0) {
        const obj = raw as { infoMarkdown: string; surfaces: ReviewSurfaceInventoryItem[] };
        const grounded = groundSurfaceInventory(obj.surfaces, repositoryFiles);
        if (grounded.dropped.length > 0) {
          log?.(`inventory: dropped ${grounded.dropped.length} surface(s) with no real files: ${grounded.dropped.join(", ")}`);
        }
        const inventory: ReviewSurfaceInventory = {
          items: grounded.items,
          sourceFiles: repositoryFiles.map(normalizeRelPath),
          issues: [],
          expanded: expandSurfaceInventory(grounded.items, repositoryFiles),
        };
        return { infoMarkdown: obj.infoMarkdown, inventory, repaired: attempt > 0, costUsd };
      }
      lastError = issues.join("; ");
      log?.(`inventory: validation failed (attempt ${attempt + 1}): ${lastError}`);
    } catch (err) {
      lastError = (err as Error).message;
      log?.(`inventory: parse failed (attempt ${attempt + 1}): ${lastError}`);
    }
    attempt += 1;
  }
  throw new Error(`surface inventory generation failed after 2 attempts: ${lastError}`);
}
