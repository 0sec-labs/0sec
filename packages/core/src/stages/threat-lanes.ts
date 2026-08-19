/**
 * Threat-model planner stage — a pre-candidate-selection pass that finds
 * trust-boundary lanes before the finders run.
 *
 * The postmortem (cloudflare-os campaign, 2026-08-05) showed that per-file
 * breadth-first reading structurally misses cross-component bugs. The two best
 * bug findings spanned KV/R2+UX and sharing+scheduler+spawner. A threat-model-
 * first pass (lanes per trust boundary) found them.
 *
 * This stage runs BEFORE candidate selection: one cheap model call over the
 * repo map (top-level file tree + README/docs excerpts, bounded tokens) returns
 * N trust-boundary lanes. Each lane has a name, rationale, and path/subsystem
 * patterns. The lane-aware allocator then spreads the candidate budget across
 * lanes so each boundary gets coverage.
 *
 * Fail-closed: planner failure or invalid JSON → callers fall back to the
 * current module-spread selection with a warning. No behavior change when
 * the optional flag is off.
 */

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { Runtime, RuntimeResult } from "../runtime/types.js";

// ── Types ────────────────────────────────────────────────────────────────────

/** A single trust-boundary lane identified by the threat model planner. */
export interface ThreatLane {
  /** Short name describing the trust boundary (e.g. "kv-r2-sharing"). */
  name: string;
  /** Why this boundary could have cross-component bugs. */
  rationale: string;
  /**
   * Subsystem or directory path prefixes that belong to this lane.
   * Matched against candidate file paths relative to the scope root.
   * A file matching multiple lanes is assigned to the first matching lane.
   */
  subsystems: string[];
}

// ── Repo map builder ─────────────────────────────────────────────────────────

/**
 * Build a compact text representation of the repository for the planner prompt.
 * Returns a bounded (≤4K token) string with the top-level directory tree
 * (2 levels deep) and README/doc excerpts from the root.
 */
function buildRepoMap(sourceRoot: string): string {
  const parts: string[] = [];
  parts.push("=== REPOSITORY TREE ===\n");

  let rootEntries: string[];
  try {
    rootEntries = readdirSync(sourceRoot);
  } catch {
    return "=== REPOSITORY TREE ===\n<unreadable>\n";
  }
  rootEntries.sort();
  for (const entry of rootEntries) {
    if (entry.startsWith(".") || entry === "node_modules") continue;
    const full = join(sourceRoot, entry);
    try {
      const st = statSync(full);
      if (st.isDirectory()) {
        parts.push(`  ${entry}/`);
        let sub: string[];
        try {
          sub = readdirSync(full);
        } catch {
          continue;
        }
        sub.sort();
        const shown = sub.filter((s) => !s.startsWith(".") && s !== "node_modules").slice(0, 3);
        for (const s of shown) {
          const subFull = join(full, s);
          try {
            if (statSync(subFull).isDirectory()) {
              parts.push(`    ${s}/`);
            } else {
              parts.push(`    ${s}`);
            }
          } catch {
            continue;
          }
        }
        if (shown.length < sub.filter((s) => !s.startsWith(".")).length) {
          parts.push(`    ...`);
        }
      } else {
        parts.push(`  ${entry}`);
      }
    } catch {
      continue;
    }
  }

  for (const readmeName of ["README.md", "README", "Readme.md"]) {
    try {
      const readmePath = join(sourceRoot, readmeName);
      const content = readFileSync(readmePath, "utf8");
      const excerpt = content.slice(0, 2000);
      const lines = excerpt.split("\n").slice(0, 80).join("\n");
      parts.push("\n=== README ===\n");
      parts.push(lines);
      break;
    } catch {
      continue;
    }
  }

  return parts.join("\n");
}

// ── Planner prompt ───────────────────────────────────────────────────────────

const PLANNER_SYSTEM_PROMPT = `You are a security threat model planner. Analyze the repository structure below and identify 3-6 security-relevant trust-boundary lanes that could harbor CROSS-COMPONENT bugs (bugs that span two or more subsystems touching different trust boundaries).

For each lane, provide:
1. name: a short dash-separated identifier (e.g. "kv-r2-sharing")
2. rationale: why this boundary is security-relevant and what cross-component bugs could arise
3. subsystems: an array of directory or subsystem paths whose files belong to this lane (e.g. ["kv", "r2", "ux"])

Rules:
- Focus on boundaries between different components, not within a single component.
- A good lane has files from MULTIPLE subsystems interacting across a trust boundary.
- Priority-order the lanes: the highest-risk boundary first.
- Keep total lanes between 3 and 6.
- Respond with ONLY a valid JSON array. No markdown, no code fences, no explanation.`;

/**
 * Run the threat model planner: one cheap model call over the repo map.
 * Returns the identified lanes, or null on any failure.
 */
export async function runThreatModelPlanner(
  sourceRoot: string,
  runtime: Runtime,
  log?: (msg: string) => void,
): Promise<ThreatLane[] | null> {
  const logMsg = log ?? (() => {});

  try {
    const repoMap = buildRepoMap(sourceRoot);
    const prompt = `${PLANNER_SYSTEM_PROMPT}\n\n${repoMap}\n\nThreat lanes JSON:`;

    logMsg(`[threat-model] planning lanes from repo map (${repoMap.length} chars)...`);
    const result: RuntimeResult = await runtime.execute(prompt, {
      systemPrompt: PLANNER_SYSTEM_PROMPT,
    });

    if (result.error && !result.output) {
      logMsg(`[threat-model] planner execution failed: ${result.error}`);
      return null;
    }

    const output = result.output.trim();
    return parseThreatLaneJson(output, logMsg);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logMsg(`[threat-model] planner error: ${msg}`);
    return null;
  }
}

/**
 * Parse and validate the JSON response from the planner model.
 * Handles both raw JSON and JSON-in-markdown (```json … ```).
 */
export function parseThreatLaneJson(raw: string, log?: (msg: string) => void): ThreatLane[] | null {
  const logMsg = log ?? (() => {});
  try {
    let json = raw;
    const fenceMatch = json.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
    if (fenceMatch) {
      json = fenceMatch[1]!.trim();
    }

    const parsed = JSON.parse(json);

    if (!Array.isArray(parsed)) {
      logMsg(`[threat-model] planner returned non-array JSON: ${typeof parsed}`);
      return null;
    }

    const lanes: ThreatLane[] = [];
    for (const item of parsed) {
      if (!item || typeof item !== "object") {
        logMsg(`[threat-model] skipping invalid lane entry: ${JSON.stringify(item)}`);
        continue;
      }
      const name = typeof item.name === "string" ? item.name.trim() : "";
      const rationale = typeof item.rationale === "string" ? item.rationale.trim() : "";
      const subsystems = Array.isArray(item.subsystems)
        ? item.subsystems.filter((s: unknown): s is string => typeof s === "string" && s.length > 0)
        : [];
      if (!name || !rationale || subsystems.length === 0) {
        logMsg(`[threat-model] skipping incomplete lane: name=${name}, rationale=${rationale}, subsystems=${subsystems.length}`);
        continue;
      }
      lanes.push({ name, rationale, subsystems });
    }

    if (lanes.length === 0) {
      logMsg(`[threat-model] no valid lanes parsed from ${parsed.length} entries`);
      return null;
    }

    logMsg(`[threat-model] parsed ${lanes.length} threat lane(s): ${lanes.map((l) => l.name).join(", ")}`);
    return lanes;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logMsg(`[threat-model] JSON parse error: ${msg}`);
    return null;
  }
}

// ── Lane-aware candidate allocation ──────────────────────────────────────────

/**
 * Allocate the candidate budget across threat lanes, round-robin with
 * largest-first within each lane. Files that don't match any lane are placed
 * in an "other" bucket that participates in the round-robin after the named
 * lanes. Lanes that match no files are dropped with a warning.
 *
 * This EXTENDS the module-spread semantics in {@link selectCandidatesModuleSpread}:
 * when no lanes are provided, the caller should use the original module-spread
 * selection. When lanes ARE provided, this function provides the lane-aware
 * allocation.
 */
export function allocateCandidatesAcrossLanes(
  entries: { p: string; size: number }[],
  lanes: ThreatLane[],
  scopeRoot: string,
  maxCandidates: number,
  log?: (msg: string) => void,
): string[] {
  const logMsg = log ?? (() => {});
  const cap = Math.max(1, maxCandidates);

  const cmp = (a: { p: string; size: number }, b: { p: string; size: number }): number =>
    b.size - a.size || a.p.localeCompare(b.p);

  const UNMATCHED_KEY = "__other__";
  const laneBuckets = new Map<string, { p: string; size: number }[]>();
  for (const lane of lanes) {
    laneBuckets.set(lane.name, []);
  }
  laneBuckets.set(UNMATCHED_KEY, []);

  for (const entry of entries) {
    let assigned = false;
    for (const lane of lanes) {
      if (matchesLane(entry.p, scopeRoot, lane.subsystems)) {
        laneBuckets.get(lane.name)!.push(entry);
        assigned = true;
        break;
      }
    }
    if (!assigned) {
      laneBuckets.get(UNMATCHED_KEY)!.push(entry);
    }
  }

  for (const [, bucket] of laneBuckets) {
    bucket.sort(cmp);
  }

  const activeBucketNames: string[] = [];
  for (const lane of lanes) {
    const bucket = laneBuckets.get(lane.name)!;
    if (bucket.length === 0) {
      logMsg(`[threat-model] lane "${lane.name}" matched no files — dropping`);
      laneBuckets.delete(lane.name);
    } else {
      activeBucketNames.push(lane.name);
    }
  }

  const otherBucket = laneBuckets.get(UNMATCHED_KEY)!;
  if (otherBucket.length > 0) {
    activeBucketNames.push(UNMATCHED_KEY);
  } else {
    laneBuckets.delete(UNMATCHED_KEY);
  }

  const out: string[] = [];
  for (let round = 0; out.length < cap; round++) {
    let advanced = false;
    for (const name of activeBucketNames) {
      const bucket = laneBuckets.get(name)!;
      if (round >= bucket.length) continue;
      out.push(bucket[round]!.p);
      advanced = true;
      if (out.length >= cap) break;
    }
    if (!advanced) break;
  }

  logMsg(
    `[threat-model] allocated ${out.length} candidate(s) across ` +
      `${activeBucketNames.filter((n) => n !== UNMATCHED_KEY).length} lane(s) ` +
      `${activeBucketNames.includes(UNMATCHED_KEY) ? "+ unmatched " : ""}` +
      `(budget=${cap})`,
  );
  return out;
}

/**
 * Check if a file path matches any of a lane's subsystem path prefixes.
 * Exported for testing.
 */
export function matchesLane(absPath: string, scopeRoot: string, subsystems: string[]): boolean {
  const rel = relative(scopeRoot, absPath);
  if (rel === "" || rel.startsWith("..")) return false;
  const segments = rel.split(/[/\\]+/).filter(Boolean);
  for (const sub of subsystems) {
    const subSegments = sub.split(/[/\\]+/).filter(Boolean);
    if (subSegments.length === 0) continue;
    // Prefix match: the first N path segments match the subsystem segments
    let prefixMatch = true;
    for (let i = 0; i < subSegments.length && i < segments.length; i++) {
      if (segments[i] !== subSegments[i]) {
        prefixMatch = false;
        break;
      }
    }
    if (prefixMatch && subSegments.length <= segments.length) return true;
  }
  return false;
}