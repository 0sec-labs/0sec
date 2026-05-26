/**
 * EGATS — Evidence-Gated Attack Tree Search
 *
 * Inspired by the MAPTA paper (arXiv:2508.20816). Instead of a linear agent
 * loop that may chase dead ends, EGATS models the attack as a tree:
 *
 *   - Each node is a hypothesis ("SQLi via /login username param")
 *   - A mini agent loop runs at each node to gather evidence
 *   - Evidence is scored against the hypothesis (0-1)
 *   - Only branches whose evidence exceeds a threshold are expanded
 *   - Beam search keeps the top-K most promising branches per level
 *   - The tree terminates when a FLAG is found, all branches die, or
 *     max depth is reached
 *
 * This is a generalisation of pwnkit's existing early-stop mechanism:
 * early-stop gates a single linear run, while EGATS gates every branch.
 */

import { randomUUID } from "node:crypto";
import type { NativeRuntime, NativeMessage, NativeContentBlock } from "../runtime/types.js";
import type { Finding } from "@pwnkit/shared";
import { runNativeAgentLoop } from "./native-loop.js";
import { getToolsForRole, TOOL_DEFINITIONS } from "./tools.js";
import { shellPentestPrompt } from "./prompts.js";
import type { ToolDefinition } from "./types.js";
import type { pwnkitDB } from "@pwnkit/db";

// ── Types ──

/** A piece of evidence collected from a branch run. */
export interface Evidence {
  /** Short label for the evidence ("HTTP 500 on ' payload", "reflected input"). */
  label: string;
  /** Raw text excerpt (trimmed). */
  excerpt: string;
  /** Where this came from — usually a tool name. */
  source: string;
}

/** Status of a node in the attack tree. */
export type NodeStatus = "pending" | "explored" | "confirmed" | "dead";

/** A single node in the attack tree. */
export interface AttackNode {
  id: string;
  parent: string | null;
  /** The hypothesis this branch is testing. */
  hypothesis: string;
  /** Accumulated evidence from running this branch. */
  evidence: Evidence[];
  status: NodeStatus;
  children: AttackNode[];
  /** 0-1 promise score based on evidence gathered. */
  score: number;
  /** Any findings produced by this branch. */
  findings: Finding[];
  /** The mini-loop summary text (for debugging). */
  summary: string;
  /** Turn count for this branch's mini-loop. */
  turnCount: number;
  /** Estimated cost for this branch. */
  estimatedCostUsd: number;
  /** Depth in the tree (root = 0). */
  depth: number;
}

/** Configuration for an EGATS run. */
export interface EGATSConfig {
  /** Initial attack vector guess that seeds the tree. */
  rootHypothesis: string;
  /** Max depth of the tree (root = 0). Typically 5. */
  maxDepth: number;
  /** Max children expanded from a single node. Typically 3. */
  maxBranches: number;
  /** Required score (0.0-1.0) to expand a node into children. */
  evidenceThreshold: number;
  /** Turns to run the mini-loop at each node. Default 8. */
  turnsPerNode?: number;
  /** Beam width: only expand the top-K nodes at each level. Default 3. */
  beamWidth?: number;
  /** Target URL / host. */
  target: string;
  /** Scan ID for event logging. */
  scanId: string;
  /** Optional source code path for white-box mode. */
  repoPath?: string;
  /** Optional hint (e.g. XBOW challenge description). */
  challengeHint?: string;
}

/** Result of an EGATS run. */
export interface AttackTreeResult {
  /** The root of the explored tree. */
  root: AttackNode;
  /** Every node that was explored, in visit order. */
  allNodes: AttackNode[];
  /** Combined findings across the entire tree. */
  findings: Finding[];
  /** Total turn count across all branches. */
  totalTurns: number;
  /** Total estimated cost across all branches. */
  totalCostUsd: number;
  /** Terminal reason the search ended. */
  terminationReason: "flag_found" | "all_dead" | "max_depth" | "no_expansions";
  /** If a flag was found, the node that found it. */
  flagNode: AttackNode | null;
}

// ── Evidence scoring ──

/** Patterns that suggest a branch is making real progress. */
const POSITIVE_SIGNALS: Array<{ pattern: RegExp; weight: number; label: string }> = [
  { pattern: /flag\{[^}]*\}/i, weight: 1.0, label: "flag" },
  { pattern: /HTTP\/\d\.\d\s+200/i, weight: 0.15, label: "http 200" },
  { pattern: /HTTP\/\d\.\d\s+500/i, weight: 0.25, label: "http 500 (error leak)" },
  { pattern: /HTTP\/\d\.\d\s+30[12]/i, weight: 0.1, label: "redirect" },
  { pattern: /Set-Cookie/i, weight: 0.1, label: "session cookie" },
  { pattern: /SQL syntax|mysql_|ORA-\d+|postgres|sqlite/i, weight: 0.35, label: "sql error" },
  { pattern: /Traceback|Exception|stack trace/i, weight: 0.25, label: "stack trace" },
  { pattern: /admin|root|sudo/i, weight: 0.1, label: "privileged term" },
  { pattern: /password[\s:="]+\S+/i, weight: 0.3, label: "password leaked" },
  { pattern: /token[\s:="]+[\w.-]{10,}/i, weight: 0.3, label: "token leaked" },
  { pattern: /api[_-]?key[\s:="]+\S+/i, weight: 0.3, label: "api key leaked" },
  { pattern: /\/etc\/passwd|root:x:/i, weight: 0.5, label: "lfi success" },
  { pattern: /49|7\*7|uid=\d+/i, weight: 0.4, label: "ssti/rce success" },
  { pattern: /vulnerable|confirmed|exploited/i, weight: 0.15, label: "confirmation keyword" },
  { pattern: /save_finding/, weight: 0.4, label: "finding saved" },
];

/** Patterns that suggest a branch is a dead end. */
const NEGATIVE_SIGNALS: Array<{ pattern: RegExp; weight: number }> = [
  { pattern: /403\s+Forbidden/i, weight: 0.05 },
  { pattern: /404\s+Not Found/i, weight: 0.05 },
  { pattern: /connection refused|timed out/i, weight: 0.1 },
  { pattern: /not vulnerable|no injection/i, weight: 0.15 },
];

/**
 * Score a blob of branch output against its hypothesis.
 * Returns a number in [0, 1] and the evidence list used.
 */
export function scoreEvidence(
  branchOutput: string,
  findings: Finding[],
): { score: number; evidence: Evidence[] } {
  const evidence: Evidence[] = [];
  let positive = 0;
  let negative = 0;

  for (const sig of POSITIVE_SIGNALS) {
    const match = branchOutput.match(sig.pattern);
    if (match) {
      positive += sig.weight;
      evidence.push({
        label: sig.label,
        excerpt: match[0].slice(0, 200),
        source: "branch_output",
      });
    }
  }

  for (const sig of NEGATIVE_SIGNALS) {
    if (sig.pattern.test(branchOutput)) {
      negative += sig.weight;
    }
  }

  // Findings are the strongest positive signal.
  if (findings.length > 0) {
    positive += 0.5 * findings.length;
    for (const f of findings.slice(0, 3)) {
      evidence.push({
        label: `finding: ${f.severity}`,
        excerpt: (f.title ?? f.templateId ?? "").slice(0, 200),
        source: "save_finding",
      });
    }
  }

  // Squash to [0, 1] via a simple logistic-ish transform.
  const raw = Math.max(0, positive - negative);
  const score = Math.min(1, raw);
  return { score, evidence };
}

/** Check if any finding or evidence indicates a flag was captured. */
export function hasFlag(node: AttackNode): boolean {
  for (const e of node.evidence) {
    if (/flag\{[^}]*\}/i.test(e.excerpt)) return true;
  }
  for (const f of node.findings) {
    const blob = JSON.stringify(f);
    if (/flag\{[^}]*\}/i.test(blob)) return true;
  }
  return false;
}

// ── Child hypothesis generation ──

/**
 * Ask the runtime to propose child hypotheses that drill into a parent.
 * The runtime returns a list of short strings; we cap to maxBranches.
 *
 * Falls back to a fixed list of generic follow-ups if the runtime call fails.
 */
async function proposeChildHypotheses(
  parent: AttackNode,
  config: EGATSConfig,
  runtime: NativeRuntime,
): Promise<string[]> {
  const evidenceBlob = parent.evidence
    .map((e) => `- ${e.label}: ${e.excerpt}`)
    .join("\n") || "(no concrete evidence yet)";

  const prompt = [
    `Parent hypothesis: ${parent.hypothesis}`,
    "",
    `Evidence collected so far (score=${parent.score.toFixed(2)}):`,
    evidenceBlob,
    "",
    `Propose ${config.maxBranches} MORE SPECIFIC child hypotheses that drill into the most promising aspect.`,
    "Each child should name the exact vector (endpoint, parameter, payload family).",
    "Respond as a numbered list, one hypothesis per line, no commentary.",
    "Example:",
    "1. SQLi via username param on POST /login (time-based blind)",
    "2. Auth bypass via JWT 'none' algorithm on /api/me",
    "3. IDOR via user_id param on GET /api/users/:id",
  ].join("\n");

  try {
    const result = await runtime.executeNative(
      "You are a red-team planner. Produce concrete, testable attack hypotheses.",
      [{ role: "user", content: [{ type: "text", text: prompt }] }],
      [],
    );
    const text = result.content
      .filter((b): b is NativeContentBlock & { type: "text" } => b.type === "text")
      .map((b) => b.text)
      .join("\n");

    const lines = text
      .split("\n")
      .map((l) => l.replace(/^\s*\d+[.)]\s*/, "").trim())
      .filter((l) => l.length > 5 && l.length < 300);

    if (lines.length > 0) return lines.slice(0, config.maxBranches);
  } catch {
    // fall through to fallback
  }

  return [
    `Exploit injection point implied by parent: ${parent.hypothesis}`,
    `Try alternate payload family for: ${parent.hypothesis}`,
    `Pivot from auth bypass to data exfiltration via: ${parent.hypothesis}`,
  ].slice(0, config.maxBranches);
}

// ── Tree search engine ──

/** Build the shared tool set for branch mini-loops. */
async function buildBranchTools(repoPath?: string): Promise<ToolDefinition[]> {
  const hasSource = !!repoPath;
  let hasBrowser = false;
  try { await import("playwright"); hasBrowser = true; } catch { /* not installed */ }

  const names = hasSource
    ? ["bash", ...(hasBrowser ? ["browser"] : []), "read_file", "run_command", "save_finding", "done"]
    : ["bash", ...(hasBrowser ? ["browser"] : []), "save_finding", "done"];
  return names
    .map((n) => TOOL_DEFINITIONS[n])
    .filter((t): t is ToolDefinition => t !== undefined);
}

/** Build the system prompt for a single branch mini-loop. */
function buildBranchPrompt(node: AttackNode, config: EGATSConfig, hasBrowser: boolean): string {
  const base = shellPentestPrompt(config.target, config.repoPath, { hasBrowser });
  const ancestry: string[] = [];
  // (ancestry walked by caller; here we just include this node's hypothesis)
  const header = [
    "",
    "## EGATS Branch Focus",
    `Depth: ${node.depth}/${config.maxDepth}`,
    `Hypothesis to test: ${node.hypothesis}`,
    "",
    "You MUST gather concrete evidence (tool output, HTTP responses, error traces) that either",
    "confirms or refutes this specific hypothesis. Do not wander — stay on this branch.",
    "If you find a flag, call save_finding and done immediately.",
  ].join("\n");
  let prompt = base + "\n" + header;
  if (config.challengeHint) prompt += "\n" + config.challengeHint;
  return prompt;
}

/** Run the mini-loop for a single attack tree node. */
async function exploreNode(
  node: AttackNode,
  config: EGATSConfig,
  runtime: NativeRuntime,
  db: pwnkitDB | null,
  tools: ToolDefinition[],
  onEvent?: (eventType: string, payload: Record<string, unknown>) => void,
): Promise<void> {
  const turns = config.turnsPerNode ?? 8;
  let hasBrowser = false;
  try { await import("playwright"); hasBrowser = true; } catch { /* not installed */ }

  onEvent?.("egats_node_start", {
    nodeId: node.id,
    depth: node.depth,
    hypothesis: node.hypothesis,
  });

  const systemPrompt = buildBranchPrompt(node, config, hasBrowser);

  try {
    const state = await runNativeAgentLoop({
      config: {
        role: "attack",
        systemPrompt,
        tools,
        maxTurns: turns,
        target: config.target,
        scanId: config.scanId,
        scopePath: config.repoPath,
        retryCount: 0,
      },
      runtime,
      db,
      onEvent: (eventType, payload) => {
        if (db) {
          db.logEvent({
            scanId: config.scanId,
            stage: "attack",
            eventType: `egats_${eventType}`,
            agentRole: "attack",
            payload: { ...payload, nodeId: node.id, depth: node.depth },
            timestamp: Date.now(),
          });
        }
      },
    });

    node.findings = state.findings;
    node.summary = state.summary;
    node.turnCount = state.turnCount;
    node.estimatedCostUsd = state.estimatedCostUsd;

    // Collect a text blob from the final messages for scoring.
    const blob = collectOutputBlob(state.messages);
    const { score, evidence } = scoreEvidence(blob + "\n" + state.summary, state.findings);
    node.evidence = evidence;
    node.score = score;
    node.status = score >= config.evidenceThreshold ? "explored" : "dead";
    if (hasFlag(node)) node.status = "confirmed";
  } catch (err) {
    node.status = "dead";
    node.summary = `Error: ${err instanceof Error ? err.message : String(err)}`;
  }

  onEvent?.("egats_node_done", {
    nodeId: node.id,
    depth: node.depth,
    score: node.score,
    status: node.status,
    findingCount: node.findings.length,
  });
}

/** Collect a textual blob from NativeMessages for evidence scoring. */
function collectOutputBlob(messages: NativeMessage[]): string {
  const parts: string[] = [];
  for (const msg of messages) {
    for (const block of msg.content) {
      if (block.type === "text") parts.push(block.text);
      else if (block.type === "tool_use") parts.push(`${block.name}(${JSON.stringify(block.input)})`);
      else if (block.type === "tool_result") parts.push(block.content);
    }
  }
  // Cap to avoid regex pathology on giant logs.
  return parts.join("\n").slice(0, 100_000);
}

/**
 * Run EGATS: explore the attack tree via evidence-gated beam search.
 *
 * Algorithm:
 *   1. Seed the tree with the root hypothesis.
 *   2. Each frontier level: explore every pending node via a mini-loop.
 *   3. Score each node; mark dead if score < threshold.
 *   4. Keep the top beamWidth live nodes from the level.
 *   5. For each kept node, propose maxBranches child hypotheses.
 *   6. Repeat until max depth, flag found, or frontier is empty.
 */
export async function runEGATS(
  config: EGATSConfig,
  runtime: NativeRuntime,
  db: pwnkitDB | null = null,
  onEvent?: (eventType: string, payload: Record<string, unknown>) => void,
): Promise<AttackTreeResult> {
  const beamWidth = config.beamWidth ?? 3;
  const tools = await buildBranchTools(config.repoPath);

  const root: AttackNode = {
    id: randomUUID().slice(0, 8),
    parent: null,
    hypothesis: config.rootHypothesis,
    evidence: [],
    status: "pending",
    children: [],
    score: 0,
    findings: [],
    summary: "",
    turnCount: 0,
    estimatedCostUsd: 0,
    depth: 0,
  };

  const allNodes: AttackNode[] = [root];
  let frontier: AttackNode[] = [root];
  let flagNode: AttackNode | null = null;
  let terminationReason: AttackTreeResult["terminationReason"] = "max_depth";

  onEvent?.("egats_start", {
    target: config.target,
    rootHypothesis: config.rootHypothesis,
    maxDepth: config.maxDepth,
    maxBranches: config.maxBranches,
    evidenceThreshold: config.evidenceThreshold,
    beamWidth,
  });

  if (db) {
    db.logEvent({
      scanId: config.scanId,
      stage: "attack",
      eventType: "egats_start",
      agentRole: "attack",
      payload: {
        rootHypothesis: config.rootHypothesis,
        maxDepth: config.maxDepth,
        maxBranches: config.maxBranches,
        evidenceThreshold: config.evidenceThreshold,
        beamWidth,
      },
      timestamp: Date.now(),
    });
  }

  for (let depth = 0; depth <= config.maxDepth; depth++) {
    if (frontier.length === 0) {
      terminationReason = "all_dead";
      break;
    }

    // 1. Explore all frontier nodes sequentially (could be parallelised later).
    for (const node of frontier) {
      await exploreNode(node, config, runtime, db, tools, onEvent);
      if (node.status === "confirmed") {
        flagNode = node;
        terminationReason = "flag_found";
        break;
      }
    }
    if (flagNode) break;

    // 2. Rank and beam-select.
    const live = frontier
      .filter((n) => n.status !== "dead")
      .sort((a, b) => b.score - a.score)
      .slice(0, beamWidth);

    if (live.length === 0) {
      terminationReason = "all_dead";
      break;
    }

    // 3. Stop if we've already hit max depth — don't expand further.
    if (depth >= config.maxDepth) {
      terminationReason = "max_depth";
      break;
    }

    // 4. Expand the kept nodes into children.
    const nextFrontier: AttackNode[] = [];
    for (const parent of live) {
      const childHypotheses = await proposeChildHypotheses(parent, config, runtime);
      for (const hyp of childHypotheses) {
        const child: AttackNode = {
          id: randomUUID().slice(0, 8),
          parent: parent.id,
          hypothesis: hyp,
          evidence: [],
          status: "pending",
          children: [],
          score: 0,
          findings: [],
          summary: "",
          turnCount: 0,
          estimatedCostUsd: 0,
          depth: parent.depth + 1,
        };
        parent.children.push(child);
        allNodes.push(child);
        nextFrontier.push(child);
      }
    }

    if (nextFrontier.length === 0) {
      terminationReason = "no_expansions";
      break;
    }
    frontier = nextFrontier;
  }

  // Aggregate results across the whole tree.
  const findings: Finding[] = [];
  let totalTurns = 0;
  let totalCostUsd = 0;
  for (const node of allNodes) {
    findings.push(...node.findings);
    totalTurns += node.turnCount;
    totalCostUsd += node.estimatedCostUsd;
  }

  onEvent?.("egats_complete", {
    terminationReason,
    nodeCount: allNodes.length,
    findingCount: findings.length,
    totalTurns,
    totalCostUsd,
  });

  if (db) {
    db.logEvent({
      scanId: config.scanId,
      stage: "attack",
      eventType: "egats_complete",
      agentRole: "attack",
      payload: {
        terminationReason,
        nodeCount: allNodes.length,
        findingCount: findings.length,
        totalTurns,
        totalCostUsd,
        tree: summariseTree(root),
      },
      timestamp: Date.now(),
    });
  }

  return {
    root,
    allNodes,
    findings,
    totalTurns,
    totalCostUsd,
    terminationReason,
    flagNode,
  };
}

/** Convenience: run EGATS with a sensible default config derived from a target. */
export function runEGATSWithDefaults(
  target: string,
  scanId: string,
  runtime: NativeRuntime,
  db: pwnkitDB | null,
  opts?: {
    rootHypothesis?: string;
    repoPath?: string;
    challengeHint?: string;
    maxDepth?: number;
    maxBranches?: number;
    evidenceThreshold?: number;
    onEvent?: (eventType: string, payload: Record<string, unknown>) => void;
  },
): Promise<AttackTreeResult> {
  return runEGATS(
    {
      rootHypothesis:
        opts?.rootHypothesis
          ?? `The target ${target} has at least one exploitable web vulnerability reachable from the root endpoint.`,
      maxDepth: opts?.maxDepth ?? 3,
      maxBranches: opts?.maxBranches ?? 3,
      evidenceThreshold: opts?.evidenceThreshold ?? 0.25,
      turnsPerNode: 8,
      beamWidth: 2,
      target,
      scanId,
      repoPath: opts?.repoPath,
      challengeHint: opts?.challengeHint,
    },
    runtime,
    db,
    opts?.onEvent,
  );
}

/** Render a compact JSON summary of the tree for logging. */
export function summariseTree(node: AttackNode): Record<string, unknown> {
  return {
    id: node.id,
    depth: node.depth,
    hypothesis: node.hypothesis.slice(0, 120),
    status: node.status,
    score: Number(node.score.toFixed(3)),
    evidenceCount: node.evidence.length,
    findingCount: node.findings.length,
    children: node.children.map(summariseTree),
  };
}
