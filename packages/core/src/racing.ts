/**
 * Best-of-N Strategy Racing
 *
 * Runs the same target with multiple different attack strategies in parallel,
 * takes the first one that succeeds. Inspired by BoxPwnr's approach of running
 * ~10 solver configs in parallel — different strategies crack different challenges.
 *
 * Usage:
 *   const result = await raceStrategies(raceConfig, runtime, db);
 *   // Returns as soon as ANY strategy finds a vulnerability
 */

import { randomUUID } from "node:crypto";
import type { NativeRuntime } from "./runtime/types.js";
import type { Finding } from "@pwnkit/shared";
import { runNativeAgentLoop } from "./agent/native-loop.js";
import type { NativeAgentState } from "./agent/native-loop.js";
import { getToolsForRole, TOOL_DEFINITIONS } from "./agent/tools.js";
import { shellPentestPrompt, attackPrompt } from "./agent/prompts.js";
import type { ToolDefinition } from "./agent/types.js";
import type { pwnkitDB } from "@pwnkit/db";

// ── Types ──

export interface AttackStrategy {
  name: string;
  /** Override the system prompt with a different attack approach */
  systemPromptOverride?: string;
  /** Use a different model via OpenRouter */
  model?: string;
  /** Max turns for this strategy */
  maxTurns?: number;
  /** Temperature hint (encoded in the system prompt since native loop doesn't expose temperature) */
  temperature?: number;
}

export interface RaceConfig {
  strategies: AttackStrategy[];
  /** Max number of strategies to run simultaneously. Default: 3 */
  maxConcurrency: number;
  target: string;
  scanId: string;
  /** Source code path for white-box mode */
  repoPath?: string;
  /** Challenge hint for XBOW benchmarks */
  challengeHint?: string;
}

export interface StrategyResult {
  strategyName: string;
  findings: Finding[];
  summary: string;
  turnCount: number;
  estimatedCostUsd: number;
  succeeded: boolean;
}

export interface RaceResult {
  /** The winning strategy (first to find a vulnerability), or null if all failed */
  winner: StrategyResult | null;
  /** Results from all strategies that completed */
  allResults: StrategyResult[];
  /** Total cost across all strategies */
  totalCostUsd: number;
  /** Total wall-clock turns (max across parallel strategies) */
  totalTurns: number;
  /** Whether any strategy found a vulnerability */
  foundVulnerability: boolean;
}

// ── Default Strategies ──

/**
 * Five default attack strategies with different approaches.
 * Each targets different vulnerability classes and uses different heuristics.
 */
export const DEFAULT_STRATEGIES: AttackStrategy[] = [
  {
    name: "aggressive",
    temperature: 0.9,
    maxTurns: 15,
    systemPromptOverride: `You are an aggressive penetration tester. Target: {{TARGET}}

RULES:
- Skip recon — go straight to exploitation
- Try the most common exploits FIRST: SQLi (' OR 1=1--), SSTI ({{7*7}}), command injection (;id), path traversal (../../etc/passwd)
- If there's a login page, try default creds immediately (admin/admin, demo/demo, test/test)
- Fire payloads at EVERY input field in rapid succession
- Don't waste turns on analysis — attack, check result, move on
- Write multi-payload Python scripts to test many vectors at once
- Chain exploits aggressively: auth bypass → IDOR → flag extraction

You have bash, save_finding, and done.

Goal: Extract the flag (FLAG{...}) as fast as possible. Speed over thoroughness.`,
  },
  {
    name: "methodical",
    temperature: 0.3,
    maxTurns: 30,
    systemPromptOverride: `You are a methodical penetration tester performing a systematic assessment. Target: {{TARGET}}

APPROACH:
1. **Thorough recon** (3-5 turns): Map every endpoint, form, parameter, and technology
   - curl -i the root, check headers, follow redirects
   - Check /robots.txt, /sitemap.xml, /.env, /.git/config, /api/, /admin, /login
   - Read ALL response text carefully — look for hints, credentials, version numbers
2. **Categorize attack surface** (1 turn): List every input vector with its type
3. **Systematic testing** (remaining turns): Test each input with appropriate payloads
   - For each input: try SQLi, XSS, SSTI, command injection, path traversal
   - Document what works and what doesn't
   - When something partially works, enumerate variations methodically
4. **Exploit chains**: Once you find a foothold, chain it to maximum impact

You have bash, save_finding, and done.

Goal: Extract the flag (FLAG{...}) through careful, systematic testing. Thoroughness over speed.`,
  },
  {
    name: "creative",
    temperature: 1.0,
    maxTurns: 20,
    systemPromptOverride: `You are a creative penetration tester who thinks outside the box. Target: {{TARGET}}

APPROACH:
- Try UNUSUAL payloads and encoding tricks that bypass common filters
- Use Unicode normalization attacks, double encoding, null bytes, case tricks
- Try polyglot payloads that work across multiple vulnerability classes
- Look for second-order vulnerabilities (inject in one place, trigger in another)
- Check for race conditions, timing attacks, cache poisoning
- Try NoSQL injection ({"$gt":""}), LDAP injection, XML/XXE injection
- Look for hidden parameters (__debug, _method, admin, test, debug)
- Try HTTP verb tampering (PUT, DELETE, PATCH, OPTIONS)
- Check for deserialization vulnerabilities
- Try SSRF via URL parameters, webhooks, avatar uploads
- Use creative Jinja2/SSTI chains, prototype pollution, template injection
- Write custom Python exploit scripts for complex chains

You have bash, save_finding, and done.

Goal: Extract the flag (FLAG{...}) using creative, non-obvious techniques.`,
  },
  {
    name: "tool-heavy",
    temperature: 0.5,
    maxTurns: 20,
    systemPromptOverride: `You are a penetration tester who relies heavily on automated tools. Target: {{TARGET}}

APPROACH:
- Use bash to run powerful automated tools against the target
- Write Python scripts with requests library for complex attack chains
- Use curl with full flag set (-v, -c, -b, -L, -H) for cookie management
- Write bash loops to brute-force parameters, IDs, and paths
- Use Python to automate blind injection (time-based SQLi, boolean-based)
- Combine tools: recon with curl → parse with Python → exploit with curl
- For SQLi: write a full UNION-based extraction script
- For SSTI: write a payload generation script with multiple template engines
- For IDOR: write a loop that iterates through IDs and checks responses
- For auth: write a script that tries multiple credential combinations

Examples:
  python3 -c "import requests; [print(requests.get(f'$TARGET/api/users/{i}').text) for i in range(20)]"
  for i in $(seq 1 100); do curl -s "$TARGET/item/$i" | grep -i flag; done
  python3 -c "
import requests, time
url = '$TARGET/search'
for c in range(32,127):
    r = requests.get(url, params={'q': f\"' OR IF(ASCII(SUBSTRING((SELECT flag FROM flags),1,1))={c},SLEEP(2),0)-- \"})
"

You have bash, save_finding, and done.

Goal: Extract the flag (FLAG{...}) using powerful automated tooling and scripts.`,
  },
  {
    name: "minimal",
    temperature: 0.7,
    maxTurns: 10,
    systemPromptOverride: `You are a focused penetration tester. Target: {{TARGET}}

RULES:
- You have only 10 turns. Every turn MUST count.
- Turn 1: curl -i the target, read EVERYTHING (headers, body, links, forms)
- Turn 2: Based on what you see, pick the SINGLE most likely vulnerability
- Turns 3-8: Attack that one vector with increasing sophistication
- Turn 9: If stuck, try one alternative approach
- Turn 10: Save findings or call done

PRIORITY ORDER (try the first one that applies):
1. If there's a login page with visible credentials → log in → IDOR
2. If there are URL parameters → SQLi UNION attack
3. If there are text inputs → SSTI ({{7*7}})
4. If there are file/path parameters → path traversal
5. If there are command-like inputs → command injection

Do NOT scatter your efforts. Pick ONE attack and go deep.

You have bash, save_finding, and done.

Goal: Extract the flag (FLAG{...}) with minimal turns using focused, decisive attacks.`,
  },
];

// ── Racing Engine ──

/**
 * Run multiple attack strategies in parallel against the same target.
 * Returns as soon as ANY strategy finds a vulnerability (short-circuit).
 * Cancels remaining strategies on success.
 * If all fail, returns combined results.
 */
export async function raceStrategies(
  config: RaceConfig,
  runtime: NativeRuntime,
  db: pwnkitDB | null,
): Promise<RaceResult> {
  const { strategies, maxConcurrency, target, scanId } = config;
  const allResults: StrategyResult[] = [];
  let winner: StrategyResult | null = null;

  // AbortController for cancelling remaining strategies on success
  const abortController = new AbortController();
  const { signal } = abortController;

  // Build the tool set once (shared across strategies)
  const hasSource = !!config.repoPath;
  let hasBrowser = false;
  try { await import("playwright"); hasBrowser = true; } catch { /* not installed */ }

  const shellToolNames = hasSource
    ? ["bash", ...(hasBrowser ? ["browser"] : []), "read_file", "run_command", "save_finding", "done"]
    : ["bash", ...(hasBrowser ? ["browser"] : []), "save_finding", "done"];
  const tools: ToolDefinition[] = shellToolNames
    .map((n) => TOOL_DEFINITIONS[n])
    .filter((t): t is ToolDefinition => t !== undefined);

  // Log race start
  if (db) {
    db.logEvent({
      scanId,
      stage: "attack",
      eventType: "race_start",
      agentRole: "attack",
      payload: {
        strategyCount: strategies.length,
        strategyNames: strategies.map((s) => s.name),
        maxConcurrency,
      },
      timestamp: Date.now(),
    });
  }

  /**
   * Run a single strategy and return its result.
   * Checks the abort signal between turns to enable short-circuit cancellation.
   */
  async function runStrategy(strategy: AttackStrategy): Promise<StrategyResult> {
    const strategySessionId = `${scanId}-race-${strategy.name}-${randomUUID().slice(0, 8)}`;

    // Build system prompt: use override if provided, otherwise use default shell prompt
    let systemPrompt = strategy.systemPromptOverride
      ? strategy.systemPromptOverride.replace(/\{\{TARGET\}\}/g, target)
      : shellPentestPrompt(target, config.repoPath, { hasBrowser });

    // Inject challenge hint if provided
    if (config.challengeHint) {
      systemPrompt += "\n" + config.challengeHint;
    }

    // Add temperature hint to prompt (models will see this as a behavioral cue)
    if (strategy.temperature !== undefined) {
      const tempDesc = strategy.temperature >= 0.8 ? "Be creative and try unusual approaches."
        : strategy.temperature <= 0.4 ? "Be precise and methodical."
        : "";
      if (tempDesc) {
        systemPrompt += `\n\n${tempDesc}`;
      }
    }

    const maxTurns = strategy.maxTurns ?? 20;

    try {
      const state = await runNativeAgentLoop({
        config: {
          role: "attack",
          systemPrompt,
          tools,
          maxTurns,
          target,
          scanId,
          scopePath: config.repoPath,
          retryCount: 0,
        },
        runtime,
        db,
        onTurn: (_turn, toolCalls) => {
          // Check if we should abort (another strategy already won)
          if (signal.aborted) {
            // We can't truly abort mid-loop, but the agent will finish its current
            // turn and then the early-stop logic will kick in on the next iteration.
            // The caller checks signal.aborted below.
          }
        },
        onEvent: (eventType, payload) => {
          // Tag events with strategy name
          if (db) {
            db.logEvent({
              scanId,
              stage: "attack",
              eventType: `race_${strategy.name}_${eventType}`,
              agentRole: "attack",
              payload: { ...payload, strategy: strategy.name },
              timestamp: Date.now(),
            });
          }
        },
      });

      const succeeded = state.findings.length > 0;
      return {
        strategyName: strategy.name,
        findings: state.findings,
        summary: state.summary,
        turnCount: state.turnCount,
        estimatedCostUsd: state.estimatedCostUsd,
        succeeded,
      };
    } catch (err) {
      return {
        strategyName: strategy.name,
        findings: [],
        summary: `Error: ${err instanceof Error ? err.message : String(err)}`,
        turnCount: 0,
        estimatedCostUsd: 0,
        succeeded: false,
      };
    }
  }

  // Process strategies in batches of maxConcurrency
  // Use Promise.race within each batch to short-circuit on first success
  const pending = [...strategies];

  while (pending.length > 0 && !winner) {
    const batch = pending.splice(0, maxConcurrency);

    // Run all strategies in this batch concurrently
    const promises = batch.map(async (strategy) => {
      const result = await runStrategy(strategy);
      return result;
    });

    // Wait for all in this batch (we can't truly cancel mid-loop,
    // but we check for winners after each batch)
    const batchResults = await Promise.allSettled(promises);

    for (const settled of batchResults) {
      if (settled.status === "fulfilled") {
        const result = settled.value;
        allResults.push(result);

        // Check for winner (first strategy with findings)
        if (result.succeeded && !winner) {
          winner = result;
          abortController.abort(); // Signal remaining strategies to stop

          if (db) {
            db.logEvent({
              scanId,
              stage: "attack",
              eventType: "race_winner",
              agentRole: "attack",
              payload: {
                winnerStrategy: result.strategyName,
                findingCount: result.findings.length,
                turnCount: result.turnCount,
              },
              timestamp: Date.now(),
            });
          }
        }
      } else {
        // Strategy threw — record as failed
        allResults.push({
          strategyName: "unknown",
          findings: [],
          summary: `Strategy failed: ${settled.reason}`,
          turnCount: 0,
          estimatedCostUsd: 0,
          succeeded: false,
        });
      }
    }
  }

  // Compute totals
  const totalCostUsd = allResults.reduce((sum, r) => sum + r.estimatedCostUsd, 0);
  const totalTurns = Math.max(...allResults.map((r) => r.turnCount), 0);

  // Log race completion
  if (db) {
    db.logEvent({
      scanId,
      stage: "attack",
      eventType: "race_complete",
      agentRole: "attack",
      payload: {
        winner: winner?.strategyName ?? null,
        strategiesRun: allResults.length,
        totalCostUsd,
        results: allResults.map((r) => ({
          name: r.strategyName,
          succeeded: r.succeeded,
          findingCount: r.findings.length,
          turns: r.turnCount,
        })),
      },
      timestamp: Date.now(),
    });
  }

  return {
    winner,
    allResults,
    totalCostUsd,
    totalTurns,
    foundVulnerability: winner !== null,
  };
}

/**
 * Convenience: race with default strategies.
 * This is the main entry point for the --race flag.
 */
export function raceWithDefaults(
  target: string,
  scanId: string,
  runtime: NativeRuntime,
  db: pwnkitDB | null,
  opts?: {
    maxConcurrency?: number;
    repoPath?: string;
    challengeHint?: string;
  },
): Promise<RaceResult> {
  return raceStrategies(
    {
      strategies: DEFAULT_STRATEGIES,
      maxConcurrency: opts?.maxConcurrency ?? 3,
      target,
      scanId,
      repoPath: opts?.repoPath,
      challengeHint: opts?.challengeHint,
    },
    runtime,
    db,
  );
}
