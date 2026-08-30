/**
 * Chat capability registry — typed metadata catalogue of every primary harness
 * action and OpenTUI pane that can be reached from the chat surface.
 *
 * This is PURE METADATA. It classifies capabilities by safety tier so
 * outbound and mutating operations are never invisible to the operator.
 * It MUST NOT execute commands or bypass scope/event gates.
 */

import type { ChatDestination } from "./chat-screen.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Safety tier for a capability:
 *   - `automatic`       — read-only info, navigation, display. No approvals.
 *   - `operator-confirmed` — outbound or mutating: the operator must be
 *                            prompted before execution.
 *   - `blocked`         — explicitly withheld from the chat surface without
 *                         a dedicated gate.
 */
export type SafetyTier = "automatic" | "operator-confirmed" | "blocked";

/**
 * Functional category grouping semantically related capabilities.
 */
export type CapabilityCategory =
  | "engagement"
  | "findings"
  | "verification"
  | "connect"
  | "settings"
  | "evolution"
  | "automation";

/**
 * One entry in the capability catalogue.
 */
export interface CapabilityEntry {
  /** Stable identifier (kebab-case). Used for lookups and UI keys. */
  readonly id: string;
  /** Human-readable label for menus and affordances. */
  readonly label: string;
  /** Functional category. */
  readonly category: CapabilityCategory;
  /**
   * Chat-pane route for UI entries. Capability adapters with no direct pane
   * omit it and must pass through the shared harness dispatcher.
   */
  readonly route?: ChatDestination;
  /**
   * Whether this capability reaches out to non-chat network targets or
   * modifies files/settings/credentials outside the chat session itself.
   * `false` means the capability is purely chat-scoped display or navigation.
   */
  readonly outboundOrMutating: boolean;
  /** Safety tier. */
  readonly safetyTier: SafetyTier;
  /** Plain‑language description shown in help / confirmation prompts. */
  readonly description: string;
}

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

const CAPABILITIES: readonly CapabilityEntry[] = [
  // ── Engagement launch ─────────────────────────────────────────────────────
  {
    id: "launcher",
    label: "Engagement Launcher",
    category: "engagement",
    route: "launcher",
    outboundOrMutating: false,
    safetyTier: "automatic",
    description: "Home screen for launching new engagements and browsing recent sessions.",
  },
  {
    id: "scan",
    label: "Scan",
    category: "engagement",
    outboundOrMutating: true,
    safetyTier: "operator-confirmed",
    description: "Run a web-application security scan against a target.",
  },
  {
    id: "review",
    label: "Code Review",
    category: "engagement",
    outboundOrMutating: true,
    safetyTier: "operator-confirmed",
    description: "Run a source-code security review against a repository or directory.",
  },
  {
    id: "audit",
    label: "Package Audit",
    category: "engagement",
    outboundOrMutating: true,
    safetyTier: "operator-confirmed",
    description: "Run a package-ecosystem audit against a supply-chain target.",
  },
  {
    id: "resume",
    label: "Resume Session",
    category: "engagement",
    route: "resume",
    outboundOrMutating: true,
    safetyTier: "operator-confirmed",
    description: "Re-engage a previously saved or interrupted session.",
  },
  {
    id: "ops",
    label: "Engagement Ops",
    category: "engagement",
    route: "ops",
    outboundOrMutating: false,
    safetyTier: "automatic",
    description: "Browse active and recent engagement operations.",
  },
  {
    id: "herd",
    label: "Agent Herd",
    category: "engagement",
    route: "herd",
    outboundOrMutating: false,
    safetyTier: "automatic",
    description: "Browse the roster of active subagent workers.",
  },

  // ── Findings / History / Replay ───────────────────────────────────────────
  {
    id: "history",
    label: "Scan History",
    category: "findings",
    route: "history",
    outboundOrMutating: false,
    safetyTier: "automatic",
    description: "Browse past scan runs and their results.",
  },
  {
    id: "findings",
    label: "Findings",
    category: "findings",
    route: "findings",
    outboundOrMutating: false,
    safetyTier: "automatic",
    description: "Browse and filter security findings.",
  },
  {
    id: "finding-detail",
    label: "Finding Detail",
    category: "findings",
    route: "finding",
    outboundOrMutating: false,
    safetyTier: "automatic",
    description: "View the full detail of a single security finding.",
  },
  {
    id: "replay",
    label: "Replay",
    category: "findings",
    route: "replay",
    outboundOrMutating: false,
    safetyTier: "operator-confirmed",
    description: "Replay an animated attack chain from a prior scan.",
  },

  // ── Verification / Fix / Disclosure ───────────────────────────────────────
  {
    id: "verify",
    label: "Verify Finding",
    category: "verification",
    outboundOrMutating: true,
    safetyTier: "operator-confirmed",
    description: "Reproduce and verify a finding through deterministic PoC replay.",
  },
  {
    id: "fix",
    label: "Auto-Fix",
    category: "verification",
    outboundOrMutating: true,
    safetyTier: "operator-confirmed",
    description: "Apply an automated source-code fix for a confirmed finding.",
  },
  {
    id: "disclose",
    label: "Disclosure Pipeline",
    category: "verification",
    outboundOrMutating: true,
    safetyTier: "blocked",
    description: "Prepare and file a vendor disclosure notification. Requires explicit gate from chat.",
  },

  // ── Provider Connect ──────────────────────────────────────────────────────
  {
    id: "connect",
    label: "Provider Connect",
    category: "connect",
    route: "connect",
    outboundOrMutating: true,
    safetyTier: "operator-confirmed",
    description: "Add an API key or complete OAuth device sign-in for a model provider.",
  },

  // ── Model / Settings ──────────────────────────────────────────────────────
  {
    id: "models",
    label: "Model Picker",
    category: "settings",
    route: "models",
    outboundOrMutating: true,
    safetyTier: "operator-confirmed",
    description: "Select and configure the active model provider and model.",
  },
  {
    id: "settings",
    label: "Settings",
    category: "settings",
    route: "settings",
    outboundOrMutating: true,
    safetyTier: "operator-confirmed",
    description: "Modify TUI, convergence, and security settings.",
  },
  {
    id: "usage",
    label: "Usage Report",
    category: "settings",
    route: "usage",
    outboundOrMutating: false,
    safetyTier: "automatic",
    description: "View context-window, token, and cost metrics.",
  },
  {
    id: "market",
    label: "Marketplace",
    category: "settings",
    route: "market",
    outboundOrMutating: true,
    safetyTier: "operator-confirmed",
    description: "Browse and install plugins and themes.",
  },
  {
    id: "doctor",
    label: "Doctor",
    category: "settings",
    route: "doctor",
    outboundOrMutating: false,
    safetyTier: "automatic",
    description: "Run TUI and runtime diagnostics.",
  },
  {
    id: "mode",
    label: "Autonomy Mode",
    category: "settings",
    outboundOrMutating: true,
    safetyTier: "operator-confirmed",
    description: "Switch between Standard, Co-pilot, YOLO, and Recon autonomy modes.",
  },
  {
    id: "shortcuts",
    label: "Keyboard Shortcuts",
    category: "settings",
    outboundOrMutating: false,
    safetyTier: "automatic",
    description: "View and browse TUI keyboard shortcuts.",
  },

  // ── Evolution ─────────────────────────────────────────────────────────────
  {
    id: "lens-evolution",
    label: "Lens Evolution",
    category: "evolution",
    outboundOrMutating: true,
    safetyTier: "operator-confirmed",
    description: "Automated self-evolution worker that promotes candidates from lens-synthesis results.",
  },

  // ── Advanced Automation / Research (placeholders) ─────────────────────────
  {
    id: "research",
    label: "Research Engine",
    category: "automation",
    outboundOrMutating: true,
    safetyTier: "blocked",
    description: "Run target-specific evidence research engines. Requires explicit gate from chat.",
  },
  {
    id: "orchestrate",
    label: "Orchestrate",
    category: "automation",
    outboundOrMutating: true,
    safetyTier: "blocked",
    description: "Autonomous verification worker that processes persisted case-work queues.",
  },
  {
    id: "eval",
    label: "Safety Eval",
    category: "automation",
    outboundOrMutating: true,
    safetyTier: "blocked",
    description: "Run adversarial safety evaluations against an AI/LLM endpoint.",
  },
  {
    id: "bench",
    label: "Benchmarks",
    category: "automation",
    outboundOrMutating: true,
    safetyTier: "blocked",
    description: "Run benchmark suites for capability measurement.",
  },
];

// ---------------------------------------------------------------------------
// Index — static id-keyed lookup table
// ---------------------------------------------------------------------------

const ID_INDEX: Record<string, CapabilityEntry> = {};
for (const cap of CAPABILITIES) {
  ID_INDEX[cap.id] = cap;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Look up a capability by its stable id. Returns `undefined` when no match
 * exists.
 */
export function getCapabilityById(id: string): CapabilityEntry | undefined {
  return ID_INDEX[id];
}

/**
 * Filter the capability catalogue by category. Returns entries ordered
 * deterministically by their position in the vocabulary array.
 */
export function getCapabilitiesByCategory(
  category: CapabilityCategory,
): readonly CapabilityEntry[] {
  return CAPABILITIES.filter((cap) => cap.category === category);
}

/**
 * Filter the capability catalogue by safety tier. Returns entries ordered
 * deterministically by their position in the vocabulary array.
 */
export function getCapabilitiesByTier(
  tier: SafetyTier,
): readonly CapabilityEntry[] {
  return CAPABILITIES.filter((cap) => cap.safetyTier === tier);
}

/**
 * Return every registered capability, in deterministic vocabulary order.
 */
export function getAllCapabilities(): readonly CapabilityEntry[] {
  return CAPABILITIES;
}

/**
 * Return every capability whose `route` matches a known chat-pane
 * `ChatDestination` value. Entries with no route are skipped.
 */
export function getPaneCapabilities(): readonly CapabilityEntry[] {
  return CAPABILITIES.filter((cap) => cap.route !== undefined);
}