/**
 * Lens-synthesis stage 2 — SYNTHESIZE.
 *
 * Cluster {@link LensCandidate}s (by the flywheel's class-token join key) and,
 * for each cluster, ask the model to generate ONE candidate appsec archetype in
 * the registry schema. Structured output comes back as a NATIVE TOOL CALL (the
 * reliable path used by `invariant-spec-builder.ts` / `second-audit.ts`), not
 * fence-parsed text.
 *
 * Fail-closed: a cluster whose model output is missing, malformed, or whose
 * `challenge_hint` is not demonstrably cross-language (cites < 2 ecosystem/sink
 * tokens, like the seed lenses) is DROPPED — never synthesized, never thrown up
 * the stack. Nothing here confirms a finding; it emits lens PROPOSALS for the
 * validation gate.
 */

import { LlmApiRuntime } from "../../runtime/llm-api.js";
import type {
  NativeContentBlock,
  NativeMessage,
  NativeRuntimeResult,
  NativeToolDef,
} from "../../runtime/types.js";
import { classTokens } from "../hunt-flywheel.js";
import type {
  LensCandidate,
  SynthesizedArchetype,
  SynthesizedArchetypeContent,
} from "./types.js";

// ── Injectable model ──────────────────────────────────────────────────────

/**
 * The stage-2 LLM call. Mirrors `second-audit.ts`'s injectable-model pattern:
 * a thin `(system, messages, tools) => NativeRuntimeResult` so tests inject a
 * deterministic fake and production uses {@link defaultLensSynthesisModel}.
 */
export type LensSynthesisModel = (
  system: string,
  messages: NativeMessage[],
  tools: NativeToolDef[],
) => Promise<NativeRuntimeResult>;

/** The real LlmApiRuntime-backed model. Never hardcodes a key (routes via the runtime). */
export function makeDefaultLensSynthesisModel(modelId?: string): LensSynthesisModel {
  return (system, messages, tools) => {
    const runtime = new LlmApiRuntime({
      type: "api",
      timeout: 300_000,
      ...(modelId ? { model: modelId } : {}),
    });
    return runtime.executeNative(system, messages, tools);
  };
}

// ── The synthesis tool (structured archetype output) ──────────────────────

export const SYNTH_TOOL_NAME = "propose_appsec_lens";

/**
 * The archetype schema the model fills. Deterministic/fixed fields
 * (domain/route/engine_lens/uid) and provenance (source/validated_at/miss_refs)
 * are NOT in the tool — the loop owns those; the model authors only the
 * human-written content.
 */
export const SYNTH_TOOL: NativeToolDef = {
  name: SYNTH_TOOL_NAME,
  description:
    "Propose ONE cross-language application-security bug-class lens (an appsec archetype) that would catch the described finder MISS. Author only the content fields; the registry fills domain/route/uid/provenance.",
  input_schema: {
    type: "object",
    properties: {
      id: {
        type: "string",
        description:
          "kebab-case class id, e.g. 'ssrf-url-fetch' or 'insecure-deserialization'. Lowercase letters, digits, hyphens.",
      },
      name: { type: "string", description: "Human-readable class name." },
      cwe: {
        type: "string",
        description: "CWE code(s), e.g. 'CWE-918' or 'CWE-502 / CWE-915'.",
      },
      subsystem: {
        type: "string",
        description: "The affected subsystem, framework-agnostic (e.g. 'HTTP client / URL fetch (any runtime)').",
      },
      pattern: {
        type: "string",
        description:
          "The generalized anti-pattern: what tainted data reaches what sink, and what guard is missing. No exploit code.",
      },
      detection_signature: {
        type: "string",
        description:
          "Language-agnostic grep/read evidence: concrete sink shapes across MULTIPLE ecosystems (Node/.NET/Java/Python/PHP/Ruby as relevant), and the safe shape that is NOT a finding.",
      },
      challenge_hint: {
        type: "string",
        description:
          "The load-bearing field: a cross-language, sink-shape-citing hunt angle. MUST cite concrete sinks from >= 2 ecosystems (e.g. Node child_process AND Python subprocess), tell the finder to cite file:line and the taint path, and state the safe shape to skip. Written like the seed lenses.",
      },
      grounding: {
        type: "array",
        items: { type: "string" },
        description: "CWE/OWASP witnesses and the concrete miss(es) this lens closes.",
      },
      confirmable: {
        type: "string",
        description:
          "The honest confirmability limit: a source-static hypothesis needing the skeptic + multi-lens verify quorum; no build/exec lane proves it here.",
      },
    },
    required: [
      "id",
      "name",
      "cwe",
      "subsystem",
      "pattern",
      "detection_signature",
      "challenge_hint",
      "grounding",
      "confirmable",
    ],
  },
};

// ── Cross-language / concrete-sink quality gate ───────────────────────────
//
// The same property appsec-catalog.test.ts asserts on the seed lenses: a hint
// is only useful if it names sink shapes from more than one ecosystem, so the
// finder hunts the class in any language. A synthesized hint that fails this is
// dropped (fail-closed) rather than registered as a weak lens.

const ECOSYSTEM_MARKERS = [
  "Node", ".NET", "Java", "Python", "PHP", "Ruby", "Go", "Rust",
  "React", "Angular", "Vue", "Spring", "Rails", "Express", "Django", "Flask",
  "[Authorize]", "@PreAuthorize", "middleware",
  "subprocess", "os.system", "Runtime.exec", "ProcessBuilder", "child_process", "Process.Start",
  "Handlebars", "Thymeleaf", "JSP", "Jinja2", "EJS", "Pug", "Mustache", "Freemarker", "Velocity",
  "SAML", "OIDC", "OAuth2", "JWT",
  "requests", "HttpClient", "urllib", "fetch", "axios", "cURL", "WebClient",
  "pickle", "ObjectInputStream", "yaml.load", "Marshal", "unserialize",
  "Thread.sleep", "setTimeout", "time.sleep", "Task.Delay", "Inflater", "gunzip", "zlib", "ReDoS",
] as const;

/** True when `hint` names concrete sinks from >= 2 ecosystems (the seed-lens bar). */
export function isCrossLanguageHint(hint: string): boolean {
  let hits = 0;
  for (const m of ECOSYSTEM_MARKERS) {
    if (hint.includes(m)) hits++;
    if (hits >= 2) return true;
  }
  return false;
}

// ── Clustering ────────────────────────────────────────────────────────────

export interface LensCandidateCluster {
  /** Stable cluster key (the shared class-token join, or a slugged class hint). */
  key: string;
  members: LensCandidate[];
}

function slug(text: string): string {
  return text.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "generic";
}

/**
 * Group candidates that describe the same class. The join key is the flywheel's
 * `classTokens` (so "CWE-918" and "server-side request forgery" cluster
 * together); when a candidate yields no class tokens, fall back to its slugged
 * class hint. Deterministic: clusters and members are ordered by first
 * appearance.
 */
export function clusterCandidates(candidates: LensCandidate[]): LensCandidateCluster[] {
  const byKey = new Map<string, LensCandidate[]>();
  const order: string[] = [];
  for (const c of candidates) {
    const toks = classTokens(c.classHint, c.sinkPattern, c.whyMissed);
    const key = toks.size > 0 ? [...toks].sort().join("+") : `hint:${slug(c.classHint)}`;
    if (!byKey.has(key)) {
      byKey.set(key, []);
      order.push(key);
    }
    byKey.get(key)!.push(c);
  }
  return order.map((key) => ({ key, members: byKey.get(key)! }));
}

// ── Tool-output parsing (fail-closed) ─────────────────────────────────────

function findToolInput(result: NativeRuntimeResult): Record<string, unknown> | null {
  const blocks: NativeContentBlock[] = result.content ?? [];
  for (const block of blocks) {
    if (block.type === "tool_use" && block.name === SYNTH_TOOL_NAME) {
      return block.input ?? null;
    }
  }
  return null;
}

function asNonEmptyString(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

function asStringArray(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const out: string[] = [];
  for (const item of value) {
    const s = asNonEmptyString(item);
    if (!s) return null;
    out.push(s);
  }
  return out.length > 0 ? out : null;
}

const KEBAB_ID = /^[a-z0-9][a-z0-9-]{1,63}$/;
const CWE_CODE = /CWE-\d+/;

/**
 * Coerce a tool-call input into a validated {@link SynthesizedArchetypeContent},
 * or `null` when any required field is missing/ill-typed, the id is not
 * kebab-case, the cwe has no CWE code, or the hint is not cross-language.
 * Fail-closed: a bad candidate is dropped here, never registered.
 */
export function parseSynthesizedContent(input: Record<string, unknown> | null): SynthesizedArchetypeContent | null {
  if (!input) return null;
  const id = asNonEmptyString(input.id);
  const name = asNonEmptyString(input.name);
  const cwe = asNonEmptyString(input.cwe);
  const subsystem = asNonEmptyString(input.subsystem);
  const pattern = asNonEmptyString(input.pattern);
  const detection_signature = asNonEmptyString(input.detection_signature);
  const challenge_hint = asNonEmptyString(input.challenge_hint);
  const grounding = asStringArray(input.grounding);
  const confirmable = asNonEmptyString(input.confirmable);
  if (
    !id || !name || !cwe || !subsystem || !pattern ||
    !detection_signature || !challenge_hint || !grounding || !confirmable
  ) {
    return null;
  }
  if (!KEBAB_ID.test(id)) return null;
  if (!CWE_CODE.test(cwe)) return null;
  if (!isCrossLanguageHint(challenge_hint)) return null;
  return { id, name, cwe, subsystem, pattern, detection_signature, challenge_hint, grounding, confirmable };
}

// ── Prompt ────────────────────────────────────────────────────────────────

const SYNTH_SYSTEM =
  "You are an application-security lens author for an autonomous source-audit finder. " +
  "You turn a cluster of finder MISSES (bug classes the finder failed to surface) into ONE reusable, " +
  "cross-language detection lens. Call the provided tool exactly once. The challenge_hint you write is " +
  "read directly by the finder as its hunt angle, so it must be concrete and cite sink shapes across at " +
  "least two languages/ecosystems, must ask the finder to cite file:line and the taint path, and must " +
  "state the safe shape that is NOT a finding. Never emit exploit code.";

function clusterPrompt(cluster: LensCandidateCluster): string {
  const lines = [
    `A cluster of ${cluster.members.length} finder miss(es) share a bug class. Synthesize ONE lens that would catch them.`,
    "",
    "Misses:",
  ];
  for (const [i, m] of cluster.members.entries()) {
    lines.push(
      `  ${i + 1}. class="${m.classHint}" sink="${m.sinkPattern || "(none — coverage gap)"}" ` +
        `at ${m.exampleFileLine} — why missed: ${m.whyMissed} [${m.source}]`,
    );
  }
  lines.push(
    "",
    "Author a cross-language appsec lens (call propose_appsec_lens once) whose challenge_hint would make the finder surface this class next time.",
  );
  return lines.join("\n");
}

// ── The stage ──────────────────────────────────────────────────────────────

export interface SynthesizeOptions {
  model: LensSynthesisModel;
  /** Cap clusters processed per run (each produces at most one archetype). Default 8. */
  maxClusters?: number;
  log?: (msg: string) => void;
}

/**
 * Cluster the candidates and synthesize one archetype per cluster (up to
 * `maxClusters`). A cluster whose model call throws or whose output fails
 * validation is skipped with a logged reason — the run continues and returns
 * the archetypes that DID synthesize cleanly. Order follows `clusterCandidates`.
 */
export async function synthesizeArchetypes(
  candidates: LensCandidate[],
  opts: SynthesizeOptions,
): Promise<SynthesizedArchetype[]> {
  const log = opts.log ?? (() => {});
  const maxClusters = Math.max(1, opts.maxClusters ?? 8);
  const clusters = clusterCandidates(candidates).slice(0, maxClusters);
  const out: SynthesizedArchetype[] = [];
  for (const cluster of clusters) {
    let result: NativeRuntimeResult;
    try {
      result = await opts.model(
        SYNTH_SYSTEM,
        [{ role: "user", content: [{ type: "text", text: clusterPrompt(cluster) }] }],
        [SYNTH_TOOL],
      );
    } catch (err) {
      log(`[lens-synth] cluster '${cluster.key}' model call failed: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    const content = parseSynthesizedContent(findToolInput(result));
    if (!content) {
      log(`[lens-synth] cluster '${cluster.key}' produced no valid cross-language archetype — dropped`);
      continue;
    }
    out.push({
      content,
      missRefs: cluster.members.map((m) => m.exampleFileLine),
      clusterSize: cluster.members.length,
    });
  }
  return out;
}
