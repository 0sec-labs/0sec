/**
 * Craft memory: preseed + consolidation on top of the tiered store.
 *
 * - preseedMemory(): seed an empty store with format-construction recipes
 *   (procedural) + sanitizer/bug-class concepts (semantic) + a few invariants
 *   (principle), all benchmark-agnostic — the same idea as Crystalline's
 *   crystalline-seed-v5.db (zero task-specific data).
 * - consolidateMemory(): the Hebbian promotion loop — an LLM reviews recent
 *   episodes and extracts higher-tier concepts/recipes/principles.
 */

import { CraftMemoryStore } from "./store.js";
import { lookupFormatPrimer, knownFormatIds } from "../stages/format-knowledge.js";
import { LlmApiRuntime } from "../runtime/llm-api.js";

export { CraftMemoryStore } from "./store.js";
export type { Memory, MemoryLevel } from "./store.js";

/** Benchmark-agnostic semantic/principle seeds (sanitizer + bug-class knowledge). */
const SEMANTIC_SEEDS: string[] = [
  "ASan detects heap-buffer-overflow (read/write past a malloc), stack-buffer-overflow, use-after-free, double-free, and heap-use-after-return.",
  "MSan detects use of uninitialized memory; the crash depends on a value that was never written, so a successful PoC reaches a read of an uninitialized buffer/struct field.",
  "UBSan flags signed integer overflow, OOB array index, misaligned/invalid pointer, and 'call through pointer to incorrect function type' (a harness signature mismatch that fires on ANY input).",
  "A sanitizer abort exits the process with a nonzero code; a clean run exits 0. The differential oracle wants: nonzero on the vulnerable build AND 0 on the patched build.",
  "OSS-Fuzz harnesses define LLVMFuzzerTestOneInput(const uint8_t* data, size_t size); some split `data` into sub-inputs (e.g. font bytes + shaping text) — read the harness to learn the split before crafting.",
];

const PRINCIPLE_SEEDS: string[] = [
  "A length/size/count field must be validated BEFORE any field is read at an offset that depends on it; an unchecked 'length > 0' that is followed by a multi-byte read at offset k needs length >= k+width.",
  "After a realloc/grow of a backing buffer, every cached pointer/index into the old allocation is stale and must be re-derived — classic source of use-after-realloc OOB.",
  "Signed integer parse functions used in size/length/offset contexts must reject negative values, or a negative length becomes a huge unsigned size.",
  "Intractable-both-crash basin: if a PoC crashes BOTH the vulnerable and patched builds, it triggers a PRE-EXISTING bug, not the target. Shrink/simplify the input toward the EXACT described code path; remove the bytes that trigger the unrelated crash, keep only what reaches the described function.",
  "Prefer mutating a known-valid corpus seed over constructing a complex binary format from scratch — it guarantees you reach the parser, then perturb only the field the bug is about.",
];

/** Seed an empty store (no-op if it already has memories). */
export function preseedMemory(store: CraftMemoryStore): void {
  if (store.count() > 0) return;
  for (const id of knownFormatIds()) {
    const p = lookupFormatPrimer(id);
    if (p) store.remember({ level: "procedural", content: `${p.id} format: ${p.primer}`, source: "preseed", context: p.match.join(" ") });
  }
  for (const s of SEMANTIC_SEEDS) store.remember({ level: "semantic", content: s, source: "preseed" });
  for (const s of PRINCIPLE_SEEDS) store.remember({ level: "principle", content: s, source: "preseed" });
}

/**
 * Hebbian consolidation: ask the LLM to promote recent episodes into reusable
 * semantic concepts, procedural recipes, and principles. Appends the promoted
 * memories. Best-effort — never throws into the caller.
 */
export async function consolidateMemory(
  store: CraftMemoryStore,
  opts: { runtime?: "auto"; model?: string; everyN?: number } = {},
): Promise<number> {
  if (!store.consolidationDue(opts.everyN ?? 20)) return 0;
  const episodes = store.recentEpisodes(30);
  if (episodes.length < 5) {
    store.markConsolidated();
    return 0;
  }
  const system =
    "You distill specific vulnerability-reproduction episodes into REUSABLE, generalizable knowledge for a " +
    "PoC-crafting agent. Given recent episodes, extract concepts, construction recipes, and invariants that " +
    "would help solve FUTURE, different tasks. Be concrete and crisp. Output ONLY a JSON object: " +
    '{"semantic":[".."],"procedural":[".."],"principle":[".."],"analogical":[".."]} — each an array of short ' +
    "one-line strings (omit a key if empty). No task ids, no prose outside the JSON.";
  const user =
    "Recent episodes:\n" + episodes.map((e, i) => `${i + 1}. ${e.content}`).join("\n") +
    "\n\nDistill the recurring, transferable patterns.";
  let text = "";
  try {
    const rt = new LlmApiRuntime({ type: "api", ...(opts.model ? { model: opts.model } : {}), timeout: 120_000 });
    const res = await rt.executeNative(system, [{ role: "user", content: [{ type: "text", text: user }] }] as never, [] as never,
      { onThinking() {}, onDelta() {}, onText() {}, onUsage() {} } as never);
    text = ((res.content ?? []) as Array<{ type: string; text?: string }>).map((b) => (b.type === "text" ? b.text ?? "" : "")).join("");
  } catch {
    store.markConsolidated();
    return 0;
  }
  let added = 0;
  try {
    const m = /\{[\s\S]*\}/.exec(text);
    if (m) {
      const obj = JSON.parse(m[0]) as Record<string, unknown>;
      for (const level of ["semantic", "procedural", "principle", "analogical"] as const) {
        const arr = obj[level];
        if (Array.isArray(arr)) {
          for (const c of arr) {
            if (typeof c === "string" && store.remember({ level, content: c, source: "consolidation" })) added++;
          }
        }
      }
    }
  } catch {
    /* malformed — skip */
  }
  store.markConsolidated();
  return added;
}
