/**
 * Anthropic prompt-caching (`cache_control`) breakpoint placement.
 *
 * WHY THIS EXISTS
 * ---------------
 * The native agent loop re-sends the ENTIRE conversation on every turn — that
 * is how a stateless Messages API works. Without caching, turn N re-bills and
 * re-processes the system prompt, every tool schema, and all N-1 prior turns
 * at full input price. That is what produced the latency curve quoted in
 * `agent-runner.ts` (5s at turn 1 → 60s at turn 14) and the turn-budget
 * amputation that followed from it. Prompt caching is the direct fix: mark the
 * stable prefix once and every later turn reads it at ~0.1x price and a
 * fraction of the prefill latency.
 *
 * WIRE CONTRACT (Anthropic Messages API)
 * --------------------------------------
 * This engine speaks the raw `/v1/messages` wire (there is no `@anthropic-ai/sdk`
 * dependency in this workspace), so the constants below encode the documented
 * API contract rather than an SDK type:
 *
 *   - `cache_control: { type: "ephemeral" }` attaches to a CONTENT BLOCK, not to
 *     the request. Valid on tool definitions, `system` text blocks, and message
 *     content blocks (`text` / `tool_use` / `tool_result` / `image` / `document`).
 *   - At most FOUR breakpoints per request. A fifth is a request error, so the
 *     budget below is a hard cap, not a tuning knob.
 *   - Render order is `tools` → `system` → `messages`. A breakpoint on the last
 *     `system` block therefore covers the tool schemas too — they sit earlier in
 *     the same prefix — which is why we spend ONE breakpoint, not two, on the
 *     whole static header.
 *   - Caching is a strict PREFIX match: one changed byte anywhere before a
 *     breakpoint invalidates that breakpoint and every later one.
 *   - Each breakpoint looks back at most TWENTY content blocks to find an
 *     existing cache entry. A turn that appends more than 20 blocks therefore
 *     strands the previous entry unless an intermediate breakpoint bridges the
 *     gap — see `planMessageBreakpoints`.
 *   - Below the model's minimum cacheable prefix (512–4096 tokens depending on
 *     model) a breakpoint is silently ignored: no cache entry, no error. Marking
 *     a short prompt is therefore harmless, which is why placement here is
 *     unconditional rather than gated on an estimated token count.
 *
 * RELATIONSHIP TO COMPACTION
 * --------------------------
 * `native-loop.ts` compacts history at `COMPACTION_THRESHOLD` by REWRITING the
 * message array (middle turns collapse into one summary message). That mutates
 * the cached prefix, so it necessarily invalidates every message-level cache
 * entry — no placement strategy can avoid that, it is inherent to rewriting
 * history. What we can control is recovery, and the design here handles it
 * structurally: breakpoints are recomputed from the CURRENT array on every
 * single call and never persisted across turns. The first post-compaction call
 * therefore re-establishes a fresh set of breakpoints over the rewritten
 * transcript and pays one cache write; turn N+1 reads it again. The system
 * breakpoint is unaffected either way — compaction never touches `system` or
 * the tool schemas, so the largest static block keeps hitting straight through
 * a compaction event.
 */

/** A single Anthropic cache breakpoint marker. */
export interface CacheControl {
  type: "ephemeral";
}

/**
 * Loosely-typed Anthropic wire block. The request body is assembled as plain
 * JSON (this engine posts to `/v1/messages` directly rather than through an
 * SDK), so blocks are index signatures rather than a discriminated union. The
 * looseness is confined to this module and `llm-api.ts`'s body builder.
 */
export type WireBlock = Record<string, unknown>;

/**
 * Hard API limit: at most 4 `cache_control` breakpoints per request. Exceeding
 * it is a request error, so every allocation below draws from this budget.
 */
export const MAX_CACHE_BREAKPOINTS = 4;

/**
 * Breakpoints reserved for the `messages` array. One of the four is always
 * spent on the static header (tool schemas + system prompt), which is the
 * single largest and most stable span in the request.
 */
export const MESSAGE_CACHE_BREAKPOINTS = MAX_CACHE_BREAKPOINTS - 1;

/**
 * How far back Anthropic scans from a breakpoint for an existing cache entry.
 * Documented as 20 content blocks.
 */
export const CACHE_LOOKBACK_BLOCKS = 20;

/**
 * Target spacing between consecutive ROLLING message breakpoints, in content
 * blocks.
 *
 * What this buys, concretely. Breakpoints are placed relative to the tail, so
 * on turn N+1 each new breakpoint must land within `CACHE_LOOKBACK_BLOCKS` of
 * an entry written on turn N. If a turn appends G blocks (a turn firing many
 * parallel tools appends one block per `tool_use` plus one per `tool_result`,
 * so G can be large), the new tail breakpoint is G blocks past the old tail
 * entry — it misses outright once G > 20. The second rolling breakpoint sits
 * `BREAKPOINT_SPACING_BLOCKS` further back, so its distance to that same old
 * entry is |G − 15|, which stays inside the window for G up to ~35.
 *
 * So: two rolling breakpoints at this spacing keep the cache warm across turns
 * appending up to roughly 35 content blocks, versus 20 for a lone tail
 * breakpoint. They cost nothing on small turns — the spacing test simply never
 * fires and no extra marker is emitted.
 *
 * Note this reasoning covers the rolling breakpoints only. The head anchor is
 * pinned to message 0, so its entry is re-found at distance zero on every turn
 * regardless of spacing; it is deliberately not part of this chain.
 */
export const BREAKPOINT_SPACING_BLOCKS = 15;

/** Minimal structural view of a message — just enough to count content blocks. */
interface BlockBearingMessage {
  content: readonly unknown[];
}

/**
 * Providers whose `/v1/messages` implementation is KNOWN to honour
 * `cache_control`. Anthropic proper is the only verified member.
 *
 * `z-ai` (GLM) and `kimi` (Moonshot) ride the same Anthropic-compatible wire
 * and the same body builder, but neither has been verified against this engine
 * to accept — let alone act on — `cache_control`. An unknown field on a
 * compatible-but-not-identical endpoint is a request-rejection risk on the hot
 * path of every scan, so they are opt-in via
 * `0SEC_PROMPT_CACHE_EXTRA_PROVIDERS` rather than assumed. Every other
 * provider (`openai`, `azure`, `openrouter`, `chatgpt-codex`) speaks a
 * different wire entirely and is structurally excluded: their request bodies
 * are built in separate branches that never call into this module.
 */
const NATIVE_CACHE_PROVIDERS: ReadonlySet<string> = new Set(["anthropic"]);

/** Anthropic-compatible providers that may be opted in by the operator. */
const OPT_IN_CACHE_PROVIDERS: ReadonlySet<string> = new Set(["z-ai", "kimi"]);

/**
 * Whether `provider` should receive `cache_control` markers.
 *
 * Fails closed: an unrecognised provider never gets Anthropic-shaped fields.
 */
export function providerSupportsPromptCache(provider: string): boolean {
  if (NATIVE_CACHE_PROVIDERS.has(provider)) return true;
  if (!OPT_IN_CACHE_PROVIDERS.has(provider)) return false;
  return readExtraCacheProviders().has(provider);
}

/**
 * Parse `0SEC_PROMPT_CACHE_EXTRA_PROVIDERS` (comma-separated provider ids).
 * Read per call rather than cached at import so the CLI `--features`-style
 * late env mutation is honoured, matching the getter convention in
 * `agent/features.ts`.
 */
function readExtraCacheProviders(): ReadonlySet<string> {
  const raw = process.env["0SEC_PROMPT_CACHE_EXTRA_PROVIDERS"];
  if (!raw) return new Set();
  return new Set(
    raw
      .split(",")
      .map((entry) => entry.trim().toLowerCase())
      .filter((entry) => entry.length > 0),
  );
}

/**
 * Choose which messages get a trailing `cache_control` breakpoint, returning
 * ascending message indices. The marker goes on the message's LAST content
 * block, so the cached prefix covers that message in full.
 *
 * Allocation, in priority order:
 *
 *  1. **The tail** (always). The newest message is where the conversation's
 *     growing edge is; marking it writes a cache entry covering everything
 *     said so far, which the NEXT turn reads back. This is the breakpoint that
 *     actually converts an O(turns²) re-prefill into an O(turns) one.
 *  2. **Spaced bridges**, walking backwards while budget remains, placed
 *     whenever `BREAKPOINT_SPACING_BLOCKS` blocks have accumulated since the
 *     last pick. These exist purely to defeat the 20-block lookback limit: on a
 *     turn that appends a large parallel-tool batch, the tail breakpoint alone
 *     could not see the previous entry, and every hit would be lost exactly
 *     when the conversation is largest. They cost nothing when turns are small
 *     — the spacing test simply never fires, and no breakpoint is emitted.
 *  3. **The head anchor** (message 0), if budget is left over. Message 0 is the
 *     task prompt: the largest, oldest, most stable message, and the one
 *     `compactMessagesWithLLM` preserves verbatim. Anchoring it means even a
 *     compaction or a TTL expiry of the rolling entries still leaves a warm
 *     prefix to read from.
 *
 * @param messages Conversation in wire order.
 * @param budget   Breakpoints available for messages (≤ `MESSAGE_CACHE_BREAKPOINTS`).
 */
export function planMessageBreakpoints(
  messages: readonly BlockBearingMessage[],
  budget: number = MESSAGE_CACHE_BREAKPOINTS,
): number[] {
  if (messages.length === 0 || budget <= 0) return [];

  const lastIndex = messages.length - 1;
  const picks = new Set<number>([lastIndex]);

  // Reserve one breakpoint for the head anchor, but never at the cost of the
  // rolling tail — with a budget of 1 the tail is strictly more valuable, since
  // it is the only breakpoint that grows with the conversation.
  const rollingBudget = Math.max(1, budget - 1);

  let blocksSincePick = blockCount(messages[lastIndex]);
  for (let i = lastIndex - 1; i >= 0 && picks.size < rollingBudget; i--) {
    if (blocksSincePick >= BREAKPOINT_SPACING_BLOCKS) {
      picks.add(i);
      blocksSincePick = 0;
    }
    blocksSincePick += blockCount(messages[i]);
  }

  if (picks.size < budget) picks.add(0);

  return [...picks].sort((a, b) => a - b).slice(0, budget);
}

function blockCount(message: BlockBearingMessage | undefined): number {
  return message?.content.length ?? 0;
}

/**
 * Attach a breakpoint to `block`, returning a NEW object.
 *
 * Non-mutating on purpose: the caller maps over freshly-built wire blocks, and
 * an in-place write here would be one refactor away from stamping
 * `cache_control` onto a caller-owned `NativeMessage` that then gets replayed —
 * and persisted into the session blob — on every subsequent turn.
 */
export function withCacheControl(block: WireBlock): WireBlock {
  return { ...block, cache_control: { type: "ephemeral" } satisfies CacheControl };
}

/**
 * Cache-accounting fields parsed out of an Anthropic `usage` object.
 *
 * `inputTokens` is normalised to the TOTAL prompt size. This matters: on the
 * wire, Anthropic's `input_tokens` counts only the tokens NOT served from cache,
 * so reporting it verbatim once caching is on would make prompts appear to
 * shrink by an order of magnitude. Two things downstream would silently break —
 * `estimateCost` would under-report spend, and `native-loop`'s
 * `COMPACTION_THRESHOLD` (which compares cumulative input tokens against 77k)
 * would stop firing. Folding the cached spans back in keeps both behaving
 * exactly as they did before caching existed.
 */
export interface CacheUsage {
  /** Total prompt tokens: uncached + cache reads + cache writes. */
  inputTokens: number;
  outputTokens: number;
  /** Tokens served from cache this request, billed at roughly 0.1x input. */
  cachedInputTokens?: number;
  /** Tokens written to cache this request, billed at roughly 1.25x input. */
  cacheWriteTokens?: number;
}

/**
 * Read an Anthropic-shaped `usage` object into the engine's usage shape.
 *
 * Returns `undefined` when there is no usage to report, matching the existing
 * `NativeRuntimeResult.usage` optionality.
 *
 * COST NOTE: `cacheWriteTokens` is folded into `inputTokens` and billed at the
 * full input rate by `estimateCost`, which under-reports a cache WRITE by its
 * 1.25x premium. `TokenUsageForPricing` has no cache-write field to express
 * that, and the error is bounded and conservative in the direction that
 * matters: writes happen once per prefix while reads happen every turn after,
 * so the read discount (correctly modelled, ~0.9x saved) dominates the
 * unmodelled write premium (~0.25x paid once) by a wide margin on any run
 * longer than two turns.
 */
export function readCacheUsage(raw: unknown): CacheUsage | undefined {
  if (typeof raw !== "object" || raw === null) return undefined;
  const usage = raw as Record<string, unknown>;

  const uncachedInput = numberOr(usage.input_tokens, 0);
  const outputTokens = numberOr(usage.output_tokens, 0);
  const cacheRead = numberOr(usage.cache_read_input_tokens, undefined);
  const cacheWrite = numberOr(usage.cache_creation_input_tokens, undefined);

  return {
    inputTokens: uncachedInput + (cacheRead ?? 0) + (cacheWrite ?? 0),
    outputTokens,
    ...(cacheRead !== undefined ? { cachedInputTokens: cacheRead } : {}),
    ...(cacheWrite !== undefined ? { cacheWriteTokens: cacheWrite } : {}),
  };
}

function numberOr<T extends number | undefined>(value: unknown, fallback: T): number | T {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}
