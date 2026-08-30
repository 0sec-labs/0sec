/**
 * Memorable agent names.
 *
 * A spawned agent is far easier to follow as `SilentScout` than as
 * `subagent-9f3a-…`. Names are `AdjectiveNoun` (matching Oh My Pi), derived
 * deterministically from the agent's id so the SAME agent always gets the SAME
 * name — stable across a UI re-render or a resumed session — and then uniquified
 * against the names already in use so two agents never collide.
 *
 * `Main` is the reserved primary-session name and is never produced here. Pure:
 * no clock, no randomness (a hash of the id is the only entropy), so a test can
 * assert an exact name for an id.
 */

/** The reserved name for the primary session. Never generated. */
export const PRIMARY_AGENT_NAME = "Main";

/**
 * Adjective + noun word banks. Kept calm and professional (this is a security
 * tool, not a toy) and deliberately co-prime-ish in length so `adj * NOUNS +
 * noun` spreads names widely before repeating. Both are single tokens so a name
 * is always a clean `[A-Za-z]+` id — safe as a mailbox/roster id with no
 * sanitisation surprises.
 */
const ADJECTIVES = [
  "Silent", "Swift", "Keen", "Bold", "Calm", "Sharp", "Quiet", "Rapid",
  "Clever", "Steady", "Bright", "Amber", "Cobalt", "Crimson", "Golden", "Ivory",
  "Iron", "Lunar", "Solar", "Nimble", "Prime", "Vivid", "Astral", "Ember",
  "Frost", "Onyx", "Quartz", "Scarlet", "Slate", "Umber", "Verdant", "Zephyr",
] as const;

const NOUNS = [
  "Scout", "Falcon", "Warden", "Sentinel", "Ranger", "Probe", "Cipher", "Beacon",
  "Vector", "Harrier", "Lantern", "Compass", "Anchor", "Drifter", "Forge", "Gauge",
  "Herald", "Lookout", "Marshal", "Nomad", "Oracle", "Pilot", "Quill", "Runner",
  "Seeker", "Tracer", "Voyager", "Watcher", "Weaver", "Wraith", "Sparrow", "Delver",
] as const;

/**
 * djb2 hash (unsigned 32-bit) of the id — the same family used for the accent
 * colour, so name and colour are both stable functions of the id. Inlined here
 * rather than imported to keep `core` free of a dependency on the CLI package.
 */
function hashId(text: string): number {
  let hash = 5381;
  for (let i = 0; i < text.length; i += 1) {
    hash = ((hash << 5) + hash) ^ text.charCodeAt(i);
  }
  return hash >>> 0;
}

/** The base `AdjectiveNoun` name for an id, before uniquification. */
export function baseAgentName(id: string): string {
  const h = hashId(id || "peer");
  const adj = ADJECTIVES[h % ADJECTIVES.length];
  const noun = NOUNS[Math.floor(h / ADJECTIVES.length) % NOUNS.length];
  return `${adj}${noun}`;
}

/**
 * Make `name` unique against `taken` (case-insensitive, matching OMP's uniquify)
 * by appending `-2`, `-3`, … The suffix search is bounded only by how many
 * collisions exist, which in practice is a tiny fleet.
 */
export function uniquifyAgentName(name: string, taken: Iterable<string>): string {
  const lower = new Set<string>();
  for (const t of taken) lower.add(t.toLowerCase());
  if (!lower.has(name.toLowerCase())) return name;
  let n = 2;
  while (lower.has(`${name}-${n}`.toLowerCase())) n += 1;
  return `${name}-${n}`;
}

/**
 * The name for a freshly spawned agent: a stable `AdjectiveNoun` from its id,
 * uniquified against the names already in use (which always includes `Main`).
 * A child of a child is dot-qualified under its parent (`Explorer.Scout`) so the
 * lineage is legible in the id itself, matching OMP's nesting scheme.
 */
export function assignAgentName(
  id: string,
  taken: Iterable<string>,
  parentName?: string,
): string {
  const base = baseAgentName(id);
  const qualified = parentName && parentName !== PRIMARY_AGENT_NAME ? `${parentName}.${base}` : base;
  return uniquifyAgentName(qualified, taken);
}
