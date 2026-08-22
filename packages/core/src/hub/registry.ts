/**
 * Hub peer roster — the pure, side-effect-free core of the coordination hub.
 *
 * This module is the FIRST increment of the hub (see DESIGN.md). It owns the
 * data model for the set of peers that can address one another — concurrently
 * running subagents inside one 0sec session, and separate 0sec sessions working
 * the same project directory — and the pure reconciliation logic that keeps that
 * set consistent as peers appear, heartbeat, restart, and go stale.
 *
 * Deliberately NOT here (later increments own these): the filesystem/socket
 * transport that persists and gossips the roster, message delivery, `wait`,
 * process supervision. Nothing in this file touches the filesystem, network,
 * a clock, or spawns a process. `pid` and `cwd` are opaque DATA carried on a
 * record, never dereferenced. `now` and `ttlMs` are always INJECTED so every
 * function is pure, total, and deterministically testable — the codebase forbids
 * `Date.now()` (or any ambient clock) inside logic that has tests.
 */

/** What a roster entry represents. */
export type PeerKind = "session" | "subagent";

/** Liveness of a roster entry, derived purely from `lastSeen` vs. a TTL. */
export type PeerStatus = "active" | "stale";

/**
 * One entry in the peer roster. All fields are plain data: nothing here is
 * dereferenced (no `process.kill(pid)`, no `fs.stat(cwd)`) inside this module.
 */
export interface PeerRecord {
  /** Stable roster id, e.g. "Main" or a subagent task id. Used for addressing. */
  id: string;
  kind: PeerKind;
  /** OS process id of the peer. Opaque data here. */
  pid: number;
  /** Project directory this peer is working in. Opaque data here. */
  cwd: string;
  /**
   * Epoch ms of the peer's last heartbeat. Injected by the caller from a real
   * clock at the edge; never read from a clock inside these pure functions.
   */
  lastSeen: number;
  /** Optional human label, e.g. the engagement target. */
  label?: string;
}

/**
 * Default heartbeat time-to-live. A peer whose last heartbeat is older than this
 * is considered stale (its process likely crashed or exited without cleanup).
 *
 * Chosen to be several heartbeat intervals: with a ~10s heartbeat (a later
 * increment's concern), 90s tolerates a couple of missed beats under GC pauses,
 * provider stalls, or a laptop briefly sleeping, without keeping a truly dead
 * peer addressable for long. Callers may override per call via `ttlMs`.
 */
export const DEFAULT_PEER_TTL_MS = 90_000;

/**
 * Fallback id assigned when `desired` sanitizes to the empty string. It is a
 * valid id under {@link sanitizeId} (so it never needs re-sanitizing) and is
 * suffixed like any other collision by {@link nextPeerId}.
 */
export const FALLBACK_PEER_ID = "peer";

/**
 * Max id length after sanitization. Roster ids surface in operator UIs and, in
 * later increments, in transport paths; an unbounded id (e.g. a pasted blob)
 * would be a footgun. Truncation happens before collision suffixing so the
 * suffix is never lost off the end.
 */
const MAX_ID_LENGTH = 64;

/**
 * Reduce an arbitrary string to a safe roster id.
 *
 * Roster ids are used for ADDRESSING and, later, for building transport paths,
 * so they must never carry path separators (`/`, `\`), whitespace, control
 * characters, or other shell/path metacharacters. We take the allowlist
 * approach — keep only `[A-Za-z0-9._-]` — which is safe by construction rather
 * than trying to blocklist every dangerous character. Leading dots are stripped
 * so an id can never become `.`, `..`, or a hidden dotfile-style name. An input
 * that has nothing left after this returns "" and the caller substitutes
 * {@link FALLBACK_PEER_ID}.
 */
export function sanitizeId(raw: string): string {
  const kept = raw
    // Replace every disallowed char with nothing. This removes path separators,
    // whitespace (incl. tabs/newlines), and control chars in one pass.
    .replace(/[^A-Za-z0-9._-]/g, "")
    // No leading dots: forbids ".", "..", and ".hidden" style ids.
    .replace(/^\.+/, "");
  return kept.slice(0, MAX_ID_LENGTH);
}

/**
 * Is `peer` stale as of `now`? Pure comparison of the heartbeat age against the
 * TTL. The boundary is INCLUSIVE-alive: a peer whose age exactly equals the TTL
 * is still active; it becomes stale only once strictly older. `ttlMs` defaults
 * to {@link DEFAULT_PEER_TTL_MS}. A non-positive or non-finite `ttlMs` is
 * treated as the default so a caller cannot accidentally mark everything stale.
 */
export function isStale(peer: PeerRecord, now: number, ttlMs: number = DEFAULT_PEER_TTL_MS): boolean {
  const ttl = Number.isFinite(ttlMs) && ttlMs > 0 ? ttlMs : DEFAULT_PEER_TTL_MS;
  return now - peer.lastSeen > ttl;
}

/**
 * Derive a peer's {@link PeerStatus} at `now`. Convenience wrapper over
 * {@link isStale}.
 */
export function statusOf(peer: PeerRecord, now: number, ttlMs?: number): PeerStatus {
  return isStale(peer, now, ttlMs) ? "stale" : "active";
}

/**
 * Merge `incoming` into `existing`, returning a NEW array (never mutating the
 * input or its elements).
 *
 * If a record with the same `id` already exists it is REPLACED in place (a
 * restarted session reusing its id must update — not duplicate — its entry);
 * otherwise `incoming` is appended. Relative order of untouched entries is
 * preserved, and a replaced entry keeps its original position so the roster does
 * not reshuffle on every heartbeat.
 *
 * `now` is accepted for signature symmetry with the other reconcilers and to
 * leave room for future age-aware merge policy; it is intentionally unused today.
 */
export function reconcileRoster(
  existing: readonly PeerRecord[],
  incoming: PeerRecord,
  now: number,
): PeerRecord[] {
  void now;
  let replaced = false;
  const next = existing.map((peer) => {
    if (peer.id === incoming.id) {
      replaced = true;
      return incoming;
    }
    return peer;
  });
  if (!replaced) next.push(incoming);
  return next;
}

/**
 * Drop every stale peer as of `now`, returning a NEW array of the survivors in
 * original order. Never mutates the input. `ttlMs` is forwarded to
 * {@link isStale}.
 */
export function pruneRoster(
  peers: readonly PeerRecord[],
  now: number,
  ttlMs?: number,
): PeerRecord[] {
  return peers.filter((peer) => !isStale(peer, now, ttlMs));
}

/**
 * Return a unique, sanitized roster id derived from `desired`, given the ids
 * already present in `existing`.
 *
 * - `desired` is first run through {@link sanitizeId}; if that yields the empty
 *   string, {@link FALLBACK_PEER_ID} is used as the base.
 * - If the base is free, it is returned unchanged.
 * - Otherwise the smallest integer suffix `-2`, `-3`, … that is free is
 *   appended. Uniqueness is checked against the SANITIZED ids of `existing`, so
 *   a caller that stored ids some other way cannot smuggle a collision past us.
 *
 * Termination is guaranteed: there are finitely many existing ids (N), so at
 * most N+1 candidates are tried before one is necessarily free.
 */
/**
 * Ids that can never be assigned to a peer. Kept here rather than imported
 * from `mailbox.ts` because mailbox already depends on this module's id
 * rules, and the reverse import would create a cycle. `mailbox.ts` exports
 * the same value as `RESERVED_PEER_IDS`; a test asserts they agree.
 */
export const RESERVED_HUB_IDS: readonly string[] = ["all"];

export function nextPeerId(existing: readonly PeerRecord[], desired: string): string {
  const taken = new Set(existing.map((peer) => sanitizeId(peer.id)));
  // "all" is the broadcast address in the mailbox. Handing it to a real peer
  // would make every broadcast look like it came from — and was addressed to
  // — that peer, so it is treated as permanently taken rather than assignable.
  for (const reserved of RESERVED_HUB_IDS) taken.add(reserved);
  const base = sanitizeId(desired) || FALLBACK_PEER_ID;
  if (!taken.has(base)) return base;
  // At most taken.size + 1 iterations: some candidate in [2, taken.size + 2]
  // must be free because only taken.size ids can be occupied.
  for (let suffix = 2; suffix <= taken.size + 2; suffix++) {
    const candidate = `${base}-${suffix}`;
    if (!taken.has(candidate)) return candidate;
  }
  // Unreachable by the counting argument above; present so the function is total
  // and the type checker sees a guaranteed string return.
  /* c8 ignore next */
  return `${base}-${taken.size + 2}`;
}

/**
 * Render the roster as operator-facing lines (one per peer), marking stale
 * entries explicitly. Pure: builds and returns strings, prints nothing.
 *
 * Format per line: `<id> [<kind>] pid=<pid> — <status>[ (<label>)]`, e.g.
 *   `Main [session] pid=4131 — active (api.example.com)`
 *   `scan-7-sub-ab12 [subagent] pid=4200 — STALE`
 */
export function describeRoster(peers: readonly PeerRecord[], now: number): string[] {
  return peers.map((peer) => {
    const status = isStale(peer, now) ? "STALE" : "active";
    const label = peer.label ? ` (${peer.label})` : "";
    return `${peer.id} [${peer.kind}] pid=${peer.pid} — ${status}${label}`;
  });
}
