// Shared helpers for tool-level dedup / similarity logic.
//
// 0sec#281 — `saveFinding` needs cheap fuzzy title comparison so the same
// SQLi reported across attack + verify stages doesn't end up as 3 advisory
// drafts. Keeping the helpers here lets future call sites (e.g. disclose
// bundle dedup at `bundle.ts:218 assembleBundleIndex`) reuse the same
// normalization + edit-distance functions without pulling in a dep.

/**
 * Normalize a finding title for similarity comparison.
 *
 * - lowercased
 * - non-alphanumeric characters stripped (drops ".php", "/" path slashes,
 *   parentheses, etc. so "SQL Injection in /users" and "SQL injection in
 *   /users.php" collapse)
 * - whitespace collapsed and trimmed
 */
export function normalizeFindingTitle(title: string): string {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9 ]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Iterative Levenshtein edit distance (insertions, deletions, substitutions
 * each cost 1). O(n * m) time, O(min(n, m)) space via rolling row.
 *
 * Pure helper — no deps, no surprises. Returns `Infinity` only if either
 * input is non-string (defensive; callers should pass strings).
 */
export function levenshtein(a: string, b: string): number {
  if (typeof a !== "string" || typeof b !== "string") return Infinity;
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // Ensure `b` is the shorter so the rolling row stays small.
  if (a.length < b.length) {
    const tmp = a;
    a = b;
    b = tmp;
  }

  const n = a.length;
  const m = b.length;
  let prev = new Array<number>(m + 1);
  let curr = new Array<number>(m + 1);
  for (let j = 0; j <= m; j++) prev[j] = j;

  for (let i = 1; i <= n; i++) {
    curr[0] = i;
    const ai = a.charCodeAt(i - 1);
    for (let j = 1; j <= m; j++) {
      const cost = ai === b.charCodeAt(j - 1) ? 0 : 1;
      const del = prev[j] + 1;
      const ins = curr[j - 1] + 1;
      const sub = prev[j - 1] + cost;
      curr[j] = del < ins ? (del < sub ? del : sub) : ins < sub ? ins : sub;
    }
    const swap = prev;
    prev = curr;
    curr = swap;
  }

  return prev[m];
}

/**
 * 0sec#281 — fuzzy-title threshold for finding dedup. Levenshtein ≤ 5
 * tolerates typical agent reformulations like "SQL injection in /users" vs
 * "SQL Injection in /users.php" (after normalization) without collapsing
 * legitimately distinct findings such as "/admin/users" vs "/admin/orders"
 * which share a prefix but diverge in the endpoint segment.
 */
export const FUZZY_TITLE_DISTANCE_THRESHOLD = 5;

/**
 * Length of the `evidence.request` prefix used as the third axis of the
 * dedup similarity key. Matches the contract documented on saveFinding.
 */
export const EVIDENCE_REQUEST_PREFIX_LEN = 200;

/**
 * Build the evidence-request prefix used in dedup similarity keys.
 */
export function evidenceRequestPrefix(request: string | undefined | null): string {
  return (request ?? "").slice(0, EVIDENCE_REQUEST_PREFIX_LEN);
}
