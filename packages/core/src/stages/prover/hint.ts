/**
 * Alias matching for {@link ProverPlugin.matches}.
 *
 * Split out of the plugins because the naive version — `hint.includes(alias)` —
 * has a specific, silent failure: the hint `"gzip_fuzzer"` contains `"zip"`, so
 * the ZIP plugin would confidently claim a gzip target and hand the agent a
 * central directory it will never use. Requiring the alias to start at a
 * non-letter boundary fixes that while still matching the shapes fuzzer names
 * actually take (`png_read_fuzzer`, `read_png_fuzzer`, `libpng-1.6`,
 * `zip_read_fuzzer`).
 *
 * Deliberately not a tokeniser: fuzzer names are separated by `_`, `-`, `.`,
 * digits and nothing consistent, and a full tokeniser would be more machinery
 * than the problem needs.
 */

/**
 * Longest alias that occurs in `hint` at a non-letter boundary, or `undefined`.
 * Longest-wins so `apng` beats `png` when both are registered aliases, which
 * keeps the reported reason precise.
 */
export function matchAlias(hint: string, aliases: readonly string[]): string | undefined {
  const h = hint.toLowerCase();
  let best: string | undefined;
  for (const alias of aliases) {
    const a = alias.toLowerCase();
    let from = 0;
    for (;;) {
      const at = h.indexOf(a, from);
      if (at < 0) break;
      const prev = at === 0 ? "" : h[at - 1]!;
      if (!/[a-z]/.test(prev)) {
        if (best === undefined || a.length > best.length) best = a;
        break;
      }
      from = at + 1;
    }
  }
  return best;
}
