/**
 * Line-editing transforms for the chat composer.
 *
 * The composer is APPEND-ONLY: it holds a single string and a caret that is
 * always at the end. There is no cursor position to move, so the readline
 * verbs that are *relative to a caret* (Ctrl+A / Ctrl+E / Ctrl+K, left/right
 * arrows) cannot be implemented honestly here — they would either be no-ops
 * or a lie. What CAN be implemented exactly are the two kill verbs that
 * operate on the tail of the buffer, and they are what operators actually
 * reach for:
 *
 *   Ctrl+U  →  {@link deleteToLineStart}   (macOS Cmd+Backspace maps here)
 *   Ctrl+W  →  {@link deletePreviousWord}  (also Alt/Option+Backspace)
 *
 * They live here rather than inline in the key handler because word-boundary
 * handling is exactly the kind of thing that is quietly wrong forever when it
 * is three characters inside a `useKeyboard` callback.
 */

/**
 * Delete everything before the caret.
 *
 * With an append-only composer the caret is the end of the buffer, so this
 * is the whole line. It is a named function rather than a literal `""` so
 * the key handler reads as an editing verb and so the contract is pinned by
 * a test if the composer ever grows a real cursor.
 */
export function deleteToLineStart(_text: string): string {
  return "";
}

/**
 * Delete the word before the caret, plus any whitespace between the caret
 * and that word — the readline/bash `unix-word-rubout` behaviour.
 *
 * `\S*\s*$` anchors at the end and the engine takes the leftmost match that
 * can reach it, which is precisely "the last run of whitespace, and the run
 * of non-whitespace immediately before it":
 *
 *   "foo bar"    → "foo "     (word only)
 *   "foo bar "   → "foo "     (trailing space AND the word it follows)
 *   "   "        → ""         (all whitespace collapses in one step)
 *   ""           → ""         (idempotent on empty)
 *
 * Both runs are matched as whole units, so a cut never lands inside a
 * surrogate pair: the boundaries are whitespace, and no whitespace character
 * is half of an astral code point.
 */
export function deletePreviousWord(text: string): string {
  return text.replace(/\S*\s*$/, "");
}
