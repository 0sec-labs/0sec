import { useEffect, useState } from "react";

/**
 * Persist a value to the native bridge when available, falling back to
 * localStorage. Surface persistence rejection via a custom DOM event so the
 * workspace hook (or any consumer) can display the error.
 */
async function persistPreference(key: string, value: unknown): Promise<void> {
  // Always write to localStorage — it's the canonical read source for React
  // hydration and the web fallback.
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch (cause) {
    window.dispatchEvent(
      new CustomEvent("osec:preference-error", {
        detail: `Failed to save "${key}": ${cause instanceof Error ? cause.message : String(cause)}`,
      }),
    );
    return;
  }

  // Desktop bridge persistence — surface rejection without throwing.
  const bridge = window.osecDesktop;
  if (!bridge) return;

  try {
    await bridge.setPreference(key, value);
  } catch (cause) {
    window.dispatchEvent(
      new CustomEvent("osec:preference-error", {
        detail: `Failed to persist "${key}": ${cause instanceof Error ? cause.message : String(cause)}`,
      }),
    );
  }
}

/**
 * React hook that persists state across reloads.
 *
 * - Reads initial value from `localStorage` (populated by Main's bootstrap for
 *   desktop native prefs, or by web's own prior writes).
 * - Writes every update through both `localStorage` and, when available,
 *   `window.osecDesktop.setPreference` for Electron-side persistence.
 * - Rejections surface via `osec:preference-error` CustomEvent — the
 *   workspace hook listens for those.
 *
 * Keys MUST be prefixed `0sec:`.
 *
 * @param key   Storage key (e.g. `"0sec:drafts"`).
 * @param initial  Fallback value when nothing is stored.
 * @returns  Standard React state setter tuple.
 */
export function useStoredState<T>(
  key: string,
  initial: T,
): [T, React.Dispatch<React.SetStateAction<T>>] {
  const [value, setValue] = useState<T>(() => {
    if (typeof window === "undefined") return initial;
    try {
      const raw = window.localStorage.getItem(key);
      return raw ? (JSON.parse(raw) as T) : initial;
    } catch {
      return initial;
    }
  });

  useEffect(() => {
    // Non-blocking persistence — fire-and-forget to avoid delaying renders.
    void persistPreference(key, value);
  }, [key, value]);

  return [value, setValue] as const;
}
