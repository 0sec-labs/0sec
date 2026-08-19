import { useEffect, useState } from "react";

function readStoredValue<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;

  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export function usePersistentState<T>(key: string, fallback: T) {
  const [value, setValue] = useState<T>(() => readStoredValue(key, fallback));

  useEffect(() => {
    try {
      window.localStorage.setItem(key, JSON.stringify(value));
    } catch {
      // Ignore storage failures in private browsing or restricted environments.
    }
  }, [key, value]);

  return [value, setValue] as const;
}
