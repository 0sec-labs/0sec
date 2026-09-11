import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";

/** UI state only. Engine credentials and authorization never belong here. */
export class DesktopPreferences {
  private readonly values: Record<string, unknown>;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private pending: { promise: Promise<void>; resolve: () => void; reject: (error: unknown) => void } | undefined;

  constructor(private readonly path: string) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    try {
      const value: unknown = JSON.parse(readFileSync(path, "utf8"));
      if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Desktop preferences must be an object.");
      this.values = Object.fromEntries(Object.entries(value).filter(([key]) => key.startsWith("0sec:")));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      this.values = {};
    }
  }

  snapshot(): Record<string, unknown> {
    return { ...this.values };
  }

  set(key: unknown, value: unknown): Promise<void> {
    if (typeof key !== "string" || !key.startsWith("0sec:")) throw new Error("Invalid desktop preference key.");
    const encoded = JSON.stringify(value);
    if (encoded === undefined) throw new Error("Desktop preferences must contain JSON values.");
    this.values[key] = JSON.parse(encoded);
    if (!this.pending) {
      let resolve!: () => void;
      let reject!: (error: unknown) => void;
      const promise = new Promise<void>((yes, no) => { resolve = yes; reject = no; });
      this.pending = { promise, resolve, reject };
      // Coalesce rapid draft edits; each IPC caller observes the eventual write.
      this.timer = setTimeout(() => { void this.flush().catch(() => undefined); }, 150);
    }
    return this.pending.promise;
  }

  flush(): Promise<void> {
    clearTimeout(this.timer);
    this.timer = undefined;
    const pending = this.pending;
    if (!pending) return Promise.resolve();
    this.pending = undefined;
    try {
      writeFileSync(`${this.path}.tmp`, JSON.stringify(this.values), { mode: 0o600 });
      renameSync(`${this.path}.tmp`, this.path);
      pending.resolve();
    } catch (error) {
      pending.reject(error);
    }
    return pending.promise;
  }
}
