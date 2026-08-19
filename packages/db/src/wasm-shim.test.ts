import { describe, expect, it, afterEach } from "vitest";
import { createShimmedDatabase, isBunRuntime } from "./wasm-shim.js";

/**
 * These tests exercise the WASM (node-sqlite3-wasm) branch of the shim — the
 * one that runs under plain Node. The Bun branch of `createShimmedDatabase`
 * is exercised end-to-end by the bun-compiled binary (see scripts/bun-compile.sh).
 *
 * The runtime-detection branch test verifies that `isBunRuntime()` returns
 * the expected boolean for the current process AND that toggling the global
 * `Bun` symbol flips the result — proving the gate that picks bun:sqlite vs
 * node-sqlite3-wasm actually keys off runtime state.
 */
describe("isBunRuntime()", () => {
  afterEach(() => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    delete (globalThis as any).Bun;
  });

  it("returns false under plain Node (no Bun global, no process.versions.bun)", () => {
    // Sanity-check the test's own assumption: vitest under Node should
    // not have a `Bun` global. If a future migration runs vitest under
    // Bun, this assertion will alert us to flip the test polarity.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    expect((globalThis as any).Bun).toBeUndefined();
    expect(process.versions.bun).toBeUndefined();
    expect(isBunRuntime()).toBe(false);
  });

  it("returns true when a Bun global is present", () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    (globalThis as any).Bun = { version: "test-stub" };
    expect(isBunRuntime()).toBe(true);
  });
});

describe("ShimmedDatabase (WASM engine, in-memory)", () => {
  it("round-trips inserts, named bindings, and transaction rollback", () => {
    // ":memory:" keeps the test hermetic — no disk artifacts to clean up.
    const db = createShimmedDatabase(":memory:");
    try {
      db.exec(`
        CREATE TABLE kv (
          k TEXT PRIMARY KEY,
          v INTEGER NOT NULL
        )
      `);

      // Positional varargs: stmt.run(a, b)
      const insert = db.prepare("INSERT INTO kv (k, v) VALUES (?, ?)");
      const r1 = insert.run("a", 1);
      expect(r1.changes).toBe(1);

      // Named binding via plain-key object — the shim auto-prefixes `@`.
      const insertNamed = db.prepare("INSERT INTO kv (k, v) VALUES (@k, @v)");
      insertNamed.run({ k: "b", v: 2 });

      // .all() returns row objects.
      const rows = db.prepare("SELECT k, v FROM kv ORDER BY k").all() as Array<{
        k: string;
        v: number;
      }>;
      expect(rows).toEqual([
        { k: "a", v: 1 },
        { k: "b", v: 2 },
      ]);

      // .raw().all() returns ordered value arrays — drizzle uses this.
      const rawRows = (db.prepare("SELECT k, v FROM kv ORDER BY k").raw() as
        ReturnType<typeof db.prepare>).all();
      expect(rawRows).toEqual([
        ["a", 1],
        ["b", 2],
      ]);

      // .get() with no match → undefined (not null).
      const missing = db.prepare("SELECT v FROM kv WHERE k = ?").get("zzz");
      expect(missing).toBeUndefined();

      // .transaction() commits on success.
      const tx = db.transaction((k: string, v: number) => {
        db.prepare("INSERT INTO kv (k, v) VALUES (?, ?)").run(k, v);
      });
      tx("c", 3);
      const after = db.prepare("SELECT count(*) as n FROM kv").get() as {
        n: number;
      };
      expect(after.n).toBe(3);

      // .transaction() rolls back on throw.
      const failing = db.transaction(() => {
        db.prepare("INSERT INTO kv (k, v) VALUES (?, ?)").run("d", 4);
        throw new Error("boom");
      });
      expect(() => failing()).toThrow(/boom/);
      const afterRollback = db.prepare("SELECT count(*) as n FROM kv").get() as {
        n: number;
      };
      expect(afterRollback.n).toBe(3);
    } finally {
      db.close();
    }
  });

  it("pragma() swallows engine-specific errors silently", () => {
    const db = createShimmedDatabase(":memory:");
    try {
      // foreign_keys = ON is universally supported.
      expect(() => db.pragma("foreign_keys = ON")).not.toThrow();
      // A nonsense pragma should not propagate even if the engine errors.
      expect(() => db.pragma("definitely_not_a_real_pragma = 1")).not.toThrow();
    } finally {
      db.close();
    }
  });
});
