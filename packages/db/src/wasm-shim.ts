/**
 * SQLite engine → better-sqlite3 API shim.
 *
 * Exposes `createShimmedDatabase(path)` and `createDrizzleFromShim(...)`,
 * both of which return objects that present the better-sqlite3 surface area
 * expected by drizzle-orm's `BetterSQLiteSession`. This lets 0sec use a
 * pure-WASM SQLite implementation (no native bindings, no NODE_MODULE_VERSION
 * drift) while keeping the existing drizzle query-builder code unchanged.
 *
 * Background: better-sqlite3 ships native `.node` files per Node ABI and
 * occasionally the `prebuild-install` dependency chain picks the wrong one,
 * producing the infamous `NODE_MODULE_VERSION X requires NODE_MODULE_VERSION Y`
 * crash. WASM sidesteps this entirely — one binary runs on every Node version,
 * Bun, Deno, Electron, whatever.
 *
 * Bun runtime branch (v0.10.1+): when running under Bun (e.g. inside the
 * `bun build --compile` single-file binary), we route to the built-in
 * `bun:sqlite` engine instead of `node-sqlite3-wasm`. node-sqlite3-wasm
 * resolves its `.wasm` sidecar via `__dirname`, which after `--compile`
 * points at the build host's filesystem — so the binary crashes on startup
 * with `ENOENT … node-sqlite3-wasm.wasm` on any other machine. bun:sqlite
 * is statically linked into the Bun runtime itself, so it has no external
 * asset to resolve. The public shim surface (StatementShim / ShimmedDatabase
 * / createDrizzleFromShim) is unchanged.
 */

// We DO NOT statically import either engine at the top level:
//
//   - `node-sqlite3-wasm` runs `fs.readFileSync(__dirname + "/...wasm")` at
//     module-load time. Inside a `bun build --compile` binary, `__dirname`
//     resolves to the build host's filesystem (baked into the binary), so a
//     top-level import crashes with `ENOENT … node-sqlite3-wasm.wasm` on
//     ANY other machine — even though the Bun branch never actually calls
//     into it. The crash happens during module evaluation, before
//     `isBunRuntime()` can ever fire. Hence: lazy require inside
//     `createWasmEngine`, which only executes on the Node path.
//
//   - `bun:sqlite` only resolves under the Bun runtime, so a static import
//     would fail under Node. Loaded lazily inside `createBunEngine`.
//
// We import BetterSQLiteSession from the deep `/session` subpath to avoid
// pulling in `drizzle-orm/better-sqlite3/driver.js`, which `import`s
// `better-sqlite3` at module load and would defeat the whole point.
import { BetterSQLiteSession } from "drizzle-orm/better-sqlite3/session";
import { BaseSQLiteDatabase } from "drizzle-orm/sqlite-core/db";
import { SQLiteSyncDialect } from "drizzle-orm/sqlite-core/dialect";
import {
  createTableRelationsHelpers,
  extractTablesRelationalConfig,
  type RelationalSchemaConfig,
  type TablesRelationalConfig,
} from "drizzle-orm/relations";
import { createRequire } from "node:module";

/**
 * Detect the Bun runtime. We check both the global `Bun` object and
 * `process.versions.bun` because either may be unavailable in test setups
 * that mock one but not the other. Exported for tests so they can stub
 * the detection result.
 */
export function isBunRuntime(): boolean {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  if (typeof g.Bun !== "undefined") return true;
  const versions = (typeof process !== "undefined" && process.versions) as
    | (NodeJS.ProcessVersions & { bun?: string })
    | undefined;
  return !!(versions && versions.bun);
}

type BindValue = number | bigint | string | Uint8Array | null | boolean;

interface RunResult {
  changes: number;
  lastInsertRowid: number | bigint;
}

/**
 * Normalize the varargs drizzle-orm (and better-sqlite3 users) pass to
 * `stmt.run(...args)` into the single-argument form node-sqlite3-wasm expects.
 *
 * Rules:
 *  - zero args           → undefined (no binding)
 *  - N positional args   → array of args
 *  - single object arg   → assume named binding; prepend `@` to each key so
 *                          node-sqlite3-wasm matches the existing `@name`
 *                          placeholders used in our raw-SQL sites
 */
function normalizeBindArgs(args: unknown[]): unknown {
  if (args.length === 0) return undefined;
  if (args.length === 1) {
    const a = args[0];
    if (
      a !== null &&
      typeof a === "object" &&
      !Array.isArray(a) &&
      !(a instanceof Uint8Array)
    ) {
      // Named binding: keys like { id, scope } → { "@id": ..., "@scope": ... }
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(a as Record<string, unknown>)) {
        // If the caller already included a sigil, respect it; otherwise add @.
        out[/^[:@$]/.test(k) ? k : `@${k}`] = v;
      }
      return out;
    }
    // Single positional value (string/number/etc) — wrap in array so the
    // wasm driver treats it as positional rather than named.
    return [a as BindValue];
  }
  return args as BindValue[];
}

/**
 * Engine-agnostic statement adapter. Both `node-sqlite3-wasm`'s Statement
 * and `bun:sqlite`'s Statement satisfy this interface (with thin wrappers
 * for `run`'s return shape and `null` → `undefined` normalisation).
 */
interface RawStatement {
  run(bind: unknown): RunResult;
  get(bind: unknown): Record<string, unknown> | undefined;
  all(bind: unknown): Array<Record<string, unknown>>;
  /** Same rows as `all`, but as ordered value arrays. Used by drizzle's `raw()`. */
  values(bind: unknown): unknown[][];
}

/**
 * Engine-agnostic database adapter.
 */
interface RawDatabase {
  prepare(sql: string): RawStatement;
  exec(sql: string): void;
  close(): void;
  readonly inTransaction: boolean;
  readonly isOpen: boolean;
}

class StatementShim {
  constructor(private readonly stmt: RawStatement, private readonly rawMode = false) {}

  run(...args: unknown[]): RunResult {
    const bind = normalizeBindArgs(args);
    return this.stmt.run(bind);
  }

  get(...args: unknown[]): unknown {
    const bind = normalizeBindArgs(args);
    if (this.rawMode) {
      // drizzle's `raw().get()` expects row values as an ordered array.
      const rows = this.stmt.values(bind);
      return rows[0];
    }
    const row = this.stmt.get(bind);
    if (row == null) return undefined;
    return row;
  }

  all(...args: unknown[]): unknown[] {
    const bind = normalizeBindArgs(args);
    if (this.rawMode) return this.stmt.values(bind);
    return this.stmt.all(bind);
  }

  /** better-sqlite3 compat: return a statement that yields rows as arrays. */
  raw(): StatementShim {
    return new StatementShim(this.stmt, true);
  }

  // Stubs for methods drizzle never calls but better-sqlite3 exposes.
  // Keeps TypeScript structural typing happy if something reaches for them.
  pluck(): this {
    return this;
  }
  expand(): this {
    return this;
  }
  bind(): this {
    return this;
  }
}

/**
 * better-sqlite3 Database look-alike. Wraps an engine-agnostic `RawDatabase`
 * (either node-sqlite3-wasm or bun:sqlite) and exposes the subset of the
 * better-sqlite3 API that 0sec's database.ts and drizzle's
 * `BetterSQLiteSession` actually call.
 */
export class ShimmedDatabase {
  constructor(private readonly engine: RawDatabase) {}

  prepare(sql: string): StatementShim {
    return new StatementShim(this.engine.prepare(sql));
  }

  exec(sql: string): this {
    this.engine.exec(sql);
    return this;
  }

  /**
   * better-sqlite3 uses `.pragma()` both as a getter and a setter. Our code
   * only uses it as a setter ("journal_mode = WAL", "foreign_keys = ON"), so
   * we just `exec()` the pragma and swallow errors — some PRAGMAs (notably
   * WAL journal mode) are not supported by node-sqlite3-wasm's VFS and error
   * here, but losing them is acceptable for 0sec's single-process workload.
   */
  pragma(query: string, _opts?: { simple?: boolean }): unknown {
    try {
      this.engine.exec(`PRAGMA ${query}`);
    } catch {
      // Silently ignore PRAGMAs the engine doesn't support (e.g. WAL on WASM).
    }
    return undefined;
  }

  /**
   * better-sqlite3's `db.transaction(fn)` returns a callable object with
   * `.deferred`, `.immediate`, `.exclusive`, and `.default` methods, each
   * running `fn` inside a BEGIN/COMMIT of the corresponding isolation level.
   * All three variants are functionally equivalent for 0sec's single-writer
   * workload, so we wire them to the same underlying implementation.
   */
  transaction<Args extends unknown[], R>(fn: (...args: Args) => R) {
    const engine = this.engine;
    const runInTx = (...args: Args): R => {
      engine.exec("BEGIN");
      try {
        const result = fn(...args);
        engine.exec("COMMIT");
        return result;
      } catch (err) {
        try {
          engine.exec("ROLLBACK");
        } catch {
          // If the rollback itself fails, surface the original error.
        }
        throw err;
      }
    };
    return Object.assign(runInTx, {
      default: runInTx,
      deferred: runInTx,
      immediate: runInTx,
      exclusive: runInTx,
    });
  }

  close(): void {
    this.engine.close();
  }

  get inTransaction(): boolean {
    return this.engine.inTransaction;
  }

  get open(): boolean {
    return this.engine.isOpen;
  }
}

/**
 * node-sqlite3-wasm engine adapter. Pure pass-through — node-sqlite3-wasm's
 * Statement already returns the row shapes RawStatement requires.
 *
 * The `require()` is lazy on purpose: node-sqlite3-wasm's module-level code
 * does `fs.readFileSync(__dirname + "/node-sqlite3-wasm.wasm")`. In a
 * `bun build --compile` binary, `__dirname` is the build host's path, so
 * loading the module on any other machine throws ENOENT. Keeping the
 * require inside this function means the WASM-loading side effect only
 * fires on the Node path, which the Bun-compiled binary never enters.
 */
function createWasmEngine(path: string): RawDatabase {
  const sqliteWasm = createRequire(import.meta.url)(
    "node-sqlite3-wasm",
  ) as typeof import("node-sqlite3-wasm");
  const { Database: WasmDatabaseCtor } = sqliteWasm;
  type WasmDatabase = InstanceType<typeof sqliteWasm.Database>;
  type WasmStatement = InstanceType<typeof sqliteWasm.Statement>;
  const wasm: WasmDatabase = new WasmDatabaseCtor(path);
  const wrapStatement = (stmt: WasmStatement): RawStatement => ({
    run: (bind) => stmt.run(bind as any) as unknown as RunResult,
    get: (bind) => {
      const row = stmt.get(bind as any);
      return row == null ? undefined : (row as Record<string, unknown>);
    },
    all: (bind) => stmt.all(bind as any) as Array<Record<string, unknown>>,
    values: (bind) => {
      // node-sqlite3-wasm has no native `.values()`; reconstruct from `.all()`.
      // Insertion order on the returned plain objects matches result-column
      // order, so Object.values() preserves it.
      const rows = stmt.all(bind as any) as Array<Record<string, unknown>>;
      return rows.map((r) => Object.values(r));
    },
  });
  return {
    prepare: (sql) => wrapStatement(wasm.prepare(sql)),
    exec: (sql) => {
      wasm.exec(sql);
    },
    close: () => wasm.close(),
    get inTransaction() {
      return wasm.inTransaction;
    },
    get isOpen() {
      return wasm.isOpen;
    },
  };
}

/**
 * bun:sqlite engine adapter. bun:sqlite is a built-in module statically
 * linked into the Bun runtime, so it has no external `.wasm` sidecar to
 * resolve at runtime — which is exactly what makes `bun build --compile`
 * binaries portable across machines.
 *
 * API alignment with better-sqlite3:
 *   - `new Database(path)`: same.
 *   - `db.exec(sql)`: same.
 *   - `db.prepare(sql)` returns a Statement with `.run/.get/.all/.values`.
 *   - `Statement.run(args)` returns `{ changes, lastInsertRowid }`.
 *   - `Statement.get(args)` returns `null` (not `undefined`) when no row
 *     matches — we normalize to `undefined` to match the WASM branch.
 *   - Named bindings accept both `@name` and bare `name` keys.
 *   - `db.inTransaction`, `db.close()`: same.
 *
 * We use `createRequire` on the special `bun:sqlite` URL so that bundlers
 * which can't statically resolve `bun:` builtins still let the binary
 * import it at runtime. Marked external in scripts/bundle-cli.mjs and
 * scripts/bun-compile.sh to keep esbuild/bun bundle from rewriting it.
 */
function createBunEngine(path: string): RawDatabase {
  // Lazy require — bun:sqlite only exists under the Bun runtime, so any
  // top-level import would crash a Node load.
  const requireFromHere = createRequire(import.meta.url);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { Database: BunDatabase } = requireFromHere("bun:sqlite") as {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    Database: any;
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const db: any = new BunDatabase(path);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const wrapStatement = (stmt: any): RawStatement => ({
    run: (bind) => {
      const r = bind === undefined ? stmt.run() : stmt.run(bind);
      return { changes: r.changes, lastInsertRowid: r.lastInsertRowid };
    },
    get: (bind) => {
      const row = bind === undefined ? stmt.get() : stmt.get(bind);
      return row == null ? undefined : (row as Record<string, unknown>);
    },
    all: (bind) =>
      (bind === undefined ? stmt.all() : stmt.all(bind)) as Array<
        Record<string, unknown>
      >,
    values: (bind) =>
      (bind === undefined ? stmt.values() : stmt.values(bind)) as unknown[][],
  });
  return {
    prepare: (sql) => wrapStatement(db.prepare(sql)),
    exec: (sql) => {
      db.exec(sql);
    },
    close: () => db.close(),
    get inTransaction() {
      return Boolean(db.inTransaction);
    },
    get isOpen() {
      // bun:sqlite doesn't expose an `isOpen` flag; treat the handle as
      // open for the lifetime of the wrapper. Callers only use this for
      // diagnostics.
      return true;
    },
  };
}

export function createShimmedDatabase(path: string): ShimmedDatabase {
  const engine = isBunRuntime() ? createBunEngine(path) : createWasmEngine(path);
  return new ShimmedDatabase(engine);
}

/**
 * Build a drizzle BaseSQLiteDatabase bound to our shimmed client. Mirrors
 * what `drizzle-orm/better-sqlite3/driver.js::construct()` does, minus the
 * top-of-file `import Client from "better-sqlite3"` that would load the
 * native binding.
 */
export function createDrizzleFromShim<
  TSchema extends Record<string, unknown>,
>(
  client: ShimmedDatabase,
  config: { schema?: TSchema } = {},
): BaseSQLiteDatabase<"sync", RunResult, TSchema> {
  const dialect = new SQLiteSyncDialect({});
  let schema: RelationalSchemaConfig<TablesRelationalConfig> | undefined;
  if (config.schema) {
    const tablesConfig = extractTablesRelationalConfig(
      config.schema,
      createTableRelationsHelpers,
    );
    schema = {
      fullSchema: config.schema,
      schema: tablesConfig.tables,
      tableNamesMap: tablesConfig.tableNamesMap,
    };
  }
  // `client` is structurally compatible with better-sqlite3's Database for
  // the methods BetterSQLiteSession actually calls (prepare, transaction).
  const session = new BetterSQLiteSession(
    client as any,
    dialect,
    schema as any,
    {},
  );
  const db = new BaseSQLiteDatabase("sync", dialect, session, schema as any);
  (db as any).$client = client;
  return db as BaseSQLiteDatabase<"sync", RunResult, TSchema>;
}
