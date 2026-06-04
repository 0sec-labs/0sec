/**
 * Structural / JSON-key SQL injection probe (#774, part of #763).
 *
 * The "structural" SQLi vector is injection where the injectable surface is a
 * JSON **key / field name** that the backend concatenates into a SQL statement
 * (e.g. `SELECT <key> FROM ...`, `ORDER BY <key>`, `... WHERE <key> = ?`),
 * NOT a parameterised value. Scanners that only fuzz JSON *values* (ZAP, most
 * commercial DAST) miss it entirely — the "McKinsey vector" referenced in the
 * issue. Values are usually parameterised; keys almost never are.
 *
 * Because the surface is blind (no reflected output), confirmation is driven
 * by an **error-message feedback loop**: each iteration mutates the injected
 * key, the response (often a DB error string) is fingerprinted, and the next
 * payload is *refined* toward the dialect the error reveals. This module is the
 * pure, deterministic core of that loop — no network, no LLM. The agent feeds
 * it observed response bodies; it returns the next payload to try and a verdict.
 *
 * Verification-oriented: a verdict is only `confirmed` when a payload that is
 * expected to be syntactically valid produces NO error while a deliberately
 * broken sibling DID — i.e. the key is being parsed as SQL, not as data. This
 * is authorized tooling for 0sec's own pentest product.
 */

export type SqlDialect = "mysql" | "postgres" | "mssql" | "oracle" | "sqlite";

export type ProbeVerdict =
  /** Keep iterating — not enough signal yet. */
  | "iterate"
  /** A DB error fingerprint proves the key reaches a SQL parser. */
  | "error_signal"
  /** Differential proof: broken key errored, balanced key did not. Confirmed. */
  | "confirmed"
  /** Budget exhausted with no SQL signal — surface looks non-injectable. */
  | "exhausted";

/** One observed (payload → response) pair fed back into the loop. */
export interface ProbeObservation {
  /** The JSON key that was injected on this iteration. */
  payloadKey: string;
  /** Raw response body / error text the target returned. */
  responseText: string;
  /** HTTP status, if the caller has it (used only as a weak tiebreaker). */
  status?: number;
}

/** A candidate JSON-key payload the loop wants the agent to send next. */
export interface KeyPayload {
  /** The literal JSON key to place in the request body. */
  key: string;
  /**
   * Whether this payload is *expected* to keep the SQL statement syntactically
   * valid (balanced). The differential between a balanced and an unbalanced
   * payload is what confirms structural injection.
   */
  balanced: boolean;
  /** Human-readable note for the iteration trail. */
  note: string;
}

// ── DB error fingerprints ───────────────────────────────────────────
//
// Ordered most-specific-first. Each entry maps a regex over the response body
// to the dialect it reveals. Kept deliberately tight to avoid false dialect
// guesses that would send the refinement loop down the wrong branch.

interface DialectFingerprint {
  dialect: SqlDialect;
  patterns: RegExp[];
}

const FINGERPRINTS: DialectFingerprint[] = [
  {
    dialect: "mysql",
    patterns: [
      /You have an error in your SQL syntax/i,
      /\bMySQL\b/i,
      /MariaDB/i,
      /com\.mysql\.jdbc/i,
      /Unknown column '[^']*' in '[^']*'/i,
      /check the manual that corresponds to your (?:MySQL|MariaDB)/i,
    ],
  },
  {
    dialect: "postgres",
    patterns: [
      /PostgreSQL/i,
      /\bpg_[a-z]+/i,
      /org\.postgresql\.util\.PSQLException/i,
      /column "[^"]*" does not exist/i,
      /unterminated quoted string at or near/i,
      /syntax error at or near/i,
    ],
  },
  {
    dialect: "mssql",
    patterns: [
      /Microsoft SQL Server/i,
      /System\.Data\.SqlClient\.SqlException/i,
      /Unclosed quotation mark after the character string/i,
      /Invalid column name '[^']*'/i,
      /Incorrect syntax near/i,
      /\bODBC SQL Server Driver\b/i,
    ],
  },
  {
    dialect: "oracle",
    patterns: [
      /ORA-\d{5}/i,
      /Oracle error/i,
      /quoted string not properly terminated/i,
      /oracle\.jdbc/i,
    ],
  },
  {
    dialect: "sqlite",
    patterns: [
      /SQLite3?::/i,
      /sqlite3?\.OperationalError/i,
      /no such column:/i,
      /unrecognized token:/i,
      /near "[^"]*": syntax error/i,
    ],
  },
];

/**
 * Inspect a response body for a DB error that reveals the SQL dialect.
 * Returns the matched dialect, or `null` if no recognised DB error is present.
 *
 * Requires a single confident pattern hit; the patterns are specific enough
 * that one match is reliable (unlike value-fuzz heuristics).
 */
export function fingerprintDialect(responseText: string): SqlDialect | null {
  for (const fp of FINGERPRINTS) {
    for (const re of fp.patterns) {
      if (re.test(responseText)) return fp.dialect;
    }
  }
  return null;
}

/**
 * Generic "this looks like a SQL parser choked" signal, independent of which
 * dialect. Used to decide whether a key reaches SQL at all before a dialect is
 * pinned down.
 */
const GENERIC_SQL_ERROR = [
  /SQL syntax/i,
  /syntax error/i,
  /unterminated/i,
  /unclosed quotation/i,
  /quoted string not properly terminated/i,
  /unrecognized token/i,
  /unknown column/i,
  /no such column/i,
  /column .* does not exist/i,
  /invalid column name/i,
  /near .*: syntax error/i,
  /ORA-\d{5}/i,
];

export function looksLikeSqlError(responseText: string): boolean {
  return GENERIC_SQL_ERROR.some((re) => re.test(responseText));
}

// ── Per-dialect payload refinement ──────────────────────────────────
//
// Once a dialect is known we can pick the comment/quote syntax that keeps a
// statement balanced for THAT engine, which is the load-bearing refinement.

interface DialectSyntax {
  /** Line-comment token used to neutralise the rest of the statement. */
  comment: string;
  /** A concatenation expression valid in the dialect (key-position safe). */
  balancedExpr: (base: string) => string;
}

const DIALECT_SYNTAX: Record<SqlDialect, DialectSyntax> = {
  // MySQL/MariaDB require a space (or newline) after `-- ` to start a comment.
  mysql: { comment: "-- -", balancedExpr: (b) => `${b}` },
  postgres: { comment: "--", balancedExpr: (b) => `${b}` },
  mssql: { comment: "--", balancedExpr: (b) => `${b}` },
  oracle: { comment: "--", balancedExpr: (b) => `${b}` },
  sqlite: { comment: "--", balancedExpr: (b) => `${b}` },
};

/**
 * Build the next key payload to try, given the base field name and what the
 * loop knows so far. When a dialect is known, the balancing payload uses that
 * dialect's comment syntax (the refinement); otherwise a dialect-agnostic
 * probe pair is used.
 *
 * `phase`:
 *   - "break"   → a deliberately broken key (single trailing quote) meant to
 *                 elicit a DB error and reveal the dialect.
 *   - "balance" → a key that re-closes the quote / comments out the tail so a
 *                 *correctly parsed* SQL statement is produced. If this stops
 *                 erroring while "break" errored, injection is structural.
 */
export function nextKeyPayload(
  baseKey: string,
  phase: "break" | "balance",
  dialect: SqlDialect | null,
): KeyPayload {
  if (phase === "break") {
    return {
      key: `${baseKey}'`,
      balanced: false,
      note: `unbalanced quote on key "${baseKey}" to elicit a DB error`,
    };
  }
  // phase === "balance"
  if (dialect) {
    const syntax = DIALECT_SYNTAX[dialect];
    return {
      key: `${baseKey}'${syntax.comment}`,
      balanced: true,
      note: `re-balanced key for ${dialect} using "${syntax.comment}" comment`,
    };
  }
  // Dialect unknown: use a quote-doubling close that is broadly valid.
  return {
    key: `${baseKey}''`,
    balanced: true,
    note: `dialect-agnostic quote-balancing close on key "${baseKey}"`,
  };
}

// ── The blind-iteration refinement loop ─────────────────────────────

export interface ProbeStep {
  iteration: number;
  /** Payload sent this step. */
  payload: KeyPayload;
  /** Dialect fingerprinted from the response, if any. */
  dialect: SqlDialect | null;
  /** Whether the response carried a generic SQL error signal. */
  sqlError: boolean;
  verdict: ProbeVerdict;
  note: string;
}

export interface ProbeResult {
  baseKey: string;
  verdict: ProbeVerdict;
  dialect: SqlDialect | null;
  /** Full ordered trail for the finding evidence. */
  trail: ProbeStep[];
}

export interface ProbeConfig {
  /** Field name being probed (the JSON key). */
  baseKey: string;
  /** Hard cap on iterations so the loop is always bounded. */
  maxIterations?: number;
}

/**
 * Drive the structural-SQLi refinement loop against an injected oracle.
 *
 * `sendKey` is supplied by the caller (the agent / a test). Given a payload it
 * returns the observed response text + status. This module owns ONLY the
 * decision logic: which payload to send next and when to declare a verdict.
 *
 * Flow:
 *   1. Send a broken key (trailing quote). If it errors, the key reaches SQL.
 *      Fingerprint the dialect from the error → `error_signal`.
 *   2. Send a balanced key using the discovered dialect's comment syntax.
 *      If THAT response no longer errors, the statement parsed cleanly →
 *      differential `confirmed`.
 *   3. If the broken key never errors within budget → `exhausted`
 *      (surface is not concatenating the key into SQL).
 */
export function runStructuralSqliProbe(
  config: ProbeConfig,
  sendKey: (payload: KeyPayload) => ProbeObservation,
): ProbeResult {
  const baseKey = config.baseKey;
  const maxIterations = Math.max(2, config.maxIterations ?? 6);
  const trail: ProbeStep[] = [];

  let dialect: SqlDialect | null = null;
  let sawBreakError = false;
  let iteration = 0;

  while (iteration < maxIterations) {
    iteration++;

    // Alternate: while we have not yet seen the broken key error, keep
    // breaking (and refining the broken key per dialect once known). Once a
    // break error is observed, switch to a balanced payload to get the
    // differential confirmation.
    const phase: "break" | "balance" = sawBreakError ? "balance" : "break";
    const payload = nextKeyPayload(baseKey, phase, dialect);
    const obs = sendKey(payload);

    const observedDialect = fingerprintDialect(obs.responseText);
    if (observedDialect) dialect = observedDialect;
    const sqlError = looksLikeSqlError(obs.responseText);

    let verdict: ProbeVerdict = "iterate";
    let note = payload.note;

    if (phase === "break") {
      if (sqlError) {
        sawBreakError = true;
        verdict = "error_signal";
        note = dialect
          ? `broken key triggered a ${dialect} SQL error — key reaches the parser`
          : `broken key triggered a SQL error (dialect not yet pinned)`;
      } else {
        verdict = "iterate";
        note = `broken key produced no SQL error — keep probing`;
      }
    } else {
      // balance phase — the differential check
      if (!sqlError) {
        verdict = "confirmed";
        note = dialect
          ? `balanced ${dialect} key parsed cleanly while broken key errored — structural SQLi confirmed`
          : `balanced key parsed cleanly while broken key errored — structural SQLi confirmed`;
      } else {
        // Still erroring even when balanced: our close was wrong (maybe wrong
        // dialect guess). Stay in the loop; next break iteration may refine
        // the dialect. Drop back to breaking.
        sawBreakError = false;
        verdict = "iterate";
        note = `balanced close still errored — refining dialect/syntax`;
      }
    }

    trail.push({ iteration, payload, dialect, sqlError, verdict, note });

    if (verdict === "confirmed") {
      return { baseKey, verdict, dialect, trail };
    }
  }

  // Loop ended without confirmation. If we ever saw a SQL error the surface is
  // at least reachable (error_signal); otherwise it is exhausted/non-injectable.
  const finalVerdict: ProbeVerdict = sawBreakError ? "error_signal" : "exhausted";
  return { baseKey, verdict: finalVerdict, dialect, trail };
}

/**
 * Async sibling of {@link runStructuralSqliProbe} for driving the loop over
 * real HTTP from the agent tool layer (`structural_sqli_probe`). The decision
 * logic is byte-identical — only `sendKey` is awaited — so the sync version
 * (used by the skill methodology + its unit tests) stays untouched. A parity
 * test pins the two against the same oracle sequence.
 */
export async function runStructuralSqliProbeAsync(
  config: ProbeConfig,
  sendKey: (payload: KeyPayload) => Promise<ProbeObservation>,
): Promise<ProbeResult> {
  const baseKey = config.baseKey;
  const maxIterations = Math.max(2, config.maxIterations ?? 6);
  const trail: ProbeStep[] = [];

  let dialect: SqlDialect | null = null;
  let sawBreakError = false;
  let iteration = 0;

  while (iteration < maxIterations) {
    iteration++;
    const phase: "break" | "balance" = sawBreakError ? "balance" : "break";
    const payload = nextKeyPayload(baseKey, phase, dialect);
    const obs = await sendKey(payload);

    const observedDialect = fingerprintDialect(obs.responseText);
    if (observedDialect) dialect = observedDialect;
    const sqlError = looksLikeSqlError(obs.responseText);

    let verdict: ProbeVerdict = "iterate";
    let note = payload.note;

    if (phase === "break") {
      if (sqlError) {
        sawBreakError = true;
        verdict = "error_signal";
        note = dialect
          ? `broken key triggered a ${dialect} SQL error — key reaches the parser`
          : `broken key triggered a SQL error (dialect not yet pinned)`;
      } else {
        verdict = "iterate";
        note = `broken key produced no SQL error — keep probing`;
      }
    } else {
      if (!sqlError) {
        verdict = "confirmed";
        note = dialect
          ? `balanced ${dialect} key parsed cleanly while broken key errored — structural SQLi confirmed`
          : `balanced key parsed cleanly while broken key errored — structural SQLi confirmed`;
      } else {
        sawBreakError = false;
        verdict = "iterate";
        note = `balanced close still errored — refining dialect/syntax`;
      }
    }

    trail.push({ iteration, payload, dialect, sqlError, verdict, note });

    if (verdict === "confirmed") {
      return { baseKey, verdict, dialect, trail };
    }
  }

  const finalVerdict: ProbeVerdict = sawBreakError ? "error_signal" : "exhausted";
  return { baseKey, verdict: finalVerdict, dialect, trail };
}
