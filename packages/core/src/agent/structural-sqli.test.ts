import { describe, it, expect } from "vitest";
import {
  fingerprintDialect,
  looksLikeSqlError,
  nextKeyPayload,
  runStructuralSqliProbe,
  type KeyPayload,
  type ProbeObservation,
} from "./structural-sqli.js";

// ── Simulated vulnerable backend ────────────────────────────────────
//
// Models an app that concatenates a JSON KEY into SQL, e.g.:
//   `SELECT ${key} FROM accounts`
// A trailing single quote in the key unbalances the statement and the DB
// emits a dialect-specific error. A key that re-closes the quote and comments
// out the tail parses cleanly. This is the exact structural surface #774
// targets — the injection is the field name, never a parameterised value.

const DIALECT_ERRORS = {
  mysql:
    "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near \"'\" at line 1",
  postgres:
    'org.postgresql.util.PSQLException: ERROR: unterminated quoted string at or near "\'"',
  mssql:
    "System.Data.SqlClient.SqlException: Unclosed quotation mark after the character string ''.",
  oracle: "ORA-01756: quoted string not properly terminated",
  sqlite: 'sqlite3.OperationalError: unrecognized token: "\'"',
} as const;

type Dialect = keyof typeof DIALECT_ERRORS;

/**
 * Build a `sendKey` oracle for a given dialect. A key is "balanced" (parses
 * cleanly) iff it contains the dialect's comment token AND ends the quote.
 * Otherwise a bare trailing quote yields the dialect error; a clean key yields
 * a normal 200.
 */
function makeOracle(dialect: Dialect) {
  const commentTokens = ["-- -", "--"];
  const calls: KeyPayload[] = [];
  const send = (payload: KeyPayload): ProbeObservation => {
    calls.push(payload);
    const key = payload.key;
    const balanced =
      key.includes("'") && commentTokens.some((c) => key.includes(c));
    const quoteCount = (key.match(/'/g) ?? []).length;
    if (balanced || quoteCount === 0 || quoteCount % 2 === 0) {
      return { responseText: '{"rows": []}', status: 200 };
    }
    // Unbalanced quote → dialect error
    return { responseText: DIALECT_ERRORS[dialect], status: 500 };
  };
  return { send, calls };
}

describe("fingerprintDialect", () => {
  it("identifies each dialect from its canonical error string", () => {
    expect(fingerprintDialect(DIALECT_ERRORS.mysql)).toBe("mysql");
    expect(fingerprintDialect(DIALECT_ERRORS.postgres)).toBe("postgres");
    expect(fingerprintDialect(DIALECT_ERRORS.mssql)).toBe("mssql");
    expect(fingerprintDialect(DIALECT_ERRORS.oracle)).toBe("oracle");
    expect(fingerprintDialect(DIALECT_ERRORS.sqlite)).toBe("sqlite");
  });

  it("returns null for a benign response", () => {
    expect(fingerprintDialect('{"rows": []}')).toBeNull();
    expect(fingerprintDialect("HTTP/1.1 200 OK")).toBeNull();
  });
});

describe("looksLikeSqlError", () => {
  it("flags generic SQL error text", () => {
    expect(looksLikeSqlError("You have an error in your SQL syntax")).toBe(true);
    expect(looksLikeSqlError("near \"foo\": syntax error")).toBe(true);
    expect(looksLikeSqlError("ORA-00933")).toBe(true);
  });

  it("does not flag benign output", () => {
    expect(looksLikeSqlError('{"ok": true}')).toBe(false);
  });
});

describe("nextKeyPayload", () => {
  it("break phase produces an unbalanced quoted key", () => {
    const p = nextKeyPayload("name", "break", null);
    expect(p.balanced).toBe(false);
    expect(p.key).toBe("name'");
  });

  it("balance phase refines the comment token to the known dialect", () => {
    const mysql = nextKeyPayload("name", "balance", "mysql");
    expect(mysql.balanced).toBe(true);
    expect(mysql.key).toBe("name'-- -"); // MySQL needs the space variant

    const pg = nextKeyPayload("name", "balance", "postgres");
    expect(pg.key).toBe("name'--");
  });

  it("balance phase falls back to quote-doubling when dialect unknown", () => {
    const p = nextKeyPayload("name", "balance", null);
    expect(p.balanced).toBe(true);
    expect(p.key).toBe("name''");
  });
});

describe("runStructuralSqliProbe — blind error-iteration loop", () => {
  it("confirms structural SQLi and records the dialect for MySQL", () => {
    const oracle = makeOracle("mysql");
    const result = runStructuralSqliProbe({ baseKey: "name" }, oracle.send);

    expect(result.verdict).toBe("confirmed");
    expect(result.dialect).toBe("mysql");
    // The trail must show the refinement: an error_signal step then a
    // confirmed step.
    const verdicts = result.trail.map((s) => s.verdict);
    expect(verdicts).toContain("error_signal");
    expect(verdicts[verdicts.length - 1]).toBe("confirmed");
  });

  it("confirms and fingerprints across all dialects", () => {
    for (const dialect of Object.keys(DIALECT_ERRORS) as Dialect[]) {
      const oracle = makeOracle(dialect);
      const result = runStructuralSqliProbe(
        { baseKey: "sort_field" },
        oracle.send,
      );
      expect(result.verdict, `dialect ${dialect}`).toBe("confirmed");
      expect(result.dialect, `dialect ${dialect}`).toBe(dialect);
    }
  });

  it("refines from a wrong first dialect guess to the right close", () => {
    // Oracle that errors on the broken key with a MySQL error, but ONLY
    // accepts the MySQL space-comment as balanced. The loop must fingerprint
    // mysql from the error and pick "-- -" on the balance step.
    const calls: KeyPayload[] = [];
    const send = (payload: KeyPayload): ProbeObservation => {
      calls.push(payload);
      const balanced = payload.key.includes("'-- -");
      if (balanced) return { responseText: '{"rows": []}', status: 200 };
      const quoteCount = (payload.key.match(/'/g) ?? []).length;
      if (quoteCount % 2 === 1) {
        return { responseText: DIALECT_ERRORS.mysql, status: 500 };
      }
      // Even quotes but not the right comment → still a syntax error here.
      return { responseText: DIALECT_ERRORS.mysql, status: 500 };
    };

    const result = runStructuralSqliProbe(
      { baseKey: "col", maxIterations: 8 },
      send,
    );
    expect(result.verdict).toBe("confirmed");
    expect(result.dialect).toBe("mysql");
    // A balanced payload using the MySQL comment must appear in the trail.
    expect(result.trail.some((s) => s.payload.key.includes("'-- -"))).toBe(true);
  });

  it("returns exhausted for a non-injectable (parameterised) surface", () => {
    // A safe backend: the key is bound as a parameter, so a trailing quote is
    // just data — never a SQL error.
    const send = (): ProbeObservation => ({
      responseText: '{"rows": [], "note": "no such field"}',
      status: 200,
    });
    const result = runStructuralSqliProbe(
      { baseKey: "name", maxIterations: 4 },
      send,
    );
    expect(result.verdict).toBe("exhausted");
    expect(result.dialect).toBeNull();
  });

  it("is bounded by maxIterations", () => {
    let count = 0;
    const send = (): ProbeObservation => {
      count++;
      // Always errors on broken key but never accepts a balanced close, so
      // the loop can never confirm and must hit the cap.
      return { responseText: DIALECT_ERRORS.postgres, status: 500 };
    };
    const result = runStructuralSqliProbe(
      { baseKey: "x", maxIterations: 5 },
      send,
    );
    expect(count).toBeLessThanOrEqual(5);
    expect(result.trail.length).toBeLessThanOrEqual(5);
    // It saw errors but could never balance → error_signal, not confirmed.
    expect(result.verdict).toBe("error_signal");
  });
});
