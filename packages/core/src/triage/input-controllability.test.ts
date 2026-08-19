import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import type { AttackCategory, Finding } from "@0sec/shared";

import {
  analyzeInputControllability,
  extractTaintedParam,
  controllabilityDowngradeTarget,
} from "./input-controllability.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "ctrl-test",
    templateId: "audit-sink",
    title: "Potential SQL injection",
    description: "A SQL sink was flagged",
    severity: "medium",
    category: "sql-injection" as AttackCategory,
    status: "discovered",
    evidence: { request: "", response: "" },
    confidence: 0.7,
    timestamp: Date.now(),
    ...overrides,
  };
}

let root: string;

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "0sec-ctrl-"));
});

afterEach(() => {
  try {
    rmSync(root, { recursive: true, force: true });
  } catch {
    // ignore
  }
});

function write(relPath: string, content: string): void {
  const abs = join(root, relPath);
  const dirEnd = abs.lastIndexOf("/");
  if (dirEnd > 0) mkdirSync(abs.slice(0, dirEnd), { recursive: true });
  writeFileSync(abs, content, "utf8");
}

// ── realistic fixtures mirroring the prod Sequelize findings ──────────

const SEQUELIZE_DIALECT_SINK = `
'use strict';
class MySQLQueryGenerator extends AbstractQueryGenerator {
  removeColumnQuery(tableName, attributeName) {
    // BUG: attributeName concatenated without quoteIdentifier
    return 'ALTER TABLE ' + this.quoteTable(tableName) +
      ' DROP COLUMN ' + attributeName + ';';
  }
  addConstraintQuery(tableName, constraintName, onDelete) {
    return 'ALTER TABLE ' + this.quoteTable(tableName) +
      ' ADD CONSTRAINT ' + constraintName + ' ON DELETE ' + onDelete;
  }
}
module.exports = MySQLQueryGenerator;
`;

const APP_ROUTE_SINK = `
const express = require('express');
const router = express.Router();
const db = require('../db');

router.get('/search', async (req, res) => {
  const term = req.query.term;
  // BUG: req.query.term concatenated straight into SQL
  const rows = await db.raw('SELECT * FROM products WHERE name = ' + term);
  res.json(rows);
});

module.exports = router;
`;

describe("extractTaintedParam", () => {
  it("pulls the identifier param named in backticks", () => {
    const f = makeFinding({
      title: "MSSQL removeColumn SQL injection via unescaped `attributeName`",
    });
    expect(extractTaintedParam(f)).toBe("attributeName");
  });

  it("pulls an identifier param from prose", () => {
    const f = makeFinding({
      description: "The dialect concatenates an unescaped constraintName into the DDL.",
    });
    expect(extractTaintedParam(f)?.toLowerCase()).toBe("constraintname");
  });

  it("returns null when no identifier param is mentioned", () => {
    const f = makeFinding({ description: "some unrelated prose about a value" });
    expect(extractTaintedParam(f)).toBeNull();
  });
});

describe("analyzeInputControllability — internal identifier (downgrade path)", () => {
  it("classifies an ORM dialect identifier-injection as internal-identifier", () => {
    write("lib/dialects/mysql/query-generator.js", SEQUELIZE_DIALECT_SINK);
    const f = makeFinding({
      title: "MySQL removeColumn SQL injection via unescaped attributeName",
      description:
        "lib/dialects/mysql/query-generator.js:5 concatenates attributeName into ALTER TABLE.",
      evidence: {
        request: "lib/dialects/mysql/query-generator.js:5",
        response: "DROP COLUMN ' + attributeName",
        analysis: "attributeName is passed via QueryInterface.removeColumn",
      },
    });
    const res = analyzeInputControllability(f, root);
    expect(res.controllability).toBe("internal-identifier");
    expect(res.confidence).toBeGreaterThanOrEqual(0.75);
    expect(res.ormInternal).toBe(true);
    expect(res.taintedParam?.toLowerCase()).toBe("attributename");
    expect(res.evidence.join(" ")).toMatch(/orm/i);
  });

  it("uses AST-extracted identifier params when the finding text is vague", () => {
    write("src/query/query-interface.ts", SEQUELIZE_DIALECT_SINK);
    const f = makeFinding({
      title: "SQL injection in query generation",
      description: "src/query/query-interface.ts builds DDL by string concatenation.",
    });
    const res = analyzeInputControllability(f, root);
    expect(res.controllability).toBe("internal-identifier");
    // tableName / attributeName / constraintName / onDelete are all identifier params
    expect(res.taintedParam).not.toBeNull();
  });
});

describe("analyzeInputControllability — untrusted input (protect path)", () => {
  it("never downgrades a sink that reads req.query", () => {
    write("routes/search.js", APP_ROUTE_SINK);
    const f = makeFinding({
      title: "SQL injection via req.query.term",
      description: "routes/search.js:8 concatenates req.query.term into a SELECT.",
    });
    const res = analyzeInputControllability(f, root);
    expect(res.controllability).toBe("untrusted-input");
    expect(res.evidence.join(" ")).toMatch(/untrusted/i);
  });

  it("protects even an ORM-pathed file if it reads untrusted input", () => {
    // Adversarial: ORM-looking path but actually wires req.body into SQL.
    write(
      "lib/dialects/custom/query-generator.js",
      `class QueryGenerator {
         build(req) { return 'SELECT * WHERE x = ' + req.body.x; }
       }`,
    );
    const f = makeFinding({
      title: "SQL injection via tableName",
      description: "lib/dialects/custom/query-generator.js concatenates tableName",
    });
    const res = analyzeInputControllability(f, root);
    expect(res.controllability).toBe("untrusted-input");
  });
});

describe("analyzeInputControllability — unknown (no action)", () => {
  it("returns unknown for non-analyzable categories", () => {
    write("lib/dialects/mysql/query-generator.js", SEQUELIZE_DIALECT_SINK);
    const f = makeFinding({
      category: "xss" as AttackCategory,
      description: "lib/dialects/mysql/query-generator.js",
    });
    const res = analyzeInputControllability(f, root);
    expect(res.controllability).toBe("unknown");
    expect(res.confidence).toBe(0);
  });

  it("returns unknown when the sink file cannot be resolved", () => {
    const f = makeFinding({ description: "no file hints here" });
    const res = analyzeInputControllability(f, root);
    expect(res.controllability).toBe("unknown");
  });

  it("returns unknown for non-JS/TS sinks (e.g. .py)", () => {
    write("app/db.py", "def q(table):\n    return 'DROP ' + table\n");
    const f = makeFinding({
      description: "app/db.py concatenates table identifier into SQL",
    });
    const res = analyzeInputControllability(f, root);
    expect(res.controllability).toBe("unknown");
  });

  it("returns unknown for an ORM file with no identifier signal", () => {
    write(
      "lib/dialects/mysql/query-generator.js",
      `class QueryGenerator { ping() { return 'SELECT 1'; } }`,
    );
    const f = makeFinding({
      title: "SQL injection",
      description: "lib/dialects/mysql/query-generator.js flagged",
    });
    const res = analyzeInputControllability(f, root);
    expect(res.controllability).toBe("unknown");
  });
});

describe("controllabilityDowngradeTarget — assume-FP-safe tiering", () => {
  it("drops medium to low", () => {
    expect(controllabilityDowngradeTarget("medium", 0.8)).toBe("low");
  });

  it("never changes severity below the 0.75 confidence floor", () => {
    expect(controllabilityDowngradeTarget("medium", 0.74)).toBeNull();
    expect(controllabilityDowngradeTarget("high", 0.74)).toBeNull();
  });

  it("only drops high to low at high confidence", () => {
    expect(controllabilityDowngradeTarget("high", 0.78)).toBeNull();
    expect(controllabilityDowngradeTarget("high", 0.8)).toBe("low");
  });

  it("never nukes critical below medium, and only at very high confidence", () => {
    expect(controllabilityDowngradeTarget("critical", 0.8)).toBeNull();
    expect(controllabilityDowngradeTarget("critical", 0.85)).toBe("medium");
  });

  it("leaves already-low / info findings unchanged (annotate only)", () => {
    expect(controllabilityDowngradeTarget("low", 0.99)).toBeNull();
    expect(controllabilityDowngradeTarget("info", 0.99)).toBeNull();
  });
});

describe("analyzeInputControllability — prod FP-reduction proof", () => {
  // Mirrors the real Sequelize audit scan (275f21b4…) that produced ~26
  // ORM-internal identifier-injection findings. We rebuild a dialect tree and
  // run the actual prod finding titles/locations through the analyzer, proving
  // the identifier-injection family downgrades while a genuine req-input SQLi is
  // protected — and that NOTHING is classified in a way that would drop it.
  beforeEach(() => {
    write("lib/dialects/mysql/query-generator.js", SEQUELIZE_DIALECT_SINK);
    write("lib/dialects/mssql/query-generator.js", SEQUELIZE_DIALECT_SINK);
    write("lib/dialects/db2/query-generator.js", SEQUELIZE_DIALECT_SINK);
    write("lib/dialects/oracle/query-generator.js", SEQUELIZE_DIALECT_SINK);
    write("lib/dialects/abstract/query-interface.js", SEQUELIZE_DIALECT_SINK);
    write("app/routes/report.js", APP_ROUTE_SINK);
  });

  const ormFindings: Array<{ title: string; file: string }> = [
    {
      title: "MSSQL removeColumn SQL injection via unescaped attributeName",
      file: "lib/dialects/mssql/query-generator.js",
    },
    {
      title: "MySQL QueryInterface.removeColumn builds injectable foreign key constraintName",
      file: "lib/dialects/mysql/query-generator.js",
    },
    {
      title: "DB2 dialect reorg retry injects unescaped table name into ALTER",
      file: "lib/dialects/db2/query-generator.js",
    },
    {
      title: "Oracle query generator allows raw SQL injection through unvalidated onDelete",
      file: "lib/dialects/oracle/query-generator.js",
    },
    {
      title: "Sequelize addIndexQuery concatenates untrusted index operator",
      file: "lib/dialects/abstract/query-interface.js",
    },
  ];

  it("downgrades the ORM identifier-injection family (FP reduction), never drops", () => {
    let downgraded = 0;
    for (const tc of ormFindings) {
      const f = makeFinding({
        severity: "medium",
        title: tc.title,
        description: `${tc.file}:5 concatenates the identifier into generated SQL`,
        evidence: { request: `${tc.file}:5`, response: "", analysis: tc.title },
      });
      const res = analyzeInputControllability(f, root);
      // assume-FP-safe: the worst outcome here is a downgrade, never "drop".
      expect(["internal-identifier", "unknown"]).toContain(res.controllability);
      if (res.controllability === "internal-identifier") {
        expect(res.confidence).toBeGreaterThanOrEqual(0.75);
        downgraded++;
      }
    }
    // The whole point of #658: the bulk of this family is recognized and de-noised.
    expect(downgraded).toBeGreaterThanOrEqual(4);
  });

  it("does NOT downgrade a genuine attacker-controlled SQLi (no true-positive loss)", () => {
    const f = makeFinding({
      severity: "high",
      title: "SQL injection via req.query in report route",
      description: "app/routes/report.js builds SQL from req.query.term",
    });
    const res = analyzeInputControllability(f, root);
    expect(res.controllability).toBe("untrusted-input");
  });
});

describe("analyzeInputControllability — robustness", () => {
  it("does not throw on unparseable source (returns a verdict)", () => {
    write("lib/dialects/mysql/query-generator.js", "class { this is not valid <<< js");
    const f = makeFinding({
      title: "SQL injection via attributeName",
      description: "lib/dialects/mysql/query-generator.js attributeName",
    });
    expect(() => analyzeInputControllability(f, root)).not.toThrow();
  });

  it("treats a substring of req.body inside a string literal precisely (AST, not grep)", () => {
    // 'req.body' only appears inside a comment/string — AST must NOT flag it as
    // an untrusted property access. This is an ORM identifier sink.
    write(
      "lib/dialects/pg/query-generator.js",
      `class PgQueryGenerator extends AbstractQueryGenerator {
         // historically this used req.body but now takes a tableName arg
         removeColumnQuery(tableName, columnName) {
           return 'ALTER TABLE ' + tableName + ' DROP ' + columnName;
         }
       }`,
    );
    const f = makeFinding({
      title: "Postgres removeColumn SQL injection via unescaped columnName",
      description: "lib/dialects/pg/query-generator.js concatenates columnName",
    });
    const res = analyzeInputControllability(f, root);
    expect(res.controllability).toBe("internal-identifier");
  });
});
