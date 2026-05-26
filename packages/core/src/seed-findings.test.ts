import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  GEMMAFORGE_LEADS_SCHEMA,
  parseSeedFindings,
  readSeedFindings,
} from "./seed-findings.js";

function gemmaforgeLead(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    schema: GEMMAFORGE_LEADS_SCHEMA,
    file: "src/router.js",
    start_line: 38,
    end_line: 52,
    snippet: "db.query('SELECT * FROM users WHERE id=' + req.params.id)",
    gemmaforge_confidence: 0.93,
    gemmaforge_top_cwe: "CWE-89",
    gemmaforge_layer: 17,
    model_id: "google/gemma-4-E2B-it",
    rank: 0,
    ...extra,
  });
}

describe("parseSeedFindings", () => {
  it("parses a single gemmaforge.leads/v1 record", () => {
    const seeds = parseSeedFindings(gemmaforgeLead());
    expect(seeds).toHaveLength(1);
    const s = seeds[0]!;
    expect(s.file).toBe("src/router.js");
    expect(s.startLine).toBe(38);
    expect(s.endLine).toBe(52);
    expect(s.cwe).toBe("CWE-89");
    expect(s.confidence).toBe(0.93);
    expect(s.source).toBe("gemmaforge");
  });

  it("preserves producer-specific fields under metadata", () => {
    const [s] = parseSeedFindings(gemmaforgeLead());
    expect(s!.metadata?.gemmaforge_layer).toBe(17);
    expect(s!.metadata?.model_id).toBe("google/gemma-4-E2B-it");
    expect(s!.metadata?.rank).toBe(0);
  });

  it("accepts pwnkit-native field names (startLine/endLine)", () => {
    const ndjson = JSON.stringify({
      file: "x.py",
      startLine: 10,
      endLine: 14,
      snippet: "exec(req.q)",
      cwe: "CWE-78",
      confidence: 0.8,
      source: "manual",
    });
    const [s] = parseSeedFindings(ndjson);
    expect(s!.startLine).toBe(10);
    expect(s!.cwe).toBe("CWE-78");
    expect(s!.source).toBe("manual");
  });

  it("skips blank lines and invalid JSON rather than aborting", () => {
    const ndjson = [
      "",
      "not json",
      gemmaforgeLead(),
      "",
      gemmaforgeLead({ file: "second.js" }),
    ].join("\n");
    const seeds = parseSeedFindings(ndjson);
    expect(seeds).toHaveLength(2);
    expect(seeds[1]!.file).toBe("second.js");
  });

  it("drops records missing required fields", () => {
    const ndjson = [
      JSON.stringify({ file: "x.py" }), // no snippet, no lines
      gemmaforgeLead(),
    ].join("\n");
    const seeds = parseSeedFindings(ndjson);
    expect(seeds).toHaveLength(1);
    expect(seeds[0]!.file).toBe("src/router.js");
  });

  it("uses explicit source over schema-derived source", () => {
    const ndjson = JSON.stringify({
      schema: GEMMAFORGE_LEADS_SCHEMA,
      file: "x.py", start_line: 1, end_line: 5,
      snippet: "code", source: "manual-override",
    });
    const [s] = parseSeedFindings(ndjson);
    expect(s!.source).toBe("manual-override");
  });

  it("falls back to defaultSource when nothing identifies the producer", () => {
    const ndjson = JSON.stringify({
      file: "x.py", start_line: 1, end_line: 5, snippet: "code",
    });
    const [s] = parseSeedFindings(ndjson, { defaultSource: "operator" });
    expect(s!.source).toBe("operator");
  });
});

describe("readSeedFindings", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "pwnkit-seed-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("reads from a file path", () => {
    const file = join(dir, "leads.jsonl");
    writeFileSync(file, gemmaforgeLead() + "\n");
    const seeds = readSeedFindings(file);
    expect(seeds).toHaveLength(1);
    expect(seeds[0]!.source).toBe("gemmaforge");
  });
});
