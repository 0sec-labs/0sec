/**
 * Tests for unsafe-deser-detector.ts
 *
 * Each detector has positive fixtures (real sink → flagged) and negative
 * fixtures (safe / literal usage → NOT flagged) so the precision gates that
 * keep FP volume down are pinned by tests.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  detectPythonPickle,
  detectPythonUnsafeYaml,
  detectNodeInsecureDeserialize,
  detectDynamicCodeExec,
  scanSourceForUnsafeDeser,
  scanForUnsafeDeser,
} from "./unsafe-deser-detector.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), "unsafe-deser-test-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function writeSource(rel: string, content: string): string {
  const abs = join(tmp, rel);
  const parent = abs.slice(0, abs.lastIndexOf("/"));
  mkdirSync(parent, { recursive: true });
  writeFileSync(abs, content);
  return abs;
}

// ────────────────────────────────────────────────────────────────────
// Detector 1 — Python pickle / marshal / dill / shelve
// ────────────────────────────────────────────────────────────────────

describe("detectPythonPickle", () => {
  it("flags pickle.loads of request bytes", () => {
    const hits = detectPythonPickle(`obj = pickle.loads(request.body)`);
    expect(hits).toHaveLength(1);
    expect(hits[0].templateId).toBe("deser-python-pickle");
    expect(hits[0].severity).toBe("critical");
    expect(hits[0].category).toBe("unsafe-deserialization");
  });

  it("flags cPickle.load, marshal.loads, dill.loads", () => {
    expect(detectPythonPickle(`x = cPickle.load(f)`)).toHaveLength(1);
    expect(detectPythonPickle(`x = marshal.loads(blob)`)).toHaveLength(1);
    expect(detectPythonPickle(`x = dill.loads(blob)`)).toHaveLength(1);
  });

  it("flags shelve.open (pickle-backed) with a shelve-specific title", () => {
    const hits = detectPythonPickle(`db = shelve.open("cache.db")`);
    expect(hits).toHaveLength(1);
    expect(hits[0].title).toContain("shelve");
  });

  it("does NOT flag json.loads or a pickle import line", () => {
    expect(detectPythonPickle(`data = json.loads(body)`)).toHaveLength(0);
    expect(detectPythonPickle(`import pickle`)).toHaveLength(0);
  });

  it("does NOT flag a comment mentioning pickle.loads", () => {
    expect(detectPythonPickle(`# never call pickle.loads(x) on user input`)).toHaveLength(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// Detector 2 — Python unsafe YAML
// ────────────────────────────────────────────────────────────────────

describe("detectPythonUnsafeYaml", () => {
  it("flags bare yaml.load(...)", () => {
    const hits = detectPythonUnsafeYaml(`cfg = yaml.load(stream)`);
    expect(hits).toHaveLength(1);
    expect(hits[0].templateId).toBe("deser-python-unsafe-yaml");
    expect(hits[0].severity).toBe("high");
  });

  it("flags yaml.unsafe_load and yaml.full_load with higher confidence", () => {
    const a = detectPythonUnsafeYaml(`cfg = yaml.unsafe_load(stream)`);
    const b = detectPythonUnsafeYaml(`cfg = yaml.full_load(stream)`);
    expect(a).toHaveLength(1);
    expect(b).toHaveLength(1);
    expect(a[0].confidence).toBeGreaterThan(0.8);
  });

  it("does NOT flag yaml.safe_load", () => {
    expect(detectPythonUnsafeYaml(`cfg = yaml.safe_load(stream)`)).toHaveLength(0);
  });

  it("does NOT flag yaml.load with an explicit SafeLoader", () => {
    expect(
      detectPythonUnsafeYaml(`cfg = yaml.load(stream, Loader=yaml.SafeLoader)`),
    ).toHaveLength(0);
    expect(
      detectPythonUnsafeYaml(`cfg = yaml.load(stream, Loader=yaml.BaseLoader)`),
    ).toHaveLength(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// Detector 3 — Node insecure-deserialize + vm sinks
// ────────────────────────────────────────────────────────────────────

describe("detectNodeInsecureDeserialize", () => {
  it("flags node-serialize unserialize()", () => {
    const hits = detectNodeInsecureDeserialize(`const o = unserialize(req.cookies.session);`);
    expect(hits).toHaveLength(1);
    expect(hits[0].templateId).toBe("deser-node-insecure-lib");
    expect(hits[0].severity).toBe("critical");
    expect(hits[0].category).toBe("unsafe-deserialization");
  });

  it("flags vm.runInNewContext as a code-injection sink", () => {
    const hits = detectNodeInsecureDeserialize(`vm.runInNewContext(userCode, sandbox);`);
    expect(hits).toHaveLength(1);
    expect(hits[0].templateId).toBe("deser-node-vm-eval");
    expect(hits[0].category).toBe("code-injection");
  });

  it("flags vm.runInThisContext and compileFunction", () => {
    expect(detectNodeInsecureDeserialize(`vm.runInThisContext(src);`)).toHaveLength(1);
    expect(detectNodeInsecureDeserialize(`vm.compileFunction(body, args);`)).toHaveLength(1);
  });

  it("does NOT flag JSON.parse", () => {
    expect(detectNodeInsecureDeserialize(`const o = JSON.parse(body);`)).toHaveLength(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// Detector 4 — dynamic code execution
// ────────────────────────────────────────────────────────────────────

describe("detectDynamicCodeExec", () => {
  it("flags eval() of a template literal with interpolation", () => {
    const hits = detectDynamicCodeExec("const r = eval(`do(${userInput})`);");
    expect(hits).toHaveLength(1);
    expect(hits[0].templateId).toBe("deser-dynamic-eval");
    expect(hits[0].category).toBe("code-injection");
  });

  it("flags eval() of a bare variable", () => {
    expect(detectDynamicCodeExec(`const r = eval(payload);`)).toHaveLength(1);
  });

  it("flags eval() of a string concatenation", () => {
    expect(detectDynamicCodeExec(`eval("run(" + arg + ")");`)).toHaveLength(1);
  });

  it("flags new Function() built from a variable", () => {
    const hits = detectDynamicCodeExec(`const f = new Function(bodyFromInput);`);
    expect(hits).toHaveLength(1);
    expect(hits[0].templateId).toBe("deser-dynamic-function");
  });

  it("does NOT flag eval() of a pure string literal", () => {
    expect(detectDynamicCodeExec(`const r = eval("1 + 1");`)).toHaveLength(0);
    expect(detectDynamicCodeExec(`const r = eval('a.b.c');`)).toHaveLength(0);
  });

  it("does NOT flag eval() of a plain template with no interpolation", () => {
    expect(detectDynamicCodeExec("const r = eval(`2 * 2`);")).toHaveLength(0);
  });

  it("does NOT flag a comment containing eval(x)", () => {
    expect(detectDynamicCodeExec(`// do not eval(userInput) here`)).toHaveLength(0);
  });
});

// ────────────────────────────────────────────────────────────────────
// Aggregate + Finding emission
// ────────────────────────────────────────────────────────────────────

describe("scanSourceForUnsafeDeser", () => {
  it("merges hits across detectors", () => {
    const src = [
      `import pickle, yaml`,
      `a = pickle.loads(body)`,
      `b = yaml.load(stream)`,
      `c = eval(userInput)`,
    ].join("\n");
    const hits = scanSourceForUnsafeDeser(src);
    expect(hits.length).toBe(3);
  });
});

describe("scanForUnsafeDeser", () => {
  it("walks a package tree and emits verified Finding objects with location", () => {
    writeSource("svc/loader.py", `obj = pickle.loads(request.body)\n`);
    writeSource("safe.py", `obj = json.loads(body)\n`);
    const findings = scanForUnsafeDeser({ packagePath: tmp, packageName: "demo" });
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.status).toBe("verified");
    expect(f.category).toBe("unsafe-deserialization");
    expect(f.description).toContain("svc/loader.py:1");
    expect(f.evidence?.request).toBe("svc/loader.py:1");
    expect(f.confidence).toBeGreaterThan(0);
  });

  it("returns [] for a non-existent path (fail-soft)", () => {
    expect(scanForUnsafeDeser({ packagePath: join(tmp, "nope") })).toEqual([]);
  });

  it("scans a single file path directly", () => {
    const file = writeSource("one.js", `const o = unserialize(payload);\n`);
    const findings = scanForUnsafeDeser({ packagePath: file });
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
  });
});
