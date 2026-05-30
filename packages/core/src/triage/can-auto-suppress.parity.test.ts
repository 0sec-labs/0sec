import { describe, it, expect } from "vitest";
import {
  AUTO_SUPPRESS_PROTECTED_SEVERITIES,
  AUTO_SUPPRESS_HIGH_IMPACT_CATEGORIES,
} from "./can-auto-suppress.js";

// #650 — cross-workspace parity guard for the disclosure-worthiness severity/
// class guard.
//
// The pwnkit engine and the 0cloud orchestrator are decoupled by design (linked
// only by the cloud-sink wire format), and the engine is a separate publishable
// workspace that cannot import a private `@0cloud/*` package. So the engine
// keeps its own copy of this guard (`can-auto-suppress.ts`) and 0cloud keeps the
// single source in `@0cloud/cloud-contracts` `disclosure-worthiness.ts`.
//
// The CANONICAL_* tables below are duplicated VERBATIM from that package's
// `disclosure-worthiness.test.ts`. Each side asserts its own exported sets
// against this identical table, so any divergence between the engine guard and
// the 0cloud single source is caught here — without a physical cross-workspace
// import. PARITY: when you change a list, update BOTH this fixture and the
// 0cloud one (and both source modules).

const CANONICAL_PROTECTED_SEVERITIES = ["critical", "high"];

const CANONICAL_HIGH_IMPACT_CATEGORIES = [
  "command-injection",
  "code-injection",
  "sql-injection",
  "unsafe-deserialization",
  "ssrf",
  "path-traversal",
  "heap-overflow",
  "out-of-bounds-read",
  "out-of-bounds-write",
  "use-after-free",
  "stack-buffer-overflow",
  "integer-overflow",
  "type-confusion",
  "double-free",
  "format-string",
  "uninitialized-memory",
  "race-condition",
  "toctou",
  "known-vulnerable-package",
  "supply-chain",
  "prototype-pollution",
  "prompt-injection",
  "data-exfiltration",
  "tool-misuse",
];

describe("can-auto-suppress parity with @0cloud/cloud-contracts (#650)", () => {
  it("engine PROTECTED_SEVERITIES matches the canonical table", () => {
    expect([...AUTO_SUPPRESS_PROTECTED_SEVERITIES].sort()).toEqual(
      [...CANONICAL_PROTECTED_SEVERITIES].sort(),
    );
  });

  it("engine HIGH_IMPACT_CATEGORIES matches the canonical table", () => {
    expect([...AUTO_SUPPRESS_HIGH_IMPACT_CATEGORIES].sort()).toEqual(
      [...CANONICAL_HIGH_IMPACT_CATEGORIES].sort(),
    );
  });
});
