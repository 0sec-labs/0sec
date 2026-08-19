// Concurrency harness for #415. Forked by writer.test.ts (twice in parallel)
// to exercise the same O_APPEND + fsync code path the production writer uses.
// Kept as a standalone .mjs so the test can `fork()` it directly without
// needing tsx/ts-node in dev dependencies.
import { closeSync, fsyncSync, mkdirSync, openSync, writeSync } from "node:fs";
import { join } from "node:path";

const runDir = process.env["0SEC_TEST_RUN_DIR"];
const writerId = process.env["0SEC_TEST_WRITER_ID"];
const iterations = Number.parseInt(process.env["0SEC_TEST_ITERATIONS"] ?? "100", 10);

if (!runDir || !writerId || !Number.isFinite(iterations)) {
  console.error("missing 0SEC_TEST_RUN_DIR / 0SEC_TEST_WRITER_ID / 0SEC_TEST_ITERATIONS");
  process.exit(2);
}

mkdirSync(runDir, { recursive: true, mode: 0o700 });
const journalPath = join(runDir, "journal.jsonl");

for (let i = 0; i < iterations; i += 1) {
  const entry = {
    schemaVersion: 1,
    id: `${writerId}-${i}`,
    runId: "concurrent",
    timestamp: new Date().toISOString(),
    kind: "decision",
    writer: writerId,
    iteration: i,
    decision: "continue",
    rationale: `writer ${writerId} iter ${i}`,
  };
  const line = JSON.stringify(entry) + "\n";
  const fd = openSync(journalPath, "a", 0o600);
  try {
    writeSync(fd, line);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

process.exit(0);
