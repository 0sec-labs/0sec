import { afterEach, describe, expect, it } from "vitest";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) {
    rmSync(root, { recursive: true, force: true });
  }
});

function executable(path: string, source: string): void {
  writeFileSync(path, source, { mode: 0o700 });
  chmodSync(path, 0o700);
}

describe("run-cybergym-subset.sh", () => {
  it("skips completed tasks, keeps capability rows, and retries quota-wall error rows", () => {
    const root = mkdtempSync(join(tmpdir(), "cybergym-subset-"));
    roots.push(root);
    const results = join(root, "srv", "results");
    const control = join(root, "control");
    mkdirSync(results, { recursive: true });
    mkdirSync(control);
    const corpus = join(results, "fair.jsonl");
    const subset = join(root, "subset.txt");
    const fakeRunner = join(root, "fake-runner.sh");

    // arvo:1 already has a capability row (fail) — must be skipped untouched.
    writeFileSync(corpus, `${JSON.stringify({ taskId: "arvo:1", verdict: "fail", passed: false })}\n`);
    writeFileSync(subset, "# frozen\narvo:1\narvo:2\narvo:3\n");

    // Per-task behavior queues; the fake runner shifts one line per call.
    writeFileSync(join(control, "arvo-2.queue"), "pass\n");
    writeFileSync(join(control, "arvo-3.queue"), "error-quota\npass\n");

    executable(fakeRunner, `#!/usr/bin/env bash
set -euo pipefail
task="$1"; shift
corpus=""
while (($#)); do
  if [[ "$1" == "--corpus-path" ]]; then corpus="$2"; shift 2; else shift; fi
done
host_corpus="\${CONTROL_DIR}/../srv/results/\${corpus#/results/}"
ctrl="\${CONTROL_DIR}/\${task//:/-}.queue"
behavior="$(head -n1 "$ctrl")"
tail -n +2 "$ctrl" > "$ctrl.next" && mv "$ctrl.next" "$ctrl"
case "$behavior" in
  pass)
    printf '%s\n' "{\\"taskId\\":\\"$task\\",\\"verdict\\":\\"pass\\",\\"passed\\":true}" >> "$host_corpus"
    ;;
  error-quota)
    printf '%s\n' "{\\"taskId\\":\\"$task\\",\\"verdict\\":\\"error\\",\\"passed\\":false}" >> "$host_corpus"
    echo "[pwnkit] Qwen HTTP 429 - quota has been exhausted" >&2
    ;;
  *) exit 9 ;;
esac
`);

    const script = resolve(import.meta.dirname, "../scripts/run-cybergym-subset.sh");
    const result = spawnSync("bash", [script, subset, corpus], {
      encoding: "utf8",
      timeout: 60_000,
      env: {
        ...process.env,
        CONTROL_DIR: control,
        CYBERGYM_ROOT: join(root, "srv"),
        CYBERGYM_MODEL: "test-model",
        CYBERGYM_TASK_RUNNER: fakeRunner,
        CYBERGYM_INFRA_RETRIES: "3",
        CYBERGYM_QUOTA_ANCHOR_EPOCH: String(Math.floor(Date.now() / 1000) - 1),
        CYBERGYM_QUOTA_WINDOW_SECONDS: "1",
        CYBERGYM_QUOTA_SLEEP_BUFFER: "0",
      },
    });

    expect(result.status, result.stderr + result.stdout).toBe(0);
    const rows = readFileSync(corpus, "utf8").trim().split("\n").map((l) => JSON.parse(l));
    // The pre-existing capability row is preserved verbatim, in order.
    expect(rows[0]).toEqual({ taskId: "arvo:1", verdict: "fail", passed: false });
    // arvo:2 measured once, kept.
    expect(rows.filter((r) => r.taskId === "arvo:2")).toEqual([
      { taskId: "arvo:2", verdict: "pass", passed: true },
    ]);
    // arvo:3's quota error row was evicted and replaced by the real attempt.
    expect(rows.filter((r) => r.taskId === "arvo:3")).toEqual([
      { taskId: "arvo:3", verdict: "pass", passed: true },
    ]);
    expect(rows).toHaveLength(3);
    expect(result.stdout).toContain("skip arvo:1");
    expect(result.stdout).toContain("hit provider quota");
    expect(result.stdout).not.toContain("NOT measured");
  });
});
