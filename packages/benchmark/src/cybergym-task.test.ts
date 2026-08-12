import { afterEach, describe, expect, it } from "vitest";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function executable(path: string, source: string): void {
  writeFileSync(path, source, { mode: 0o700 });
  chmodSync(path, 0o700);
}

describe("run-cybergym-task.sh", () => {
  it("fails before task generation when the server's pinned image aliases are absent", () => {
    const root = mkdtempSync(join(tmpdir(), "cybergym-task-"));
    roots.push(root);
    const bin = join(root, "bin");
    const cybergymRoot = join(root, "cybergym");
    const pwnkitRoot = join(root, "pwnkit");
    const auth = join(root, "auth.json");
    const pythonCalls = join(root, "python-calls.txt");
    mkdirSync(bin);
    mkdirSync(cybergymRoot);
    mkdirSync(join(pwnkitRoot, "packages", "benchmark", "scripts"), { recursive: true });
    writeFileSync(auth, "{}");
    writeFileSync(join(pwnkitRoot, "packages", "benchmark", "scripts", "cybergym-oracle-bridge.py"), "");
    writeFileSync(join(pwnkitRoot, "packages", "benchmark", "scripts", "run-cybergym-container.sh"), "");

    const fakePython = join(bin, "cybergym-python");
    executable(fakePython, `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "${pythonCalls}"
printf '%s\\n' '{"network":{"host_gateway":"172.18.0.1"}}'
`);
    executable(join(bin, "docker"), `#!/usr/bin/env bash
if [[ "$1" == "image" && "$2" == "inspect" ]]; then exit 1; fi
exit 99
`);

    const script = resolve(import.meta.dirname, "../scripts/run-cybergym-task.sh");
    const result = spawnSync("bash", [script, "arvo:10400"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH}`,
        PWNKIT_ROOT: pwnkitRoot,
        CYBERGYM_ROOT: cybergymRoot,
        CYBERGYM_PYTHON: fakePython,
        CYBERGYM_AUTH_FILE: auth,
      },
    });

    expect(result.status).toBe(2);
    expect(result.stderr).toMatch(/missing required CyberGym image alias: n132\/arvo:10400-vul/);
    expect(readFileSync(pythonCalls, "utf8")).toContain("-m cybergym.firewall status");
    expect(readFileSync(pythonCalls, "utf8")).not.toContain("cybergym.task.gen_task");
  });
});
