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

  it("uses the preflight-verified aliases without pulling mutable tags", () => {
    const root = mkdtempSync(join(tmpdir(), "cybergym-task-pinned-"));
    roots.push(root);
    const bin = join(root, "bin");
    const cybergymRoot = join(root, "cybergym");
    const pwnkitRoot = join(root, "pwnkit");
    const auth = join(root, "auth.json");
    const dockerCalls = join(root, "docker-calls.txt");
    const containerCalls = join(root, "container-calls.txt");
    mkdirSync(bin);
    mkdirSync(cybergymRoot);
    mkdirSync(join(pwnkitRoot, "packages", "benchmark", "scripts"), { recursive: true });
    writeFileSync(auth, "{}");
    writeFileSync(join(pwnkitRoot, "packages", "benchmark", "scripts", "cybergym-oracle-bridge.py"), "");
    executable(
      join(pwnkitRoot, "packages", "benchmark", "scripts", "run-cybergym-container.sh"),
      `#!/usr/bin/env bash
printf '%s\n' "$*" >> "${containerCalls}"
`,
    );

    const fakePython = join(bin, "cybergym-python");
    executable(fakePython, `#!/usr/bin/env bash
if [[ "$1" == "-c" ]]; then
  printf '%s\n' 'fixture-agent'
  exit 0
fi
if [[ "$1" == "-m" && "$2" == "cybergym.firewall" && "$3" == "status" ]]; then
  printf '%s\n' '{"network":{"host_gateway":"172.18.0.1"}}'
  exit 0
fi
if [[ "$1" == "-m" && "$2" == "cybergym.task.gen_task" ]]; then
  out=""
  while (($#)); do
    if [[ "$1" == "--out-dir" ]]; then out="$2"; shift 2; continue; fi
    shift
  done
  mkdir -p "$out/repo-vul"
  printf '%s\n' 'fixture task' > "$out/description.txt"
  printf '%s\n' '{"agent_id": "fixture-agent"}' > "$out/submit.sh"
  exit 0
fi
if [[ "$1" == *cybergym-oracle-bridge.py ]]; then
  [[ "$2" == "issue" ]] && printf '%s\n' 'fixture-token'
  exit 0
fi
exit 98
`);
    executable(join(bin, "docker"), `#!/usr/bin/env bash
printf '%s\n' "$*" >> "${dockerCalls}"
if [[ "$1" == "image" && "$2" == "inspect" ]]; then exit 0; fi
exit 97
`);
    executable(join(bin, "install"), `#!/usr/bin/env bash
args=("$@")
if [[ "$1" == "-d" ]]; then
  for arg in "\${args[@]}"; do [[ "$arg" == /* ]] && mkdir -p "$arg"; done
  exit 0
fi
n=$#
cp "\${args[$((n - 2))]}" "\${args[$((n - 1))]}"
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

    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(dockerCalls, "utf8").trim().split("\n")).toEqual([
      "image inspect n132/arvo:10400-vul",
      "image inspect n132/arvo:10400-fix",
    ]);
    expect(readFileSync(containerCalls, "utf8")).toContain("--task-id arvo:10400");
  });
});
