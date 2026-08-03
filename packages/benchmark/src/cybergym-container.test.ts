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

describe("run-cybergym-container.sh", () => {
  it("attaches the agent to the isolated network and mounts optional CPG evidence", () => {
    const root = mkdtempSync(join(tmpdir(), "cybergym-container-"));
    roots.push(root);
    const bin = join(root, "bin");
    const harness = join(root, "harness");
    const task = join(root, "task");
    const auth = join(root, "auth.json");
    const capture = join(root, "docker-args.txt");
    const cpg = join(root, "task.cpg.json");
    mkdirSync(bin);
    mkdirSync(task);
    writeFileSync(auth, "{}");
    writeFileSync(cpg, "{}");

    executable(join(bin, "docker"), `#!/usr/bin/env bash
if [[ "$1" == "network" && "$2" == "inspect" ]]; then
  exit 0
fi
if [[ "$1" == "inspect" ]]; then
  printf '%s\\n' '172.18.0.2'
  exit 0
fi
if [[ "$1" == "run" ]]; then
  printf '%s\\n' "$@" > "${capture}"
  exit 0
fi
exit 64
`);
    executable(join(bin, "chown"), "#!/usr/bin/env bash\nexit 0\n");

    const script = resolve(import.meta.dirname, "../scripts/run-cybergym-container.sh");
    const result = spawnSync("bash", [script, "--task-id", "arvo:10731"], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH ?? ""}`,
        CYBERGYM_ROOT: harness,
        CYBERGYM_NETWORK: "cybergym-internal",
        CYBERGYM_AUTH_FILE: auth,
        CYBERGYM_TASK_DIR: task,
        CYBERGYM_SERVER: "http://172.18.0.1:8666",
        CYBERGYM_ORACLE_BRIDGE: "http://172.18.0.1:8667",
        CYBERGYM_ORACLE_BRIDGE_TOKEN: "test-token",
        PWNKIT_CYBERGYM_IMAGE: "test-agent:image",
        CYBERGYM_CPG_PATH: cpg,
      },
    });

    expect(result.status, result.stderr).toBe(0);
    const args = readFileSync(capture, "utf8").trim().split("\n");
    expect(args.slice(0, 4)).toEqual(["run", "--rm", "--network", "cybergym-internal"]);
    expect(args).toContain("HTTP_PROXY=http://172.18.0.2:3128");
    expect(args).toContain(`type=bind,src=${cpg},dst=/run/cybergym/cpg.json,readonly`);
    expect(args).toContain("CYBERGYM_CPG_PATH=/run/cybergym/cpg.json");
    expect(args).toContain("test-agent:image");
  });
});
