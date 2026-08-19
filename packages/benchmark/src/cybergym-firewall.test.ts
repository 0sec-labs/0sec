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

describe("start-cybergym-firewall.sh", () => {
  it("opens only submission and oracle ports to the internal Docker bridge when UFW is active", () => {
    const root = mkdtempSync(join(tmpdir(), "cybergym-firewall-"));
    roots.push(root);
    const bin = join(root, "bin");
    const capture = join(root, "ufw-args.txt");
    const python = join(bin, "cybergym-python");
    mkdirSync(bin);

    executable(python, `#!/usr/bin/env bash
if [[ "$3" == "status" ]]; then
  printf '%s\n' '{"network":{"host_gateway":"172.18.0.1"}}'
fi
`);
    executable(join(bin, "python3"), "#!/usr/bin/env bash\nprintf '172.18.0.1\\n'\n");
    executable(join(bin, "docker"), `#!/usr/bin/env bash
if [[ "$4" == '{{.Id}}' ]]; then
  printf '%s\n' '7d0f7a38d0560000000000000000000000000000000000000000000000000000'
else
  printf '%s\n' '172.18.0.0/16'
fi
`);
    executable(join(bin, "ufw"), `#!/usr/bin/env bash
if [[ "$1" == "status" ]]; then
  printf 'Status: active\n'
else
  printf '%s\n' "$@" >> "${capture}"
fi
`);

    const script = resolve(import.meta.dirname, "../scripts/start-cybergym-firewall.sh");
    const result = spawnSync("bash", [script], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: `${bin}:${process.env.PATH ?? ""}`,
        CYBERGYM_ROOT: root,
        CYBERGYM_PYTHON: python,
      },
    });

    expect(result.status, result.stderr).toBe(0);
    expect(readFileSync(capture, "utf8").trim().split("\n")).toEqual([
      "allow", "in", "on", "br-7d0f7a38d056", "from", "172.18.0.0/16", "to", "172.18.0.1", "port", "8666", "proto", "tcp", "comment", "CyberGym submit",
      "allow", "in", "on", "br-7d0f7a38d056", "from", "172.18.0.0/16", "to", "172.18.0.1", "port", "8667", "proto", "tcp", "comment", "CyberGym oracle",
    ]);
  });
});
