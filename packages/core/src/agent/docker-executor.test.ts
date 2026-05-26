import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  DockerExecutor,
  buildDockerRunArgs,
  generateContainerName,
} from "./docker-executor.js";

describe("generateContainerName", () => {
  beforeEach(() => {
    DockerExecutor.resetInstance();
  });

  it("uses the pwnkit-{scanId}-{random8} format", () => {
    const name = generateContainerName("scan-abc");
    // pwnkit-scan-abc-<8 hex chars>
    expect(name).toMatch(/^pwnkit-scan-abc-[0-9a-f]{8}$/);
  });

  it("produces a different suffix on each call", () => {
    // 8 hex chars = 32 bits of entropy → collisions astronomically unlikely.
    const a = generateContainerName("s");
    const b = generateContainerName("s");
    expect(a).not.toBe(b);
    // Same prefix, different 8-char tails.
    expect(a.slice(0, -8)).toBe(b.slice(0, -8));
  });

  it("sanitises Docker-unsafe characters in scanId", () => {
    const name = generateContainerName("scan/with spaces!");
    // Slash + space + bang → '-' replacement; trailing dash stripped.
    expect(name).toMatch(/^pwnkit-scan-with-spaces-[0-9a-f]{8}$/);
  });

  it("falls back to 'anon' when scanId is empty", () => {
    const name = generateContainerName("");
    expect(name).toMatch(/^pwnkit-anon-[0-9a-f]{8}$/);
  });
});

describe("buildDockerRunArgs", () => {
  it("includes the --rm flag for auto-cleanup on exit", () => {
    const args = buildDockerRunArgs({
      containerName: "pwnkit-scan-abcd1234",
      image: "ghcr.io/0sec-labs/pwnkit-kali:latest",
      network: "bridge",
      target: "https://example.com",
      mounts: [],
    });
    expect(args).toContain("--rm");
  });

  it("constructs a valid docker run arg list with -d, --name, --network", () => {
    const args = buildDockerRunArgs({
      containerName: "pwnkit-scan-abcd1234",
      image: "kalilinux/kali-rolling",
      network: "host",
      target: "https://example.com",
      mounts: [],
    });
    expect(args[0]).toBe("run");
    expect(args).toContain("-d");
    expect(args).toContain("--name");
    expect(args[args.indexOf("--name") + 1]).toBe("pwnkit-scan-abcd1234");
    expect(args).toContain("--network");
    expect(args[args.indexOf("--network") + 1]).toBe("host");
  });

  it("emits -v <host>:<container> for each bind mount", () => {
    const args = buildDockerRunArgs({
      containerName: "pwnkit-scan-abcd1234",
      image: "img",
      network: "bridge",
      target: "https://example.com",
      mounts: [
        { host: "/tmp/payload.bin", container: "/work/payload.bin" },
        { host: "/etc/scan.cfg", container: "/etc/scan.cfg", readOnly: true },
      ],
    });
    // Both mounts present, in declaration order.
    const mountFlags: string[] = [];
    for (let i = 0; i < args.length; i++) {
      if (args[i] === "-v") mountFlags.push(args[i + 1]);
    }
    expect(mountFlags).toEqual([
      "/tmp/payload.bin:/work/payload.bin",
      "/etc/scan.cfg:/etc/scan.cfg:ro",
    ]);
  });

  it("propagates TARGET env into the container", () => {
    const args = buildDockerRunArgs({
      containerName: "pwnkit-scan-abcd1234",
      image: "img",
      network: "bridge",
      target: "https://example.com",
      mounts: [],
    });
    const eIdx = args.indexOf("-e");
    expect(eIdx).toBeGreaterThan(-1);
    expect(args[eIdx + 1]).toBe("TARGET=https://example.com");
  });
});

describe("DockerExecutor instance naming", () => {
  beforeEach(() => {
    DockerExecutor.resetInstance();
  });

  afterEach(() => {
    DockerExecutor.resetInstance();
  });

  it("two consecutive forScan() calls with different ids produce different names", () => {
    const a = DockerExecutor.forScan("scan-a");
    const b = DockerExecutor.forScan("scan-b");
    expect(a.getContainerName()).not.toBe(b.getContainerName());
    expect(a.getContainerName()).toMatch(/^pwnkit-scan-a-[0-9a-f]{8}$/);
    expect(b.getContainerName()).toMatch(/^pwnkit-scan-b-[0-9a-f]{8}$/);
  });

  it("forScan() returns the same instance for the same scanId (cache)", () => {
    const a1 = DockerExecutor.forScan("scan-a");
    const a2 = DockerExecutor.forScan("scan-a");
    expect(a1).toBe(a2);
    expect(a1.getContainerName()).toBe(a2.getContainerName());
  });

  it("buildRunArgs() on an instance contains --rm and --name <pwnkit-...>", () => {
    const exec = DockerExecutor.forScan("scan-foo");
    exec.setTarget("https://target.example");
    const args = exec.buildRunArgs();
    expect(args).toContain("--rm");
    const nameIdx = args.indexOf("--name");
    expect(nameIdx).toBeGreaterThan(-1);
    expect(args[nameIdx + 1]).toMatch(/^pwnkit-scan-foo-[0-9a-f]{8}$/);
  });

  it("buildRunArgs() includes default /tmp/pwnkit-shared bind mount", () => {
    const exec = DockerExecutor.forScan("scan-default-mount");
    const args = exec.buildRunArgs();
    const mountFlags: string[] = [];
    for (let i = 0; i < args.length; i++) {
      if (args[i] === "-v") mountFlags.push(args[i + 1]);
    }
    expect(mountFlags).toContain("/tmp/pwnkit-shared:/shared");
  });

  it("addBindMount() injects host:container -v flag for fixture files", () => {
    const exec = DockerExecutor.forScan("scan-mount");
    exec.addBindMount({ host: "/tmp/fixture.txt", container: "/work/fixture.txt" });
    exec.addBindMount({
      host: "/tmp/secret.cfg",
      container: "/etc/secret.cfg",
      readOnly: true,
    });
    const args = exec.buildRunArgs();
    const mountFlags: string[] = [];
    for (let i = 0; i < args.length; i++) {
      if (args[i] === "-v") mountFlags.push(args[i + 1]);
    }
    expect(mountFlags).toContain("/tmp/fixture.txt:/work/fixture.txt");
    expect(mountFlags).toContain("/tmp/secret.cfg:/etc/secret.cfg:ro");
  });

  it("4 mock executors run concurrently with no name collisions", async () => {
    const scanIds = ["bench-1", "bench-2", "bench-3", "bench-4"];
    const execs = await Promise.all(
      scanIds.map(async (id) => {
        // Simulate concurrency — yield to the event loop before constructing.
        await Promise.resolve();
        return DockerExecutor.forScan(id);
      }),
    );
    const names = execs.map((e) => e.getContainerName());
    const argsLists = execs.map((e) => e.buildRunArgs());

    // No two run-arg lists name the same container.
    const namesFromArgs = argsLists.map((args) => args[args.indexOf("--name") + 1]);
    const unique = new Set(namesFromArgs);
    expect(unique.size).toBe(scanIds.length);
    expect(namesFromArgs).toEqual(names);

    // Every name is the expected pwnkit-{scanId}-{8hex} shape.
    for (const n of names) {
      expect(n).toMatch(/^pwnkit-bench-[1-4]-[0-9a-f]{8}$/);
    }
  });
});

describe("DockerExecutor.cleanupOrphans", () => {
  const realRunner = DockerExecutor.dockerRunner;

  beforeEach(() => {
    DockerExecutor.resetInstance();
  });

  afterEach(() => {
    DockerExecutor.resetInstance();
    DockerExecutor.dockerRunner = realRunner;
  });

  /** Format a date the way `docker ps --format '{{.CreatedAt}}'` does. */
  const fmtDocker = (d: Date): string => {
    const iso = d.toISOString();
    const date = iso.slice(0, 10);
    const time = iso.slice(11, 19);
    return `${date} ${time} +0000 UTC`;
  };

  it("leaves an in-flight container (younger than maxAge) alone", () => {
    const now = new Date();
    const fiveMinAgo = new Date(now.getTime() - 5 * 60 * 1000);
    const twelveHoursAgo = new Date(now.getTime() - 12 * 60 * 60 * 1000);

    const calls: string[][] = [];
    DockerExecutor.dockerRunner = (args: string[]): string => {
      calls.push(args);
      if (args[0] === "ps") {
        return [
          `pwnkit-scan-young-aaaaaaaa\t${fmtDocker(fiveMinAgo)}`,
          `pwnkit-scan-old-bbbbbbbb\t${fmtDocker(twelveHoursAgo)}`,
        ].join("\n");
      }
      return "";
    };

    const { removed } = DockerExecutor.cleanupOrphans(6);
    expect(removed).toEqual(["pwnkit-scan-old-bbbbbbbb"]);

    // Only the OLD container received `docker rm -f`.
    const rmCalls = calls.filter((a) => a[0] === "rm");
    expect(rmCalls).toHaveLength(1);
    expect(rmCalls[0]).toEqual(["rm", "-f", "pwnkit-scan-old-bbbbbbbb"]);

    // The young container never appears in any rm invocation.
    for (const call of rmCalls) {
      expect(call.join(" ")).not.toContain("pwnkit-scan-young-aaaaaaaa");
    }
  });

  it("returns empty list when docker ps fails (docker unavailable)", () => {
    DockerExecutor.dockerRunner = () => {
      throw new Error("docker not found");
    };
    const { removed } = DockerExecutor.cleanupOrphans(6);
    expect(removed).toEqual([]);
  });

  it("ignores non-pwnkit container names even if filter leaks them", () => {
    const now = new Date();
    const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const calls: string[][] = [];
    DockerExecutor.dockerRunner = (args: string[]): string => {
      calls.push(args);
      if (args[0] === "ps") {
        return [
          `unrelated-container\t${fmtDocker(dayAgo)}`,
          `pwnkit-scan-old-cccccccc\t${fmtDocker(dayAgo)}`,
        ].join("\n");
      }
      return "";
    };

    const { removed } = DockerExecutor.cleanupOrphans(6);
    expect(removed).toEqual(["pwnkit-scan-old-cccccccc"]);

    const rmCalls = calls.filter((a) => a[0] === "rm");
    expect(rmCalls).toHaveLength(1);
  });
});
