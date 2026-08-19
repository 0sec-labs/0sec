import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "@pwnkit/shared";

vi.mock("./kernel-vm-runner.js", () => ({
  runReproducerInKernelVm: vi.fn(),
}));

import { compileAndRunReproducer, verifyKernelCrash, verifyStandaloneKernelReproducer, matchCrashSignature } from "./kernel-oracle.js";
import { runReproducerInKernelVm } from "./kernel-vm-runner.js";

const runVmMock = vi.mocked(runReproducerInKernelVm);

describe("compileAndRunReproducer", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv };
    delete process.env.PWNKIT_KERNEL_QEMU;
    runVmMock.mockReset();
  });

  it("returns a dry-run result when kernel VM execution is disabled", async () => {
    const result = await compileAndRunReproducer({
      raw: "BUG: KASAN: slab-out-of-bounds",
      crashType: "kasan-oob",
      faultingFunction: "nfsd_dispatch",
      stackFrames: ["nfsd_dispatch+0x1a2/0x340"],
      reproducer: "int main(void) { return 0; }",
    });

    expect(result.executed).toBe(false);
    expect(result.output).toContain("PWNKIT_KERNEL_QEMU not set");
    expect(runVmMock).not.toHaveBeenCalled();
  });

  it("delegates to the kernel VM runner when enabled", async () => {
    process.env.PWNKIT_KERNEL_QEMU = "1";
    runVmMock.mockResolvedValue({
      compiled: true,
      executed: true,
      output: "executing program",
      dmesg: "BUG: KASAN: slab-out-of-bounds in nfsd_dispatch+0x1a2/0x340",
      exitCode: 0,
      timedOut: false,
    });

    const report = {
      raw: "BUG: KASAN: slab-out-of-bounds",
      crashType: "kasan-oob",
      faultingFunction: "nfsd_dispatch",
      stackFrames: ["nfsd_dispatch+0x1a2/0x340"],
      reproducer: "int main(void) { return 0; }",
    };

    const result = await compileAndRunReproducer(report);

    expect(runVmMock).toHaveBeenCalledWith(report);
    expect(result.executed).toBe(true);
    expect(result.dmesg).toContain("KASAN");
  });
});

describe("verifyKernelCrash", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv, PWNKIT_KERNEL_QEMU: "1" };
    runVmMock.mockReset();
  });

  it("returns a verified verdict when the VM runner reproduces a matching crash", async () => {
    runVmMock.mockResolvedValue({
      compiled: true,
      executed: true,
      output: "executing program",
      dmesg: `
BUG: KASAN: slab-out-of-bounds in nfsd_dispatch+0x1a2/0x340
Read of size 4 at addr ffff88800abcde10 by task nfsd/1234
Call Trace:
 nfsd_dispatch+0x1a2/0x340
 svc_process+0x15c/0x2c0
 nfsd+0x1e7/0x310
`,
      exitCode: 0,
      timedOut: false,
    });

    const finding: Finding = {
      id: "finding-1",
      templateId: "kernel-kasan-oob",
      title: "Linux kernel kasan-oob: nfsd_dispatch in fs/nfsd",
      description: "desc",
      severity: "critical",
      category: "heap-overflow",
      status: "discovered",
      evidence: { request: "req", response: "resp", analysis: "analysis" },
      confidence: 0.8,
      timestamp: Date.now(),
    };

    const result = await verifyKernelCrash(finding, {
      raw: `
BUG: KASAN: slab-out-of-bounds in nfsd_dispatch+0x1a2/0x340
Read of size 4 at addr ffff88800abcde10 by task nfsd/1234
Allocated by task 1100:
 nfsd_svc+0x58/0x90
`,
      crashType: "kasan-oob",
      faultingFunction: "nfsd_dispatch",
      stackFrames: [
        "nfsd_dispatch+0x1a2/0x340",
        "svc_process+0x15c/0x2c0",
        "nfsd+0x1e7/0x310",
      ],
      reproducer: "int main(void) { return 0; }",
      accessType: "read",
      accessSize: 4,
      subsystem: "nfs",
    });

    expect(result.verified).toBe(true);
    expect(result.reproduced).toBe(true);
    expect(result.crashMatch).toBe(true);
    expect(result.reproducedCrashType).toBe("kasan-oob");
  });
});

describe("verifyStandaloneKernelReproducer", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv, PWNKIT_KERNEL_QEMU: "1" };
    runVmMock.mockReset();
  });

  it("verifies a standalone reproducer when dmesg contains a kernel crash signature", async () => {
    runVmMock.mockResolvedValue({
      compiled: true,
      executed: true,
      output: "ran",
      dmesg: "BUG: KASAN: slab-use-after-free in vulnerable_path+0x10/0x20",
      exitCode: 0,
      timedOut: false,
    });

    const result = await verifyStandaloneKernelReproducer({
      raw: "",
      crashType: "unknown",
      faultingFunction: "unknown",
      stackFrames: [],
      reproducer: "int main(void) { return 0; }",
      reproducerLanguage: "c",
    });

    expect(result.verified).toBe(true);
    expect(result.reproduced).toBe(true);
    expect(result.crashMatch).toBe(false);
    expect(result.reproducedCrashType).toBe("kasan-uaf");
  });

  it("surfaces the syz-execprog guest contract for raw syzkaller programs", async () => {
    runVmMock.mockResolvedValue({
      compiled: false,
      executed: false,
      output: "syz-execprog not found in guest",
      dmesg: "",
      exitCode: 127,
      timedOut: false,
    });

    const result = await verifyStandaloneKernelReproducer({
      raw: "",
      crashType: "unknown",
      faultingFunction: "unknown",
      stackFrames: [],
      reproducer: "r0 = openat$sysfs(0xffffffffffffff9c, &(0x7f0000000000)='/sys/kernel/debug/x00', 0x0, 0x0)",
      reproducerLanguage: "syz",
    });

    expect(result.verified).toBe(false);
    expect(result.reason).toContain("syz-execprog");
  });
});

describe("matchCrashSignature", () => {
  it("ignores generic reporting frames and accepts invalid-free for double-free reports", () => {
    const result = matchCrashSignature(
      {
        raw: "BUG: KASAN: invalid-free",
        crashType: "kasan-double-free",
        faultingFunction: "release_gid_table",
        stackFrames: [
          "dump_stack_lvl+0xe8/0x150",
          "print_address_description+0x55/0x1e0",
          "print_report+0x58/0x70",
          "release_gid_table+0x1a/0x30",
          "gid_table_release_one+0x384/0x470",
        ],
      },
      `
BUG: KASAN: invalid-free in release_gid_table+0x1a/0x30
Call Trace:
 release_gid_table+0x1a/0x30
 gid_table_release_one+0x384/0x470
 ib_device_release+0xd2/0x1c0
`,
    );

    expect(result.matched).toBe(true);
    expect(result.matchedFields).toContain("crashType");
    expect(result.matchedFields).toContain("faultingFunction");
    expect(result.mismatchedFields).not.toContain("stackFrame[0]:dump_stack_lvl");
  });

  it("matches a KCSAN data-race crashType against a KCSAN splat (race lane)", () => {
    const result = matchCrashSignature(
      {
        raw: "BUG: KCSAN: data-race",
        crashType: "kcsan-data-race",
        faultingFunction: "ep_poll",
        stackFrames: ["ep_poll+0x1c/0x680", "do_epoll_wait+0x2a0/0x400"],
      },
      "BUG: KCSAN: data-race in ep_poll / ep_free\n ep_poll+0x1c/0x680 fs/eventpoll.c:1900\n",
    );
    expect(result.matched).toBe(true);
    expect(result.matchedFields).toContain("crashType");
  });
});

describe("verifyStandaloneKernelReproducer — KCSAN race lane", () => {
  const originalEnv = { ...process.env };
  beforeEach(() => {
    process.env = { ...originalEnv, PWNKIT_KERNEL_QEMU: "1" };
    runVmMock.mockReset();
  });

  it("confirms a standalone reproducer that triggers a KCSAN data-race", async () => {
    runVmMock.mockResolvedValue({
      compiled: true,
      executed: true,
      output: "ran",
      dmesg: "BUG: KCSAN: data-race in ep_poll / ep_free\n value changed: 0x1 -> 0x0\n",
      exitCode: 0,
      timedOut: false,
    });

    const result = await verifyStandaloneKernelReproducer({
      raw: "",
      crashType: "unknown",
      faultingFunction: "unknown",
      stackFrames: [],
      reproducer: "int main(void) { return 0; }",
      reproducerLanguage: "c",
    });

    expect(result.verified).toBe(true);
    expect(result.reproduced).toBe(true);
    expect(result.reproducedCrashType).toBe("kcsan-data-race");
  });
});
