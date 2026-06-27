/**
 * `xnu-fuzz` §3 execution harness — the disposable Apple-Silicon macOS-VM lane
 * (tart / Virtualization.framework).
 *
 * STATE OF THIS MODULE (honest): the ORCHESTRATION is built — snapshot
 * clone-per-shard, push a program to the in-guest opener, harvest a panic,
 * discard + re-clone. The heavy part (actually booting golden macOS VMs and
 * running a fuzzing campaign) is NOT runnable on a 16GB dev Mac and is NOT run
 * here. `planSingleShardRun()` documents exactly what a real single-shard run
 * needs and on what hardware. The shell-out runner is injectable so the
 * orchestration logic is unit-tested with a fake runner (no tart, no VM).
 *
 * GUARDRAIL: `preflight()` refuses to spawn VMs unless `allowVmSpawn` is
 * explicitly set, precisely so an accidental run does not OOM-reboot the host.
 * macOS guests need ~4–8GB RAM each; multiple shards must run on a beefier
 * Apple-Silicon Mac, in VMs, never on the orchestrating host directly.
 */

import { execFileSync } from "node:child_process";
import { encodeProgram, type ProgramCall } from "./program.js";
import type { FuzzInput } from "./input-gen.js";

export interface VmLaneConfig {
  /** Golden tart VM image name (must match the kernelcache build under test). */
  goldenImage: string;
  /** macOS build the golden image (and kernelcache) correspond to, e.g. "26.0 (25A...)". */
  guestBuild: string;
  /** Host dir shared into the guest for the program channel + panic logs. */
  sharedDir: string;
  /** tart binary (default "tart"). */
  tartBin?: string;
  /**
   * Hard safety switch. Defaults false: the lane will PLAN and shell out for
   * inert ops but refuses real VM spawn (`tart clone`/`run`) unless set true.
   * Only set on a Mac with adequate RAM — never on the 16GB dev host.
   */
  allowVmSpawn?: boolean;
  /** KDK research-kernel oracle to boot, when configured (§4.1). */
  oracle?: "release" | "kasan" | "kfence";
}

/** Injectable command runner — defaults to a real `execFileSync` at call sites. */
export type CommandRunner = (bin: string, args: string[], stdin?: Uint8Array) => string;

export interface ShardSpec {
  shardId: number;
  /** Selector indices this shard owns (for crash attribution, §3.1). */
  selectors: number[];
  /** Privilege context the opener runs under (§3.2). */
  privilege: "sandbox" | "root";
}

export interface PanicReport {
  panicked: boolean;
  /** Raw panic log text harvested from the shared dir, if any. */
  log?: string;
}

export interface ShardRunResult {
  shardId: number;
  vmName: string;
  panic: PanicReport;
  /** Programs pushed to the guest this run. */
  programsRun: number;
}

const PROGRAM_FILE = "program.bin";
const RESULT_FILE = "result.bin";
const PANIC_GLOB = "panic-*.txt";

export class TartVmLane {
  private readonly tart: string;
  constructor(
    private readonly config: VmLaneConfig,
    private readonly run: CommandRunner = defaultRunner,
  ) {
    this.tart = config.tartBin ?? "tart";
  }

  /**
   * Refuse to do anything that boots a VM unless explicitly allowed. Returns a
   * structured reason so a caller can surface it instead of crashing the host.
   */
  preflight(): { ok: boolean; reason?: string } {
    if (!this.config.allowVmSpawn) {
      return {
        ok: false,
        reason:
          "VM spawn disabled (allowVmSpawn=false). Each macOS guest needs ~4–8GB RAM; " +
          "enable only on an Apple-Silicon Mac with adequate RAM, never the 16GB dev host.",
      };
    }
    return { ok: true };
  }

  /** Ephemeral VM name for a shard — distinct so panicked clones are discardable. */
  shardVmName(shardId: number): string {
    return `xnu-fuzz-shard-${shardId}-${process.pid}`;
  }

  /** `tart clone <golden> <ephemeral>` — a fresh disposable snapshot per shard. */
  cloneShard(shardId: number): string {
    this.assertSpawnable();
    const name = this.shardVmName(shardId);
    this.run(this.tart, ["clone", this.config.goldenImage, name]);
    return name;
  }

  /** `tart delete <ephemeral>` — discard a (possibly panicked) clone. */
  discardShard(vmName: string): void {
    this.run(this.tart, ["delete", vmName]);
  }

  /**
   * Run one shard end-to-end: clone → push program(s) to the in-guest opener →
   * wait for result/heartbeat or panic → harvest → discard. On a panic the
   * clone is thrown away and the caller re-clones for the next batch.
   */
  runShard(shard: ShardSpec, programs: (FuzzInput | ProgramCall)[][]): ShardRunResult {
    this.assertSpawnable();
    const vmName = this.cloneShard(shard.shardId);
    let programsRun = 0;
    let panic: PanicReport = { panicked: false };
    try {
      this.run(this.tart, ["run", "--no-graphics", `--dir=shared:${this.config.sharedDir}`, vmName]);
      for (const program of programs) {
        this.pushProgram(encodeProgram(program));
        programsRun++;
        panic = this.harvestPanic(vmName);
        if (panic.panicked) break;
      }
    } finally {
      this.discardShard(vmName);
    }
    return { shardId: shard.shardId, vmName, panic, programsRun };
  }

  /** Write the encoded program to the shared-folder channel the opener polls. */
  pushProgram(bytes: Uint8Array): void {
    this.run("cp", ["/dev/stdin", `${this.config.sharedDir}/${PROGRAM_FILE}`], bytes);
  }

  /** Harvest a panic from the shared dir (serial/diagnostic logs, §4.2). */
  harvestPanic(_vmName: string): PanicReport {
    const out = this.run("/bin/sh", [
      "-c",
      `cat ${this.config.sharedDir}/${PANIC_GLOB} 2>/dev/null || true`,
    ]);
    const log = out.trim();
    return log ? { panicked: true, log } : { panicked: false };
  }

  private assertSpawnable(): void {
    const pf = this.preflight();
    if (!pf.ok) throw new Error(`xnu-fuzz VM lane refused: ${pf.reason}`);
  }
}

function defaultRunner(bin: string, args: string[], stdin?: Uint8Array): string {
  return execFileSync(bin, args, {
    encoding: "utf8",
    input: stdin ? Buffer.from(stdin) : undefined,
    maxBuffer: 64 * 1024 * 1024,
  });
}

/**
 * Document exactly what a single real single-shard run needs and the command
 * sequence it would execute — the "built + documented, pending an Apple-Silicon
 * host with RAM" deliverable. Returns plain data so the CLI can print it.
 */
export function planSingleShardRun(config: VmLaneConfig): {
  prerequisites: string[];
  steps: string[];
  artifacts: { programChannel: string; resultChannel: string; panicLogs: string };
  warning: string;
} {
  const tart = config.tartBin ?? "tart";
  return {
    prerequisites: [
      "Apple-Silicon Mac with adequate RAM (each macOS guest ~4–8GB; do NOT use the 16GB dev host).",
      "tart installed (`brew install cirruslabs/cli/tart`).",
      `A golden macOS VM image "${config.goldenImage}" matching guest build "${config.guestBuild}" ` +
        "— selector indices and struct sizes drift across releases, so the VM must match the modeled kernelcache.",
      "The in-guest opener (opener/iokit-opener.c) compiled inside the guest and set to poll the shared folder.",
      config.oracle && config.oracle !== "release"
        ? `KDK ${config.oracle.toUpperCase()} research kernel installed in the guest + boot-args/SIP set to load it (§4.1).`
        : "Release kernel oracle (panic-only); install a KDK KASAN/KFENCE kernel for latent-bug detection (§4.1).",
      `A host-shared folder at "${config.sharedDir}" for the program/result channel and panic logs.`,
    ],
    steps: [
      `${tart} clone ${config.goldenImage} xnu-fuzz-shard-0   # disposable snapshot`,
      `${tart} run --no-graphics --dir=shared:${config.sharedDir} xnu-fuzz-shard-0`,
      `# host writes ${PROGRAM_FILE}; in-guest opener executes IOConnectCallMethod per call`,
      `# host reads ${RESULT_FILE} (per-call kern_return + out bytes) and watches ${PANIC_GLOB}`,
      `# on panic: harvest ${PANIC_GLOB} + serial log, then ${tart} delete xnu-fuzz-shard-0 and re-clone`,
    ],
    artifacts: {
      programChannel: `${config.sharedDir}/${PROGRAM_FILE}`,
      resultChannel: `${config.sharedDir}/${RESULT_FILE}`,
      panicLogs: `${config.sharedDir}/${PANIC_GLOB}`,
    },
    warning:
      "This lane spawns macOS VMs and WILL panic the guest kernel by design. Run it on a beefier " +
      "Apple-Silicon Mac, in VMs — never directly on the 16GB dev host (OOM-reboot risk).",
  };
}
