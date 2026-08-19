import { describe, it, expect } from "vitest";
import {
  synthesizeHarness,
  type HarnessTarget,
  type HarnessRunner,
  type HarnessSynthModel,
  type HarnessProgram,
  type HarnessRunResult,
} from "./harness-synth.js";

const kernelTarget: HarnessTarget = {
  domain: "kernel-ioctl",
  sink: "foo_ioctl_handler+0x40",
  context: "static long foo_ioctl(struct file *f, unsigned cmd, unsigned long arg) { ... }",
  devicePath: "/dev/foo",
  ioctlCode: "0x1234",
  initHandshake: "FOO_INIT ioctl must run first to allocate ctx",
};

const windowsTarget: HarnessTarget = {
  domain: "windows-ioctl",
  sink: "DispatchDeviceControl+0x88",
  context: "NTSTATUS DispatchDeviceControl(...) { if (code == 0x222004) memcpy(out, in, in_len); }",
  devicePath: "\\\\.\\FooDevice",
  ioctlCode: "0x222004",
  argStructLayout: "struct { uint32 len; uint8 buf[0]; }",
};

function prog(source = "int main(){ return 0; }", lang: HarnessProgram["lang"] = "c"): HarnessProgram {
  return { lang, source };
}

/** Build a runner from a scripted sequence of results, one per attempt. */
function scriptedRunner(seq: HarnessRunResult[]): HarnessRunner {
  let i = 0;
  return async () => seq[Math.min(i++, seq.length - 1)]!;
}

const alwaysEmit: HarnessSynthModel = async () => prog();

describe("synthesizeHarness", () => {
  it("escalates reach→refine and returns reached-and-crashed on the win", async () => {
    // attempt 0 (reach): reached → escalate. attempt 1 (refine): reached + crashed.
    const runner = scriptedRunner([
      { built: true, reached: true, crashed: false },
      { built: true, reached: true, crashed: true, crashOutput: "BUG: KASAN: slab-out-of-bounds" },
    ]);
    const r = await synthesizeHarness(kernelTarget, alwaysEmit, runner);
    expect(r.status).toBe("reached-and-crashed");
    expect(r.crashOutput).toMatch(/KASAN/);
    // First attempt was reach phase, second was refine.
    expect(r.attempts[0]!.phase).toBe("reach");
    expect(r.attempts[1]!.phase).toBe("refine");
  });

  it("feeds coverage feedback back into the next prompt", async () => {
    const prompts: string[] = [];
    const model: HarnessSynthModel = async (p) => {
      prompts.push(p);
      return prog();
    };
    const runner = scriptedRunner([
      { built: true, reached: false, coverageFeedback: "returned -EINVAL at foo_ioctl+0x20 — handshake missing" },
      { built: true, reached: true, crashed: true, crashOutput: "crash" },
    ]);
    // twoPhase off so the first reached+crashed wins immediately on attempt 1.
    const r = await synthesizeHarness(kernelTarget, model, runner, { twoPhase: false });
    expect(r.status).toBe("reached-and-crashed");
    // The 2nd prompt must carry the feedback from the 1st run.
    expect(prompts[1]).toMatch(/handshake missing/);
  });

  it("banks a reached-but-benign harness for the N× / bounded-check path", async () => {
    const runner = scriptedRunner([{ built: true, reached: true, crashed: false }]);
    const r = await synthesizeHarness(windowsTarget, alwaysEmit, runner, { twoPhase: false, maxAttempts: 1 });
    expect(r.status).toBe("reached");
    expect(r.harness).toBeDefined();
  });

  it("reports not-reached when the sink is never landed within budget", async () => {
    const runner = scriptedRunner([{ built: true, reached: false, coverageFeedback: "stalled at arg check" }]);
    const r = await synthesizeHarness(kernelTarget, alwaysEmit, runner, { maxAttempts: 3 });
    expect(r.status).toBe("not-reached");
    expect(r.attempts).toHaveLength(3);
  });

  it("reports no-harness when the model never emits one", async () => {
    const runner = scriptedRunner([{ built: false, reached: false }]);
    const r = await synthesizeHarness(kernelTarget, async () => null, runner, { maxAttempts: 2 });
    expect(r.status).toBe("no-harness");
  });

  it("survives a runner throw without aborting the loop", async () => {
    let call = 0;
    const runner: HarnessRunner = async () => {
      call++;
      if (call === 1) throw new Error("qemu boot failed");
      return { built: true, reached: true, crashed: true, crashOutput: "crash" };
    };
    const r = await synthesizeHarness(kernelTarget, alwaysEmit, runner, { twoPhase: false });
    expect(r.status).toBe("reached-and-crashed");
    expect(r.attempts[0]!.note).toMatch(/runner error/);
  });

  it("survives a model throw without aborting the loop", async () => {
    let call = 0;
    const model: HarnessSynthModel = async () => {
      call++;
      if (call === 1) throw new Error("model timeout");
      return prog();
    };
    const runner = scriptedRunner([{ built: true, reached: true, crashed: true, crashOutput: "crash" }]);
    const r = await synthesizeHarness(kernelTarget, model, runner, { twoPhase: false });
    expect(r.status).toBe("reached-and-crashed");
  });
});
