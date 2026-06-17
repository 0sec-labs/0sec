import { describe, expect, it } from "vitest";

import type {
  NativeMessage,
  NativeRuntime,
  NativeRuntimeResult,
  NativeToolDef,
} from "../runtime/types.js";
import {
  generateSyzlangSpec,
  structurallyValidateSyzlang,
  extractSyzlang,
} from "./spec-gen.js";

// ── Fixtures: representative driver-ioctl syzlang (KernelGPT-shaped) ──

const VALID_SPEC = [
  'resource fd_gpio[fd]',
  'syz_open_dev$KGPT_gpiochip(dev ptr[in, string["/dev/gpiochip#"]], id proc[0, 1], flags flags[open_flags]) fd_gpio',
  'ioctl$GPIO_GET_CHIPINFO_IOCTL(fd fd_gpio, cmd const[GPIO_GET_CHIPINFO_IOCTL], arg ptr[out, gpiochip_info])',
  'gpiochip_info {',
  '\tname\tarray[int8, 32]',
  '\tlabel\tarray[int8, 32]',
  '\tlines\tint32',
  '}',
].join("\n");

// Unbalanced brackets + an unknown type + an arg missing its type.
const INVALID_SPEC = [
  'resource fd_gpio[fd]',
  'ioctl$GPIO_GET_CHIPINFO_IOCTL(fd fd_gpio, cmd, arg ptr[out, gpiochip_info]', // missing `)` and `cmd` has no type
  'gpiochip_info {',
  '\tname\tarray[mystery_t, 32]', // mystery_t is undeclared
  '}',
].join("\n");

/**
 * A scripted NativeRuntime: returns each queued response in turn, wrapping it
 * in a ```syzlang fenced block the way a real model would. Records prompts so
 * we can assert the repair prompt carried the validation error.
 */
function mockLlm(responses: string[]): NativeRuntime & { prompts: string[] } {
  const prompts: string[] = [];
  let i = 0;
  return {
    type: "api",
    prompts,
    async executeNative(
      _system: string,
      messages: NativeMessage[],
      _tools: NativeToolDef[],
    ): Promise<NativeRuntimeResult> {
      const text = messages[0].content
        .map((b) => (b.type === "text" ? b.text : ""))
        .join("");
      prompts.push(text);
      const body = responses[Math.min(i, responses.length - 1)];
      i++;
      return {
        content: [{ type: "text", text: "```syzlang\n" + body + "\n```" }],
        stopReason: "end_turn",
        durationMs: 1,
      };
    },
    async isAvailable() {
      return true;
    },
  };
}

describe("structurallyValidateSyzlang", () => {
  it("accepts a well-formed driver-ioctl spec", () => {
    const r = structurallyValidateSyzlang(VALID_SPEC);
    expect(r.valid).toBe(true);
    expect(r.errors).toEqual([]);
  });

  it("rejects unbalanced brackets", () => {
    const r = structurallyValidateSyzlang(
      "ioctl$FOO(fd fd_x, arg ptr[in, bar]\nbar {\n\tx\tint32\n}",
    );
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => /unbalanced/.test(e.message))).toBe(true);
  });

  it("rejects an unknown type reference", () => {
    const r = structurallyValidateSyzlang(
      "ioctl$FOO(fd fd_x, arg ptr[in, mystery_t])\nresource fd_x[fd]",
    );
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => /unknown type `mystery_t`/.test(e.message))).toBe(
      true,
    );
  });

  it("rejects a malformed arg missing its type", () => {
    const r = structurallyValidateSyzlang(
      "ioctl$FOO(fd fd_x, cmd)\nresource fd_x[fd]",
    );
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => /malformed arg/.test(e.message))).toBe(true);
  });

  it("rejects a spec with no syscall declaration", () => {
    const r = structurallyValidateSyzlang("resource fd_x[fd]");
    expect(r.valid).toBe(false);
    expect(r.errors.some((e) => /no syscall/.test(e.message))).toBe(true);
  });

  it("rejects the empty spec", () => {
    expect(structurallyValidateSyzlang("   ").valid).toBe(false);
  });
});

describe("extractSyzlang", () => {
  it("pulls the body out of a ```syzlang fence", () => {
    expect(extractSyzlang("blah\n```syzlang\nfoo(a int8)\n```\ntail")).toBe(
      "foo(a int8)",
    );
  });
});

describe("generateSyzlangSpec repair loop", () => {
  it("converges: invalid first, valid second → returns the valid spec", async () => {
    const llm = mockLlm([INVALID_SPEC, VALID_SPEC]);

    const result = await generateSyzlangSpec(
      "drivers/gpio",
      "static const struct file_operations gpio_fileops = { .unlocked_ioctl = lineinfo_ioctl };",
      llm,
    );

    expect(result.ok).toBe(true);
    expect(result.spec).toBe(VALID_SPEC);
    expect(result.iterations).toBe(2);
    expect(result.errors).toEqual([]);

    // The second (repair) prompt must have carried the validation errors back.
    expect(llm.prompts).toHaveLength(2);
    expect(llm.prompts[1]).toMatch(/Validation errors/);
    expect(llm.prompts[1]).toMatch(/malformed arg|unbalanced|unknown type/);
  });

  it("gives up after maxIterations and reports the last errors", async () => {
    const llm = mockLlm([INVALID_SPEC]); // always invalid

    const result = await generateSyzlangSpec("drivers/gpio", "src", llm, {
      maxIterations: 3,
    });

    expect(result.ok).toBe(false);
    expect(result.iterations).toBe(3);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(llm.prompts).toHaveLength(3);
  });

  it("honors a pluggable validator (the syz-check drop-in point)", async () => {
    const llm = mockLlm([VALID_SPEC]);
    let called = 0;
    const result = await generateSyzlangSpec("drivers/gpio", "src", llm, {
      validator: () => {
        called++;
        return { valid: true, errors: [] };
      },
    });
    expect(called).toBe(1);
    expect(result.ok).toBe(true);
    expect(result.iterations).toBe(1);
  });
});
