import { describe, expect, it, vi } from "vitest";

import {
  createSyzCheckValidator,
  assertSemanticResult,
  statusMessage,
  defaultSyzProcessExecutor,
} from "./syz-check-validator.js";
import type { SyzProcessExecutor, SyzkallerSemanticResult } from "./syz-check-validator.js";
import type { SyzlangValidator } from "./spec-gen.js";

// ── Fixtures ──

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

// Structurally valid but semantically wrong — e.g. a type name that syz-check
// would reject because it references a nonexistent kernel definition.
const STRUCTURALLY_VALID_BUT_SEMANTICALLY_WRONG = [
  'resource fd_nonexistent[fd]',
  'ioctl$NOPE(fd fd_nonexistent, cmd const[NOPE_CMD], arg ptr[in, int32])',
].join("\n");

// Manifestly structurally invalid — the semantic validator should not shell out.
const STRUCTURALLY_INVALID_SPEC = [
  'resource fd_gpio[fd]',
  'ioctl$GPIO_GET_CHIPINFO_IOCTL(fd fd_gpio, cmd const[GPIO_GET_CHIPINFO_IOCTL]', // missing `)`
].join("\n");

// ── Fake process executors ──

/** Executor that returns status 0 — syz-check accepted the spec. */
function fakeExecutorSuccess(): SyzProcessExecutor {
  return (_args, _opts) => ({ stdout: "", stderr: "", status: 0 });
}

/** Executor that returns non-zero with parseable syz-check stderr. */
function fakeExecutorReject(
  stderrLines: string[] = [
    "input.txt:1: undefined type \"NOPE_CMD\"",
    "input.txt:2: unknown field \"nonexistent\"",
  ],
): SyzProcessExecutor {
  return (_args, _opts) => ({
    stdout: "",
    stderr: stderrLines.join("\n"),
    status: 1,
  });
}

/**
 * Executor that returns non-zero with no parseable error lines — an
 * abnormal rejection the validator falls back to wrapping.
 */
function fakeExecutorAbnormalReject(): SyzProcessExecutor {
  return (_args, _opts) => ({
    stdout: "",
    stderr: "syz-check: internal error: cannot open archive",
    status: 2,
  });
}

/**
 * Executor that throws ENOENT — the syz-check binary doesn't exist.
 * This is the ONLY reason the executor throws (launch failure).
 */
function fakeExecutorMissing(): SyzProcessExecutor {
  const err = new Error("spawn syz-check ENOENT") as NodeJS.ErrnoException;
  err.code = "ENOENT";
  err.message = "spawn syz-check ENOENT";
  return (_args, _opts) => { throw err; };
}

/**
 * Executor that throws EACCES — binary exists but is not executable.
 */
function fakeExecutorNotExecutable(): SyzProcessExecutor {
  const err = new Error("spawn syz-check EACCES") as NodeJS.ErrnoException;
  err.code = "EACCES";
  err.message = "spawn syz-check EACCES";
  return (_args, _opts) => { throw err; };
}

// ── Tests ──

describe("createSyzCheckValidator", () => {
  it("returns valid when the executor returns status 0", () => {
    const validator = createSyzCheckValidator({
      executor: fakeExecutorSuccess(),
    });
    const result = validator(VALID_SPEC) as SyzkallerSemanticResult;
    expect(result.status).toBe("valid");
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  it("returns invalid when the executor returns non-zero with parseable syz-check stderr", () => {
    const validator = createSyzCheckValidator({
      executor: fakeExecutorReject(),
    });
    const result = validator(
      STRUCTURALLY_VALID_BUT_SEMANTICALLY_WRONG,
    ) as SyzkallerSemanticResult;
    expect(result.status).toBe("invalid");
    expect(result.valid).toBe(false);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0].line).toBe(1);
    expect(result.errors[0].message).toContain("undefined type");
  });

  it("returns invalid with a fallback error when stderr lacks parseable syz-check lines", () => {
    const validator = createSyzCheckValidator({
      executor: fakeExecutorAbnormalReject(),
    });
    const result = validator(
      STRUCTURALLY_VALID_BUT_SEMANTICALLY_WRONG,
    ) as SyzkallerSemanticResult;
    expect(result.status).toBe("invalid");
    expect(result.valid).toBe(false);
    expect(result.errors[0].line).toBe(0);
    expect(result.errors[0].message).toContain("syz-check rejected spec");
  });

  it("returns toolchain-unavailable when the executor throws ENOENT", () => {
    const validator = createSyzCheckValidator({
      executor: fakeExecutorMissing(),
    });
    const result = validator(VALID_SPEC) as SyzkallerSemanticResult;
    expect(result.status).toBe("toolchain-unavailable");
    expect(result.valid).toBe(false);
    expect(result.errors[0].message).toContain("cannot execute");
  });

  it("returns toolchain-unavailable when the executor throws EACCES", () => {
    const validator = createSyzCheckValidator({
      executor: fakeExecutorNotExecutable(),
    });
    const result = validator(VALID_SPEC) as SyzkallerSemanticResult;
    expect(result.status).toBe("toolchain-unavailable");
    expect(result.valid).toBe(false);
    expect(result.errors[0].message).toContain("cannot execute");
  });

  it("returns structural errors without invoking the executor for structurally invalid input", () => {
    const executorSpy = vi.fn(fakeExecutorSuccess()) as unknown as SyzProcessExecutor;
    const validator = createSyzCheckValidator({ executor: executorSpy });
    const result = validator(STRUCTURALLY_INVALID_SPEC) as SyzkallerSemanticResult;
    expect(result.valid).toBe(false);
    expect(result.status).toBe("invalid");
    // Structural errors: unbalanced brackets.
    expect(result.errors.some((e) => /unbalanced/.test(e.message))).toBe(true);
    // Executor must NOT have been called.
    expect(executorSpy).not.toHaveBeenCalled();
  });

  it("passes extraArgs and temp-file path as array-shaped args to the executor", () => {
    const executorSpy = vi.fn(fakeExecutorSuccess()) as unknown as SyzProcessExecutor;
    const validator = createSyzCheckValidator({
      extraArgs: ["-arch", "amd64"],
      executor: executorSpy,
    });
    validator(VALID_SPEC);

    expect(executorSpy).toHaveBeenCalledOnce();
    const [args, options] = executorSpy.mock.calls[0];
    // args is an array — proves array-shaped argument passing
    expect(Array.isArray(args)).toBe(true);
    expect(args).toContain("-arch");
    expect(args).toContain("amd64");
    // Last argument is the temp-file path — ends with "input.txt"
    expect(args[args.length - 1]).toMatch(/input\.txt$/);
    // options is a plain object with required fields
    expect(options).toHaveProperty("cwd");
    expect(options).toHaveProperty("encoding", "utf-8");
  });

  it("satisfies the SyzlangValidator type contract (valid: boolean + errors)", () => {
    const validator: SyzlangValidator = createSyzCheckValidator({
      executor: fakeExecutorSuccess(),
    });
    // SyzlangValidator accepts both sync and async returns.
    const result = validator(VALID_SPEC);
    expect(result).toHaveProperty("valid");
    expect(result).toHaveProperty("errors");
    expect(Array.isArray(result.errors)).toBe(true);
  });
});

describe("assertSemanticResult", () => {
  it("passes for a result with status", () => {
    const r: SyzkallerSemanticResult = {
      status: "valid",
      valid: true,
      errors: [],
    };
    expect(() => assertSemanticResult(r)).not.toThrow();
  });

  it("throws for a plain SyzlangValidationResult without status", () => {
    const r = { valid: false, errors: [{ line: 0, message: "bad" }] };
    expect(() => assertSemanticResult(r)).toThrow("missing `status` discriminant");
  });
});

describe("statusMessage", () => {
  it("returns a readable string for each status", () => {
    const valid: SyzkallerSemanticResult = { status: "valid", valid: true, errors: [] };
    expect(statusMessage(valid)).toContain("valid");

    const invalid: SyzkallerSemanticResult = {
      status: "invalid", valid: false,
      errors: [{ line: 1, message: "unknown type" }],
    };
    expect(statusMessage(invalid)).toContain("unknown type");

    const noTool: SyzkallerSemanticResult = {
      status: "toolchain-unavailable", valid: false,
      errors: [{ line: 0, message: "cannot execute syz-check: ENOENT" }],
    };
    expect(statusMessage(noTool)).toContain("unavailable");

    const execErr: SyzkallerSemanticResult = {
      status: "execution-error", valid: false,
      errors: [{ line: 0, message: "syz-check terminated by signal: SIGSEGV" }],
    };
    expect(statusMessage(execErr)).toContain("execution error");
  });
});

describe("defaultSyzProcessExecutor", () => {
  it("is exported and throws on a nonexistent PATH-resolved syz-check (smoke)", () => {
    // The default executor always spawns the literal "syz-check" binary via
    // argument arrays — no shell interpolation, no injectable executable.
    expect(() =>
      defaultSyzProcessExecutor(
        ["--version"],
        { cwd: "/tmp", encoding: "utf-8", maxBuffer: 1024, timeout: 1000 },
      ),
    ).toThrow();
  });
});