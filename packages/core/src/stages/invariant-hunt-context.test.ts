/**
 * invariant-hunt-context — the Engine A → seeded-hunt adapter (`--invariant`).
 *
 * Proven here against a synthetic C fixture in a real temp tree:
 *   (a) deriveSubsystemScope recovers the plurality touched dir from `diff --git`
 *       headers (and the `+++ b/` fallback), and returns null on unscoped input.
 *   (b) formatInvariantPromptBlock renders the model rules + violation hypotheses
 *       as ONE bounded context block (pure function — the injection shape).
 *   (c) buildInvariantHuntContext runs build-or-load + the deterministic checker
 *       end-to-end (LLM mocked at `../runtime/llm-api.js`, checker REAL): the
 *       prompt block carries the modeled rules and a concrete file:line
 *       hypothesis, the model artifact lands at the derived default path, and a
 *       second call LOADS it (no second LLM call — the compounding property).
 *   (d) fail-open: an unscoped seed or a missing subsystem dir yields null, so
 *       the CLI degrades to the plain seeded hunt.
 */

import { existsSync, mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// LLM boundary — used only by the one-time model build inside the stage.
const executeNativeMock = vi.fn();
vi.mock("../runtime/llm-api.js", () => ({
  LlmApiRuntime: class {
    executeNative(...args: unknown[]) {
      return executeNativeMock(...args);
    }
  },
}));

const {
  deriveSubsystemScope,
  buildInvariantHuntContext,
  formatInvariantPromptBlock,
} = await import("./invariant-hunt-context.js");
const { INVARIANT_MODEL_VERSION } = await import("./subsystem-invariant-model.js");
type InvariantModel = import("./subsystem-invariant-model.js").InvariantModel;
type InvariantViolation = import("./subsystem-invariant-model.js").InvariantViolation;

// ── Fixture: net/unix-ish subsystem, one compliant path and two known-bad ones ──
const AF_UNIX_C = `
struct unix_sock {
	spinlock_t lock;
	int state;
	int refs;
};

/* COMPLIANT: holds sk->lock while touching ->state. Must NOT be flagged. */
void unix_set_state(struct unix_sock *sk, int s)
{
	spin_lock(&sk->lock);
	sk->state = s;
	spin_unlock(&sk->lock);
}

/* VIOLATION (unlocked-field-access): reads ->state with no sk->lock. */
int unix_peek_state(struct unix_sock *sk)
{
	return sk->state;
}

/* VIOLATION (use-after-free-order): kfree(sk) then sk->state. */
void unix_free_and_use(struct unix_sock *sk)
{
	kfree(sk);
	sk->state = 0;
}
`;

const GARBAGE_C = `
/* Small sibling the seed fix touches. */
int unix_gc_enabled = 1;
`;

const SEED_DIFF = `diff --git a/net/unix/garbage.c b/net/unix/garbage.c
index 1111111..2222222 100644
--- a/net/unix/garbage.c
+++ b/net/unix/garbage.c
@@ -1,2 +1,3 @@
 /* Small sibling the seed fix touches. */
+/* hardened */
 int unix_gc_enabled = 1;
diff --git a/include/net/af_unix.h b/include/net/af_unix.h
index 3333333..4444444 100644
--- a/include/net/af_unix.h
+++ b/include/net/af_unix.h
@@ -1,1 +1,1 @@
-/* old decl */
+/* new decl */
`;

const MODEL_OBJECT = {
  object: "struct unix_sock",
  allocSite: "unix_create1",
  freeSite: "unix_sock_destructor",
  lockRules: [{ lock: "sk->lock", guardedFields: ["state"], acquireFns: ["spin_lock"] }],
  refcountRules: [{ name: "unix_sock refs", getFn: "unix_sock_get", putFn: "unix_sock_put" }],
  lifecycleRules: [{ freeFn: "kfree", note: "frees struct unix_sock" }],
  initOrder: ["state"],
};

function makeSourceRoot(): string {
  const root = mkdtempSync(join(tmpdir(), "invctx-"));
  mkdirSync(join(root, "net", "unix"), { recursive: true });
  writeFileSync(join(root, "net", "unix", "af_unix.c"), AF_UNIX_C, "utf8");
  writeFileSync(join(root, "net", "unix", "garbage.c"), GARBAGE_C, "utf8");
  return root;
}

function mockModelLlm(): void {
  executeNativeMock.mockReset().mockResolvedValue({
    content: [{ type: "tool_use", name: "emit_invariant_model", input: { objects: [MODEL_OBJECT], notes: "test model" } }],
  });
}

beforeEach(() => mockModelLlm());
afterEach(() => vi.restoreAllMocks());

// ── (a) scope derivation ─────────────────────────────────────────────────────────
describe("deriveSubsystemScope", () => {
  it("picks the plurality touched dir from diff --git headers", () => {
    const scope = deriveSubsystemScope(SEED_DIFF);
    expect(scope).not.toBeNull();
    expect(scope!.subsystem).toBe("net/unix");
    expect(scope!.touchedFiles).toEqual(["net/unix/garbage.c"]);
  });

  it("falls back to +++ b/ lines when no diff --git header exists", () => {
    const diff = `--- a/net/nfc/llcp/core.c\n+++ b/net/nfc/llcp/core.c\n@@ -1 +1 @@\n-a\n+b\n`;
    expect(deriveSubsystemScope(diff)?.subsystem).toBe("net/nfc/llcp");
  });

  it("returns null when no repo-relative path with a directory is recoverable", () => {
    expect(deriveSubsystemScope("not a diff at all\njust prose")).toBeNull();
    expect(deriveSubsystemScope("diff --git a/Makefile b/Makefile\n")).toBeNull();
  });

  it.each([
    "../outside/secret.c",
    "net/../../outside/secret.c",
    "net\\..\\outside\\secret.c",
    "/tmp/outside/secret.c",
    "C:\\Windows\\secret.c",
    "net//secret.c",
    "net/./secret.c",
    "./net/secret.c",
  ])("rejects non-canonical or absolute diff path %s", (path) => {
    const diff = `diff --git a/net/safe.c b/${path}\n+++ b/${path}\n`;
    expect(deriveSubsystemScope(diff)).toBeNull();
  });
});

// ── (b) prompt-block shape (pure function) ───────────────────────────────────────
describe("formatInvariantPromptBlock", () => {
  const model: InvariantModel = {
    modelVersion: INVARIANT_MODEL_VERSION,
    subsystem: "net/unix",
    subsystemFiles: ["net/unix/af_unix.c"],
    objects: [MODEL_OBJECT],
    builtAt: new Date().toISOString(),
  };
  const violations: InvariantViolation[] = [
    {
      kind: "unlocked-field-access",
      object: "struct unix_sock",
      file: "net/unix/af_unix.c",
      line: 17,
      functionName: "unix_peek_state",
      invariant: "field 'state' of struct unix_sock must only be accessed while holding sk->lock",
      detail: "test",
    },
  ];

  it("carries the modeled rules, the file:line hypothesis, and the UNVERIFIED directive", () => {
    const block = formatInvariantPromptBlock(model, violations, { modelLoaded: true });
    expect(block).toContain("INVARIANT MODEL of net/unix");
    expect(block).toContain("lock `sk->lock` guards [state]");
    expect(block).toContain("refcount unix_sock_get()/unix_sock_put() must balance");
    expect(block).toContain("no use after kfree()");
    expect(block).toContain("UNLOCKED FIELD ACCESS: net/unix/af_unix.c:17 in unix_peek_state()");
    expect(block).toContain("UNVERIFIED");
  });

  it("bounds the block even with a huge model", () => {
    const big: InvariantModel = {
      ...model,
      objects: Array.from({ length: 50 }, (_, i) => ({
        ...MODEL_OBJECT,
        object: `struct obj_${i}_with_a_rather_long_name_to_fill_space`,
      })),
    };
    const block = formatInvariantPromptBlock(big, violations);
    expect(block.length).toBeLessThanOrEqual(6_100);
    expect(block).toContain("truncated");
  });
});

// ── (c) end-to-end context build (LLM mocked, checker + filesystem real) ─────────
describe("buildInvariantHuntContext", () => {
  it("builds the model, flags the known violations, stores the artifact, then LOADS it", async () => {
    const root = makeSourceRoot();

    const ctx = await buildInvariantHuntContext({ sourceRoot: root, seedDiff: SEED_DIFF, runtime: "api" });
    expect(ctx).not.toBeNull();
    expect(ctx!.subsystem).toBe("net/unix");
    // Touched file first, then siblings by size (af_unix.c > garbage.c).
    expect(ctx!.subsystemFiles).toEqual(["net/unix/garbage.c", "net/unix/af_unix.c"]);
    expect(ctx!.modelLoaded).toBe(false);
    expect(executeNativeMock).toHaveBeenCalledTimes(1);

    // The REAL deterministic checker flagged the two known-bad paths in af_unix.c.
    const fns = ctx!.violations.map((v) => v.functionName);
    expect(fns).toContain("unix_peek_state");
    expect(fns).toContain("unix_free_and_use");
    expect(fns).not.toContain("unix_set_state");

    // The prompt block is the finder-injection shape.
    expect(ctx!.promptBlock).toContain("INVARIANT MODEL of net/unix");
    expect(ctx!.promptBlock).toContain("net/unix/af_unix.c:");

    // Model artifact at the derived default path, under the tree it models.
    const expectedPath = join(root, ".0sec", "invariant-models", "net__unix.json");
    expect(ctx!.modelPath).toBe(expectedPath);
    expect(existsSync(expectedPath)).toBe(true);

    // Second call LOADS the stored model — no second LLM call.
    executeNativeMock.mockClear();
    const ctx2 = await buildInvariantHuntContext({ sourceRoot: root, seedDiff: SEED_DIFF, runtime: "api" });
    expect(ctx2!.modelLoaded).toBe(true);
    expect(executeNativeMock).not.toHaveBeenCalled();
    expect(ctx2!.violations.length).toBe(ctx!.violations.length);
  });

  it("returns null when the seed has no derivable scope (fail-open)", async () => {
    const root = makeSourceRoot();
    const ctx = await buildInvariantHuntContext({ sourceRoot: root, seedDiff: "prose, not a diff", runtime: "api" });
    expect(ctx).toBeNull();
    expect(executeNativeMock).not.toHaveBeenCalled();
  });

  it("returns null when the derived subsystem dir does not exist (fail-open)", async () => {
    const root = makeSourceRoot();
    const diff = `diff --git a/drivers/gpu/thing.c b/drivers/gpu/thing.c\n--- a/drivers/gpu/thing.c\n+++ b/drivers/gpu/thing.c\n`;
    const ctx = await buildInvariantHuntContext({ sourceRoot: root, seedDiff: diff, runtime: "api" });
    expect(ctx).toBeNull();
    expect(executeNativeMock).not.toHaveBeenCalled();
  });

  it("does not enumerate or read the concrete outside-tree sentinel from a crafted seed diff", async () => {
    const root = makeSourceRoot();
    const outside = mkdtempSync(join(tmpdir(), "invctx-outside-"));
    const outsideFile = join(outside, "secret.c");
    const sentinel = "0SEC_OUTSIDE_TREE_SENTINEL_7f57a4";
    writeFileSync(outsideFile, `/* ${sentinel} */\nint secret;\n`, "utf8");
    const traversal = relative(root, outsideFile).replaceAll("\\", "/");
    expect(traversal).toMatch(/^\.\.\//);
    const diff = `diff --git a/net/unix/garbage.c b/${traversal}\n+++ b/${traversal}\n`;

    const ctx = await buildInvariantHuntContext({ sourceRoot: root, seedDiff: diff, runtime: "api" });

    expect(ctx).toBeNull();
    expect(executeNativeMock).not.toHaveBeenCalled();
  });

  it("rejects a canonical-looking subsystem directory symlink that escapes sourceRoot", async () => {
    const root = makeSourceRoot();
    const outside = mkdtempSync(join(tmpdir(), "invctx-symlink-dir-"));
    writeFileSync(join(outside, "secret.c"), "int outside_secret;\n", "utf8");
    mkdirSync(join(root, "drivers"), { recursive: true });
    symlinkSync(outside, join(root, "drivers", "leak"), "dir");
    const diff = `diff --git a/drivers/leak/secret.c b/drivers/leak/secret.c\n+++ b/drivers/leak/secret.c\n`;

    const ctx = await buildInvariantHuntContext({ sourceRoot: root, seedDiff: diff, runtime: "api" });

    expect(ctx).toBeNull();
    expect(executeNativeMock).not.toHaveBeenCalled();
  });

  it("filters an outside-tree .c symlink during safe subsystem enumeration", async () => {
    const root = makeSourceRoot();
    const outside = mkdtempSync(join(tmpdir(), "invctx-symlink-file-"));
    const outsideFile = join(outside, "secret.c");
    const sentinel = "0SEC_SYMLINK_ESCAPE_SENTINEL_d18c38";
    writeFileSync(outsideFile, `/* ${sentinel} */\nint secret;\n`, "utf8");
    symlinkSync(outsideFile, join(root, "net", "unix", "leak.c"), "file");

    const ctx = await buildInvariantHuntContext({ sourceRoot: root, seedDiff: SEED_DIFF, runtime: "api" });

    expect(ctx).not.toBeNull();
    expect(ctx!.subsystemFiles).not.toContain("net/unix/leak.c");
    expect(JSON.stringify(executeNativeMock.mock.calls)).not.toContain(sentinel);
  });
});
