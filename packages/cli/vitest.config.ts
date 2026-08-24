import { defineConfig } from "vitest/config";

// Restrict discovery to source tests (mirrors packages/core/vitest.config.ts) —
// without an explicit include, vitest's default glob also picks up compiled
// test files under dist/, running everything twice.
//
// Raise the global timeout: the CLI suite's transform load is heavy
// (chat-screen.tsx et al.), so under a full `vitest run` a test doing real work
// mid-run (e.g. findings.ts's per-action `await import("@0sec/db")`) can exceed
// vitest's 5s default even though it passes in ~4s alone.
export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    testTimeout: 20_000,
  },
});
