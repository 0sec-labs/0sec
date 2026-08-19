import { defineConfig } from "vitest/config";
import { osecWorkspaceAliases } from "../../vitest.workspace-aliases.ts";

export default defineConfig({
  resolve: {
    alias: osecWorkspaceAliases,
  },
  test: {
    // Root-level runner modules (honest-eval.ts, exploit-runner.ts) live beside
    // the package root, outside the `src` rootDir tsc compiles; their tests sit
    // next to them.
    include: ["src/**/*.test.ts", "*.test.ts"],
  },
});
