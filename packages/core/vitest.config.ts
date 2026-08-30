import { defineConfig } from "vitest/config";
import { osecWorkspaceAliases } from "../../vitest.workspace-aliases.ts";

export default defineConfig({
  resolve: {
    alias: osecWorkspaceAliases,
  },
  test: {
    include: ["src/**/*.test.ts"],
    // The suite contains CPU-heavy property and integration tests. Bound worker
    // contention so each test's five-second deadline measures work, not queueing
    // on the shared self-hosted runner.
    maxWorkers: 4,
  },
});
