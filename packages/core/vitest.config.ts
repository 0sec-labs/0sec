import { defineConfig } from "vitest/config";
import { osecWorkspaceAliases } from "../../vitest.workspace-aliases.ts";

export default defineConfig({
  resolve: {
    alias: osecWorkspaceAliases,
  },
  test: {
    include: ["src/**/*.test.ts"],
    // The suite contains CPU-heavy property and integration tests. Two workers
    // keep SQLite and native-addon tests below their five-second behavioral
    // deadlines on the shared CI runner; four still starved unrelated tests.
    maxWorkers: 2,
  },
});
