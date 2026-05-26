import { defineConfig } from "vitest/config";
import { pwnkitWorkspaceAliases } from "../vitest.workspace-aliases.ts";

export default defineConfig({
  resolve: {
    alias: pwnkitWorkspaceAliases,
  },
  test: {
    include: ["src/**/*.test.ts"],
  },
});
