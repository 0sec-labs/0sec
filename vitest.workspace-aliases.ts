import { fileURLToPath } from "node:url";

const fromRoot = (path: string): string => fileURLToPath(new URL(path, import.meta.url));

// Resolve workspace deps to TypeScript source so tests do not depend on stale
// or missing dist output from sibling packages.
export const osecWorkspaceAliases = {
  "@0sec/benchmark/kernel-weaponization-collector": fromRoot(
    "./packages/benchmark/src/kernel-weaponization-collector.ts",
  ),
  "@0sec/benchmark/bench-integrations": fromRoot(
    "./packages/benchmark/src/bench-integrations/index.ts",
  ),
  "@0sec/core": fromRoot("./packages/core/src/index.ts"),
  "@0sec/db": fromRoot("./packages/db/src/index.ts"),
  "@0sec/shared": fromRoot("./packages/shared/src/index.ts"),
  "@0sec/templates": fromRoot("./packages/templates/src/index.ts"),
};
