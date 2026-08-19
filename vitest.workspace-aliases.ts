import { fileURLToPath } from "node:url";

const fromRoot = (path: string): string => fileURLToPath(new URL(path, import.meta.url));

// Resolve workspace deps to TypeScript source so tests do not depend on stale
// or missing dist output from sibling packages.
export const pwnkitWorkspaceAliases = {
  "@pwnkit/benchmark/kernel-weaponization-collector": fromRoot(
    "./packages/benchmark/src/kernel-weaponization-collector.ts",
  ),
  "@pwnkit/core": fromRoot("./packages/core/src/index.ts"),
  "@pwnkit/db": fromRoot("./packages/db/src/index.ts"),
  "@pwnkit/shared": fromRoot("./packages/shared/src/index.ts"),
  "@pwnkit/templates": fromRoot("./packages/templates/src/index.ts"),
};
