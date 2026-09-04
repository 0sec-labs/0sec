import { chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const packageDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const workspaceRoot = resolve(packageDirectory, "../..");
const resourcesDirectory = join(packageDirectory, "resources");
const dashboardSource = join(workspaceRoot, "packages", "dashboard", "dist");

function sidecarFileName(platform = process.platform, arch = process.arch) {
  if (arch !== "x64" && arch !== "arm64") {
    throw new Error(`Unsupported desktop architecture: ${arch}`);
  }
  switch (platform) {
    case "linux":
    case "darwin":
      return `0sec-${platform}-${arch}`;
    case "win32":
      return `0sec-windows-${arch}.exe`;
    default:
      throw new Error(`Unsupported desktop platform: ${platform}`);
  }
}

if (!existsSync(join(dashboardSource, "index.html"))) {
  throw new Error("Dashboard build is missing. Run pnpm --filter @0sec/dashboard build before packaging desktop.");
}

const sidecarName = sidecarFileName();
const sidecarSource = join(workspaceRoot, "dist-bin", sidecarName);
if (!existsSync(sidecarSource)) {
  throw new Error(
    `Desktop sidecar is missing at ${sidecarSource}. Build it with: bash scripts/bun-compile.sh \"\" \"dist-bin/${sidecarName}\"`,
  );
}

rmSync(resourcesDirectory, { force: true, recursive: true });
mkdirSync(resourcesDirectory, { recursive: true, mode: 0o700 });
cpSync(dashboardSource, join(resourcesDirectory, "dashboard"), { recursive: true });
mkdirSync(join(resourcesDirectory, "sidecars"), { recursive: true, mode: 0o700 });
const sidecarDestination = join(resourcesDirectory, "sidecars", sidecarName);
copyFileSync(sidecarSource, sidecarDestination);
chmodSync(sidecarDestination, 0o755);

console.log(`Prepared desktop resources for ${process.platform}-${process.arch}.`);
