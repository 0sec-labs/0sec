import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import test from "node:test";

const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..");

function hostAsset() {
  if (process.platform === "darwin" && process.arch === "arm64") return "0sec-darwin-arm64";
  if (process.platform === "linux" && process.arch === "x64") return "0sec-linux-x64";
  if (process.platform === "linux" && process.arch === "arm64") return "0sec-linux-arm64";
  return undefined;
}

test("install.sh installs a checksum-verified host binary", { skip: !hostAsset() }, () => {
  const root = mkdtempSync(join(tmpdir(), "0sec-install-test-"));
  try {
    const releaseDir = join(root, "release");
    const installDir = join(root, "bin");
    mkdirSync(releaseDir);
    const asset = hostAsset();
    assert.ok(asset);
    const fixture = "#!/usr/bin/env sh\nprintf '%s\\n' fixture-0sec\n";
    const assetPath = join(releaseDir, asset);
    const digest = createHash("sha256").update(fixture).digest("hex");

    writeFileSync(assetPath, fixture, { mode: 0o755 });
    chmodSync(assetPath, 0o755);
    writeFileSync(join(releaseDir, "checksums.txt"), `${digest}  ${asset}\n`);

    const result = spawnSync("sh", [join(repoRoot, "install.sh")], {
      encoding: "utf8",
      env: {
        ...process.env,
        RELEASE_BASE_URL: pathToFileURL(releaseDir).href.replace(/\/$/, ""),
        INSTALL_DIR: installDir,
      },
    });
    assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);

    const installed = spawnSync(join(installDir, "0sec"), ["--version"], { encoding: "utf8" });
    assert.equal(installed.status, 0, installed.stderr);
    assert.equal(installed.stdout.trim(), "fixture-0sec");

    const alias = spawnSync(join(installDir, "0"), ["--version"], { encoding: "utf8" });
    assert.equal(alias.status, 0, alias.stderr);
    assert.equal(alias.stdout.trim(), "fixture-0sec");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
