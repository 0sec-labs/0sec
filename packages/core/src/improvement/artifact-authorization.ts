import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { readEvolutionArtifact } from "./artifacts.js";
import { parseEvolutionConfig } from "./config.js";
import { evolutionDigest, loadEvolutionRegistry, verifyEvolutionReceipt, verifyEvolutionSnapshot } from "./registry.js";
import type { EvolutionArtifactKind } from "./types.js";

export interface ArtifactAuthorization {
  authorized: boolean;
  reason: string;
  fileDigest: string | null;
  expectedDigest: string | null;
  versionId: string | null;
}

/** Authorize the proposed file's exact bytes, never merely an approved artifact name. */
export function authorizeEvolutionArtifact(
  storePath: string,
  versionId: string,
  candidateFilePath: string,
  snapshotArtifactPath: string,
  expectedKind: EvolutionArtifactKind,
): ArtifactAuthorization {
  let fileDigest: string | null = null;
  let expectedDigest: string | null = null;
  try {
    const root = resolve(storePath);
    const registry = loadEvolutionRegistry(root);
    const version = registry.versions.find((entry) => entry.id === versionId);
    if (!version || registry.activeId !== versionId || version.status !== "active") throw new Error("artifact version is not currently active");
    if (version.kind !== expectedKind) throw new Error("artifact kind does not match the approved version");
    const baseline = registry.versions.find((entry) => entry.id === version.parentId);
    if (!baseline || version.receiptDigest === null) throw new Error("an unevaluated baseline cannot authorize installation");
    verifyEvolutionSnapshot(version.snapshot);
    const config = parseEvolutionConfig(readEvolutionArtifact(join(root, "configs", `${version.configDigest.replace(/^sha256:/, "")}.json`)));
    if (evolutionDigest(config) !== version.configDigest || config.storePath !== root || config.kind !== version.kind) {
      throw new Error("stored artifact configuration identity mismatch");
    }
    verifyEvolutionReceipt(root, versionId, version, baseline.snapshot.digest);
    for (let trial = 0; trial < config.canaryTrials; trial++) {
      verifyEvolutionReceipt(root, versionId, version, baseline.snapshot.digest, trial);
    }
    const artifact = version.snapshot.files.find((entry) => entry.path === snapshotArtifactPath);
    if (!artifact) throw new Error("artifact path is not in the approved snapshot");
    expectedDigest = artifact.digest;
    const fd = openSync(resolve(candidateFilePath), constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    try {
      const stat = fstatSync(fd);
      if (!stat.isFile() || stat.nlink !== 1 || stat.size !== artifact.bytes) throw new Error("candidate is not a regular file of the approved size");
      const bytes = readFileSync(fd);
      if (bytes.length !== artifact.bytes) throw new Error("candidate file changed while being read");
      fileDigest = `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
    } finally {
      closeSync(fd);
    }
    if (fileDigest !== expectedDigest) throw new Error("candidate bytes differ from the approved artifact");
    return { authorized: true, reason: "candidate bytes match the active, evaluated, canary-approved artifact", fileDigest, expectedDigest, versionId };
  } catch (error) {
    return { authorized: false, reason: error instanceof Error ? error.message : String(error), fileDigest, expectedDigest, versionId };
  }
}
