#!/usr/bin/env node
/**
 * artifact-bridge.mjs — authorize a candidate file for installation against
 * the evolution registry, reusing the EXACT core validator with zero
 * duplicated logic.
 *
 * The skill-refine and active-learning loops shell out to this BEFORE they
 * ever write a runtime artifact. It loads the built core module's
 * authorizeEvolutionArtifact (packages/core/src/improvement/
 * artifact-authorization.ts) and runs the complete digest + receipt +
 * canary check chain defined there.
 *
 * The CANDIDATE FILE (the actual bytes the Python script intends to install)
 * is hashed and compared to the snapshot file digest at the given artifact
 * path. The installer must copy only bytes matching the returned digest;
 * authorization alone cannot prevent a later source-file replacement.
 *
 * Usage:
 *   node artifact-bridge.mjs authorize <store-path> <version-id> \
 *       <candidate-file> <snapshot-artifact-path> <kind>
 *
 * Exit codes:
 *   0  artifact authorized (structured JSON on stdout)
 *   1  authorization FAILED (message on stderr)
 *   2  bad invocation / could not locate the core build
 *
 * Examples:
 *   # Authorize a skill YAML that Python wants to install
 *   node artifact-bridge.mjs authorize \
 *       /path/to/evolution-store \
 *       a1b2c3d4-... \
 *       /tmp/candidate-skill.yaml \
 *       agent/skills/vulnerabilities/sqli-advanced.yaml \
 *       skill
 *
 *   # Authorize a router model
 *   node artifact-bridge.mjs authorize \
 *       /path/to/evolution-store \
 *       e5f6g7h8-... \
 *       /tmp/candidate-model.json \
 *       triage/triage-router-v1.model.json \
 *       router
 */

import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { existsSync } from "node:fs";

const HERE = dirname(fileURLToPath(import.meta.url));

function fail(code, msg) {
  process.stderr.write(msg + "\n");
  process.exit(code);
}

const [command, storePath, versionId, candidateFile, artifactPath, kind] =
  process.argv.slice(2);

if (!command || command !== "authorize") {
  fail(
    2,
    "usage: node artifact-bridge.mjs authorize <store-path> <version-id>" +
      " <candidate-file> <snapshot-artifact-path> <kind>\n" +
      "  kind = skill | router | source | lens",
  );
}

if (!storePath || !versionId || !candidateFile || !artifactPath || !kind) {
  fail(
    2,
    "missing required arguments: store-path, version-id, candidate-file, " +
      "snapshot-artifact-path, kind",
  );
}

if (!["skill", "router", "source", "lens"].includes(kind)) {
  fail(
    2,
    `invalid kind "${kind}"; expected one of: skill, router, source, lens`,
  );
}

const absoluteStore = resolve(storePath);
if (!existsSync(absoluteStore)) {
  fail(2, `evolution store not found: ${absoluteStore}`);
}

const absoluteCandidate = resolve(candidateFile);
if (!existsSync(absoluteCandidate)) {
  fail(2, `candidate file not found: ${absoluteCandidate}`);
}

// Default to the sibling core package's build output.
// scripts/train -> scripts -> benchmark -> packages -> core/dist
const distDir = resolve(HERE, "../../../core/dist");
const indexPath = join(distDir, "improvement", "index.js");
if (!existsSync(indexPath)) {
  fail(
    2,
    `core build not found at ${indexPath}\n` +
      `Run: pnpm --filter @0sec/core build  (or build the dist/)`,
  );
}

const mod = await import(indexPath);
if (typeof mod.authorizeEvolutionArtifact !== "function") {
  fail(
    2,
    "authorizeEvolutionArtifact not exported from core build — build stale?",
  );
}

try {
  const result = mod.authorizeEvolutionArtifact(
    absoluteStore,
    versionId,
    absoluteCandidate,
    artifactPath,
    kind,
  );

  if (!result.authorized) {
    fail(1, `AUTHORIZATION FAILED: ${result.reason}`);
  }

  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exit(0);
} catch (err) {
  fail(1, `AUTHORIZATION ERROR: ${err?.message ?? err}`);
}