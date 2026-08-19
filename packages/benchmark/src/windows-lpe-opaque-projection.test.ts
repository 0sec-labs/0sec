import { chmodSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it, vi } from "vitest";
import {
  createWindowsLpeOpaqueProjection,
  loadWindowsLpeAgentProjection,
  resolveWindowsLpeOpaqueHandle,
  validateWindowsLpeAgentProjection,
  validateWindowsLpeHandleResolver,
  validateWindowsLpeOpaqueProjectionMount,
  windowsLpeProjectionCommitment,
  type WindowsLpeAgentProjection,
  type WindowsLpeHandleResolver,
  type WindowsLpeOpaqueRuntimeIdentity,
} from "./windows-lpe-opaque-projection.js";
import type { WindowsLpePairedCorpusManifest } from "./windows-lpe-paired-corpus.js";

const fixturePath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../fixtures/windows-lpe-paired-corpus-contract-v2.json",
);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as WindowsLpePairedCorpusManifest;

function copy<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function opaque(byte: number): string {
  return Buffer.alloc(32, byte).toString("base64url");
}

function deterministicRandom(): (size: number) => Uint8Array {
  let byte = 0;
  return (size) => {
    expect(size).toBe(32);
    byte += 1;
    return Buffer.alloc(32, byte);
  };
}

function executionFixture(): WindowsLpePairedCorpusManifest {
  const manifest = copy(fixture);
  for (const entry of manifest.cases) {
    if (entry.split === "holdout") entry.scope.dynamicExecutionAllowed = true;
  }
  return manifest;
}

function runtimeFor(
  resolver: WindowsLpeHandleResolver,
  handle: string,
): WindowsLpeOpaqueRuntimeIdentity {
  const binding = resolver.entries.find((entry) => entry.handle === handle)!;
  return {
    windowsBuildLabEx: binding.target.windowsBuildLabEx,
    currentBuildNumber: binding.target.currentBuildNumber,
    updateBuildRevision: binding.target.updateBuildRevision,
    architecture: binding.target.architecture,
    artifactSha256: binding.target.artifactSha256,
    scopeManifestSha256: binding.scope.scopeManifestSha256,
    workerAcceptanceSha256: "a".repeat(64),
  };
}

function authority(workerAcceptanceSha256 = "a".repeat(64)) {
  return {
    authorityId: opaque(210),
    runNonce: opaque(211),
    expiresAt: "2030-01-01T00:00:00.000Z",
    workerAcceptanceSha256,
  };
}

function allKeys(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(allKeys);
  if (!value || typeof value !== "object") return [];
  return Object.entries(value as Record<string, unknown>).flatMap(([key, child]) => [key, ...allKeys(child)]);
}

describe("Windows LPE opaque holdout projection", () => {
  it("gives the agent random handles only and withholds all target and label-inference metadata", () => {
    const bundle = createWindowsLpeOpaqueProjection(copy(fixture), { randomSource: deterministicRandom() });
    expect(bundle.projection.targets).toHaveLength(2);
    expect(bundle.projection.targets.map(({ handle }) => handle)).toEqual(
      [...bundle.projection.targets.map(({ handle }) => handle)].sort(),
    );
    const agentJson = JSON.stringify(bundle.projection);
    const agentKeys = allKeys(bundle.projection);
    for (const forbiddenField of [
      "caseId", "split", "family", "pairId", "advisoryId", "target", "scope", "corpusId",
      "inventorySha256", "projectionSha256", "resolverSha256", "createdAt", "labelCommitments",
    ]) {
      expect(agentKeys).not.toContain(forbiddenField);
    }
    for (const entry of fixture.cases.filter(({ split }) => split === "holdout")) {
      for (const secret of [
        entry.caseId, entry.family, entry.pairId, entry.advisoryId, entry.target.windowsBuildLabEx,
        entry.target.currentBuildNumber, entry.target.artifactSha256, entry.scope.scopeManifestSha256,
        ...entry.target.provenance.refs,
      ]) {
        if (secret) expect(agentJson).not.toContain(String(secret));
      }
    }
    expect(bundle.resolver.entries.map(({ handle }) => handle)).toEqual(
      bundle.projection.targets.map(({ handle }) => handle),
    );
    expect(bundle.projection.policy).toMatchObject({
      execution: "authority-gated", disclosure: "human-only", noveltyEligible: false,
      bountyClaimEligible: false, weaponization: false, autoDisclosure: false,
    });
  });

  it("rejects collisions, hidden fields, noncanonical ordering, and projection mutation", () => {
    expect(() => createWindowsLpeOpaqueProjection(copy(fixture), {
      randomSource: () => Buffer.alloc(32, 7),
    })).toThrow(/collision/);

    const bundle = createWindowsLpeOpaqueProjection(copy(fixture), { randomSource: deterministicRandom() });
    expect(() => validateWindowsLpeAgentProjection({ ...copy(bundle.projection), caseId: "hidden" })).toThrow(/unknown or missing/);
    const reversed = copy(bundle.projection);
    reversed.targets.reverse();
    expect(() => validateWindowsLpeAgentProjection(reversed)).toThrow(/canonical randomized-handle order/);
    const mutated = copy(bundle.projection);
    mutated.targets[0]!.handle = opaque(99);
    mutated.targets.sort((a, b) => a.handle.localeCompare(b.handle));
    expect(() => validateWindowsLpeHandleResolver({ manifest: copy(fixture), projection: mutated, resolver: bundle.resolver }))
      .toThrow(/bind the current projection/);
  });

  it("rejects resolver swaps, target tampering, manifest mutation, and metadata-bearing errors", async () => {
    const bundle = createWindowsLpeOpaqueProjection(copy(fixture), { randomSource: deterministicRandom() });
    const swapped = copy(bundle.resolver);
    [swapped.entries[0]!.caseId, swapped.entries[1]!.caseId] = [swapped.entries[1]!.caseId, swapped.entries[0]!.caseId];
    let message = "";
    try {
      validateWindowsLpeHandleResolver({ manifest: copy(fixture), projection: bundle.projection, resolver: swapped });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/evidence does not match/);
    for (const entry of fixture.cases.filter(({ split }) => split === "holdout")) expect(message).not.toContain(entry.caseId);

    const targetTamper = copy(bundle.resolver);
    targetTamper.entries[0]!.target.artifactSha256 = "f".repeat(64);
    expect(() => validateWindowsLpeHandleResolver({ manifest: copy(fixture), projection: bundle.projection, resolver: targetTamper }))
      .toThrow(/evidence does not match/);

    const manifestTamper = copy(fixture);
    manifestTamper.cases.find(({ split }) => split === "holdout")!.scope.scopeManifestSha256 = "e".repeat(64);
    expect(() => validateWindowsLpeHandleResolver({ manifest: manifestTamper, projection: bundle.projection, resolver: bundle.resolver }))
      .toThrow(/current inventory/);

    const remapped = copy(bundle.resolver);
    const first = copy(remapped.entries[0]!);
    const second = copy(remapped.entries[1]!);
    remapped.entries[0] = { ...second, handle: first.handle };
    remapped.entries[1] = { ...first, handle: second.handle };
    const remappedBundle = validateWindowsLpeHandleResolver({
      manifest: copy(fixture), projection: bundle.projection, resolver: remapped,
    });
    expect(remappedBundle.resolverSha256).not.toBe(bundle.resolverSha256);
    await expect(resolveWindowsLpeOpaqueHandle({
      manifest: copy(fixture), projection: bundle.projection, resolver: remapped,
      expectedResolverSha256: bundle.resolverSha256, handle: bundle.projection.targets[0]!.handle,
      authority: {}, observedRuntime: runtimeFor(remapped, bundle.projection.targets[0]!.handle),
      authorityVerifier: { verify: async () => authority() }, replayStore: { consumeOnce: async () => true },
    })).rejects.toThrow(/evaluator-pinned commitment/);
  });

  it("resolves only after exact runtime authority and atomic one-time consumption", async () => {
    const manifest = executionFixture();
    const bundle = createWindowsLpeOpaqueProjection(manifest, { randomSource: deterministicRandom() });
    const handle = bundle.projection.targets[0]!.handle;
    const runtime = runtimeFor(bundle.resolver, handle);
    const verify = vi.fn(async (_raw, expected) => {
      expect(expected).toMatchObject({
        projectionId: bundle.projection.projectionId,
        projectionSha256: bundle.projectionSha256,
        resolverSha256: bundle.resolverSha256,
        inventorySha256: bundle.inventorySha256,
        handle,
        ...runtime,
      });
      return authority();
    });
    const consumed = new Set<string>();
    const consumeOnce = vi.fn(async (key: string) => {
      if (consumed.has(key)) return false;
      consumed.add(key);
      return true;
    });
    const args = {
      manifest, projection: bundle.projection, resolver: bundle.resolver,
      expectedResolverSha256: bundle.resolverSha256, handle,
      authority: { signed: "external-verifier-input" }, observedRuntime: runtime,
      authorityVerifier: { verify }, replayStore: { consumeOnce }, now: () => Date.parse("2029-01-01T00:00:00Z"),
    };
    const result = await resolveWindowsLpeOpaqueHandle(args);
    expect(result.case.split).toBe("holdout");
    expect(result.case.caseId).toBe(bundle.resolver.entries[0]!.caseId);
    expect(result.replayKey).toMatch(/^[a-f0-9]{64}$/);
    await expect(resolveWindowsLpeOpaqueHandle(args)).rejects.toThrow(/already consumed/);
  });

  it("fails closed on runtime, verifier output, worker acceptance, expiry, and concurrent replay", async () => {
    const manifest = executionFixture();
    const bundle = createWindowsLpeOpaqueProjection(manifest, { randomSource: deterministicRandom() });
    const handle = bundle.projection.targets[0]!.handle;
    const runtime = runtimeFor(bundle.resolver, handle);
    const base = {
      manifest, projection: bundle.projection, resolver: bundle.resolver,
      expectedResolverSha256: bundle.resolverSha256, handle,
      authority: {}, observedRuntime: runtime, replayStore: { consumeOnce: async () => true },
      now: () => Date.parse("2029-01-01T00:00:00Z"),
    };
    const verify = vi.fn(async () => authority());
    await expect(resolveWindowsLpeOpaqueHandle({
      ...base,
      observedRuntime: { ...runtime, updateBuildRevision: runtime.updateBuildRevision + 1 },
      authorityVerifier: { verify },
    })).rejects.toThrow(/does not match/);
    expect(verify).not.toHaveBeenCalled();

    await expect(resolveWindowsLpeOpaqueHandle({
      ...base,
      observedRuntime: { ...runtime, hidden: "metadata" } as WindowsLpeOpaqueRuntimeIdentity,
      authorityVerifier: { verify },
    })).rejects.toThrow(/unknown or missing/);
    await expect(resolveWindowsLpeOpaqueHandle({
      ...base,
      authorityVerifier: { verify: async () => ({ ...authority(), hidden: true }) as never },
    })).rejects.toThrow(/unknown or missing/);
    await expect(resolveWindowsLpeOpaqueHandle({
      ...base,
      authorityVerifier: { verify: async () => authority("b".repeat(64)) },
    })).rejects.toThrow(/worker acceptance/);
    await expect(resolveWindowsLpeOpaqueHandle({
      ...base,
      authorityVerifier: { verify: async () => ({ ...authority(), expiresAt: "2028-01-01T00:00:00.000Z" }) },
    })).rejects.toThrow(/expired/);

    const consumed = new Set<string>();
    const concurrent = {
      ...base,
      authorityVerifier: { verify: async () => authority() },
      replayStore: { consumeOnce: async (key: string) => {
        if (consumed.has(key)) return false;
        consumed.add(key);
        return true;
      } },
    };
    const outcomes = await Promise.allSettled([
      resolveWindowsLpeOpaqueHandle(concurrent), resolveWindowsLpeOpaqueHandle(concurrent),
    ]);
    expect(outcomes.filter(({ status }) => status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter(({ status }) => status === "rejected")).toHaveLength(1);

    const disabledBundle = createWindowsLpeOpaqueProjection(copy(fixture), { randomSource: deterministicRandom() });
    const disabledHandle = disabledBundle.projection.targets[0]!.handle;
    const disabledVerify = vi.fn(async () => authority());
    await expect(resolveWindowsLpeOpaqueHandle({
      manifest: copy(fixture), projection: disabledBundle.projection, resolver: disabledBundle.resolver,
      expectedResolverSha256: disabledBundle.resolverSha256, handle: disabledHandle,
      authority: {}, observedRuntime: runtimeFor(disabledBundle.resolver, disabledHandle),
      authorityVerifier: { verify: disabledVerify }, replayStore: { consumeOnce: async () => true },
    })).rejects.toThrow(/not authorized for dynamic execution/);
    expect(disabledVerify).not.toHaveBeenCalled();

    await expect(resolveWindowsLpeOpaqueHandle({
      ...base,
      authorityVerifier: { verify: async () => { throw new Error("private verifier detail"); } },
    })).rejects.toThrow(/^opaque execution authority verification failed$/);
    await expect(resolveWindowsLpeOpaqueHandle({
      ...base,
      authorityVerifier: { verify: async () => authority() },
      replayStore: { consumeOnce: async () => { throw new Error("private store detail"); } },
    })).rejects.toThrow(/^opaque execution replay state is unavailable$/);
    await expect(resolveWindowsLpeOpaqueHandle({
      ...base,
      authorityVerifier: { verify: async () => authority() },
      replayStore: { consumeOnce: async () => "false" as unknown as boolean },
    })).rejects.toThrow(/^opaque execution replay state is unavailable$/);
  });

  it("uses duplicate-key-safe nofollow loading and an agent mount containing projection.json only", () => {
    const bundle = createWindowsLpeOpaqueProjection(copy(fixture), { randomSource: deterministicRandom() });
    const directory = mkdtempSync(resolve(tmpdir(), "0sec-opaque-projection-"));
    const outside = resolve(directory, "../outside-projection.json");
    try {
      const path = resolve(directory, "projection.json");
      writeFileSync(path, JSON.stringify(bundle.projection));
      chmodSync(path, 0o444);
      chmodSync(directory, 0o555);
      expect(validateWindowsLpeOpaqueProjectionMount(directory, bundle.projectionSha256)).toEqual(bundle.projection);
      expect(windowsLpeProjectionCommitment(loadWindowsLpeAgentProjection(path))).toBe(bundle.projectionSha256);

      chmodSync(directory, 0o755);
      writeFileSync(resolve(directory, "resolver.json"), JSON.stringify(bundle.resolver));
      chmodSync(directory, 0o555);
      expect(() => validateWindowsLpeOpaqueProjectionMount(directory, bundle.projectionSha256)).toThrow(/exactly one/);
      chmodSync(directory, 0o755);
      rmSync(resolve(directory, "resolver.json"));

      chmodSync(path, 0o644);
      writeFileSync(path, '{"schemaVersion":"0sec.windows-lpe-agent-projection/v1","schemaVersion":"shadow"}');
      expect(() => loadWindowsLpeAgentProjection(path)).toThrow(/duplicate JSON key/);
      rmSync(path);
      writeFileSync(outside, JSON.stringify(bundle.projection));
      symlinkSync(outside, path);
      chmodSync(directory, 0o555);
      expect(() => validateWindowsLpeOpaqueProjectionMount(directory, bundle.projectionSha256)).toThrow(/regular projection/);
    } finally {
      chmodSync(directory, 0o755);
      rmSync(directory, { recursive: true, force: true });
      rmSync(outside, { force: true });
    }
  });
});
