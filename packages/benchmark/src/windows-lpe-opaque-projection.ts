import { createHash, randomBytes as cryptoRandomBytes } from "node:crypto";
import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readdirSync,
  readSync,
} from "node:fs";
import { resolve } from "node:path";
import {
  assertNoDuplicateWindowsLpeJsonKeys,
  canonicalWindowsLpeJson,
  validateWindowsLpePairedCorpus,
  windowsLpeInventoryCommitment,
  type WindowsLpePairedCorpusCase,
  type WindowsLpePairedCorpusManifest,
} from "./windows-lpe-paired-corpus.js";

export const WINDOWS_LPE_AGENT_PROJECTION_SCHEMA = "0sec.windows-lpe-agent-projection/v1" as const;
export const WINDOWS_LPE_HANDLE_RESOLVER_SCHEMA = "0sec.windows-lpe-handle-resolver/v1" as const;

const SHA256 = /^[a-f0-9]{64}$/;
const OPAQUE = /^[A-Za-z0-9_-]{43}$/;
const CASE_ID = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const MAX_FILE_BYTES = 8 * 1024 * 1024;

export interface WindowsLpeAgentProjection {
  schemaVersion: typeof WINDOWS_LPE_AGENT_PROJECTION_SCHEMA;
  projectionId: string;
  targets: Array<{ handle: string }>;
  policy: {
    execution: "authority-gated";
    disclosure: "human-only";
    noveltyEligible: false;
    bountyClaimEligible: false;
    weaponization: false;
    autoDisclosure: false;
  };
}

export interface WindowsLpeHandleResolver {
  schemaVersion: typeof WINDOWS_LPE_HANDLE_RESOLVER_SCHEMA;
  projectionSha256: string;
  inventorySha256: string;
  corpusId: string;
  entries: Array<{
    handle: string;
    caseId: string;
    target: WindowsLpePairedCorpusCase["target"];
    scope: WindowsLpePairedCorpusCase["scope"];
  }>;
  policy: { evaluatorOnly: true; agentMountAllowed: false };
}

export interface WindowsLpeOpaqueProjectionBundle {
  projection: WindowsLpeAgentProjection;
  resolver: WindowsLpeHandleResolver;
  projectionSha256: string;
  resolverSha256: string;
  inventorySha256: string;
}

export interface WindowsLpeOpaqueRuntimeIdentity {
  windowsBuildLabEx: string;
  currentBuildNumber: string;
  updateBuildRevision: number;
  architecture: "x64" | "arm64";
  artifactSha256: string;
  scopeManifestSha256: string;
  workerAcceptanceSha256: string;
}

export interface WindowsLpeOpaqueAuthorityExpectation extends WindowsLpeOpaqueRuntimeIdentity {
  projectionId: string;
  projectionSha256: string;
  resolverSha256: string;
  inventorySha256: string;
  handle: string;
}

export interface VerifiedWindowsLpeOpaqueAuthority {
  authorityId: string;
  runNonce: string;
  expiresAt: string;
  workerAcceptanceSha256: string;
}

export interface WindowsLpeOpaqueAuthorityVerifier {
  verify(
    authority: unknown,
    expected: WindowsLpeOpaqueAuthorityExpectation,
  ): Promise<VerifiedWindowsLpeOpaqueAuthority>;
}

export interface WindowsLpeOpaqueReplayStore {
  /** Must atomically insert-if-absent and durably retain the key through expiry. */
  consumeOnce(replayKey: string, expiresAt: string): Promise<boolean>;
}

export interface WindowsLpeOpaqueResolution {
  /** Evaluator/authority-runner private output. Never return this object to an agent. */
  case: WindowsLpePairedCorpusCase;
  authorityId: string;
  runNonce: string;
  replayKey: string;
}

type JsonRecord = Record<string, unknown>;

function record(value: unknown, name: string): JsonRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${name} must be an object`);
  return value as JsonRecord;
}

function exact(value: unknown, name: string, keys: readonly string[]): JsonRecord {
  const result = record(value, name);
  const actual = Object.keys(result).sort();
  const expected = [...keys].sort();
  if (canonicalWindowsLpeJson(actual) !== canonicalWindowsLpeJson(expected)) {
    throw new Error(`${name} has unknown or missing fields`);
  }
  return result;
}

function digest(value: unknown, name: string): string {
  if (typeof value !== "string" || !SHA256.test(value)) throw new Error(`${name} must be a lowercase SHA-256`);
  return value;
}

function opaque(value: unknown, name: string): string {
  if (typeof value !== "string" || !OPAQUE.test(value)
    || Buffer.from(value, "base64url").toString("base64url") !== value
    || Buffer.from(value, "base64url").byteLength !== 32) {
    throw new Error(`${name} must be a canonical opaque 256-bit handle`);
  }
  return value;
}

function iso(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length > 64) {
    throw new Error(`${name} must be a UTC RFC3339 timestamp`);
  }
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(value);
  const milliseconds = Date.parse(value);
  if (!match || !Number.isFinite(milliseconds)) throw new Error(`${name} must be a valid UTC RFC3339 timestamp`);
  const parsed = new Date(milliseconds);
  const parts = match.slice(1, 7).map(Number);
  if (parsed.getUTCFullYear() !== parts[0] || parsed.getUTCMonth() + 1 !== parts[1]
    || parsed.getUTCDate() !== parts[2] || parsed.getUTCHours() !== parts[3]
    || parsed.getUTCMinutes() !== parts[4] || parsed.getUTCSeconds() !== parts[5]) {
    throw new Error(`${name} must be a valid UTC RFC3339 timestamp`);
  }
  return value;
}

function sha256(value: unknown): string {
  return createHash("sha256").update(canonicalWindowsLpeJson(value)).digest("hex");
}

function generateOpaque(randomSource: (size: number) => Uint8Array): string {
  const bytes = randomSource(32);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) throw new Error("opaque handle source must return exactly 32 bytes");
  return Buffer.from(bytes).toString("base64url");
}

export function validateWindowsLpeAgentProjection(value: unknown): WindowsLpeAgentProjection {
  const top = exact(value, "agent projection", ["schemaVersion", "projectionId", "targets", "policy"]);
  if (top.schemaVersion !== WINDOWS_LPE_AGENT_PROJECTION_SCHEMA) throw new Error("unsupported Windows LPE agent projection schema");
  opaque(top.projectionId, "agent projection.projectionId");
  if (!Array.isArray(top.targets) || top.targets.length < 1 || top.targets.length > 10_000) {
    throw new Error("agent projection targets must contain 1-10000 opaque handles");
  }
  const handles = top.targets.map((value, index) => {
    const row = exact(value, `agent projection.targets[${index}]`, ["handle"]);
    return opaque(row.handle, `agent projection.targets[${index}].handle`);
  });
  if (new Set(handles).size !== handles.length || handles.includes(String(top.projectionId))) {
    throw new Error("agent projection opaque identities must be globally unique");
  }
  if (canonicalWindowsLpeJson(handles) !== canonicalWindowsLpeJson([...handles].sort())) {
    throw new Error("agent projection targets must use canonical randomized-handle order");
  }
  const policy = exact(top.policy, "agent projection.policy", [
    "execution", "disclosure", "noveltyEligible", "bountyClaimEligible", "weaponization", "autoDisclosure",
  ]);
  if (policy.execution !== "authority-gated" || policy.disclosure !== "human-only"
    || policy.noveltyEligible !== false || policy.bountyClaimEligible !== false
    || policy.weaponization !== false || policy.autoDisclosure !== false) {
    throw new Error("agent projection must remain authority-gated, nonclaim, nonweaponizing, and human-only");
  }
  return value as WindowsLpeAgentProjection;
}

export function windowsLpeProjectionCommitment(value: WindowsLpeAgentProjection): string {
  return sha256(validateWindowsLpeAgentProjection(value));
}

function validateResolverEntryShape(value: unknown, index: number): WindowsLpeHandleResolver["entries"][number] {
  const name = `handle resolver.entries[${index}]`;
  const row = exact(value, name, ["handle", "caseId", "target", "scope"]);
  opaque(row.handle, `${name}.handle`);
  if (typeof row.caseId !== "string" || !CASE_ID.test(row.caseId)) throw new Error(`${name}.caseId is invalid`);
  exact(row.target, `${name}.target`, [
    "windowsBuildLabEx", "currentBuildNumber", "updateBuildRevision", "architecture", "artifactSha256", "provenance",
  ]);
  exact(record(row.target, `${name}.target`).provenance, `${name}.target.provenance`, ["source", "refs", "sealedAt"]);
  exact(row.scope, `${name}.scope`, ["authorization", "dynamicExecutionAllowed", "scopeManifestSha256"]);
  return value as WindowsLpeHandleResolver["entries"][number];
}

export function validateWindowsLpeHandleResolver(args: {
  manifest: WindowsLpePairedCorpusManifest;
  projection: WindowsLpeAgentProjection;
  resolver: unknown;
}): WindowsLpeOpaqueProjectionBundle {
  const manifest = validateWindowsLpePairedCorpus(args.manifest).manifest;
  const projection = validateWindowsLpeAgentProjection(args.projection);
  const top = exact(args.resolver, "handle resolver", [
    "schemaVersion", "projectionSha256", "inventorySha256", "corpusId", "entries", "policy",
  ]);
  if (top.schemaVersion !== WINDOWS_LPE_HANDLE_RESOLVER_SCHEMA) throw new Error("unsupported Windows LPE handle resolver schema");
  const projectionSha256 = digest(top.projectionSha256, "handle resolver.projectionSha256");
  const inventorySha256 = digest(top.inventorySha256, "handle resolver.inventorySha256");
  if (projectionSha256 !== windowsLpeProjectionCommitment(projection)) throw new Error("handle resolver does not bind the current projection");
  if (inventorySha256 !== windowsLpeInventoryCommitment(manifest)) throw new Error("handle resolver does not bind the current inventory");
  if (top.corpusId !== manifest.corpusId) throw new Error("handle resolver corpus identity mismatch");
  if (!Array.isArray(top.entries)) throw new Error("handle resolver.entries must be an array");
  const entries = top.entries.map(validateResolverEntryShape);
  const resolverHandles = entries.map((entry) => entry.handle);
  if (canonicalWindowsLpeJson(resolverHandles) !== canonicalWindowsLpeJson([...resolverHandles].sort())) {
    throw new Error("handle resolver entries must use canonical opaque-handle order");
  }
  const holdout = manifest.cases.filter((entry) => entry.split === "holdout");
  if (entries.length !== holdout.length || entries.length !== projection.targets.length) {
    throw new Error("handle resolver must exactly cover the opaque holdout projection");
  }
  const projectedHandles = new Set(projection.targets.map((entry) => entry.handle));
  const manifestByCase = new Map(holdout.map((entry) => [entry.caseId, entry]));
  const seenHandles = new Set<string>();
  const seenCases = new Set<string>();
  for (const entry of entries) {
    if (!projectedHandles.has(entry.handle) || seenHandles.has(entry.handle)) throw new Error("handle resolver contains an unknown or duplicate handle");
    if (!manifestByCase.has(entry.caseId) || seenCases.has(entry.caseId)) throw new Error("handle resolver contains an unknown, non-holdout, or duplicate case");
    const expected = manifestByCase.get(entry.caseId)!;
    if (canonicalWindowsLpeJson(entry.target) !== canonicalWindowsLpeJson(expected.target)
      || canonicalWindowsLpeJson(entry.scope) !== canonicalWindowsLpeJson(expected.scope)) {
      throw new Error("handle resolver evidence does not match its inventory binding");
    }
    seenHandles.add(entry.handle);
    seenCases.add(entry.caseId);
  }
  if (seenHandles.size !== projectedHandles.size || seenCases.size !== manifestByCase.size) {
    throw new Error("handle resolver is not a complete projection-to-inventory bijection");
  }
  const policy = exact(top.policy, "handle resolver.policy", ["evaluatorOnly", "agentMountAllowed"]);
  if (policy.evaluatorOnly !== true || policy.agentMountAllowed !== false) throw new Error("handle resolver must remain evaluator-only");
  const resolver = args.resolver as WindowsLpeHandleResolver;
  return {
    projection,
    resolver,
    projectionSha256,
    resolverSha256: sha256(resolver),
    inventorySha256,
  };
}

export function createWindowsLpeOpaqueProjection(
  manifestValue: WindowsLpePairedCorpusManifest,
  options: { randomSource?: (size: number) => Uint8Array } = {},
): WindowsLpeOpaqueProjectionBundle {
  const manifest = validateWindowsLpePairedCorpus(manifestValue).manifest;
  const holdout = manifest.cases.filter((entry) => entry.split === "holdout");
  if (holdout.length === 0) throw new Error("opaque projection requires at least one holdout case");
  const randomSource = options.randomSource ?? cryptoRandomBytes;
  const used = new Set<string>();
  const next = (): string => {
    const value = generateOpaque(randomSource);
    if (used.has(value)) throw new Error("opaque handle source produced a collision");
    used.add(value);
    return value;
  };
  const projectionId = next();
  const bindings = holdout.map((entry) => ({ handle: next(), entry }));
  bindings.sort((a, b) => a.handle.localeCompare(b.handle));
  const projection: WindowsLpeAgentProjection = {
    schemaVersion: WINDOWS_LPE_AGENT_PROJECTION_SCHEMA,
    projectionId,
    targets: bindings.map(({ handle }) => ({ handle })),
    policy: {
      execution: "authority-gated", disclosure: "human-only", noveltyEligible: false,
      bountyClaimEligible: false, weaponization: false, autoDisclosure: false,
    },
  };
  const resolver: WindowsLpeHandleResolver = {
    schemaVersion: WINDOWS_LPE_HANDLE_RESOLVER_SCHEMA,
    projectionSha256: windowsLpeProjectionCommitment(projection),
    inventorySha256: windowsLpeInventoryCommitment(manifest),
    corpusId: manifest.corpusId,
    entries: bindings.map(({ handle, entry }) => ({
      handle, caseId: entry.caseId, target: entry.target, scope: entry.scope,
    })),
    policy: { evaluatorOnly: true, agentMountAllowed: false },
  };
  return validateWindowsLpeHandleResolver({ manifest, projection, resolver });
}

export async function resolveWindowsLpeOpaqueHandle(args: {
  manifest: WindowsLpePairedCorpusManifest;
  projection: WindowsLpeAgentProjection;
  resolver: WindowsLpeHandleResolver;
  /** Trusted commitment provisioned independently of the resolver file being validated. */
  expectedResolverSha256: string;
  handle: string;
  authority: unknown;
  observedRuntime: WindowsLpeOpaqueRuntimeIdentity;
  authorityVerifier: WindowsLpeOpaqueAuthorityVerifier;
  replayStore: WindowsLpeOpaqueReplayStore;
  now?: () => number;
}): Promise<WindowsLpeOpaqueResolution> {
  const bundle = validateWindowsLpeHandleResolver(args);
  const expectedResolverSha256 = digest(args.expectedResolverSha256, "expected resolver digest");
  if (bundle.resolverSha256 !== expectedResolverSha256) {
    throw new Error("opaque resolver does not match the evaluator-pinned commitment");
  }
  const handle = opaque(args.handle, "opaque execution handle");
  const binding = bundle.resolver.entries.find((entry) => entry.handle === handle);
  if (!binding) throw new Error("opaque execution handle is not part of this projection");
  if (binding.scope.dynamicExecutionAllowed !== true) {
    throw new Error("opaque target is not authorized for dynamic execution");
  }
  const runtime = exact(args.observedRuntime, "observed runtime", [
    "windowsBuildLabEx", "currentBuildNumber", "updateBuildRevision", "architecture", "artifactSha256",
    "scopeManifestSha256", "workerAcceptanceSha256",
  ]) as unknown as WindowsLpeOpaqueRuntimeIdentity;
  digest(runtime.artifactSha256, "observed runtime artifactSha256");
  digest(runtime.scopeManifestSha256, "observed runtime scopeManifestSha256");
  digest(runtime.workerAcceptanceSha256, "observed runtime workerAcceptanceSha256");
  const expectedRuntime = {
    windowsBuildLabEx: binding.target.windowsBuildLabEx,
    currentBuildNumber: binding.target.currentBuildNumber,
    updateBuildRevision: binding.target.updateBuildRevision,
    architecture: binding.target.architecture,
    artifactSha256: binding.target.artifactSha256,
    scopeManifestSha256: binding.scope.scopeManifestSha256,
    workerAcceptanceSha256: runtime.workerAcceptanceSha256,
  };
  if (canonicalWindowsLpeJson(runtime) !== canonicalWindowsLpeJson(expectedRuntime)) {
    throw new Error("observed runtime does not match the evaluator-bound opaque target");
  }
  const resolved = args.manifest.cases.find((entry) => entry.caseId === binding.caseId && entry.split === "holdout");
  if (!resolved) throw new Error("opaque resolver inventory binding is unavailable");
  // Snapshot private metadata before crossing either asynchronous trust boundary.
  const resolvedSnapshot = JSON.parse(JSON.stringify(resolved)) as WindowsLpePairedCorpusCase;
  const expectation: WindowsLpeOpaqueAuthorityExpectation = {
    projectionId: bundle.projection.projectionId,
    projectionSha256: bundle.projectionSha256,
    resolverSha256: bundle.resolverSha256,
    inventorySha256: bundle.inventorySha256,
    handle,
    ...expectedRuntime,
  };
  let verifiedValue: unknown;
  try {
    verifiedValue = await args.authorityVerifier.verify(args.authority, expectation);
  } catch {
    throw new Error("opaque execution authority verification failed");
  }
  const verified = exact(verifiedValue, "verified authority", [
    "authorityId", "runNonce", "expiresAt", "workerAcceptanceSha256",
  ]);
  const authorityId = opaque(verified.authorityId, "verified authority ID");
  const runNonce = opaque(verified.runNonce, "verified authority run nonce");
  const expiresAt = iso(verified.expiresAt, "verified authority expiry");
  if (verified.workerAcceptanceSha256 !== runtime.workerAcceptanceSha256) {
    throw new Error("verified authority does not bind the observed worker acceptance");
  }
  const now = (args.now ?? Date.now)();
  if (!Number.isFinite(now) || now >= Date.parse(expiresAt)) throw new Error("verified opaque execution authority has expired");
  const replayKey = createHash("sha256").update([
    "0sec.windows-lpe-opaque-consume/v1", authorityId, bundle.projectionSha256, bundle.resolverSha256, handle, runNonce,
  ].join("\u0000")).digest("hex");
  let consumed: boolean;
  try {
    consumed = await args.replayStore.consumeOnce(replayKey, expiresAt);
  } catch {
    throw new Error("opaque execution replay state is unavailable");
  }
  if (consumed === false) throw new Error("opaque execution authority was already consumed");
  if (consumed !== true) throw new Error("opaque execution replay state is unavailable");
  return { case: resolvedSnapshot, authorityId, runNonce, replayKey };
}

function readBoundedJson(path: string): unknown {
  const descriptor = openSync(resolve(path), fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW | fsConstants.O_NONBLOCK);
  try {
    const before = fstatSync(descriptor);
    if (!before.isFile() || before.size > MAX_FILE_BYTES) throw new Error("opaque Windows LPE input must be a regular file no larger than 8 MiB");
    const buffer = Buffer.allocUnsafe(Math.min(MAX_FILE_BYTES + 1, Math.max(1, before.size + 1)));
    let offset = 0;
    while (offset < buffer.length) {
      const count = readSync(descriptor, buffer, offset, buffer.length - offset, offset);
      if (count === 0) break;
      offset += count;
    }
    const after = fstatSync(descriptor);
    if (offset > MAX_FILE_BYTES || offset !== after.size || before.dev !== after.dev || before.ino !== after.ino
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) {
      throw new Error("opaque Windows LPE input changed while it was being read");
    }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, offset));
    assertNoDuplicateWindowsLpeJsonKeys(text);
    return JSON.parse(text) as unknown;
  } finally {
    closeSync(descriptor);
  }
}

export function loadWindowsLpeAgentProjection(path: string): WindowsLpeAgentProjection {
  return validateWindowsLpeAgentProjection(readBoundedJson(path));
}

export function validateWindowsLpeOpaqueProjectionMount(
  directory: string,
  expectedProjectionSha256: string,
): WindowsLpeAgentProjection {
  digest(expectedProjectionSha256, "expected projection digest");
  const mountPath = resolve(directory);
  const mount = lstatSync(mountPath);
  if (!mount.isDirectory() || mount.isSymbolicLink() || (mount.mode & 0o222) !== 0) {
    throw new Error("agent projection mount must be a non-symlinked read-only directory");
  }
  const entries = readdirSync(mountPath, { withFileTypes: true });
  if (entries.length !== 1 || entries[0]!.name !== "projection.json" || !entries[0]!.isFile()) {
    throw new Error("agent projection mount must contain exactly one regular projection.json file");
  }
  const projectionPath = resolve(mountPath, "projection.json");
  const projectionEntry = lstatSync(projectionPath);
  if (!projectionEntry.isFile() || projectionEntry.isSymbolicLink() || (projectionEntry.mode & 0o222) !== 0) {
    throw new Error("agent projection mount must contain a non-symlinked read-only projection.json file");
  }
  const projection = loadWindowsLpeAgentProjection(projectionPath);
  if (windowsLpeProjectionCommitment(projection) !== expectedProjectionSha256) {
    throw new Error("agent projection mount digest mismatch");
  }
  return projection;
}
