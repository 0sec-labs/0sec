import { randomUUID } from "node:crypto";
import { closeSync, fsyncSync, lstatSync, openSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { z } from "zod";
import type { ToolResult } from "../agent/types.js";
import type { NativeMessage, NativeToolDef } from "../runtime/types.js";
import { ensureEvolutionDirectory, readEvolutionArtifact } from "../improvement/artifacts.js";
import { acquireEvolutionController } from "../improvement/controller-lock.js";
import { canonicalEvolutionJson, parseEvolutionConfig } from "../improvement/config.js";
import { runEvolution } from "../improvement/loop.js";
import { evolutionDigest, loadEvolutionRegistry, snapshotEvolutionSource, verifyEvolutionReceipt, verifyEvolutionSnapshot } from "../improvement/registry.js";
import { executeSandboxSnapshot, resolveEvolutionImage, type SandboxProgramConfig } from "../improvement/sandbox.js";
import { resolveSmolvmImage } from "../runtime/smolvm.js";
import type { EvolutionConfig, EvolutionDependencies } from "../improvement/types.js";
import { validatePluginManifest, type PluginCapability, type PluginManifest } from "./manifest.js";
import { FrameReader, decodePluginMessage, MAX_RESULT_CHARS, type PluginMessage, type PluginToolResultMessage } from "./protocol.js";
import type { SelfExtensionRegistry } from "./self-extension.js";

const MAX_SOURCE_BYTES = 2 * 1024 * 1024;
const MAX_VERSIONS = 32;
const safePath = (path: string): boolean => typeof path === "string" && /^[a-zA-Z0-9_./-]+$/.test(path) && path.length <= 512 && path.split("/").every((part) => part !== "" && part !== "." && part !== "..");
const digestSchema = z.string().regex(/^sha256:[a-f0-9]{64}$/);
const manifestSchema = z.unknown().transform((value, ctx): PluginManifest => {
  const checked = validatePluginManifest(value);
  if (checked.ok) return checked.manifest;
  ctx.addIssue({ code: z.ZodIssueCode.custom, message: checked.errors.join("; ") });
  return z.NEVER;
});
const versionSchema = z.object({
  versionId: z.string().uuid(), lineageId: z.string().uuid(),
  kind: z.enum(["tool", "skill", "agent"]), entry: z.string().refine(safePath),
  evidenceStatus: z.enum(["structural", "measured"]), manifestDigest: digestSchema,
  manifest: manifestSchema, createdAt: z.string(), failureCount: z.number().int().nonnegative(),
  lastError: z.string().max(MAX_RESULT_CHARS).optional(),
  backend: z.enum(["docker", "smolvm"]), image: digestSchema, imageArchive: z.string().optional(),
  snapshot: z.object({ id: z.string().uuid(), root: z.string(), digest: digestSchema,
    files: z.array(z.object({ path: z.string().refine(safePath), digest: digestSchema, bytes: z.number().int().nonnegative() }).strict()).min(1).max(128),
  }).strict(),
  evolutionVersionId: z.string().optional(), receiptDigest: digestSchema.optional(),
}).strict().superRefine((version, context) => {
  const measured = version.evidenceStatus === "measured";
  if (measured !== (version.receiptDigest !== undefined && version.evolutionVersionId !== undefined)
    || (!measured && (version.receiptDigest !== undefined || version.evolutionVersionId !== undefined))) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "Measured executable evidence requires its evolution version and receipt digest" });
  }
  if (version.backend === "smolvm" && !version.imageArchive) {
    context.addIssue({ code: z.ZodIssueCode.custom, message: "smolvm executable requires its image archive" });
  }
});
const recordSchema = z.object({
  id: z.string(), name: z.string(), activeVersionId: z.string().uuid(),
  evolutionEpoch: z.string().uuid(),
  versions: z.array(versionSchema).min(1).max(MAX_VERSIONS), createdAt: z.number(), updatedAt: z.number(),
}).strict();
const registrySchema = z.object({ schema: z.literal(1), plugins: z.record(recordSchema) }).strict();
export type PluginVersionRecord = z.infer<typeof versionSchema>;
export type PluginRecord = z.infer<typeof recordSchema>;
type RegistryFile = z.infer<typeof registrySchema>;
export interface PluginListEntry {
  id: string; name: string; kind: PluginVersionRecord["kind"]; versionId: string;
  evidenceStatus: PluginVersionRecord["evidenceStatus"]; tools: string[]; active: boolean;
  failureCount: number; lastError?: string;
}
export interface ExecutablePluginContext {
  signal?: AbortSignal;
  /** Must use the parent's authorized tool front door, including the supplied capability limit. */
  invokeTool?: (name: string, args: Record<string, unknown>, signal?: AbortSignal, capabilities?: readonly PluginCapability[]) => Promise<ToolResult>;
  invokeModel?: (request: { system?: string; messages: NativeMessage[]; tools?: NativeToolDef[] }, signal?: AbortSignal) => Promise<unknown>;
  onEvent?: (event: unknown) => void;
}
export interface ExecutablePluginOptions {
  registry: SelfExtensionRegistry; root: string; backend: "docker" | "smolvm"; image: string;
  imageArchive?: string; timeoutMs?: number; memoryMb?: number; cpus?: number;
  maxOutputBytes?: number; maxBrokerCalls?: number;
}
interface Submission { manifest: Record<string, unknown>; files: Record<string, string>; entry: string; kind?: "tool" | "skill" | "agent" }
interface Invocation { calls: number; signal: AbortSignal; stack: string[] }
const failure = (error: unknown): ToolResult => ({ success: false, output: null, error: error instanceof Error ? error.message : String(error) });
const DENIED_BROKER_TOOLS = new Set([
  "bash", "run_command", "python_exec", "pty_session", "monitor",
  "spawn_agent", "spawn_agents", "spawn_persistent_agent", "start_scan",
  "self_extend", "skill_evolve", "plugin_install", "plugin_uninstall",
  "apply_patch", "str_replace", "write_file",
]);

// This controller-owned loader runs inside the selected guest, never on the host.
// Its input contains only submitted arguments and source-relative entry names.
const RUNNER = String.raw`
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
const lines = createInterface({ input: process.stdin, terminal: false });
const init = await new Promise((resolve, reject) => lines.once('line', line => {
  try { resolve(JSON.parse(line)); } catch (error) { reject(error); }
}));
const pending = new Map();
const send = frame => process.stdout.write(JSON.stringify(frame) + '\n');
lines.on('line', line => {
  try {
    const reply = JSON.parse(line), waiter = pending.get(reply.id);
    if (!waiter) return;
    pending.delete(reply.id);
    if (reply.kind === 'broker_error' || !reply.ok) waiter.reject(new Error(reply.message || reply.error || 'Broker failed'));
    else waiter.resolve(reply.output);
  } catch (error) { for (const waiter of pending.values()) waiter.reject(error); pending.clear(); }
});
function request(kind, fields) {
  const id = randomUUID();
  const promise = new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
  pending.get(id).promise = promise;
  send({ ...fields, v: 1, kind, id });
  return promise;
}
const sdk = Object.freeze({
  callTool: (name, args = {}) => request('request_tool', { name, args }),
  callSkill: (name, args = {}) => request('request_skill', { name, args }),
  callModel: value => request('request_model', value),
});
try {
  const mod = await import(pathToFileURL(process.cwd() + '/' + init.entry).href);
  if (typeof mod.run !== 'function') throw new Error("Entry point must export 'run'");
  const value = init.validateOnly ? { ready: true } : await mod.run(init.toolName, init.args, sdk);
  await Promise.all([...pending.values()].map(waiter => waiter.promise));
  const content = JSON.stringify(value ?? null);
  if (content.length > 100000) throw new Error('Executable result exceeds 100000 characters');
  send({ v: 1, kind: 'tool_result', id: 'main', ok: true, content, truncated: false });
} catch (error) {
  send({ v: 1, kind: 'tool_result', id: 'main', ok: false, content: String(error.message || error).slice(0, 100000), truncated: false });
}
process.exit(0);
`;

/** Immutable source versions; next-call activation; all generated code executes in guests. */
export class ExecutablePluginManager {
  readonly ready: Promise<void>;
  private readonly root: string;
  private readonly shutdown = new AbortController();
  private readonly operations = new Set<Promise<unknown>>();
  private readonly exposed = new Map<string, string>();
  private imagePromise?: Promise<string>;
  private readonly limits: Pick<SandboxProgramConfig, "timeoutMs" | "memoryMb" | "cpus" | "maxOutputBytes">;
  private readonly maxBrokerCalls: number;

  constructor(private readonly options: ExecutablePluginOptions) {
    this.root = resolve(options.root);
    this.limits = { timeoutMs: options.timeoutMs ?? 30000, memoryMb: options.memoryMb ?? 512,
      cpus: options.cpus ?? 1, maxOutputBytes: options.maxOutputBytes ?? 1024 * 1024 };
    this.maxBrokerCalls = options.maxBrokerCalls ?? 64;
    for (const [key, value] of Object.entries({ ...this.limits, maxBrokerCalls: this.maxBrokerCalls })) {
      if (!Number.isFinite(value) || value <= 0 || (key !== "cpus" && !Number.isSafeInteger(value))) throw new Error(`Invalid executable limit: ${key}`);
    }
    if (options.backend === "smolvm" && !options.imageArchive) throw new Error("smolvm requires imageArchive");
    this.ready = Promise.resolve().then(() => {
      if (this.shutdown.signal.aborted) return;
      ensureEvolutionDirectory(this.root);
      this.refresh();
    });
  }

  private operation<T>(run: () => Promise<T>): Promise<T> {
    const pending = run().finally(() => this.operations.delete(pending));
    this.operations.add(pending);
    return pending;
  }

  private readRegistry(): RegistryFile {
    const path = join(this.root, "registry.json");
    try { if (lstatSync(path).size > 16 * 1024 * 1024) throw new Error("Executable registry exceeds retention limit"); }
    catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return { schema: 1, plugins: {} }; throw error; }
    const registry = registrySchema.parse(readEvolutionArtifact(path));
    if (Object.keys(registry.plugins).length > 128) throw new Error("Executable plugin retention limit exceeded");
    for (const [id, record] of Object.entries(registry.plugins)) {
      if (record.id !== id || !record.versions.some(v => v.versionId === record.activeVersionId)) throw new Error("Invalid executable active pointer");
      const ids = new Set<string>();
      for (const version of record.versions) {
        if (ids.has(version.versionId) || version.manifest.id !== id || evolutionDigest(version.manifest) !== version.manifestDigest
          || resolve(version.snapshot.root) !== join(this.root, "snapshots", version.snapshot.id)
          || !version.snapshot.files.some(file => file.path === version.entry)) throw new Error("Invalid executable version provenance");
        ids.add(version.versionId);
      }
    }
    return registry;
  }

  private saveRegistry(registry: RegistryFile): void {
    const temporary = join(this.root, `.registry-${randomUUID()}.tmp`);
    const fd = openSync(temporary, "wx", 0o600);
    try {
      try { writeFileSync(fd, canonicalEvolutionJson(registry)); fsyncSync(fd); } finally { closeSync(fd); }
      renameSync(temporary, join(this.root, "registry.json"));
      const directory = openSync(this.root, "r");
      try { fsyncSync(directory); } finally { closeSync(directory); }
    } finally { try { unlinkSync(temporary); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; } }
  }

  /** Refresh manifests at an explicit discovery boundary; running calls keep their version. */
  refresh(): void {
    if (this.shutdown.signal.aborted) throw new Error("ExecutablePluginManager is closed");
    for (const record of Object.values(this.readRegistry().plugins)) {
      const version = record.versions.find(v => v.versionId === record.activeVersionId)!;
      verifyEvolutionSnapshot(version.snapshot);
      if (this.exposed.get(record.id) !== version.manifestDigest) this.expose(version);
    }
  }

  private expose(version: PluginVersionRecord): void {
    const result = this.options.registry.register({ origin: "model", manifest: version.manifest }, { replace: true });
    if (!result.ok) throw new Error(`Session registry rejected executable: ${result.errors.join("; ")}`);
    this.exposed.set(version.manifest.id, version.manifestDigest);
  }

  private image(): Promise<string> {
    return this.imagePromise ??= (this.options.backend === "smolvm"
      ? resolveSmolvmImage(this.options.imageArchive!) : resolveEvolutionImage(this.options.image))
      .catch(error => { this.imagePromise = undefined; throw error; });
  }

  submit(submission: Submission, context: ExecutablePluginContext = {}): Promise<ToolResult> {
    return this.operation(async () => {
      try { await this.ready; return await this.install(submission, context); }
      catch (error) { return failure(error); }
    });
  }

  private async install(submission: Submission, context: ExecutablePluginContext,
    evolution?: { previous: PluginVersionRecord; epoch: string; evolutionVersionId: string; receiptDigest: string }): Promise<ToolResult> {
    this.shutdown.signal.throwIfAborted(); context.signal?.throwIfAborted();
    if (!this.options.registry.isEnabled()) throw new Error("Model self-extension is disabled");
    const manifest = manifestSchema.parse(submission.manifest);
    if (!safePath(submission.entry) || !/\.(?:ts|mts)$/.test(submission.entry)) throw new Error("Entry must be a source-relative TypeScript file");
    const names = Object.keys(submission.files ?? {});
    if (!names.includes(submission.entry) || names.length > 128) throw new Error("Missing entry or too many source files");
    let total = 0;
    for (const name of names) {
      const content = submission.files[name];
      if (!safePath(name) || typeof content !== "string") throw new Error(`Invalid source file: ${name}`);
      const bytes = Buffer.byteLength(content);
      if (bytes > 256 * 1024 || (total += bytes) > MAX_SOURCE_BYTES) throw new Error("Executable source exceeds size limit");
    }
    const before = this.readRegistry().plugins[manifest.id];
    if (before && before.versions.length >= MAX_VERSIONS) throw new Error("Executable version retention limit reached; no retained version was discarded");
    if (evolution && (before?.activeVersionId !== evolution.previous.versionId || before.evolutionEpoch !== evolution.epoch)) throw new Error("Executable active version changed during evolution");
    const image = evolution?.previous.image ?? await this.image();
    const temporary = await mkdtemp(join(await realpath(tmpdir()), "0sec-executable-"));
    let snapshot: PluginVersionRecord["snapshot"];
    try {
      for (const name of names) {
        await mkdir(dirname(join(temporary, name)), { recursive: true, mode: 0o700 });
        await writeFile(join(temporary, name), submission.files[name]!, { mode: 0o600 });
      }
      snapshot = await snapshotEvolutionSource({ sourceRoot: temporary, storePath: this.root, sourcePaths: names, maxSourceBytes: MAX_SOURCE_BYTES });
    } finally { await rm(temporary, { recursive: true, force: true }); }
    let published = false;
    try {
    const id = randomUUID();
    const version: PluginVersionRecord = versionSchema.parse({
      versionId: id, lineageId: evolution?.previous.lineageId ?? id, kind: submission.kind ?? "tool", entry: submission.entry,
      evidenceStatus: evolution ? "measured" : "structural", manifest, manifestDigest: evolutionDigest(manifest),
      createdAt: new Date().toISOString(), failureCount: 0, snapshot, backend: this.options.backend, image,
      ...(this.options.imageArchive ? { imageArchive: resolve(this.options.imageArchive) } : {}),
      ...(evolution ? { evolutionVersionId: evolution.evolutionVersionId, receiptDigest: evolution.receiptDigest } : {}),
    });
    const state = this.invocation(context);
    const validated = await this.run(version, "", {}, {}, state, true);
    if (!validated.success) throw new Error(`Executable admission failed: ${validated.error}`);
    state.signal.throwIfAborted();
    const release = acquireEvolutionController(this.root);
    try {
      const registry = this.readRegistry();
      const current = registry.plugins[manifest.id];
      if (current?.activeVersionId !== before?.activeVersionId || current?.evolutionEpoch !== before?.evolutionEpoch) throw new Error("Executable active version changed during submission");
      const registration = this.options.registry.register({ origin: "model", manifest }, { replace: true });
      if (!registration.ok) throw new Error(registration.errors.join("; "));
      registry.plugins[manifest.id] = {
        id: manifest.id, name: manifest.name, activeVersionId: id, versions: [version, ...(current?.versions ?? [])],
        evolutionEpoch: evolution ? current!.evolutionEpoch : id,
        createdAt: current?.createdAt ?? Date.now(), updatedAt: Date.now(),
      };
      try { this.saveRegistry(registry); published = true; }
      catch (error) {
        registration.dispose();
        if (current) this.expose(current.versions.find(v => v.versionId === current.activeVersionId)!);
        throw error;
      }
      this.exposed.set(manifest.id, version.manifestDigest);
      context.onEvent?.({ type: "executable_activated", pluginId: manifest.id, versionId: id, evidenceStatus: version.evidenceStatus });
      return { success: true, output: { pluginId: manifest.id, versionId: id, kind: version.kind, tools: manifest.tools.map(t => t.name), evidenceStatus: version.evidenceStatus } };
    } finally { release(); }
    } finally {
      if (!published) {
        // This invocation owns this unpublished snapshot. Do not prune retained versions.
        const directories = new Set<string>([snapshot.root]);
        for (const file of snapshot.files) {
          let directory = dirname(join(snapshot.root, file.path));
          while (directory !== snapshot.root) { directories.add(directory); directory = dirname(directory); }
        }
        for (const directory of directories) await chmod(directory, 0o700);
        await rm(snapshot.root, { recursive: true, force: true });
      }
    }
  }

  list(): PluginListEntry[] {
    this.refresh();
    return Object.values(this.readRegistry().plugins).flatMap(record => record.versions.map(version => ({
      id: record.id, name: record.name, kind: version.kind, versionId: version.versionId,
      evidenceStatus: version.evidenceStatus, tools: version.manifest.tools.map(t => t.name),
      active: record.activeVersionId === version.versionId, failureCount: version.failureCount,
      ...(version.lastError ? { lastError: version.lastError } : {}),
    })));
  }

  private owner(name: string): PluginVersionRecord {
    const registered = this.options.registry.tool(name);
    if (!registered) throw new Error(`Executable tool not registered: ${name}`);
    const record = this.readRegistry().plugins[registered.pluginId];
    const version = record?.versions.find(v => v.versionId === record.activeVersionId);
    if (!version || !version.manifest.tools.some(t => t.name === name)) throw new Error(`Executable tool not found: ${name}`);
    if (this.exposed.get(record!.id) !== version.manifestDigest) throw new Error("Executable manifest changed; run self_extend list to refresh the tool set");
    return version;
  }

  private invocation(context: ExecutablePluginContext): Invocation {
    return { calls: 0, stack: [], signal: AbortSignal.any([this.shutdown.signal, AbortSignal.timeout(this.limits.timeoutMs), ...(context.signal ? [context.signal] : [])]) };
  }

  execute(toolName: string, args: Record<string, unknown>, context: ExecutablePluginContext = {}): Promise<ToolResult> {
    return this.operation(async () => {
      try { await this.ready; return await this.invoke(toolName, args, context, this.invocation(context)); }
      catch (error) { return failure(error); }
    });
  }

  /** Invoke an immutable retained version without changing discovery or active pointers. */
  executeVersion(pluginId: string, versionId: string, toolName: string,
    args: Record<string, unknown>, context: ExecutablePluginContext = {}): Promise<ToolResult> {
    return this.operation(async () => {
      try {
        await this.ready;
        this.shutdown.signal.throwIfAborted();
        context.signal?.throwIfAborted();
        const version = this.inspectVersion(pluginId, versionId);
        if (!version || !version.manifest.tools.some(tool => tool.name === toolName)) {
          throw new Error(`Retained executable tool not found: ${pluginId}@${versionId}/${toolName}`);
        }
        const state = this.invocation(context);
        state.stack.push(toolName);
        return await this.run(version, toolName, args, context, state);
      } catch (error) { return failure(error); }
    });
  }

  /** Verify retained source before admission or dispatch; never activate it implicitly. */
  inspectVersion(pluginId: string, versionId: string): PluginVersionRecord | undefined {
    this.shutdown.signal.throwIfAborted();
    const version = this.readRegistry().plugins[pluginId]?.versions.find(item => item.versionId === versionId);
    if (version) {
      if (version.backend !== this.options.backend) throw new Error("Executable version backend mismatch");
      verifyEvolutionSnapshot(version.snapshot);
    }
    return version;
  }

  private async invoke(name: string, args: Record<string, unknown>, context: ExecutablePluginContext, state: Invocation,
    allowed?: readonly PluginCapability[]): Promise<ToolResult> {
    state.signal.throwIfAborted();
    if (state.stack.length >= 4 || state.stack.includes(name)) return failure("Executable skill recursion/depth limit exceeded");
    const version = this.owner(name);
    const capabilities = version.manifest.tools.find(t => t.name === name)!.capabilities;
    if (allowed && capabilities.some(capability => capability !== "compute" && !allowed.includes(capability))) return failure("Nested executable would escalate declared capabilities");
    state.stack.push(name);
    let result: ToolResult;
    try { result = await this.run(version, name, args, context, state); }
    catch (error) { result = failure(error); }
    finally { state.stack.pop(); }
    if (!result.success) {
      const release = acquireEvolutionController(this.root);
      try {
        const registry = this.readRegistry();
        const retained = registry.plugins[version.manifest.id]?.versions.find(v => v.versionId === version.versionId);
        if (retained) { retained.failureCount++; retained.lastError = (result.error ?? "Execution failed").slice(0, MAX_RESULT_CHARS); this.saveRegistry(registry); }
      } finally { release(); }
    }
    context.onEvent?.({ type: "executable_result", pluginId: version.manifest.id, versionId: version.versionId, toolName: name, success: result.success });
    return result;
  }

  private async run(version: PluginVersionRecord, toolName: string, args: Record<string, unknown>, context: ExecutablePluginContext,
    state: Invocation, validateOnly = false): Promise<ToolResult> {
    if (version.backend !== this.options.backend) throw new Error("Executable version backend differs from configured backend; explicit resubmission is required");
    const initialInput = JSON.stringify({ entry: version.entry, toolName, args, validateOnly }) + "\n";
    if (Buffer.byteLength(initialInput) > 256 * 1024) throw new Error("Executable arguments exceed size limit");
    const local = new AbortController();
    const signal = AbortSignal.any([state.signal, local.signal]);
    const reader = new FrameReader();
    let write: ((data: string) => void) | undefined;
    let result: PluginToolResultMessage | undefined;
    let protocolError: string | undefined;
    let chain = Promise.resolve();
    let queued = 0;
    const seen = new Set<string>();
    const capabilities = version.manifest.tools.find(t => t.name === toolName)?.capabilities ?? [];
    const stop = (error: unknown) => { protocolError ??= error instanceof Error ? error.message : String(error); local.abort(); };
    const respond = (frame: unknown) => {
      signal.throwIfAborted();
      const content = JSON.stringify(frame);
      if (Buffer.byteLength(content) > 256 * 1024) throw new Error("Broker response exceeds size limit");
      if (!write) throw new Error("Guest input unavailable");
      write(content + "\n");
    };
    try {
      const execution = await executeSandboxSnapshot({
        snapshot: version.snapshot,
        config: { ...this.limits, backend: version.backend, image: version.image, imageArchive: version.imageArchive,
          command: ["node", "--experimental-strip-types", "--input-type=module", "--eval", RUNNER] },
        input: null, signal,
        channel: {
          initialInput,
          onReady: sender => { write = sender; },
          onData: chunk => {
            if (signal.aborted) return;
            const batch = reader.push(chunk);
            if (batch.failures.length) { stop(batch.failures[0]!.detail); return; }
            for (const frame of batch.frames) {
              const decoded = decodePluginMessage(frame);
              if (!decoded.ok) { stop(decoded.detail); return; }
              const message = decoded.message;
              if (result) { stop("Guest sent a frame after its final result"); return; }
              if (message.kind === "tool_result" && message.id === "main") {
                if (queued) { stop("Guest returned before broker requests settled"); return; }
                result = message; continue;
              }
              if (validateOnly || !["request_tool", "request_skill", "request_model"].includes(message.kind)
                || !("id" in message) || !message.id || message.id === "main" || seen.has(message.id)) {
                stop("Unexpected or duplicate executable protocol frame"); return;
              }
              if (++state.calls > this.maxBrokerCalls) { stop("Executable broker call budget exhausted"); return; }
              seen.add(message.id); queued++;
              chain = chain.then(async () => {
                try { respond(await this.broker(message, context, { ...state, signal, stack: state.stack }, capabilities, state)); }
                catch (error) {
                  if (!signal.aborted) {
                    try { respond({ v: 1, kind: "broker_error", id: message.id, code: "broker_failed", message: failure(error).error }); }
                    catch (deliveryError) { stop(deliveryError); }
                  }
                } finally { queued--; }
              });
            }
          },
        },
      });
      if (protocolError) return failure(protocolError);
      if (execution.error || execution.timedOut || execution.exitCode !== 0) return failure(execution.error || execution.stderr || "Executable guest failed");
      if (reader.pending || !result) return failure("Guest did not produce a complete final result");
      if (!result.ok) return failure(result.content);
      let output: unknown = result.content;
      try { output = JSON.parse(result.content); } catch { /* Plain protocol content is supported. */ }
      return { success: true, output };
    } finally { local.abort(); await chain; }
  }

  private async broker(message: PluginMessage, context: ExecutablePluginContext, state: Invocation,
    capabilities: readonly PluginCapability[], shared: Invocation): Promise<unknown> {
    state.signal.throwIfAborted();
    if (message.kind === "request_model") {
      if (!capabilities.includes("model-call") || !context.invokeModel) throw new Error("Model broker unavailable or model-call capability not declared");
      const output = await context.invokeModel({ system: message.system, messages: message.messages as NativeMessage[], tools: message.tools as NativeToolDef[] | undefined }, state.signal);
      return { v: 1, kind: "model_delivery", id: message.id, ok: true, output };
    }
    if (message.kind !== "request_skill" && message.kind !== "request_tool") throw new Error("Unsupported executable broker request");
    let result: ToolResult;
    if (this.options.registry.tool(message.name)) {
      // Share the root counter across nested guests, rather than granting a fresh budget.
      const nested: Invocation = { get calls() { return shared.calls; }, set calls(value) { shared.calls = value; }, signal: state.signal, stack: state.stack };
      result = await this.invoke(message.name, message.args, context, nested, capabilities);
    } else {
      if (message.kind === "request_skill") throw new Error(`Executable skill not found: ${message.name}`);
      if (DENIED_BROKER_TOOLS.has(message.name)) throw new Error(`Host execution/control tool cannot be brokered: ${message.name}`);
      if (!context.invokeTool) throw new Error("Authorized host tool broker unavailable");
      result = await context.invokeTool(message.name, message.args, state.signal, capabilities);
    }
    return { v: 1, kind: message.kind === "request_skill" ? "skill_delivery" : "tool_delivery", id: message.id,
      ok: result.success, ...(result.success ? { output: result.output } : { error: result.error ?? "Tool failed" }), truncated: false };
  }

  rollback(pluginId: string, versionId: string, context: ExecutablePluginContext = {}): Promise<ToolResult> {
    return this.operation(async () => {
      try {
        await this.ready; this.shutdown.signal.throwIfAborted(); context.signal?.throwIfAborted();
        const release = acquireEvolutionController(this.root);
        try {
          const registry = this.readRegistry(), record = registry.plugins[pluginId];
          const version = record?.versions.find(v => v.versionId === versionId);
          if (!record || !version) throw new Error("Retained executable version not found");
          verifyEvolutionSnapshot(version.snapshot);
          if (version.backend !== this.options.backend) throw new Error("Rollback cannot change configured execution backend");
          const previous = record.versions.find(v => v.versionId === record.activeVersionId)!;
          if (record.activeVersionId !== versionId) record.evolutionEpoch = randomUUID();
          this.expose(version);
          record.activeVersionId = versionId; record.updatedAt = Date.now();
          try { this.saveRegistry(registry); } catch (error) { this.expose(previous); throw error; }
          return { success: true, output: { pluginId, versionId, rolledBackFrom: previous.versionId } };
        } finally { release(); }
      } catch (error) { return failure(error); }
    });
  }

  evolve(pluginId: string, profile: EvolutionConfig, deps: EvolutionDependencies = {}, context: ExecutablePluginContext = {}): Promise<ToolResult> {
    return this.operation(async () => {
      try {
        await this.ready; this.shutdown.signal.throwIfAborted();
        const record = this.readRegistry().plugins[pluginId];
        const previous = record?.versions.find(v => v.versionId === record.activeVersionId);
        if (!record || !previous) throw new Error("Active executable plugin not found");
        if (profile.kind !== "source" || (profile.backend ?? "docker") !== previous.backend) throw new Error("Executable evolution requires a source profile for the configured backend");
        const profileId = evolutionDigest(profile).slice(7);
        const config = parseEvolutionConfig({ ...profile, sourceRoot: previous.snapshot.root,
          storePath: join(this.root, "evolution", pluginId, record.evolutionEpoch, profileId) });
        const expectedImage = config.backend === "smolvm" ? await resolveSmolvmImage(config.imageArchive!) : await resolveEvolutionImage(config.image);
        if (expectedImage !== previous.image) throw new Error("Evolution and active executable must use the same immutable image");
        const signal = AbortSignal.any([this.shutdown.signal, ...(context.signal ? [context.signal] : []), ...(deps.signal ? [deps.signal] : [])]);
        const campaign = loadEvolutionRegistry(config.storePath);
        const campaignActive = campaign.versions.find(version => version.id === campaign.activeId);
        if (campaignActive?.status === "active" && campaignActive.id !== previous.evolutionVersionId) {
          // A controller promotion whose executable admission/publication failed
          // must not silently become the comparison baseline for the live agent.
          const release = acquireEvolutionController(this.root);
          try {
            const registry = this.readRegistry();
            const current = registry.plugins[pluginId];
            if (current?.activeVersionId !== previous.versionId || current.evolutionEpoch !== record.evolutionEpoch) {
              throw new Error("Executable evolution branch changed concurrently");
            }
            current.evolutionEpoch = randomUUID();
            this.saveRegistry(registry);
            record.evolutionEpoch = current.evolutionEpoch;
            config.storePath = join(this.root, "evolution", pluginId, current.evolutionEpoch, profileId);
          } finally { release(); }
        }
        const run = await runEvolution(config, { ...deps, signal });
        const retained = loadEvolutionRegistry(config.storePath);
        const candidate = retained.versions.find(v => v.id === retained.activeId);
        if (!candidate || candidate.status !== "active" || !candidate.receiptDigest || candidate.id === previous.evolutionVersionId) {
          return { success: true, output: { state: "not_promoted", evaluation: run } };
        }
        const receipt = verifyEvolutionReceipt(config.storePath, candidate.id, candidate);
        verifyEvolutionSnapshot(previous.snapshot); verifyEvolutionSnapshot(candidate.snapshot);
        const files: Record<string, string> = {};
        for (const file of previous.snapshot.files) files[file.path] = readFileSync(join(previous.snapshot.root, file.path), "utf8");
        // Selected files may be removed; non-selected modules stay pinned to the old version.
        for (const name of Object.keys(files)) {
          if (config.sourcePaths.some(path => path === "." || path === name || name.startsWith(path.replace(/\/$/, "") + "/"))) delete files[name];
        }
        for (const file of candidate.snapshot.files) files[file.path] = readFileSync(join(candidate.snapshot.root, file.path), "utf8");
        return await this.install({ manifest: previous.manifest as unknown as Record<string, unknown>, files, entry: previous.entry, kind: previous.kind }, { ...context, signal },
          { previous, epoch: record.evolutionEpoch, evolutionVersionId: candidate.id, receiptDigest: receipt.receiptDigest });
      } catch (error) { return failure(error); }
    });
  }

  async close(): Promise<void> {
    this.shutdown.abort(new Error("ExecutablePluginManager is closed"));
    await Promise.allSettled([this.ready, ...this.operations]);
  }
}

export const EXECUTABLE_CAPABILITIES: readonly string[] = Object.freeze(["compute", "model-call"]);
