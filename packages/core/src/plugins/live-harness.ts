import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Context, type Fiber } from "@deepseek-ai/cordis";
import type { HarnessControl, HarnessGenerationSpec, HarnessProviderSpec, HarnessSnapshot, HarnessUiEvent, HarnessUiInput, HarnessView } from "@0sec/shared";
import { z } from "zod";
import { ensureEvolutionDirectory, publishEvolutionArtifact, readEvolutionArtifact } from "../improvement/artifacts.js";
import { canonicalEvolutionJson } from "../improvement/config.js";
import { snapshotEvolutionSource, verifyEvolutionSnapshot } from "../improvement/registry.js";
import type { NativeMessage, NativeRuntimeResult, NativeToolDef } from "../runtime/types.js";
import type { ExecutablePluginContext, ExecutablePluginManager } from "./executable.js";

const MAX_GENERATIONS = 32;
const MAX_JSON_BYTES = 256 * 1024;
const idSchema = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$/);
const pathSchema = z.string().max(512).refine(value => /^[a-zA-Z0-9_./-]+$/.test(value) && value.split("/").every(part => part !== "" && part !== "." && part !== ".."));
const sourceSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("sandboxed"), pluginId: idSchema, versionId: z.string().uuid(), toolName: idSchema }).strict(),
  z.object({ kind: z.literal("trusted"), entry: pathSchema, files: z.record(z.string().max(256 * 1024)), ui: z.object({ tui: pathSchema.optional(), web: pathSchema.optional() }).strict().optional() }).strict(),
]);
const specSchema = z.object({ label: z.string().min(1).max(160), providers: z.array(z.object({
  id: idSchema, requires: z.array(idSchema).max(32).optional(), services: z.array(z.enum(["agent.driver", "ui.view"])).min(1).max(2), source: sourceSchema,
}).strict()).min(1).max(32) }).strict();

/** Canonical admission for operator controls and model-visible self_extend. */
export function parseHarnessGenerationSpec(raw: unknown): HarnessGenerationSpec {
  const spec = specSchema.parse(raw);
  const ids = new Set<string>();
  let drivers = 0;
  let bytes = 0;
  for (const provider of spec.providers) {
    if (ids.has(provider.id)) throw new Error(`Duplicate harness provider: ${provider.id}`);
    ids.add(provider.id);
    if (new Set(provider.services).size !== provider.services.length) throw new Error("Duplicate provider service");
    if (provider.services.includes("agent.driver")) drivers++;
    if (new Set(provider.requires).size !== (provider.requires?.length ?? 0)) throw new Error("Duplicate provider dependency");
    if (provider.source.kind === "trusted") {
      const source = provider.source;
      const paths = Object.keys(source.files);
      if (!paths.length || paths.length > 128) throw new Error("Invalid trusted source file count");
      for (const path of paths) {
        pathSchema.parse(path);
        const size = Buffer.byteLength(source.files[path]!);
        if (size > 256 * 1024 || (bytes += size) > 2 * 1024 * 1024) throw new Error("Harness source size limit exceeded");
      }
      for (const entry of [source.entry, source.ui?.tui, source.ui?.web]) {
        if (entry !== undefined && (!/\.(?:mjs|js)$/.test(entry) || !Object.hasOwn(source.files, entry))) throw new Error(`Missing self-contained ESM entry: ${entry}`);
      }
    }
  }
  if (drivers > 1) throw new Error("A generation may provide at most one agent.driver");
  orderProviders(spec.providers);
  return spec;
}

function orderProviders(providers: HarnessProviderSpec[]): HarnessProviderSpec[] {
  const byId = new Map(providers.map(provider => [provider.id, provider]));
  const visiting = new Set<string>(), visited = new Set<string>(), ordered: HarnessProviderSpec[] = [];
  const visit = (id: string): void => {
    if (visiting.has(id)) throw new Error(`Harness dependency cycle: ${id}`);
    if (visited.has(id)) return;
    const provider = byId.get(id);
    if (!provider) throw new Error(`Missing harness dependency: ${id}`);
    visiting.add(id);
    for (const dependency of provider.requires ?? []) visit(dependency);
    visiting.delete(id); visited.add(id); ordered.push(provider);
  };
  for (const provider of providers) visit(provider.id);
  return ordered;
}

const text = z.string().max(32768);
const commandSchema = z.object({ id: idSchema, label: z.string().min(1).max(200), description: text.optional() }).strict();
const settingSchema = z.object({ id: idSchema, label: z.string().min(1).max(200), description: text.optional(), type: z.enum(["boolean", "text", "select"]), value: z.union([z.boolean(), text]), options: z.array(z.object({ label: text, value: text }).strict()).max(64).optional() }).strict();
const viewSchema = z.object({ title: z.string().max(200), blocks: z.array(z.discriminatedUnion("type", [
  z.object({ type: z.literal("text"), text, tone: z.enum(["normal", "muted", "success", "warning", "error"]).optional() }).strict(),
  z.object({ type: z.literal("markdown"), text }).strict(),
  z.object({ type: z.literal("table"), columns: z.array(text).max(32), rows: z.array(z.array(text).max(32)).max(256) }).strict(),
  z.object({ type: z.literal("progress"), label: text, value: z.number().finite().nonnegative(), max: z.number().finite().positive() }).strict(),
  z.object({ type: z.literal("action"), label: text, prompt: text }).strict(),
])).max(64), commands: z.array(commandSchema).max(32).optional(), settings: z.array(settingSchema).max(32).optional(), requestedPrompt: text.optional() }).strict();
const resultSchema = z.object({ content: z.array(z.discriminatedUnion("type", [
  z.object({ type: z.literal("text"), text }).strict(),
  z.object({ type: z.literal("tool_use"), id: idSchema, name: idSchema, input: z.record(z.unknown()) }).strict(),
])).max(128), stopReason: z.enum(["end_turn", "tool_use", "max_tokens", "error"]), durationMs: z.number().finite().nonnegative(), error: text.optional(), cancelled: z.boolean().optional() });
function copyJson<T>(value: T): T {
  const encoded = canonicalEvolutionJson(value === undefined ? null : value);
  if (Buffer.byteLength(encoded) > MAX_JSON_BYTES) throw new Error("Harness state/output exceeds JSON size limit");
  return JSON.parse(encoded) as T;
}
function parseView(raw: unknown): HarnessView {
  const view = viewSchema.parse(copyJson(raw));
  for (const collection of [view.commands ?? [], view.settings ?? []]) {
    if (new Set(collection.map(item => item.id)).size !== collection.length) throw new Error("Duplicate UI contribution id");
  }
  for (const setting of view.settings ?? []) {
    if ((setting.type === "boolean") !== (typeof setting.value === "boolean")) throw new Error("Setting value type mismatch");
    if (setting.type === "select" && (!setting.options?.length || !setting.options.some(option => option.value === setting.value))) throw new Error("Invalid select setting");
  }
  for (const block of view.blocks) {
    if (block.type === "progress" && block.value > block.max) throw new Error("Progress exceeds maximum");
    if (block.type === "table" && block.rows.some(row => row.length !== block.columns.length)) throw new Error("Table column count mismatch");
  }
  return view;
}
function parseResult(raw: unknown): NativeRuntimeResult {
  // The parent's authorized SDK is the sole source of billing/provider metadata.
  const result = resultSchema.parse(raw);
  const calls = result.content.filter(block => block.type === "tool_use");
  if ((result.stopReason === "tool_use") !== (calls.length > 0) || new Set(calls.map(call => call.id)).size !== calls.length) throw new Error("Invalid driver tool-call result");
  return copyJson({ content: result.content, stopReason: result.stopReason, durationMs: result.durationMs,
    ...(result.error !== undefined ? { error: result.error } : {}),
    ...(result.cancelled !== undefined ? { cancelled: result.cancelled } : {}),
  });
}
const message = (error: unknown): string => (error instanceof Error ? error.message : String(error)).slice(0, 32768);
const serviceKey = (id: string): string => `harness.provider.${id}`;
type SourceSnapshot = Awaited<ReturnType<typeof snapshotEvolutionSource>>;
type DriverRequest = { system: string; messages: NativeMessage[]; tools: NativeToolDef[] };
interface ProviderImplementation {
  driver?: (request: DriverRequest, execution: ExecutablePluginContext) => unknown | Promise<unknown>;
  view?: (input: HarnessUiInput) => unknown | Promise<unknown>;
  dispose?: () => void | Promise<void>;
}
interface RetainedGeneration { id: string; spec: HarnessGenerationSpec; sources: Record<string, SourceSnapshot> }
interface MountedProvider { spec: HarnessProviderSpec; state: unknown; implementation: ProviderImplementation; fiber?: Fiber; ui?: { tui?: string; web?: string } }
interface Generation {
  retained: RetainedGeneration; context: Context; abort: AbortController; providers: Map<string, MountedProvider>;
  order: MountedProvider[]; leases: number; drained: Array<() => void>; views: HarnessSnapshot["views"];
  trusted: boolean; disposed: boolean; cleanupErrors: string[];
}
export interface LiveHarnessOptions {
  executablePlugins: ExecutablePluginManager; root: string; workspaceRoot: string;
  allowTrusted: () => boolean; onChange?: (snapshot: HarnessSnapshot) => void;
}

/** A live-session coordinator around real Cordis scopes, not a durable campaign engine. */
export class LiveHarnessHost {
  private readonly root: string;
  private readonly retained = new Map<string, RetainedGeneration>();
  private readonly listeners = new Set<(snapshot: HarnessSnapshot) => void>();
  private readonly driverAuthorities = new WeakMap<NativeRuntimeResult, Generation>();
  private readonly failedUiGenerations = new Set<string>();
  private readonly shutdown = new AbortController();
  private active?: Generation;
  private previousId: string | null = null;
  private pending: string | null | undefined;
  private state: HarnessSnapshot["status"] = "builtin";
  private error?: string;
  private lane: Promise<void> = Promise.resolve();
  private controls: Promise<unknown> = Promise.resolve();
  private gates = 0;
  private closing = false;
  private closePromise?: Promise<void>;
  private cleanupBudget?: { signal: AbortSignal; timer: ReturnType<typeof setTimeout> };
  private closingCleanupErrors?: string[];
  private lastInput: HarnessUiInput = { sessionId: "", phase: "idle", iterations: 0, tokensUsed: 0, tokenBudget: 0 };

  constructor(private readonly options: LiveHarnessOptions) {
    this.root = ensureEvolutionDirectory(resolve(options.root));
    const directory = ensureEvolutionDirectory(join(this.root, "generations"));
    // Source/spec history persists. Active providers, state and effects do not auto-resume.
    for (const name of readdirSync(directory)) {
      if (!/^[a-f0-9-]{36}\.json$/.test(name)) continue;
      if (this.retained.size >= MAX_GENERATIONS) throw new Error("Harness generation retention limit reached");
      const raw = readEvolutionArtifact(join(directory, name)) as RetainedGeneration;
      const id = z.string().uuid().parse(raw.id);
      if (`${id}.json` !== name) throw new Error("Harness generation identity mismatch");
      const spec = parseHarnessGenerationSpec(raw.spec);
      const sources: Record<string, SourceSnapshot> = {};
      for (const provider of spec.providers) if (provider.source.kind === "trusted") {
        const snapshot = raw.sources?.[provider.id];
        if (!snapshot || resolve(snapshot.root) !== join(this.root, "snapshots", snapshot.id)) throw new Error("Invalid retained harness source path");
        verifyEvolutionSnapshot(snapshot); sources[provider.id] = snapshot;
      }
      this.retained.set(id, { id, spec, sources });
    }
    if (options.onChange) this.listeners.add(options.onChange);
  }

  snapshot(): HarnessSnapshot {
    const active = this.active;
    const views = active?.views ?? [];
    return structuredClone({ generationId: active?.retained.id ?? null, previousGenerationId: this.previousId,
      pendingGenerationId: this.pending ?? null, label: active?.retained.spec.label ?? "Built-in harness", status: this.state,
      trusted: active?.trusted ?? false, providers: active ? active.order.map(provider => ({ id: provider.spec.id, services: provider.spec.services, kind: provider.spec.source.kind })) : [],
      views, commands: views.flatMap(({ providerId, view }) => (view.commands ?? []).map(command => ({ ...command, providerId }))),
      settings: views.flatMap(({ providerId, view }) => (view.settings ?? []).map(setting => ({ ...setting, providerId }))),
      trustedUi: active && this.options.allowTrusted() ? active.order.flatMap(provider => provider.ui ? [{ providerId: provider.spec.id, ...provider.ui }] : []) : [],
      ...(this.error ? { error: this.error } : {}),
    });
  }
  subscribe(listener: (snapshot: HarnessSnapshot) => void): () => void {
    this.assertOpen(); this.listeners.add(listener); return () => { this.listeners.delete(listener); };
  }
  private publish(): void {
    for (const listener of this.listeners) {
      try { listener(this.snapshot()); } catch { /* An observer cannot replay a committed activation. */ }
    }
  }
  private assertOpen(): void { if (this.closing) throw new Error("Live harness is closed"); }
  private serialize<T>(work: () => Promise<T>): Promise<T> {
    this.gates++;
    const next = this.lane.then(work).finally(() => { this.gates--; });
    this.lane = next.then(() => {}, () => {});
    return next;
  }
  private async drain(generation = this.active): Promise<void> {
    if (generation?.leases) await new Promise<void>(resolve => generation.drained.push(resolve));
  }
  private release(generation: Generation): void {
    if (--generation.leases === 0) for (const resolve of generation.drained.splice(0)) resolve();
  }
  private checkTrust(generation: Generation): void {
    if (generation.trusted && !this.options.allowTrusted()) throw new Error("Workspace harness trust was revoked");
    this.shutdown.signal.throwIfAborted();
  }

  /** Host-internal dispatch authority; never accepted from generated output or wire data. */
  assertDriverAuthority(result?: NativeRuntimeResult): void {
    const generation = result === undefined ? this.active : this.driverAuthorities.get(result);
    if (!generation || generation !== this.active) throw new Error("Harness driver authority is no longer active");
    this.checkTrust(generation);
    generation.abort.signal.throwIfAborted();
  }

  control(request: HarnessControl): Promise<HarnessSnapshot> {
    this.assertOpen();
    const operation = this.controls.then(async () => {
      this.assertOpen();
      switch (request.action) {
        case "list": return this.snapshot();
        case "submit": {
          const spec = parseHarnessGenerationSpec(request.generation);
          if (this.retained.size >= MAX_GENERATIONS) throw new Error("Harness generation retention limit (32) reached; active generation remains usable. Start a new engine process to reclaim compiled ESM.");
          if (spec.providers.some(provider => provider.source.kind === "trusted") && !this.options.allowTrusted()) throw new Error("Explicit workspace trust grant required for host ESM");
          await this.options.executablePlugins.ready;
          const sources: Record<string, SourceSnapshot> = {};
          for (const provider of spec.providers) {
            if (provider.source.kind === "sandboxed") {
              const { toolName } = provider.source;
              const version = this.options.executablePlugins.inspectVersion(provider.source.pluginId, provider.source.versionId);
              if (!version?.manifest.tools.some(tool => tool.name === toolName)) throw new Error(`Unknown retained executable service: ${provider.id}`);
              continue;
            }
            const temporary = await mkdtemp(join(tmpdir(), "0sec-harness-source-"));
            try {
              for (const [path, source] of Object.entries(provider.source.files)) {
                await mkdir(dirname(join(temporary, path)), { recursive: true, mode: 0o700 });
                await writeFile(join(temporary, path), source, { mode: 0o600 });
              }
              sources[provider.id] = await snapshotEvolutionSource({ sourceRoot: temporary, storePath: this.root, sourcePaths: Object.keys(provider.source.files), maxSourceBytes: 2 * 1024 * 1024 });
            } finally { await rm(temporary, { recursive: true, force: true }); }
          }
          this.assertOpen();
          const retained = { id: randomUUID(), spec, sources };
          publishEvolutionArtifact(join(this.root, "generations", `${retained.id}.json`), retained);
          this.retained.set(retained.id, retained); this.pending = retained.id;
          break;
        }
        case "rollback": {
          const id = request.generationId ?? this.previousId;
          if (!id || !this.retained.has(id)) throw new Error("No retained harness generation to roll back to");
          this.pending = id; break;
        }
        case "disable": this.pending = null; break;
        default: throw new Error("Unknown harness control");
      }
      this.state = "pending"; this.error = undefined; this.publish(); return this.snapshot();
    });
    this.controls = operation.catch(() => {});
    return operation;
  }

  checkpoint(input?: HarnessUiInput, _context?: ExecutablePluginContext): Promise<void> {
    this.assertOpen();
    return this.serialize(async () => {
      this.assertOpen();
      if (input) {
        const { event: _event, ...automatic } = input;
        this.lastInput = copyJson(automatic);
      }
      await this.drain();
      const revoked = this.active?.trusted && !this.options.allowTrusted();
      if (revoked) this.pending = null;
      if (this.pending === undefined) return;
      const target = this.pending; this.pending = undefined;
      const previous = this.active;
      let candidate: Generation | undefined;
      this.state = "preparing"; this.publish();
      try {
        if (target !== null) candidate = await this.prepare(this.retained.get(target)!);
        if (candidate) this.checkTrust(candidate);
        this.assertOpen();
      } catch (error) {
        if (candidate) await this.dispose(candidate);
        this.error = message(error); this.state = "failed"; this.publish(); return;
      }
      this.active = candidate;
      if (previous) this.previousId = previous.retained.id;
      this.state = this.pending !== undefined ? "pending" : candidate ? "active" : "builtin";
      this.error = revoked ? "Workspace trust revoked; trusted generation disabled" : undefined;
      this.publish();
      if (previous) {
        await this.dispose(previous);
        if (previous.cleanupErrors.length) { this.error = `Previous generation disposal: ${previous.cleanupErrors.join("; ")}`; this.publish(); }
      }
    });
  }

  private async prepare(retained: RetainedGeneration): Promise<Generation> {
    const generation: Generation = { retained, context: new Context(), abort: new AbortController(), providers: new Map(), order: [], leases: 0, drained: [], views: [], trusted: retained.spec.providers.some(provider => provider.source.kind === "trusted"), disposed: false, cleanupErrors: [] };
    const signal = AbortSignal.any([generation.abort.signal, this.shutdown.signal]);
    try {
      this.checkTrust(generation);
      for (const spec of orderProviders(retained.spec.providers)) {
        this.checkTrust(generation);
        const provider: MountedProvider = { spec, state: copyJson(this.active?.providers.get(spec.id)?.state ?? null), implementation: {} };
        generation.providers.set(spec.id, provider); generation.order.push(provider);
        const fiber = generation.context.plugin({ name: `harness:${spec.id}`, inject: (spec.requires ?? []).map(serviceKey), apply: async (ctx: Context) => {
          const owned = (dispose: () => void | Promise<void>): (() => Promise<void>) => ctx.effect(() => async () => {
            try { await dispose(); } catch (error) { generation.cleanupErrors.push(message(error)); }
          });
          if (spec.source.kind === "sandboxed") {
            owned(async () => { await this.guest(provider, "dispose", null, { signal: this.cleanupSignal() }); });
            await this.guest(provider, "activate", null, { signal });
            provider.implementation = {
              ...(spec.services.includes("agent.driver") ? { driver: (request: DriverRequest, context: ExecutablePluginContext) => this.guest(provider, "driver", request, context) } : {}),
              ...(spec.services.includes("ui.view") ? { view: (input: HarnessUiInput) => this.guest(provider, "view", input, { signal }) } : {}),
            };
          } else {
            const snapshot = retained.sources[spec.id]!;
            verifyEvolutionSnapshot(snapshot);
            for (const entry of [spec.source.entry, spec.source.ui?.tui, spec.source.ui?.web]) {
              if (entry !== undefined && !snapshot.files.some(file => file.path === entry)) throw new Error(`Entry absent from retained snapshot: ${entry}`);
            }
            if (spec.source.ui) provider.ui = {
              ...(spec.source.ui.tui ? { tui: readFileSync(join(snapshot.root, spec.source.ui.tui), "utf8") } : {}),
              ...(spec.source.ui.web ? { web: readFileSync(join(snapshot.root, spec.source.ui.web), "utf8") } : {}),
            };
            this.checkTrust(generation);
            const module = await import(pathToFileURL(join(snapshot.root, spec.source.entry)).href);
            this.checkTrust(generation);
            if (typeof module.activate !== "function") throw new Error(`Provider ${spec.id} must export activate`);
            const handles = new Map<string, Readonly<ProviderImplementation>>();
            const getService = (id: string): Readonly<ProviderImplementation> => {
              if (!spec.requires?.includes(id)) throw new Error(`Undeclared harness dependency: ${id}`);
              let handle = handles.get(id);
              if (!handle) {
                const resolveDependency = (): MountedProvider => {
                  if (generation.disposed) throw new Error("Harness generation disposed");
                  const dependency = ctx.get(serviceKey(id)) as MountedProvider | undefined;
                  if (!dependency) throw new Error(`Harness dependency unavailable: ${id}`);
                  return dependency;
                };
                handle = Object.freeze({
                  driver: async (request: DriverRequest, context: ExecutablePluginContext = {}) => {
                    const dependency = resolveDependency();
                    if (!dependency.spec.services.includes("agent.driver") || !dependency.implementation.driver) throw new Error("Dependency has no driver service");
                    return parseResult(await dependency.implementation.driver(request, context));
                  },
                  view: async (input: HarnessUiInput) => {
                    const dependency = resolveDependency();
                    if (!dependency.spec.services.includes("ui.view") || !dependency.implementation.view) throw new Error("Dependency has no view service");
                    return parseView(await dependency.implementation.view(input));
                  },
                }); handles.set(id, handle);
              }
              return handle;
            };
            const context = Object.freeze({ providerId: spec.id, generationId: retained.id,
              signal,
              getState: () => copyJson(provider.state), setState: (state: unknown) => { provider.state = copyJson(state); },
              onDispose: owned, effect: (execute: () => (() => void | Promise<void>)) => ctx.effect(execute),
              on: ctx.on.bind(ctx), services: Object.freeze({ get: getService }),
            });
            const implementation = await module.activate(context, copyJson(provider.state));
            if (!implementation || typeof implementation !== "object") throw new Error("activate must return provider services");
            provider.implementation = implementation;
            if (implementation.dispose !== undefined) {
              if (typeof implementation.dispose !== "function") throw new Error("Invalid provider disposer");
              owned(() => implementation.dispose());
            }
          }
          for (const service of spec.services) if (typeof provider.implementation[service === "agent.driver" ? "driver" : "view"] !== "function") throw new Error(`Provider ${spec.id} omitted ${service}`);
          ctx.provide(serviceKey(spec.id), provider);
        } });
        provider.fiber = fiber;
        await fiber;
      }
      generation.views = await this.collectViews(generation, this.lastInput);
      return generation;
    } catch (error) { await this.dispose(generation); throw error; }
  }

  private async guest(provider: MountedProvider, phase: "activate" | "driver" | "view" | "dispose", input: unknown, context: ExecutablePluginContext): Promise<unknown> {
    const source = provider.spec.source;
    if (source.kind !== "sandboxed") throw new Error("Not a sandboxed provider");
    const result = await this.options.executablePlugins.executeVersion(source.pluginId, source.versionId, source.toolName, { phase, state: copyJson(provider.state), input: copyJson(input) }, context);
    if (!result.success) throw new Error(result.error ?? "Sandboxed harness service failed");
    const envelope = z.object({ state: z.unknown(), output: z.unknown().optional() }).strict().parse(result.output);
    if (!Object.hasOwn(envelope, "state")) throw new Error("Sandboxed lifecycle response omitted state");
    provider.state = copyJson(envelope.state);
    return envelope.output;
  }

  async drive(request: DriverRequest, context: ExecutablePluginContext = {}): Promise<NativeRuntimeResult | undefined> {
    if (!this.active && !this.gates && !this.closing) return undefined;
    this.assertOpen();
    while (this.gates) await this.lane;
    this.assertOpen();
    const generation = this.active;
    const provider = generation?.order.find(item => item.spec.services.includes("agent.driver"));
    if (!generation || !provider) return undefined;
    this.checkTrust(generation); generation.leases++;
    let brokerOpen = true;
    const pending = new Set<Promise<unknown>>();
    const signal = AbortSignal.any([generation.abort.signal, this.shutdown.signal, ...(context.signal ? [context.signal] : [])]);
    const combineSignal = (requested?: AbortSignal): AbortSignal => requested ? AbortSignal.any([signal, requested]) : signal;
    const track = <T>(invoke: () => Promise<T>): Promise<T> => {
      if (!brokerOpen) return Promise.reject(new Error("Harness turn broker is no longer active"));
      const operation = Promise.resolve().then(() => { this.checkTrust(generation); signal.throwIfAborted(); return invoke(); });
      pending.add(operation);
      void operation.then(() => pending.delete(operation), () => pending.delete(operation));
      return operation;
    };
    try {
      const execution: ExecutablePluginContext = {
        signal,
        ...(context.invokeTool ? { invokeTool: (name, args, requested, capabilities) => track(() => context.invokeTool!(name, args, combineSignal(requested), capabilities)) } : {}),
        ...(context.invokeModel ? { invokeModel: (request, requested) => track(() => context.invokeModel!(request, combineSignal(requested))) } : {}),
        ...(context.onEvent ? { onEvent: (event: unknown) => {
          if (!brokerOpen) throw new Error("Harness turn broker is no longer active");
          this.checkTrust(generation); signal.throwIfAborted(); context.onEvent?.(event);
        } } : {}),
      };
      // Generated providers receive an isolated message view, never opaque provider
      // reasoning or mutable references into the authoritative session transcript.
      const input: DriverRequest = {
        system: request.system,
        messages: request.messages.map(({ role, content }) => ({ role, content: structuredClone(content) })),
        tools: structuredClone(request.tools),
      };
      const result = parseResult(await provider.implementation.driver!(input, execution));
      brokerOpen = false;
      await Promise.allSettled(pending);
      this.checkTrust(generation);
      signal.throwIfAborted();
      this.driverAuthorities.set(result, generation);
      return result;
    } catch (error) { this.error = message(error); this.state = "failed"; this.publish(); throw error; }
    finally {
      brokerOpen = false;
      await Promise.allSettled(pending);
      // A cached trusted module may retain its execution handle after this turn.
      context = {};
      this.release(generation);
    }
  }

  private async collectViews(generation: Generation, input: HarnessUiInput): Promise<HarnessSnapshot["views"]> {
    const states = new Map(generation.order.map(provider => [provider, copyJson(provider.state)]));
    try {
      const views: HarnessSnapshot["views"] = [];
      for (const provider of generation.order) if (provider.spec.services.includes("ui.view")) {
        this.checkTrust(generation);
        const { requestedPrompt: _ignored, ...view } = parseView(await provider.implementation.view!(copyJson(input)));
        views.push({ providerId: provider.spec.id, view });
      }
      copyJson(views);
      return views;
    } catch (error) { for (const [provider, state] of states) provider.state = state; throw error; }
  }
  refreshViews(input: HarnessUiInput, _context?: ExecutablePluginContext): Promise<void> {
    this.assertOpen();
    return this.serialize(async () => {
      await this.drain(); this.assertOpen();
      const { event: _event, ...automatic } = input;
      this.lastInput = copyJson(automatic);
      if (!this.active) return;
      try { this.active.views = await this.collectViews(this.active, this.lastInput); this.publish(); }
      catch (error) { this.error = message(error); this.publish(); throw error; }
    });
  }
  interact(request: { generationId: string; providerId: string; event: HarnessUiEvent }): Promise<{ snapshot: HarnessSnapshot; requestedPrompt?: string }> {
    this.assertOpen();
    return this.serialize(async () => {
      await this.drain(); this.assertOpen();
      const generation = this.active;
      if (!generation || generation.retained.id !== request.generationId) throw new Error("Stale harness generation");
      this.checkTrust(generation);
      const provider = generation.providers.get(request.providerId);
      const catalog = generation.views.find(view => view.providerId === request.providerId)?.view;
      if (!provider || !catalog) throw new Error("Harness view provider unavailable");
      const event = copyJson(request.event);
      if (event.kind === "command") {
        if (!catalog.commands?.some(command => command.id === event.id)) throw new Error("Unknown harness command");
      } else if (event.kind === "setting") {
        const setting = catalog.settings?.find(setting => setting.id === event.id);
        if (!setting || (setting.type === "boolean" ? typeof event.value !== "boolean" : typeof event.value !== "string") || (setting.type === "select" && !setting.options?.some(option => option.value === event.value))) throw new Error("Invalid harness setting value");
      } else throw new Error("Unknown harness UI event");
      generation.leases++;
      const previous = copyJson(provider.state);
      try {
        const { requestedPrompt, ...view } = parseView(await provider.implementation.view!({ ...this.lastInput, event }));
        const views = generation.views.map(item => item.providerId === provider.spec.id ? { providerId: provider.spec.id, view } : item);
        copyJson(views);
        generation.views = views;
        this.publish();
        return { snapshot: this.snapshot(), ...(requestedPrompt !== undefined ? { requestedPrompt } : {}) };
      } catch (error) { provider.state = previous; this.error = message(error); this.publish(); throw error; }
      finally { this.release(generation); }
    });
  }
  reportUiError(generationId: string, error: string): void {
    if (this.closing || this.active?.retained.id !== generationId) return;
    this.failedUiGenerations.add(generationId);
    this.error = message(error);
    this.pending = this.previousId && !this.failedUiGenerations.has(this.previousId) ? this.previousId : null;
    this.state = "pending"; this.publish();
  }
  private cleanupSignal(): AbortSignal {
    if (!this.cleanupBudget) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(new Error("Harness cleanup deadline exceeded")), 30_000);
      timer.unref();
      this.cleanupBudget = { signal: controller.signal, timer };
    }
    return this.cleanupBudget.signal;
  }
  private finishCleanup(): void {
    if (this.cleanupBudget) clearTimeout(this.cleanupBudget.timer);
    this.cleanupBudget = undefined;
  }
  private async dispose(generation: Generation): Promise<void> {
    if (generation.disposed) return;
    generation.disposed = true; generation.abort.abort(new Error("Harness generation disposed"));
    // Serialized disposal shares one fresh budget; closing also retains it across
    // failed preparation and the previously active generation.
    this.cleanupSignal();
    for (const provider of [...generation.order].reverse()) {
      try { await provider.fiber?.dispose(); } catch (error) { generation.cleanupErrors.push(message(error)); }
    }
    try { await generation.context.fiber.dispose(); } catch (error) { generation.cleanupErrors.push(message(error)); }
    generation.views = []; generation.providers.clear(); generation.order = [];
    if (this.closing && generation.cleanupErrors.length) {
      (this.closingCleanupErrors ??= []).push(...generation.cleanupErrors);
    }
    if (!this.closing) this.finishCleanup();
  }
  close(): Promise<void> {
    if (this.closePromise) return this.closePromise;
    this.closing = true; this.shutdown.abort(new Error("Live harness is closed"));
    this.closePromise = this.serialize(async () => {
      try {
        await this.controls; await this.drain();
        if (this.active) await this.dispose(this.active);
        if (this.closingCleanupErrors?.length) {
          this.error = `Harness disposal: ${this.closingCleanupErrors.join("; ")}`;
          this.closingCleanupErrors = undefined;
        }
        this.active = undefined; this.pending = undefined; this.state = "closed"; this.publish(); this.listeners.clear();
      } finally { this.finishCleanup(); }
    });
    return this.closePromise;
  }
}
