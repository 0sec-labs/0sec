import { chmodSync, mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { HarnessGenerationSpec } from "@0sec/shared";
import { ExecutablePluginManager, type PluginVersionRecord } from "./executable.js";
import { SelfExtensionRegistry } from "./self-extension.js";
import { BUILTIN_GUARDS } from "./guards.js";
import { LiveHarnessHost } from "./live-harness.js";

const request = { system: "regression", messages: [], tools: [] };
const input = { sessionId: "regression", phase: "idle" as const, iterations: 0, tokensUsed: 0, tokenBudget: 1000 };
let root: string;
let host: LiveHarnessHost;
let manager: ExecutablePluginManager;
function generation(label: string, body = ""): HarnessGenerationSpec {
  return { label, providers: [{ id: "driver", services: ["agent.driver", "ui.view"], source: { kind: "trusted", entry: "main.mjs", files: {
    "main.mjs": `import { appendFileSync } from 'node:fs';
const label = ${JSON.stringify(label)};
export function activate(ctx, previous) {
  ctx.onDispose(() => appendFileSync(${JSON.stringify(join(root, "disposed"))}, label + '\\n'));
  ${body}
  ctx.setState(previous ?? { count: 0 });
  return {
    async driver(request, execution) {
      if (execution.invokeModel) await execution.invokeModel(request);
      ctx.setState({ count: ctx.getState().count + 1 });
      return { content: [{ type: 'text', text: label + ':' + ctx.getState().count }], stopReason: 'end_turn', durationMs: 0 };
    },
    view() { return { title: label, blocks: [] }; }
  };
}`,
  } } }] };
}
async function activate(spec: HarnessGenerationSpec): Promise<string> {
  const pending = await host.control({ action: "submit", generation: spec });
  await host.checkpoint(input);
  expect(host.snapshot().generationId).toBe(pending.pendingGenerationId);
  return host.snapshot().generationId!;
}
function unlock(directory: string): void {
  chmodSync(directory, 0o700);
  for (const item of readdirSync(directory, { withFileTypes: true })) if (item.isDirectory()) unlock(join(directory, item.name));
}
function sandboxGeneration(count = 1): HarnessGenerationSpec {
  vi.spyOn(manager, "inspectVersion").mockReturnValue({
    manifest: { tools: [{ name: "fixture" }] },
  } as PluginVersionRecord);
  return { label: "sandbox", providers: Array.from({ length: count }, (_, index) => ({
    id: `provider-${index}`, services: count === 1 ? ["agent.driver", "ui.view"] : ["ui.view"],
    source: { kind: "sandboxed", pluginId: "fixture", versionId: "00000000-0000-4000-8000-000000000001", toolName: "fixture" },
  })) };
}
function guestResult(phase: unknown) {
  return { success: true, output: { state: null, output: phase === "view" ? { title: "fixture", blocks: [] } : null } };
}
function waitForGuest(ms: number, signal?: AbortSignal): Promise<void> {
  signal?.throwIfAborted();
  return new Promise((resolve, reject) => {
    const finish = (error?: unknown) => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
      if (error) reject(error); else resolve();
    };
    const abort = () => finish(signal!.reason);
    const timer = setTimeout(() => finish(), ms);
    signal?.addEventListener("abort", abort, { once: true });
  });
}
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), "0sec-live-regression-"));
  manager = new ExecutablePluginManager({ registry: new SelfExtensionRegistry({ enabled: true, baseGuards: BUILTIN_GUARDS }), root: join(root, "executable"), backend: "docker", image: "unused-for-trusted-fixtures" });
  host = new LiveHarnessHost({ executablePlugins: manager, root: join(root, "harness"), workspaceRoot: root, allowTrusted: () => true });
});
afterEach(async () => {
  try { await host.close(); await manager.close(); }
  finally { vi.useRealTimers(); vi.restoreAllMocks(); unlock(root); rmSync(root, { recursive: true, force: true }); }
});

describe("retained live harness", () => {
  it("rejects a driver queued behind preparation when the host closes instead of selecting builtin", async () => {
    let entered!: () => void;
    let release!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const barrier = new Promise<void>(resolve => { release = resolve; });
    vi.spyOn(manager, "executeVersion").mockImplementation(async (_plugin, _version, _tool, args) => {
      if (args.phase === "activate") { entered(); await barrier; }
      return guestResult(args.phase);
    });
    await host.control({ action: "submit", generation: sandboxGeneration() });
    const preparing = host.checkpoint(input);
    await started;
    const queued = host.drive(request).then(value => ({ value }), error => ({ error }));
    const closing = host.close();
    release();
    await Promise.all([preparing, closing]);
    expect(await queued).toEqual({ error: expect.any(Error) });
    expect(host.snapshot().status).toBe("closed");
  });

  it.each(["activate", "view"])("cancels sandbox %s on close but still runs fresh disposal", async phase => {
    let entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    let interrupted = false;
    let disposed = false;
    vi.spyOn(manager, "executeVersion").mockImplementation(async (_plugin, _version, _tool, args, context = {}) => {
      if (args.phase === phase) {
        entered();
        try { await waitForGuest(500, context.signal); }
        catch (error) { interrupted = true; throw error; }
      }
      if (args.phase === "dispose") {
        await waitForGuest(1, context.signal);
        disposed = true;
      }
      return guestResult(args.phase);
    });
    await host.control({ action: "submit", generation: sandboxGeneration() });
    vi.useFakeTimers();
    const preparing = host.checkpoint(input);
    await started;
    const closing = host.close();
    await vi.advanceTimersByTimeAsync(501);
    await closing;
    await preparing;
    expect(interrupted).toBe(true);
    expect(disposed).toBe(true);
    expect(host.snapshot().status).toBe("closed");
  });

  it.each(["close", "failed preparation"])("shares one cleanup deadline across sandbox disposers during %s", async mode => {
    let disposals = 0;
    let completed = 0;
    let interrupted = 0;
    const failures: string[] = [];
    vi.spyOn(manager, "executeVersion").mockImplementation(async (_plugin, _version, _tool, args, context = {}) => {
      if (args.phase === "view" && mode === "failed preparation") throw new Error("Candidate cannot render");
      if (args.phase === "dispose") {
        const delay = ++disposals === 1 ? 25_000 : 30_000;
        try { await waitForGuest(delay, context.signal); completed++; }
        catch (error) { interrupted++; failures.push(error instanceof Error ? error.message : String(error)); throw error; }
      }
      return guestResult(args.phase);
    });
    await host.control({ action: "submit", generation: sandboxGeneration(3) });
    if (mode === "close") await host.checkpoint(input);
    vi.useFakeTimers();
    let settled = false;
    const cleanup = (mode === "close" ? host.close() : host.checkpoint(input)).then(() => { settled = true; });
    try {
      await vi.advanceTimersByTimeAsync(25_000);
      expect(completed).toBe(1);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(5_000);
      expect(settled).toBe(true);
      expect(completed).toBe(1);
      expect(interrupted).toBe(2);
      expect(host.snapshot().status).toBe(mode === "close" ? "closed" : "failed");
      if (mode === "close") expect(host.snapshot().error).toContain(failures[0]);
    } finally {
      await vi.runAllTimersAsync();
      await cleanup;
      vi.useRealTimers();
    }
  });

  it("does not restart the close cleanup budget between a failed candidate and the active generation", async () => {
    let activations = 0;
    let completed = 0;
    let interrupted = 0;
    let entered!: () => void;
    let release!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const barrier = new Promise<void>(resolve => { release = resolve; });
    vi.spyOn(manager, "executeVersion").mockImplementation(async (_plugin, _version, _tool, args, context = {}) => {
      if (args.phase === "activate" && ++activations === 2) { entered(); await barrier; }
      if (args.phase === "dispose") {
        try { await waitForGuest(25_000, context.signal); completed++; }
        catch (error) { interrupted++; throw error; }
      }
      return guestResult(args.phase);
    });
    const spec = sandboxGeneration();
    await activate(spec);
    await host.control({ action: "submit", generation: spec });
    vi.useFakeTimers();
    const preparing = host.checkpoint(input);
    await started;
    let settled = false;
    const closing = host.close().then(() => { settled = true; });
    release();
    try {
      await vi.advanceTimersByTimeAsync(25_000);
      expect(completed).toBe(1);
      expect(settled).toBe(false);
      await vi.advanceTimersByTimeAsync(5_000);
      expect({ settled, completed, interrupted }).toEqual({ settled: true, completed: 1, interrupted: 1 });
      expect(host.snapshot().status).toBe("closed");
    } finally {
      release();
      await vi.runAllTimersAsync();
      await Promise.all([preparing, closing]);
      vi.useRealTimers();
    }
  });

  it("starts the cleanup deadline after draining pinned work, not when close is requested", async () => {
    let entered!: () => void;
    let release!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const barrier = new Promise<void>(resolve => { release = resolve; });
    let disposed = false;
    vi.spyOn(manager, "executeVersion").mockImplementation(async (_plugin, _version, _tool, args, context = {}) => {
      if (args.phase === "driver") {
        entered(); await barrier;
        return { success: true, output: { state: null, output: { content: [{ type: "text", text: "finished" }], stopReason: "end_turn", durationMs: 0 } } };
      }
      if (args.phase === "dispose") { await waitForGuest(1000, context.signal); disposed = true; }
      return guestResult(args.phase);
    });
    await activate(sandboxGeneration());
    vi.useFakeTimers();
    const running = host.drive(request).catch(error => error);
    await started;
    const closing = host.close();
    try {
      await vi.advanceTimersByTimeAsync(35_000);
      expect(disposed).toBe(false);
      release();
      await vi.advanceTimersByTimeAsync(1000);
      await Promise.all([running, closing]);
      expect(disposed).toBe(true);
      expect(host.snapshot()).toMatchObject({ status: "closed" });
    } finally {
      release();
      await vi.runAllTimersAsync();
      await Promise.all([running, closing]);
      vi.useRealTimers();
    }
  });

  it("publishes disposal failures on close without preventing subsequent manager cleanup", async () => {
    const failure = new Error("Guest resource release failed");
    vi.spyOn(manager, "executeVersion").mockImplementation(async (_plugin, _version, _tool, args) => {
      if (args.phase === "dispose") throw failure;
      return guestResult(args.phase);
    });
    await activate(sandboxGeneration());
    let publishedError: string | undefined;
    const unsubscribe = host.subscribe(snapshot => {
      if (snapshot.status === "closed") publishedError = snapshot.error;
    });
    try {
      await host.close();
      await manager.close();
      expect(host.snapshot().status).toBe("closed");
      expect(host.snapshot().error).toContain(failure.message);
      expect(publishedError).toContain(failure.message);
    } finally { unsubscribe(); }
  });

  it("keeps the active route and current state when candidate preparation fails", async () => {
    const active = await activate(generation("stable"));
    expect((await host.drive(request))?.content).toEqual([{ type: "text", text: "stable:1" }]);
    await host.control({ action: "submit", generation: generation("broken", "throw new Error('migration rejected');") });
    await host.checkpoint(input);
    expect(host.snapshot().generationId).toBe(active);
    expect((await host.drive(request))?.content).toEqual([{ type: "text", text: "stable:2" }]);
    expect(readFileSync(join(root, "disposed"), "utf8")).toBe("broken\n");
  });

  it("drains pinned work before migrating state and preserves new state on rollback", async () => {
    const first = await activate(generation("first"));
    let entered!: () => void;
    let release!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const barrier = new Promise<void>(resolve => { release = resolve; });
    const running = host.drive(request, { invokeModel: async () => { entered(); await barrier; return null; } });
    try {
      await started;
      const next = await host.control({ action: "submit", generation: generation("next") });
      const transition = host.checkpoint(input);
      await Promise.resolve();
      expect(host.snapshot().generationId).toBe(first);
      release();
      expect((await running)?.content).toEqual([{ type: "text", text: "first:1" }]);
      await transition;
      expect(host.snapshot().generationId).toBe(next.pendingGenerationId);
      expect((await host.drive(request))?.content).toEqual([{ type: "text", text: "next:2" }]);
      await host.control({ action: "rollback", generationId: first });
      await host.checkpoint(input);
      expect((await host.drive(request))?.content).toEqual([{ type: "text", text: "first:3" }]);
      expect(readFileSync(join(root, "disposed"), "utf8")).toBe("first\nnext\n");
    } finally { release(); await running; }
  });

  it("revokes captured turn brokers before subsequent automatic rendering", async () => {
    const spec = generation("captured");
    const source = spec.providers[0]!.source;
    if (source.kind !== "trusted") throw new Error("Expected trusted fixture");
    source.files["main.mjs"] = `export function activate() {
      let captured, emit;
      return {
        driver(request, execution) { captured = () => execution.invokeModel(request); emit = () => execution.onEvent({type:'late'}); return { content: [{type:'text',text:'finished'}], stopReason:'end_turn',durationMs:0 }; },
        async view() {
          let text = 'not invoked';
          if (captured) { try { await captured(); text = 'broker incorrectly retained'; } catch { text = 'broker revoked'; } }
          if (emit) { try { emit(); text += '; event incorrectly retained'; } catch { text += '; event revoked'; } }
          return { title:'captured', blocks:[{type:'text',text}] };
        }
      };
    }`;
    await activate(spec);
    let modelEffects = 0, eventEffects = 0;
    await host.drive(request, { invokeModel: async () => { modelEffects++; return null; }, onEvent: () => { eventEffects++; } });
    await host.refreshViews(input);
    expect(modelEffects).toBe(0);
    expect(eventEffects).toBe(0);
    expect(host.snapshot().views[0]?.view.blocks).toEqual([{ type: "text", text: "broker revoked; event revoked" }]);
  });

  it("aborts broker work on close even when the provider omits an explicit signal", async () => {
    await activate(generation("closing"));
    let entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const running = host.drive(request, { invokeModel: async (_request, signal) => {
      if (!signal) throw new Error("Broker cancellation signal missing");
      entered();
      await new Promise<void>(resolve => {
        if (signal.aborted) resolve();
        else signal.addEventListener("abort", () => resolve(), { once: true });
      });
      return null;
    } });
    const rejected = expect(running).rejects.toThrow("Live harness is closed");
    await started;
    await host.close();
    await rejected;
    expect(host.snapshot().status).toBe("closed");
    expect(readFileSync(join(root, "disposed"), "utf8")).toBe("closing\n");
  });

  it("does not cycle between generations whose UI has already failed", async () => {
    const first = await activate(generation("broken-ui-first"));
    host.reportUiError(first, "First renderer failed");
    await host.checkpoint(input);
    expect(await host.drive(request)).toBeUndefined();
    const next = await activate(generation("broken-ui-next"));
    host.reportUiError(next, "Next renderer failed");
    await host.checkpoint(input);
    expect(await host.drive(request)).toBeUndefined();
    expect(host.snapshot().generationId).toBeNull();
  });

  it("isolates prompt edits and strips opaque provider history from generated input", async () => {
    const spec = generation("isolated-request");
    const source = spec.providers[0]!.source;
    if (source.kind !== "trusted") throw new Error("Expected trusted fixture");
    source.files["main.mjs"] = `export function activate() {
      return {
        driver(request) {
          const opaqueVisible = 'providerRaw' in request.messages[0];
          request.messages[0].content[0].text = 'provider-local edit';
          return {content:[{type:'text',text:String(opaqueVisible) + ':' + request.messages[0].content[0].text}],stopReason:'end_turn',durationMs:0};
        },
        view() { return {title:'isolated',blocks:[]}; }
      };
    }`;
    await activate(spec);
    const original = { ...request, messages: [{
      role: "user" as const, content: [{ type: "text" as const, text: "original request" }],
      providerRaw: { provider: "fixture", model: "fixture", wireApi: "responses", output: ["private provider data"] },
    }] };
    expect((await host.drive(original))?.content).toEqual([{ type: "text", text: "false:provider-local edit" }]);
    expect(original.messages[0]?.content[0]?.text).toBe("original request");
  });
});
