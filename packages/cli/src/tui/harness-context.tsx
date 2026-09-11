/** @jsxImportSource @opentui/react */
import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { randomUUID } from "node:crypto";
import { getWorkspaceHarnessTrust, setWorkspaceHarnessTrust } from "@0sec/core";
import type { LiveHarnessHost } from "@0sec/core";
import type { HarnessControl, HarnessSnapshot, HarnessUiEvent } from "@0sec/shared";

type ViewProps = { snapshot: HarnessSnapshot; sendPrompt: (text: string) => void };
export interface TrustedUiContext extends ViewProps { React: typeof React }
export interface TrustedUiFactoryResult { component: React.ComponentType<ViewProps>; dispose?: () => void | Promise<void> }
export type TrustedUiFactory = (context: TrustedUiContext) => React.ComponentType<ViewProps> | TrustedUiFactoryResult;
export interface HarnessContextValue {
  snapshot: HarnessSnapshot | null;
  workspaceTrusted: boolean;
  workspaceRoot: string;
  busy: boolean;
  error: string | null;
  control: (request: HarnessControl) => Promise<void>;
  interact: (generationId: string, providerId: string, event: HarnessUiEvent) => Promise<void>;
  setWorkspaceTrusted: (trusted: boolean) => Promise<void>;
  reportUiError: (generationId: string, message: string) => void;
  stagePrompt: (text: string) => void;
  showConversation: boolean;
  setShowConversation: (show: boolean) => void;
}
const HarnessContext = createContext<HarnessContextValue | null>(null);
export function useHarness(): HarnessContextValue {
  const value = useContext(HarnessContext);
  if (!value) throw new Error("Live harness controls require the session's HarnessProvider");
  return value;
}

export function HarnessProvider({ children, host, busy, workspaceRoot, stagePrompt }: {
  children: React.ReactNode;
  host: LiveHarnessHost | null;
  busy: boolean;
  workspaceRoot: string;
  stagePrompt: (text: string) => void;
}) {
  const [observed, setObserved] = useState<{ host: LiveHarnessHost; snapshot: HarnessSnapshot } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [workspaceTrusted, setTrusted] = useState(() => getWorkspaceHarnessTrust(workspaceRoot));
  const [showConversation, setShowConversation] = useState(true);
  const current = useRef({ host, busy, stagePrompt });
  current.current = { host, busy, stagePrompt };
  const mounted = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  const snapshot = observed?.host === host ? observed?.snapshot ?? null : null;

  useEffect(() => {
    setError(null);
    setShowConversation(true);
    setTrusted(getWorkspaceHarnessTrust(workspaceRoot));
    if (!host) { setObserved(null); return; }
    let active = true;
    const unsubscribe = host.subscribe((next) => {
      if (active) setObserved({ host, snapshot: next });
    });
    setObserved({ host, snapshot: host.snapshot() });
    return () => { active = false; unsubscribe(); };
  }, [host, workspaceRoot]);

  const fail = useCallback((owner: LiveHarnessHost | null, cause: unknown) => {
    if (mounted.current && current.current.host === owner) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, []);
  // Controls queue in the host during a turn. Only the host applies them at a
  // checkpoint; the UI never cancels a turn or reconstructs a session.
  const previousBusy = useRef(busy);
  useEffect(() => {
    const becameIdle = previousBusy.current && !busy;
    previousBusy.current = busy;
    if (!becameIdle || !host) return;
    const next = host.snapshot();
    if (next.status === "pending" || (next.trusted && !getWorkspaceHarnessTrust(workspaceRoot))) {
      void host.checkpoint().catch(cause => fail(host, cause));
    }
  }, [busy, host, workspaceRoot, fail]);

  const control = useCallback(async (request: HarnessControl) => {
    const owner = current.current.host;
    if (!owner) { fail(owner, "Live harness unavailable. Use /new-chat with self-extension enabled."); return; }
    setError(null);
    try {
      await owner.control(request);
      if (current.current.host === owner && !current.current.busy && request.action !== "list") await owner.checkpoint();
    } catch (cause) { fail(owner, cause); }
  }, [fail]);
  const interact = useCallback(async (generationId: string, providerId: string, event: HarnessUiEvent) => {
    const owner = current.current.host;
    if (!owner) { fail(owner, "This chat has no live harness."); return; }
    setError(null);
    try {
      const result = await owner.interact({ generationId, providerId, event });
      if (mounted.current && current.current.host === owner && result.requestedPrompt) {
        current.current.stagePrompt(result.requestedPrompt);
      }
    } catch (cause) { fail(owner, cause); }
  }, [fail]);
  const setWorkspaceTrusted = useCallback(async (trusted: boolean) => {
    const owner = current.current.host;
    setError(null);
    try {
      setWorkspaceHarnessTrust(workspaceRoot, trusted);
      setTrusted(getWorkspaceHarnessTrust(workspaceRoot));
      if (owner && !current.current.busy) await owner.checkpoint();
    } catch (cause) { fail(owner, cause); }
  }, [workspaceRoot, fail]);
  const reportUiError = useCallback((generationId: string, message: string) => {
    const owner = host;
    if (!mounted.current || !owner || current.current.host !== owner || owner.snapshot().generationId !== generationId) return;
    setShowConversation(true);
    fail(owner, message);
    owner.reportUiError(generationId, message);
    if (!current.current.busy) void owner.checkpoint().catch(cause => fail(owner, cause));
  }, [host, fail]);
  const stage = useCallback((text: string) => {
    if (mounted.current) current.current.stagePrompt(text);
  }, []);
  return <HarnessContext.Provider value={{ snapshot, workspaceTrusted, workspaceRoot, busy, error,
    control, interact, setWorkspaceTrusted, reportUiError, stagePrompt: stage, showConversation, setShowConversation }}>
    {children}
  </HarnessContext.Provider>;
}

class TrustedViewBoundary extends React.Component<{
  children: React.ReactNode; onError: (message: string) => void;
}, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(error: Error) { this.props.onError(error.message); }
  render() { return this.state.failed ? null : this.props.children; }
}

function TrustedView({ source, generationId, snapshot, sendPrompt, reportUiError }: ViewProps & {
  source: string; generationId: string; reportUiError: HarnessContextValue["reportUiError"];
}) {
  const [loaded, setLoaded] = useState<{ component: React.ComponentType<ViewProps>; sendPrompt: ViewProps["sendPrompt"] } | null>(null);
  const latest = useRef({ snapshot, sendPrompt, reportUiError });
  latest.current = { snapshot, sendPrompt, reportUiError };
  useEffect(() => {
    let cancelled = false;
    let returnedDispose: TrustedUiFactoryResult["dispose"];
    let namedDispose: TrustedUiFactoryResult["dispose"];
    let disposed = false;
    const dispose = async () => {
      if (disposed) return;
      disposed = true;
      for (const cleanup of returnedDispose === namedDispose ? [returnedDispose] : [returnedDispose, namedDispose]) {
        if (!cleanup) continue;
        try { await cleanup(); }
        catch (cause) { latest.current.reportUiError(generationId, `Trusted view cleanup failed: ${String(cause)}`); }
      }
    };
    const load = async () => {
      try {
        // Provider-authored runtime source cannot be statically imported.
        const url = `data:text/javascript;base64,${Buffer.from(`${source}\n// UI mount ${randomUUID()}\n`).toString("base64")}`;
        const module = await import(url);
        namedDispose = typeof module.dispose === "function" ? module.dispose : undefined;
        if (cancelled) { await dispose(); return; }
        if (typeof module.default !== "function") throw new Error("Trusted view must export a component factory");
        const send = (text: string) => { if (!cancelled) latest.current.sendPrompt(text); };
        const result = (module.default as TrustedUiFactory)({ React, snapshot: latest.current.snapshot, sendPrompt: send });
        const resolved = typeof result === "function" ? { component: result } : result;
        returnedDispose = typeof resolved?.dispose === "function" ? resolved.dispose : undefined;
        if (!resolved || typeof resolved.component !== "function") throw new Error("Trusted view factory must return a component or {component, dispose}");
        if (cancelled) { await dispose(); return; }
        setLoaded({ component: resolved.component, sendPrompt: send });
      } catch (cause) {
        if (!cancelled) latest.current.reportUiError(generationId, `Trusted view failed: ${cause instanceof Error ? cause.message : String(cause)}`);
        await dispose();
      }
    };
    void load();
    return () => {
      cancelled = true;
      // React unmounts the child and runs its effect cleanup before module cleanup.
      queueMicrotask(() => { if (namedDispose || returnedDispose) void dispose(); });
    };
  }, [source, generationId]);
  if (!loaded) return <text>Loading trusted view…</text>;
  return <TrustedViewBoundary onError={message => reportUiError(generationId, message)}>
    {React.createElement(loaded.component, { snapshot, sendPrompt: loaded.sendPrompt })}
  </TrustedViewBoundary>;
}

export interface HarnessPresentationProps { fallback: React.ReactNode }
export function HarnessPresentation({ fallback }: HarnessPresentationProps) {
  const { snapshot, workspaceTrusted, showConversation, stagePrompt, reportUiError } = useHarness();
  const entries = snapshot?.trustedUi.filter(entry => entry.tui) ?? [];
  if (showConversation || !workspaceTrusted || !snapshot?.trusted || !snapshot.generationId || !entries.length) return <>{fallback}</>;
  return <>{entries.map(entry => <TrustedView key={`${snapshot.generationId}:${entry.providerId}`}
    source={entry.tui!} generationId={snapshot.generationId!} snapshot={snapshot}
    sendPrompt={stagePrompt} reportUiError={reportUiError} />)}</>;
}
