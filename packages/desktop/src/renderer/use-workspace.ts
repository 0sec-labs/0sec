import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type {
  DesktopCodexAuthStatus,
  DesktopConsoleAutonomyMode,
  DesktopConsoleDecision,
  DesktopConsoleDecisionResponse,
  DesktopConsoleEvent,
  DesktopConsoleRole,
  DesktopConsoleSession,
} from "@0sec/shared";
import { api } from "./api.js";
import { useStoredState } from "./use-stored-state.js";

const EMPTY_EVENTS: readonly DesktopConsoleEvent[] = [];
const SESSION_POLL_MS = 2_000;
const EVENT_POLL_MS = 300;

/* ── Event helpers ─────────────────────────────────────────── */

/** Merge events, deduplicating by sequence. Skips copy when nothing changed. */
function mergeEvents(
  current: readonly DesktopConsoleEvent[],
  incoming: readonly DesktopConsoleEvent[],
): DesktopConsoleEvent[] {
  if (incoming.length === 0) return current as DesktopConsoleEvent[];
  const known = new Set(current.map((e) => e.sequence));
  const fresh = incoming.filter((e) => !known.has(e.sequence));
  if (fresh.length === 0) return current as DesktopConsoleEvent[];
  return [...current, ...fresh];
}

/* ── Public interface ───────────────────────────────────────── */

export interface Workspace {
  sessions: DesktopConsoleSession[];
  activeId: string | null;
  activeSession: DesktopConsoleSession | null;
  events: DesktopConsoleEvent[];
  loading: boolean;
  error: string | null;
  busy: boolean;
  auth: DesktopCodexAuthStatus | null;
  draft: string;
  titles: Record<string, string>;

  selectSession(id: string): void;
  createSession(input?: {
    target?: string;
    role?: DesktopConsoleRole;
    autonomyMode?: DesktopConsoleAutonomyMode;
  }): Promise<string | null>;
  setDraft(text: string): void;
  renameSession(id: string, title: string): void;
  send(): Promise<void>;
  cancel(): Promise<void>;
  resolveDecision(
    decision: DesktopConsoleDecision,
    response: DesktopConsoleDecisionResponse,
  ): Promise<void>;
  connectCodex(): Promise<void>;
  cancelCodex(): Promise<void>;
  clearError(): void;
}

/* ── Hook ───────────────────────────────────────────────────── */

export function useWorkspace(): Workspace {
  /* ── Sessions ──────────────────────────────────────────────── */
  const [sessions, setSessions] = useState<DesktopConsoleSession[]>([]);
  const [activeId, setActiveId] = useStoredState<string | null>(
    "0sec:active-session",
    null,
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const creatingRef = useRef(false);
  const mutationRef = useRef(false);

  /* ── Drafts & titles ────────────────────────────────────────── */
  const [drafts, setDrafts] = useStoredState<Record<string, string>>(
    "0sec:drafts",
    {},
  );
  const [titles, setTitles] = useStoredState<Record<string, string>>(
    "0sec:thread-titles",
    {},
  );

  /* ── Derive active session & draft ──────────────────────────── */
  const activeSession = sessions.find((s) => s.id === activeId) ?? null;
  const draft = activeId ? (drafts[activeId] ?? "") : "";

  /* ── Events ──────────────────────────────────────────────────── */
  const [events, setEvents] = useState<DesktopConsoleEvent[]>([]);
  const cursorRef = useRef(0);

  /**
   * Mask events to the current activeId every render. Never shows stale
   * events from the previous session even for one frame.
   */
  const visibleEvents =
    events[0]?.sessionId === activeId ? events : EMPTY_EVENTS;

  /* ── Auth ────────────────────────────────────────────────────── */
  const [auth, setAuth] = useState<DesktopCodexAuthStatus | null>(null);

  /* ── Preference error listener ───────────────────────────────── */
  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<string>).detail;
      if (typeof detail === "string") {
        setError(detail);
      }
    };
    window.addEventListener("osec:preference-error", handler);
    return () => window.removeEventListener("osec:preference-error", handler);
  }, []);

  /* ── Apply a session update to the list ──────────────────────── */
  const applySession = useCallback((session: DesktopConsoleSession) => {
    setSessions((current) => {
      const exists = current.some((s) => s.id === session.id);
      if (exists) {
        return current.map((s) =>
          s.id === session.id && session.updatedAt >= s.updatedAt ? session : s,
        );
      }
      return [session, ...current];
    });
  }, []);

  /* ── Initial session load (no auto-create) ───────────────────── */
  useEffect(() => {
    const ctrl = new AbortController();

    void (async () => {
      try {
        const loaded = await api.getSessions();
        if (ctrl.signal.aborted) return;

        setSessions(loaded);

        // Validate persisted activeId against the live session list.
        setActiveId((current) => {
          if (current && loaded.some((s) => s.id === current)) {
            return current;
          }
          return null;
        });
      } catch (cause) {
        if (ctrl.signal.aborted) return;
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        if (!ctrl.signal.aborted) setLoading(false);
      }
    })();

    return () => ctrl.abort();
  }, [setActiveId]);

  /* ── Session polling ──────────────────────────────────────────── */
  // Separate AbortController from event polling — never share guards.
  useEffect(() => {
    const ctrl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let polling = false;

    const poll = async () => {
      if (polling || ctrl.signal.aborted) return;
      polling = true;
      try {
        const loaded = await api.getSessions();
        if (ctrl.signal.aborted) return;

        setSessions((current) => {
          // Build lookup for server-returned sessions keyed by `updatedAt`.
          // Only apply server state when its `updatedAt` is newer — this
          // prevents stale poll responses from regressing session status
          // that was already advanced by createSession / send / cancel /
          // resolveDecision or event-stream session events.
          const serverSessions = new Map<string, DesktopConsoleSession>(
            loaded.map((s) => [s.id, s]),
          );

          const merged = current.map((existing) => {
            const server = serverSessions.get(existing.id);
            if (!server) return existing;
            if (server.updatedAt > existing.updatedAt) return server;
            return existing;
          });

          // Append sessions the server returned but we don't know about.
          for (const s of loaded) {
            if (!current.some((existing) => existing.id === s.id)) {
              merged.push(s);
            }
          }

          return merged;
        });
      } catch (cause) {
        if (ctrl.signal.aborted) return;
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        polling = false;
        if (!ctrl.signal.aborted) {
          timer = setTimeout(() => void poll(), SESSION_POLL_MS);
        }
      }
    };

    void poll();
    return () => {
      ctrl.abort();
      clearTimeout(timer);
    };
  }, [setActiveId]);

  /* ── Event polling for active session ────────────────────────── */
  useEffect(() => {
    if (!activeId) {
      cursorRef.current = 0;
      setEvents([]);
      return;
    }

    const ctrl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let polling = false;

    cursorRef.current = 0;
    setEvents([]);

    const poll = async () => {
      if (polling || ctrl.signal.aborted) return;
      polling = true;
      try {
        const incoming = await api.getEvents(activeId, cursorRef.current);
        if (ctrl.signal.aborted) return;
        if (incoming.length === 0) return;

        cursorRef.current = incoming.at(-1)?.sequence ?? cursorRef.current;

        setEvents((current) => mergeEvents(current, incoming));

        // Derive title from first user message in this batch.
        const firstUser = incoming.find((e) => e.type === "user");
        if (firstUser?.type === "user") {
          const title = firstUser.text.trim().replace(/\s+/g, " ").slice(0, 80);
          setTitles((current) => {
            if (current[activeId]) return current;
            return { ...current, [activeId]: title };
          });
        }

        // Apply session-status updates embedded in events.
        for (const event of incoming) {
          if (event.type === "session") applySession(event.session);
        }
      } catch (cause) {
        if (ctrl.signal.aborted) return;
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        polling = false;
        if (!ctrl.signal.aborted) {
          timer = setTimeout(() => void poll(), EVENT_POLL_MS);
        }
      }
    };

    void poll();
    return () => {
      ctrl.abort();
      clearTimeout(timer);
    };
  }, [activeId, applySession, setTitles]);

  /* ── Auth initial + polling ──────────────────────────────────── */
  const refreshAuth = useCallback(async () => {
    const status = await api.getCodexAuthStatus();
    setAuth(status);
  }, []);

  useEffect(() => {
    void refreshAuth().catch((cause) => {
      if (cause instanceof Error) {
        setError(cause.message);
      }
    });
  }, [refreshAuth]);

  useEffect(() => {
    if (auth?.phase !== "running") return;
    const timer = window.setInterval(() => {
      void refreshAuth().catch((cause: unknown) => {
        setError(cause instanceof Error ? cause.message : String(cause));
      });
    }, 1_000);
    return () => clearInterval(timer);
  }, [auth?.phase, refreshAuth]);

  /* ── Session selection ──────────────────────────────────────── */
  const selectSession = useCallback(
    (id: string) => {
      setActiveId(id);
      setDrafts((current) => {
        if (current[id] !== undefined) return current;
        return { ...current, [id]: "" };
      });
    },
    [setActiveId, setDrafts],
  );

  /* ── Create session ──────────────────────────────────────────── */
  const createSession = useCallback(
    async (input?: {
      target?: string;
      role?: DesktopConsoleRole;
      autonomyMode?: DesktopConsoleAutonomyMode;
    }): Promise<string | null> => {
      if (creatingRef.current) return null;
      creatingRef.current = true;
      setBusy(true);
      setError(null);
      try {
        const session = await api.createSession(input);
        applySession(session);
        setActiveId(session.id);
        setDrafts((current) => ({
          ...current,
          [session.id]: "",
        }));
        return session.id;
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
        return null;
      } finally {
        setBusy(false);
        creatingRef.current = false;
      }
    },
    [applySession, setActiveId, setDrafts],
  );

  /* ── Set draft ────────────────────────────────────────────────── */
  const setDraft = useCallback(
    (text: string) => {
      if (!activeId) return;
      setDrafts((current) => ({ ...current, [activeId]: text }));
    },
    [activeId, setDrafts],
  );

  /* ── Rename session ──────────────────────────────────────────── */
  const renameSession = useCallback(
    (id: string, title: string) => {
      setTitles((current) => ({ ...current, [id]: title }));
    },
    [setTitles],
  );

  /* ── Send message ────────────────────────────────────────────── */
  const send = useCallback(async (): Promise<void> => {
    if (mutationRef.current || busy || !activeSession || !draft.trim()) return;
    if (activeSession.status !== "ready") return;

    const sessionId = activeSession.id;
    const text = draft;

    mutationRef.current = true;
    setBusy(true);
    setError(null);

    try {
      const updated = await api.sendMessage(sessionId, text);

      // Always apply the session update regardless of current activeId.
      applySession(updated);

      // Clear the submitted draft, but only if the stored draft text has
      // NOT changed since we captured it (i.e. the user didn't switch back
      // and type new content while the request was in flight).
      setDrafts((current) => {
        if (current[sessionId] !== text) return current;
        const next = { ...current };
        delete next[sessionId];
        return next;
      });
    } catch (cause) {
      // Error — draft stays visible for the user to retry.
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      mutationRef.current = false;
      setBusy(false);
    }
  }, [busy, activeSession, draft, applySession, setDrafts]);

  /* ── Cancel current turn ─────────────────────────────────────── */
  const cancel = useCallback(async (): Promise<void> => {
    if (!activeSession) return;

    try {
      const updated = await api.cancelTurn(activeSession.id);
      applySession(updated);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [activeSession, applySession]);

  /* ── Resolve decision ────────────────────────────────────────── */
  const resolveDecision = useCallback(
    async (
      decision: DesktopConsoleDecision,
      response: DesktopConsoleDecisionResponse,
    ): Promise<void> => {
      if (!activeSession || mutationRef.current) return;
      mutationRef.current = true;

      setBusy(true);
      try {
        const updated = await api.resolveDecision(
          activeSession.id,
          decision.id,
          response,
        );
        applySession(updated);
      } catch (cause) {
        setError(cause instanceof Error ? cause.message : String(cause));
      } finally {
        mutationRef.current = false;
        setBusy(false);
      }
    },
    [activeSession, applySession],
  );

  /* ── Codex auth actions ──────────────────────────────────────── */
  const connectCodex = useCallback(async (): Promise<void> => {
    setBusy(true);
    setError(null);
    try {
      setAuth(await api.startCodexDeviceAuth());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }, []);

  const cancelCodex = useCallback(async (): Promise<void> => {
    setBusy(true);
    try {
      setAuth(await api.cancelCodexDeviceAuth());
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }, []);

  /* ── Clear error ─────────────────────────────────────────────── */
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  /* ── Return ──────────────────────────────────────────────────── */
  return {
    sessions,
    activeId,
    activeSession,
    events: visibleEvents as DesktopConsoleEvent[],
    loading,
    error,
    busy,
    auth,
    draft,
    titles,

    selectSession,
    createSession,
    setDraft,
    renameSession,
    send,
    cancel,
    resolveDecision,
    connectCodex,
    cancelCodex,
    clearError,
  };
}
