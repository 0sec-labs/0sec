import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  Plus,
  X,
  Home,
  FolderOpen,
  Settings,
  PanelLeft,
  Search,
  MessageSquare,
  ListTodo,
  Folder,
  Sun,
  Moon,
  Monitor,
  ExternalLink,
} from "lucide-react";
import * as Dialog from "@radix-ui/react-dialog";
import { Command } from "cmdk";
import type {
  DesktopConsoleAutonomyMode,
  DesktopConsoleRole,
  DesktopConsoleSession,
} from "@0sec/shared";
import { useWorkspace, type Workspace } from "./use-workspace";
import { useStoredState } from "./use-stored-state";
import { Conversation, Inspector } from "./conversation";

interface Project {
  target: string;
  name: string;
}
type ThemeMode = "system" | "light" | "dark";
type SessionOptions = {
  target?: string;
  role?: DesktopConsoleRole;
  autonomyMode?: DesktopConsoleAutonomyMode;
};
const HOME = "___home___";
const isMac =
  window.osecDesktop?.platform === "darwin" || /Mac/i.test(navigator.platform);
const MOD = isMac ? "⌘" : "Ctrl+";
const ROLES: DesktopConsoleRole[] = [
  "discovery",
  "attack",
  "verify",
  "report",
  "audit",
  "review",
];
const MODES: DesktopConsoleAutonomyMode[] = [
  "standard",
  "recon",
  "copilot",
  "yolo",
];
const labelFor = (
  session: DesktopConsoleSession,
  titles: Record<string, string>,
) => titles[session.id] || session.target || "New session";
const projectName = (target: string) =>
  target.replace(/\/$/, "").split(/[\\/]/).at(-1) || target;

export function DesktopApp() {
  const ws = useWorkspace();
  const [theme, setTheme] = useStoredState<ThemeMode>("0sec:theme", "system");
  const [tabs, setTabs] = useStoredState<string[]>("0sec:tabs", [HOME]);
  const [activeTab, setActiveTab] = useStoredState("0sec:active-tab", HOME);
  const [sidebar, setSidebar] = useStoredState("0sec:sidebar", true);
  const [projects, setProjects] = useStoredState<Project[]>(
    "0sec:projects",
    [],
  );
  const [inspector, setInspector] = useState(false);
  const [newTarget, setNewTarget] = useState<string | null>(null);
  const [settings, setSettings] = useState(false);
  const [palette, setPalette] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [projectFilter, setProjectFilter] = useState<string | null>(null);
  const activeSession = ws.sessions.find((s) => s.id === activeTab) ?? null;
  const selectSession = ws.selectSession;

  useEffect(() => {
    const media = matchMedia("(prefers-color-scheme: dark)");
    const apply = () => {
      document.documentElement.dataset.theme =
        theme === "system" ? (media.matches ? "dark" : "light") : theme;
    };
    apply();
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);

  useEffect(() => {
    if (ws.loading) return;
    const live = new Set(ws.sessions.map((s) => s.id));
    setTabs((current) => {
      const next = [
        HOME,
        ...current.filter((id) => id !== HOME && live.has(id)),
      ];
      return next.length === current.length &&
        next.every((id, i) => id === current[i])
        ? current
        : next;
    });
    if (activeTab !== HOME && !live.has(activeTab)) setActiveTab(HOME);
  }, [ws.loading, ws.sessions, activeTab, setTabs, setActiveTab]);

  useEffect(() => {
    if (activeSession && ws.activeId !== activeTab) selectSession(activeTab);
  }, [activeSession, activeTab, ws.activeId, selectSession]);

  const openSession = useCallback(
    (id: string) => {
      setTabs((current) => (current.includes(id) ? current : [...current, id]));
      setActiveTab(id);
      selectSession(id);
    },
    [setTabs, setActiveTab, selectSession],
  );
  const selectTab = useCallback(
    (id: string) => {
      if (id === HOME) setActiveTab(HOME);
      else openSession(id);
    },
    [openSession, setActiveTab],
  );
  const closeTab = (id: string) => {
    if (id === HOME) return;
    setTabs((current) => current.filter((tab) => tab !== id));
    if (activeTab === id) setActiveTab(HOME);
  };
  const rememberProject = (target: string) => {
    if (!target) return;
    setProjects((current) =>
      current.some((p) => p.target === target)
        ? current
        : [...current, { target, name: projectName(target) }],
    );
  };
  const openFolder = useCallback(async () => {
    setPalette(false);
    if (!window.osecDesktop) {
      setNewTarget("");
      return;
    }
    try {
      const target = await window.osecDesktop.chooseDirectory();
      if (target) setNewTarget(target);
    } catch (cause) {
      setLocalError(String(cause));
    }
  }, []);
  const createSession = async (options: SessionOptions) => {
    const id = await ws.createSession(options);
    if (!id) return false;
    rememberProject(options.target ?? "");
    openSession(id);
    setNewTarget(null);
    return true;
  };

  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.isComposing) return;
      const mod = isMac ? event.metaKey : event.ctrlKey;
      const key = event.key.toLowerCase();
      if (mod && key === "k") {
        event.preventDefault();
        setPalette((p) => !p);
        return;
      }
      if (mod && event.shiftKey && key === "h") {
        event.preventDefault();
        setActiveTab(HOME);
        return;
      }
      if (event.ctrlKey && key === "tab") {
        event.preventDefault();
        const next =
          (tabs.indexOf(activeTab) + (event.shiftKey ? -1 : 1) + tabs.length) %
          tabs.length;
        selectTab(tabs[next] ?? HOME);
        return;
      }
      // Electron handles these accelerators through the native menu, including while typing.
      if (!mod || window.osecDesktop) return;
      if (key === "n") {
        event.preventDefault();
        setNewTarget("");
      }
      if (key === "o") {
        event.preventDefault();
        void openFolder();
      }
      if (key === "b") {
        event.preventDefault();
        setSidebar((p) => !p);
      }
      if (key === ",") {
        event.preventDefault();
        setSettings(true);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [tabs, activeTab, selectTab, setActiveTab, setSidebar, openFolder]);

  useEffect(
    () =>
      window.osecDesktop?.onCommand((command) => {
        if (command === "new-thread") setNewTarget("");
        if (command === "open-folder") void openFolder();
        if (command === "toggle-sidebar") setSidebar((p) => !p);
        if (command === "settings") setSettings(true);
      }),
    [openFolder, setSidebar],
  );

  const knownProjects = useMemo(() => {
    const result = new Map(
      projects
        .filter((p) => typeof p.target === "string")
        .map((p) => [p.target, p]),
    );
    for (const session of ws.sessions)
      if (session.target && !result.has(session.target))
        result.set(session.target, {
          target: session.target,
          name: projectName(session.target),
        });
    return [...result.values()];
  }, [projects, ws.sessions]);
  const filtered = ws.sessions.filter(
    (s) =>
      (!projectFilter || s.target === projectFilter) &&
      `${labelFor(s, ws.titles)} ${s.target} ${s.role}`
        .toLowerCase()
        .includes(filter.toLowerCase()),
  );
  const error = localError || ws.error;
  const sessionList = (sessions: DesktopConsoleSession[]) =>
    sessions.map((session) => (
      <button
        key={session.id}
        className={`target-item${activeTab === session.id ? " active" : ""}`}
        onClick={() => openSession(session.id)}
        aria-current={activeTab === session.id ? "page" : undefined}
      >
        <span
          className={`target-status ${session.status}`}
          title={session.status}
        />
        <span className="session-label">{labelFor(session, ws.titles)}</span>
      </button>
    ));

  return (
    <div className="app-shell">
      <div className={`titlebar${isMac ? " macos" : ""}`}>
        <span className="titlebar-title">0sec</span>
      </div>
      {error && (
        <div className="error-banner" role="alert">
          <span className="error-banner-text">{error}</span>
          <button
            className="btn btn-sm"
            onClick={() => {
              setLocalError(null);
              ws.clearError();
            }}
          >
            Dismiss
          </button>
        </div>
      )}
      <div className="tab-bar" role="tablist" aria-label="Workspace tabs">
        {tabs.map((id, index) => {
          const session = ws.sessions.find((s) => s.id === id);
          const label =
            id === HOME
              ? "Home"
              : session
                ? labelFor(session, ws.titles)
                : "Session";
          return (
            <div className={`tab${activeTab === id ? " active" : ""}`} key={id}>
              <button
                role="tab"
                aria-selected={activeTab === id}
                tabIndex={activeTab === id ? 0 : -1}
                onClick={() => selectTab(id)}
                onKeyDown={(event) => {
                  if (event.key === "ArrowLeft" || event.key === "ArrowRight") {
                    event.preventDefault();
                    const next =
                      (index +
                        (event.key === "ArrowLeft" ? -1 : 1) +
                        tabs.length) %
                      tabs.length;
                    selectTab(tabs[next]);
                    event.currentTarget
                      .closest('[role="tablist"]')
                      ?.querySelectorAll<HTMLButtonElement>('[role="tab"]')
                      [next]?.focus();
                  }
                  if (event.key === "Delete" && id !== HOME) closeTab(id);
                }}
              >
                {id === HOME ? <Home size={13} /> : <MessageSquare size={13} />}
                <span>{label}</span>
              </button>
              {id !== HOME && (
                <button
                  className="tab-close"
                  aria-label={`Close ${label}`}
                  onClick={() => closeTab(id)}
                >
                  <X size={12} />
                </button>
              )}
            </div>
          );
        })}
        <button
          className="new-tab-btn"
          aria-label="New session"
          onClick={() => setNewTarget("")}
        >
          <Plus size={15} />
        </button>
        <div className="workspace-toolbar">
          <button
            className="session-header-btn"
            aria-label="Toggle sidebar"
            aria-pressed={sidebar}
            onClick={() => setSidebar((p) => !p)}
          >
            <PanelLeft size={15} />
          </button>
          <button
            className="session-header-btn"
            aria-label="Command palette"
            onClick={() => setPalette(true)}
          >
            <Search size={15} />
          </button>
          <button
            className="session-header-btn"
            aria-label="Settings"
            onClick={() => setSettings(true)}
          >
            <Settings size={15} />
          </button>
        </div>
      </div>
      <div className="workspace">
        {sidebar && (
          <aside className="session-sidebar">
            <div className="sidebar-header">
              <h3>Projects</h3>
              <button
                className="session-header-btn"
                aria-label="Add project"
                onClick={() => setNewTarget("")}
              >
                <Plus size={14} />
              </button>
            </div>
            <div className="sidebar-scroll">
              <button
                className={`target-item${projectFilter === null ? " active" : ""}`}
                onClick={() => setProjectFilter(null)}
              >
                <Home size={13} />
                All sessions
              </button>
              {knownProjects.map((project) => (
                <button
                  className={`target-item${projectFilter === project.target ? " active" : ""}`}
                  key={project.target}
                  title={project.target}
                  onClick={() => {
                    setProjectFilter(project.target);
                    setActiveTab(HOME);
                  }}
                >
                  <Folder size={13} />
                  <span className="session-label">{project.name}</span>
                </button>
              ))}
              <div className="sidebar-header">
                <h3>Sessions</h3>
                <button
                  className="session-header-btn"
                  aria-label="New session in project"
                  onClick={() => setNewTarget(projectFilter ?? "")}
                >
                  <Plus size={14} />
                </button>
              </div>
              <div className="sidebar-filter">
                <input
                  aria-label="Filter sessions"
                  placeholder="Filter sessions…"
                  value={filter}
                  onChange={(event) => setFilter(event.target.value)}
                />
              </div>
              {sessionList(filtered)}
              {!filtered.length && (
                <p className="sidebar-empty">
                  {ws.loading ? "Loading sessions…" : "No sessions"}
                </p>
              )}
            </div>
            <a className="sidebar-operations" href="/operations">
              <ListTodo size={14} />
              Operations
            </a>
          </aside>
        )}
        {activeSession ? (
          <div className="session-content">
            <div className="session-main">
              <SessionHeader
                key={`header-${activeSession.id}`}
                title={labelFor(activeSession, ws.titles)}
                status={activeSession.status}
                onRename={(title) => ws.renameSession(activeSession.id, title)}
                inspector={inspector}
                onInspect={() => setInspector((p) => !p)}
              />
              {ws.activeId === activeTab ? (
                <Conversation
                  key={activeTab}
                  workspace={ws}
                  onSettings={() => setSettings(true)}
                  onNewSession={() => setNewTarget(projectFilter ?? "")}
                  onInspect={() => setInspector(true)}
                />
              ) : (
                <div className="loading-shell">Loading session…</div>
              )}
            </div>
            {inspector && ws.activeId === activeTab && (
              <div className="inspector-panel">
                <Inspector workspace={ws} onClose={() => setInspector(false)} />
              </div>
            )}
          </div>
        ) : (
          <main className="home-page">
            <div className="home-main">
              <h1 className="home-greeting">
                {projectFilter
                  ? projectName(projectFilter)
                  : "What are we working on?"}
              </h1>
              <p className="home-subtitle">
                {projectFilter ||
                  "A local workspace for security research. Your CLI runs the engine."}
              </p>
              <div className="home-actions">
                <button
                  className="btn btn-primary"
                  onClick={() => setNewTarget(projectFilter ?? "")}
                >
                  <Plus size={14} />
                  New session
                </button>
                <button className="btn" onClick={() => void openFolder()}>
                  <FolderOpen size={14} />
                  {window.osecDesktop ? "Open folder" : "Choose target"}
                </button>
              </div>
              <div className="home-section-title">
                {filter ? "Matching sessions" : "Recent sessions"}
              </div>
              <div className="home-recent-list">
                {filtered.map((session) => (
                  <button
                    className="home-recent-item"
                    key={session.id}
                    onClick={() => openSession(session.id)}
                  >
                    <div>
                      <div className="recent-title">
                        {labelFor(session, ws.titles)}
                      </div>
                      <div className="recent-meta">
                        {session.role} · {session.autonomyMode} ·{" "}
                        {new Date(session.updatedAt).toLocaleDateString()}
                      </div>
                    </div>
                  </button>
                ))}
              </div>
              {!filtered.length && (
                <div className="empty-state">
                  <MessageSquare size={28} />
                  <h2>
                    {ws.loading
                      ? "Loading workspace…"
                      : filter
                        ? "No matching sessions"
                        : "Start with a conversation"}
                  </h2>
                  <p>
                    Choose a project, or start an unscoped session. Targets and
                    tool permissions remain explicit.
                  </p>
                </div>
              )}
            </div>
          </main>
        )}
      </div>
      {newTarget !== null && (
        <NewSessionDialog
          initialTarget={newTarget}
          onClose={() => setNewTarget(null)}
          onCreate={createSession}
          error={ws.error}
        />
      )}
      {settings && (
        <SettingsDialog
          theme={theme}
          onTheme={setTheme}
          workspace={ws}
          onClose={() => setSettings(false)}
        />
      )}
      {palette && (
        <Modal
          title="Command palette"
          className="cmdk-dialog"
          onClose={() => setPalette(false)}
        >
          <Command label="Command palette">
            <Command.Input
              autoFocus
              className="cmdk-input"
              placeholder="Search actions and sessions…"
            />
            <Command.List className="cmdk-list">
              <Command.Empty>No results</Command.Empty>
              <Command.Group heading="Actions">
                {[
                  ["New session", () => setNewTarget(projectFilter ?? "")],
                  ["Open folder", () => void openFolder()],
                  ["Toggle sidebar", () => setSidebar((p) => !p)],
                  ["Settings", () => setSettings(true)],
                  ["Go to Home", () => setActiveTab(HOME)],
                ].map(([label, action]) => (
                  <Command.Item
                    key={String(label)}
                    className="cmdk-item"
                    onSelect={() => {
                      setPalette(false);
                      (action as () => void)();
                    }}
                  >
                    {String(label)}
                  </Command.Item>
                ))}
              </Command.Group>
              <Command.Group heading="Sessions">
                {ws.sessions.map((session) => (
                  <Command.Item
                    key={session.id}
                    value={`${session.id} ${labelFor(session, ws.titles)}`}
                    className="cmdk-item"
                    onSelect={() => {
                      setPalette(false);
                      openSession(session.id);
                    }}
                  >
                    {labelFor(session, ws.titles)}
                  </Command.Item>
                ))}
              </Command.Group>
            </Command.List>
          </Command>
        </Modal>
      )}
    </div>
  );
}

function Modal({
  title,
  children,
  onClose,
  busy = false,
  className = "",
}: {
  title: string;
  children: ReactNode;
  onClose(): void;
  busy?: boolean;
  className?: string;
}) {
  return (
    <Dialog.Root
      open
      onOpenChange={(open) => {
        if (!open && !busy) onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <Dialog.Content
          className={`dialog-content ${className}`}
          aria-describedby={undefined}
          onOpenAutoFocus={(event) => {
            const input = (
              event.target as HTMLElement
            ).querySelector<HTMLInputElement>("input");
            if (input) {
              event.preventDefault();
              input.focus();
            }
          }}
          onEscapeKeyDown={(event) => {
            if (busy) event.preventDefault();
          }}
          onPointerDownOutside={(event) => {
            if (busy) event.preventDefault();
          }}
        >
          <div className="dialog-header">
            <Dialog.Title>{title}</Dialog.Title>
            <Dialog.Close asChild>
              <button
                className="dialog-close"
                disabled={busy}
                aria-label="Close dialog"
              >
                <X size={16} />
              </button>
            </Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function SessionHeader({
  title,
  status,
  inspector,
  onRename,
  onInspect,
}: {
  title: string;
  status: string;
  inspector: boolean;
  onRename(title: string): void;
  onInspect(): void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(title);
  const cancelled = useRef(false);
  const commit = () => {
    setEditing(false);
    if (!cancelled.current && draft.trim() && draft.trim() !== title)
      onRename(draft.trim());
  };
  return (
    <div className="session-header">
      <div className="session-title-area">
        <span className={`session-status-dot ${status}`} />
        {editing ? (
          <input
            autoFocus
            className="session-title-input"
            aria-label="Session title"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            onBlur={commit}
            onKeyDown={(event) => {
              if (event.key === "Enter") event.currentTarget.blur();
              if (event.key === "Escape") {
                cancelled.current = true;
                setEditing(false);
              }
            }}
          />
        ) : (
          <button
            className="session-title-input"
            title="Rename session"
            onClick={() => {
              cancelled.current = false;
              setDraft(title);
              setEditing(true);
            }}
          >
            {title}
          </button>
        )}
      </div>
      <div className="session-header-actions">
        <button
          className="session-header-btn"
          aria-label="Toggle inspector"
          aria-pressed={inspector}
          onClick={onInspect}
        >
          <ListTodo size={15} />
        </button>
      </div>
    </div>
  );
}

function NewSessionDialog({
  initialTarget,
  onClose,
  onCreate,
  error,
}: {
  initialTarget: string;
  onClose(): void;
  onCreate(options: SessionOptions): Promise<boolean>;
  error: string | null;
}) {
  const [target, setTarget] = useState(initialTarget);
  const [role, setRole] = useState<DesktopConsoleRole>("audit");
  const [mode, setMode] = useState<DesktopConsoleAutonomyMode>("standard");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const [pickerError, setPickerError] = useState<string | null>(null);
  const create = async (unscoped = false) => {
    if (pending.current || (!unscoped && mode === "yolo" && !confirmed)) return;
    pending.current = true;
    setBusy(true);
    try {
      await onCreate(
        unscoped
          ? { role: "audit", autonomyMode: "standard" }
          : { target: target.trim() || undefined, role, autonomyMode: mode },
      );
    } finally {
      pending.current = false;
      setBusy(false);
    }
  };
  const pickFolder = async () => {
    if (!window.osecDesktop || pending.current) return;
    pending.current = true;
    setBusy(true);
    try {
      const selected = await window.osecDesktop.chooseDirectory();
      if (selected) setTarget(selected);
    } catch (cause) {
      setPickerError(String(cause));
    } finally {
      pending.current = false;
      setBusy(false);
    }
  };
  return (
    <Modal title="New session" onClose={onClose} busy={busy}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          void create();
        }}
      >
        <div className="dialog-body">
          {(pickerError || error) && (
            <p role="alert" className="form-warning">
              {pickerError || error}
            </p>
          )}
          <div className="form-group">
            <label className="form-label" htmlFor="session-target">
              Target
            </label>
            <div className="input-with-action">
              <input
                id="session-target"
                className="form-input"
                placeholder="URL or local path (optional)"
                value={target}
                disabled={busy}
                onChange={(event) => setTarget(event.target.value)}
              />
              {window.osecDesktop && (
                <button
                  className="btn btn-sm"
                  type="button"
                  disabled={busy}
                  onClick={() => void pickFolder()}
                >
                  <FolderOpen size={13} />
                  Browse
                </button>
              )}
            </div>
            <p className="form-hint">
              Selecting a target is not an authorization grant. The engine still
              applies scope and tool policy.
            </p>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="session-role">
              Role
            </label>
            <select
              id="session-role"
              className="form-select"
              value={role}
              disabled={busy}
              onChange={(event) =>
                setRole(event.target.value as DesktopConsoleRole)
              }
            >
              {ROLES.map((value) => (
                <option key={value} value={value}>
                  {value.charAt(0).toUpperCase() + value.slice(1)}
                </option>
              ))}
            </select>
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="session-mode">
              Autonomy
            </label>
            <select
              id="session-mode"
              className="form-select"
              value={mode}
              disabled={busy}
              onChange={(event) => {
                setMode(event.target.value as DesktopConsoleAutonomyMode);
                setConfirmed(false);
              }}
            >
              {MODES.map((value) => (
                <option key={value} value={value}>
                  {value.charAt(0).toUpperCase() + value.slice(1)}
                </option>
              ))}
            </select>
          </div>
          {mode === "yolo" && (
            <label className="form-warning">
              <input
                type="checkbox"
                checked={confirmed}
                disabled={busy}
                onChange={(event) => setConfirmed(event.target.checked)}
              />{" "}
              I understand that YOLO removes normal approval prompts. Use only
              with explicitly authorized targets.
            </label>
          )}
        </div>
        <div className="dialog-footer">
          <button
            type="button"
            className="btn btn-ghost"
            disabled={busy}
            onClick={() => void create(true)}
          >
            Unscoped chat
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={busy || (mode === "yolo" && !confirmed)}
          >
            {busy ? "Opening…" : "Start session"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function SettingsDialog({
  theme,
  onTheme,
  workspace,
  onClose,
}: {
  theme: ThemeMode;
  onTheme(theme: ThemeMode): void;
  workspace: Workspace;
  onClose(): void;
}) {
  const [section, setSection] = useState("appearance");
  const [externalError, setExternalError] = useState<string | null>(null);
  const { auth } = workspace;
  const verificationLinks = [
    ...new Set(
      (auth?.lines.join("\n").match(/https:\/\/[^\s<>]+/g) ?? []).map((value) =>
        value.replace(/[),.;]+$/, ""),
      ),
    ),
  ].filter((value) => {
    try {
      const url = new URL(value);
      return !url.username && !url.password;
    } catch {
      return false;
    }
  });
  const openExternal = async (url: string) => {
    try {
      await window.osecDesktop?.openExternal(url);
    } catch (cause) {
      setExternalError(String(cause));
    }
  };
  return (
    <Modal title="Settings" onClose={onClose} className="settings-dialog">
      <nav className="settings-tabs" aria-label="Settings sections">
        {["appearance", "connection", "shortcuts"].map((value) => (
          <button
            key={value}
            className={`settings-tab${section === value ? " active" : ""}`}
            aria-pressed={section === value}
            onClick={() => setSection(value)}
          >
            {value.charAt(0).toUpperCase() + value.slice(1)}
          </button>
        ))}
      </nav>
      <div className="dialog-body">
        {section === "appearance" && (
          <div className="settings-row">
            <div className="settings-row-info">
              <div className="settings-row-label">Appearance</div>
              <p className="settings-row-desc">
                Follow your system, or choose a theme.
              </p>
            </div>
            <div className="theme-options">
              {(["light", "dark", "system"] as const).map((mode) => (
                <button
                  key={mode}
                  className={`theme-option${theme === mode ? " active" : ""}`}
                  aria-pressed={theme === mode}
                  onClick={() => onTheme(mode)}
                >
                  {mode === "light" ? (
                    <Sun size={14} />
                  ) : mode === "dark" ? (
                    <Moon size={14} />
                  ) : (
                    <Monitor size={14} />
                  )}
                  {mode.charAt(0).toUpperCase() + mode.slice(1)}
                </button>
              ))}
            </div>
          </div>
        )}
        {section === "connection" && (
          <div className="settings-section">
            <div className="settings-row-label">OpenAI Codex</div>
            <p className="settings-row-desc">
              Sign in to OpenAI through the local CLI. This is provider
              authentication, not 0cloud.
            </p>
            <p role="status">
              {auth?.message || "Checking provider connection…"}
            </p>
            {auth?.lines.length ? (
              <pre className="auth-output">{auth.lines.join("\n")}</pre>
            ) : null}
            {verificationLinks.map((url) => (
              <a
                className="btn btn-sm"
                key={url}
                href={url}
                target="_blank"
                rel="noreferrer"
                onClick={(event) => {
                  if (window.osecDesktop) {
                    event.preventDefault();
                    void openExternal(url);
                  }
                }}
              >
                <ExternalLink size={13} />
                Open verification page
              </a>
            ))}
            {externalError && <p role="alert">{externalError}</p>}
            {workspace.error && <p role="alert">{workspace.error}</p>}
            <div className="dialog-footer">
              {auth?.phase === "running" ? (
                <button
                  className="btn"
                  disabled={workspace.busy}
                  onClick={() => void workspace.cancelCodex()}
                >
                  Cancel sign-in
                </button>
              ) : auth?.phase === "connected" ? (
                <span>Connected</span>
              ) : (
                <button
                  className="btn btn-primary"
                  disabled={workspace.busy}
                  onClick={() => void workspace.connectCodex()}
                >
                  Sign in to Codex
                </button>
              )}
            </div>
            <p className="form-hint">
              Other providers and model selection use the CLI configuration. Run{" "}
              <code>0sec console</code> and use its provider controls. Quitting
              the desktop ends its live sidecar sessions; UI preferences are
              retained.
            </p>
          </div>
        )}
        {section === "shortcuts" && (
          <div className="shortcuts-list">
            {[
              ["Command palette", `${MOD}K`],
              ["New session", `${MOD}N`],
              ["Open folder", `${MOD}O`],
              ["Toggle sidebar", `${MOD}B`],
              ["Settings", `${MOD},`],
              ["Next / previous tab", "Ctrl+Tab / Ctrl+Shift+Tab"],
              ["Home", `${MOD}Shift+H`],
              ["Send / newline", "Enter / Shift+Enter"],
            ].map(([label, keys]) => (
              <div className="shortcut-row" key={label}>
                <span>{label}</span>
                <kbd>{keys}</kbd>
              </div>
            ))}
          </div>
        )}
      </div>
    </Modal>
  );
}
