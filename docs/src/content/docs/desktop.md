---
title: Desktop — development draft
description: Contributor notes for the unreleased 0sec Desktop application and its local CLI sidecar.
draft: true
pagefind: false
---

**Desktop is not released and is under construction.** These notes are for
contributors testing development builds, not installation instructions for a
released app. Packaging support does not imply downloadable or signed releases.

The 0sec desktop is an [Electron](https://www.electronjs.org/) application
(v42, Chromium-based) that provides a native windowed control plane for the
0sec harness. Its dedicated React renderer lives in
`packages/desktop/src/renderer/`, with its own `desktop.html` build entry.
The application manages a **sidecar** — a compiled 0sec CLI process that
handles all engine communication behind a security boundary.

The renderer is still web technology, not SwiftUI. On macOS it uses real window
controls, native menus, a directory picker, and sidebar material, with system
fonts and light/dark appearance. The operations dashboard remains a separate view.

## Starting the desktop

### Source development

Use Node.js 24+, the repository's pinned pnpm, and Bun 1.3.14 (matching CI).
From the monorepo root, build the CLI and dashboard before launching:

```bash
pnpm install --frozen-lockfile
pnpm --filter '0sec-cli...' build
pnpm --filter @0sec/dashboard build
pnpm --filter @0sec/desktop start
```

The same development commands work on macOS Apple Silicon. A compiled
platform-specific sidecar is needed for packaging, **not** for this source
launch: the development app runs the built CLI entry point through Bun.
If Bun is not on `PATH`, set `BUN_PATH` to its executable.
The development sidecar can also run through Node.js 24+:
`BUN_PATH=node pnpm --filter @0sec/desktop start`. Packaging still requires Bun.

The desktop resolves assets from `packages/dashboard/dist/` (development) or
`process.resourcesPath/dashboard/` (packaged), and the sidecar from
`packages/cli/dist/index.js` run through `bun` (development) or from
`resources/sidecars/0sec-<platform>-<arch>` (packaged).

### Environment

| Variable | Role |
|----------|------|
| `OSEC_DESKTOP_ROOT` | Monorepo root path for resolving workspace layout in development (default: search upward from `cwd` for `pnpm-workspace.yaml`) |
| `OSEC_DESKTOP_DEBUG_PORT` | Bind Chromium DevTools to `127.0.0.1:<port>` for development builds only (integer, 1024–65535). Remote inspection reaches this port through an SSH tunnel only. |
| `BUN_PATH` | Custom `bun` binary path for the development sidecar (default: `"bun"` on `PATH`) |

### Packaging development builds

The build pipeline produces platform-specific artifacts through
[electron-builder](https://www.electron.build/). Packages bundle the Electron
runtime, dashboard UI, and sidecar binary together. The resulting application
is run from the desktop environment or launcher.

## Sidecar security boundary

The desktop separates the renderer (web UI) from engine operations through a
**sidecar** — the 0sec CLI binary itself, spawned as a child process.

```
┌─────────────────────────────────────┐
│ Electron main process               │
│  ┌───────────────────────────────┐  │
│  │ BrowserWindow                 │  │
│  │  - sandbox: true              │  │
│  │  - contextIsolation: true     │  │
│  │  - nodeIntegration: false     │  │
│  │  - webviewTag: false          │  │
│  │  - webSecurity: true          │  │
│  └───────────────────────────────┘  │
│                                     │
│  IPC: external HTTPS, directory picker │
│  Menu commands: typed subscriptions   │
│  Permission: scoped clipboard write │
└────────────────────┬──────────────┘
                     │ spawn (stdio: pipe)
┌────────────────────▼──────────────┐
│ Sidecar (0sec CLI binary)         │
│  - dashboard --no-open --host     │
│    127.0.0.1 --port 0             │
│  - stdout: 0SEC_DASHBOARD_READY   │
│  - lifecycle: SIGTERM → SIGKILL   │
└─────────────────────────────────────┘
```

### Sidecar lifecycle

1. **Launch**: `child_process.spawn` with `shell: false`, `windowsHide: true`.
   The sidecar command and arguments are assembled in
   `createDashboardSidecarInvocation` — the renderer never contributes a
   command, an argument, or a filesystem path to this boundary.
2. **Readiness**: stdout is parsed for a JSON-ready line of the form
   `0SEC_DASHBOARD_READY {"url":"http://127.0.0.1:<port>"}`. If the sidecar
   exits before emitting this line (or after the 20-second timeout), the
   desktop shows an error dialog and exits.
3. **Graceful stop**: SIGTERM is sent first. If the process has not exited
   after 5 seconds, SIGKILL is sent. The same sequence runs on application
   quit (`before-quit`).
4. **Stderr capture**: the last 4 KB of stderr are included in the error
   message if the sidecar fails to start.

In development, the sidecar runs through the local `bun` CLI entrypoint
(`packages/cli/dist/index.js`). In packaged builds, it runs the pre-bundled
binary from `resources/sidecars/<platform-arch>`.

On macOS, closing the last window leaves the application and sidecar running.
Dock activation or **New Session** recreates the window without starting another
sidecar. Explicit **Quit** stops it, including when startup is still in progress.
On Linux and Windows, closing the last window quits the application.

The desktop's live sessions belong to the running sidecar; quitting ends them.
Tabs, project shortcuts, drafts, titles, and appearance are UI preferences:
Electron persists them in its user-data directory, independently of the
sidecar's changing loopback port. Browser previews use local storage instead.
On a fresh sidecar, stale session tabs are removed; they are not a promise
that the desktop can reopen an ended conversation.

### Navigation policy

| Operation | Rule |
|-----------|------|
| **Window open** (`setWindowOpenHandler`) | External `https://` URLs open in the system browser; all others denied |
| **Navigation** (`will-navigate`) | Only URLs whose origin matches the dashboard's origin |
| **Redirect** (`will-redirect`) | Same-origin only |
| **WebView** (`will-attach-webview`) | Prevented entirely |
| **External URLs** | Only credential-free `https://` URLs accepted; embedded username/password rejected |

All navigation is validated by `hasSameOrigin` (origin-level URL comparison)
and `isExternalHttpsUrl` (protocol + no credentials).

### View zoom

Pinch zoom is fixed with `setVisualZoomLevelLimits(1, 1)`. The native **View**
menu also exposes page zoom and reset commands.

### IPC

The renderer receives a narrow, typed `window.osecDesktop` bridge:

```typescript
interface DesktopHostBridge {
  readonly platform: string;
  openExternal(url: string): Promise<void>;
  chooseDirectory(): Promise<string | null>;
  getPreferences(): Promise<Record<string, unknown>>;
  setPreference(key: string, value: unknown): Promise<void>;
  onCommand(listener: (command: DesktopHostCommand) => void): () => void;
}

type DesktopHostCommand =
  | "new-thread"
  | "open-folder"
  | "toggle-sidebar"
  | "settings";
```

The main process accepts renderer requests only from the current window's main
frame at the trusted dashboard origin. External URLs must be credential-free
HTTPS URLs. The directory picker accepts directories only and returns `null`
on cancellation. Picking a directory sets context; it does not grant access.
Preference writes accept only namespaced `0sec:` UI values. They do not expose
arbitrary filesystem paths, provider credentials, or engine configuration.

Menu subscriptions return an unsubscribe function. Commands that arrive while
the conversation route is loading are retained until the renderer subscribes.
Raw `ipcRenderer`, filesystem access, and arbitrary process execution are never
exposed by the bridge.

### Permission policy

Clipboard writes are allowed only from the focused main dashboard window at
the trusted local sidecar origin, so the chat's **Copy code** button works.
Clipboard reads, camera, microphone, geolocation, notifications, and all other
Chromium permission requests remain denied.

## Window

| Property | Value |
|----------|-------|
| Default size | 1280 × 860 |
| Minimum size | 900 × 600 |
| Appearance | System light/dark; translucent native macOS sidebar, opaque conversation |
| Title | `0sec` |
| Show | Hidden until `ready-to-show` to avoid white flash |
| Single-instance lock | Yes — a second launch focuses or recreates the existing application's window |

## Preload

`packages/desktop/src/preload/index.ts` exposes the frozen bridge through
`contextBridge`. It is compiled as **CommonJS** by `tsconfig.preload.json`;
sandboxed Electron preloads cannot use ESM imports. The main process remains
ESM. Shared contracts are type-only imports and add no renderer runtime access.

Context isolation and sandboxing remain enabled. Native accelerators and browser
fallback shortcuts are mutually exclusive, so a keypress does not create two
sessions or toggle the sidebar twice.

| Desktop shortcut | Action |
|------------------|--------|
| Cmd/Ctrl+N | New session form |
| Cmd/Ctrl+O | Native folder picker, then a prefilled session form |
| Cmd/Ctrl+B | Toggle sidebar |
| Cmd/Ctrl+, | Settings and provider connection |
| Cmd/Ctrl+K | Search actions and all live sessions |
| Ctrl+Tab / Ctrl+Shift+Tab | Next / previous workspace tab |
| Cmd/Ctrl+Shift+H | Home |
| Enter / Shift+Enter | Send / insert newline |
| Escape | Dismiss a dialog when no operation is pending |

## User workflow

1. Launch the desktop application from your OS (or `pnpm --filter @0sec/desktop start` in development).
2. The window opens a project-and-session workspace. Home lists recent sessions;
   the sidebar filters by project or session title. Closing a tab does not
   delete its live session; reopen it from Home or the command palette.
3. Use **New session** for a URL or path, or **Open Folder** in the native File
   menu. Select the role and autonomy mode before creating the session.
   Selecting a target is not an authorization grant. YOLO requires an explicit
   acknowledgement; an unscoped chat uses standard autonomy.
4. Responses stream progressively into the conversation, with Markdown,
   copyable code blocks, collapsible reasoning, and expandable tool activity.
   **Stop** cancels the active turn. Scrolling back preserves your position;
   **Latest** resumes following. Drafts and renamed titles stay with their session.
5. The inspector exposes context, activity, and evidence; approval cards remain
   in the conversation. **Settings** provides system/light/dark appearance and
   OpenAI Codex device sign-in. Codex authentication is not 0cloud access.
   **Operations** opens the separate findings-and-runs dashboard.
6. The renderer has no general Node.js or Electron API. Engine work goes through
   the loopback sidecar. External documentation links open in the system browser.

## Platforms and build requirements

### Supported architectures

| Platform | Architectures | Package artifacts |
|----------|---------------|-------------------|
| Linux | x64, arm64 | `.AppImage`, `.deb` |
| macOS (Darwin) | x64, arm64 | `.dmg`, `.zip` |
| Windows | x64, arm64 | NSIS installer, `.zip` |

### Building a package

Prerequisites: Node.js 24+, pnpm 9+, Bun (for sidecar compilation).

```bash
# Build all workspace packages
pnpm install --frozen-lockfile
pnpm build

# Compile the sidecar binary matching your platform
bash scripts/bun-compile.sh "" "dist-bin/0sec-linux-x64"

# Build the dashboard
pnpm --filter @0sec/dashboard build

# Package the desktop (Linux example)
pnpm --filter @0sec/desktop package:linux
```

The sidecar binary filename pattern is `0sec-<platform>-<arch>` (Linux/macOS)
or `0sec-windows-<arch>.exe` (Windows). The example above targets Linux x64.
On macOS, use `0sec-darwin-arm64` or `0sec-darwin-x64` as the output path.

The `package:*` scripts (`package:linux`, `package:mac`, `package:win`) run
`prepare-desktop-resources.mjs` before invoking electron-builder:

1. Removes any existing `resources/` directory.
2. Copies the built dashboard from `packages/dashboard/dist` to
   `resources/dashboard`. Asserts `index.html` exists.
3. Creates `resources/sidecars/` and copies the compiled CLI binary there
   (asserted to exist at the expected platform name).
4. electron-builder bundles both as `extraResources` into the release package.

The resulting package contains the Electron runtime + app code (in ASAR
archive), the dashboard web UI, and the sidecar binary.

### Package metadata

- **Linux**: app ID `com.0security.osec`, category `Development`,
  `syncDesktopName: true`
- **macOS**: category `public.app-category.developer-tools`. Code signing and
  notarisation require an Apple Developer account and are not configured in the
  open-source build.
- **Windows**: both NSIS installer and `.zip` archive produced by default.

## Sidecar asset paths by build mode

| Build mode | Dashboard assets | Sidecar binary |
|------------|------------------|----------------|
| Development | `packages/dashboard/dist/` | Bun entrypoint at `packages/cli/dist/index.js` (run through `bun`) |
| Packaged (`app.isPackaged === true`) | `process.resourcesPath/dashboard/` | `process.resourcesPath/sidecars/0sec-<platform>-<arch>` |

Both are validated at launch — the application exits with an error dialog if
either is missing.

## Debugging

In development, set `OSEC_DESKTOP_DEBUG_PORT` to attach a Chromium DevTools
inspector bound to `127.0.0.1`:

```bash
OSEC_DESKTOP_DEBUG_PORT=9222 pnpm --filter @0sec/desktop start
```

Remote inspection must traverse an SSH tunnel — the debugger is never bound to
a routable address. In packaged builds (`app.isPackaged === true`), the debug
port is ignored.

## Related

- [Console](/console/) — terminal-based interactive chat
- [Commands reference](/commands/) — all CLI flags across every command
- [Configuration](/configuration/) — runtime, mode, and feature settings
- [Getting Started](/getting-started/) — install and first scan