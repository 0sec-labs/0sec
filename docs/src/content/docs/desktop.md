---
title: Desktop
description: The 0sec native desktop application — sidecar security boundary, platform build requirements, launch workflow, and UI overview.
---

The 0sec desktop is an [Electron](https://www.electronjs.org/) application
(v42, Chromium-based) that provides a native windowed control plane for the
0sec harness. It runs the [dashboard](https://github.com/0sec-labs/0sec/tree/main/packages/dashboard)
web UI inside a sandboxed browser context and manages a **sidecar** — a
compiled 0sec CLI process that handles all engine communication behind a
security boundary.

## Starting the desktop

### Source development

From the monorepo root, the CLI, dashboard, and sidecar binary must be built
first:

```bash
pnpm install --frozen-lockfile
pnpm build
bash scripts/bun-compile.sh "" "dist-bin/0sec-linux-x64"
pnpm --filter @0sec/desktop start
```

On macOS Apple Silicon, replace the target arch:

```bash
bash scripts/bun-compile.sh "" "dist-bin/0sec-darwin-arm64"
```

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

### Packaged releases

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
│  IPC:  osec:open-external (HTTPS)   │
│  Permission: all denied             │
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

Zoom is disabled (`setVisualZoomLevelLimits(1, 1)`). Pinch-zoom and
Ctrl+Plus/Minus have no effect.

### IPC

The only IPC channel exposed from the renderer to the main process:

```
window.osecDesktop.openExternal(url: string): Promise<void>
```

Exposed via `contextBridge.exposeInMainWorld`. The main process validates:
1. The sender's frame origin must match the dashboard origin.
2. The `url` argument must be a string.
3. The URL must be a credential-free `https://` URL.

All other IPC channels are blocked.

### Permission policy

All Chromium permission requests (camera, microphone, geolocation,
notifications, clipboard read, etc.) are denied at the session level. The
renderer cannot acquire any browser-level permissions.

## Window

| Property | Value |
|----------|-------|
| Default size | 1440 × 960 |
| Minimum size | 960 × 640 |
| Background colour | `#09090b` |
| Title | `0sec` |
| Show | Hidden until `ready-to-show` to avoid white flash |
| Single-instance lock | Yes — a second launch focuses the existing window |

## Preload

The preload script (`packages/desktop/src/preload/index.ts`) exposes a single
global via `contextBridge` with `Object.freeze`:

```typescript
window.osecDesktop = { openExternal(url: string): Promise<void> }
```

No other Node.js or Electron API is available in the renderer
(`contextIsolation: true`, `sandbox: true`).

## User workflow

1. Launch the desktop application from your OS (or `pnpm --filter @0sec/desktop start` in development).
2. The Electron window opens to a dashboard web UI served by the sidecar over
   a local loopback URL.
3. Use the dashboard to configure engagements, review findings, manage provider
   connections, and inspect scan results.
4. The dashboard communicates with the sidecar process only; it has no direct
   filesystem or network access beyond the sidecar's loopback HTTP server.
5. External documentation links (e.g. provider setup pages) open in the system
   browser via `osecDesktop.openExternal`.

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