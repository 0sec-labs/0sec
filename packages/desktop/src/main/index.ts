import {
  app,
  BrowserWindow,
  dialog,
  ipcMain,
  Menu,
  type MenuItemConstructorOptions,
  nativeTheme,
  session,
  shell,
} from "electron";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { DesktopHostCommand } from "@0sec/shared";
import {
  createDashboardSidecarInvocation,
  findWorkspaceRoot,
  startDashboardSidecar,
  type DashboardSidecar,
} from "./sidecar.js";
import { hasSameOrigin, isExternalHttpsUrl } from "./security.js";
import { parseDevelopmentDebugPort } from "./development.js";
import { DesktopPreferences } from "./preferences.js";

const moduleDirectory = dirname(fileURLToPath(import.meta.url));
const developmentDebugPort = parseDevelopmentDebugPort(process.env.OSEC_DESKTOP_DEBUG_PORT);
if (!app.isPackaged && developmentDebugPort !== undefined) {
  // Loopback only. Remote inspection reaches this port through an SSH tunnel,
  // never by opening a Chromium debugger on the local network.
  app.commandLine.appendSwitch("remote-debugging-address", "127.0.0.1");
  app.commandLine.appendSwitch("remote-debugging-port", String(developmentDebugPort));
}

// Explicit app name so the macOS app-menu label is "0sec" regardless of the
// npm package name (@0sec/desktop). Must be set before 'ready'.
app.name = "0sec";

let mainWindow: BrowserWindow | null = null;
let dashboard: DashboardSidecar | null = null;
let isQuitting = false;
let windowReady: Promise<void> | null = null;
let applicationStart: Promise<void> | null = null;
let canQuit = false;
let preferences: DesktopPreferences | undefined;

function desktopAssetDirectory(): string {
  if (app.isPackaged) return join(process.resourcesPath, "dashboard");
  const workspaceRoot = findWorkspaceRoot(process.env.OSEC_DESKTOP_ROOT ?? moduleDirectory);
  return join(workspaceRoot, "packages", "dashboard", "dist");
}

function sidecarWorkingDirectory(): string {
  if (!app.isPackaged) return findWorkspaceRoot(process.env.OSEC_DESKTOP_ROOT ?? moduleDirectory);
  const userData = app.getPath("userData");
  mkdirSync(userData, { recursive: true, mode: 0o700 });
  return userData;
}

function isTrustedDashboardUrl(value: string): boolean {
  return dashboard !== null && hasSameOrigin(dashboard.url, value);
}

function installNavigationPolicy(window: BrowserWindow): void {
  const { webContents } = window;

  webContents.setWindowOpenHandler(({ url }) => {
    if (isExternalHttpsUrl(url)) void shell.openExternal(url);
    return { action: "deny" };
  });

  const preventExternalNavigation = (event: Electron.Event, url: string) => {
    if (!isTrustedDashboardUrl(url)) event.preventDefault();
  };
  webContents.on("will-navigate", preventExternalNavigation);
  webContents.on("will-redirect", preventExternalNavigation);
  webContents.on("will-attach-webview", (event) => event.preventDefault());
}

function createWindow(): BrowserWindow {
  const isMac = process.platform === "darwin";

  const options: Electron.BrowserWindowConstructorOptions = {
    width: 1280,
    height: 860,
    minWidth: 900,
    minHeight: 600,
    show: false,
    backgroundColor: nativeTheme.shouldUseDarkColors ? "#161615" : "#f5f5f3",
    title: "0sec",
    webPreferences: {
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      webviewTag: false,
      preload: join(moduleDirectory, "../preload/index.js"),
    },
  };

  if (isMac) {
    options.titleBarStyle = "hiddenInset";
    options.trafficLightPosition = { x: 18, y: 18 };
    options.vibrancy = "sidebar";
  }

  const window = new BrowserWindow(options);
  installNavigationPolicy(window);
  window.webContents.setVisualZoomLevelLimits(1, 1).catch(() => undefined);
  window.once("ready-to-show", () => window.show());
  return window;
}

async function showMainWindow(): Promise<BrowserWindow | null> {
  if (isQuitting || !dashboard) return null;
  if (!mainWindow) {
    const window = createWindow();
    mainWindow = window;
    window.on("closed", () => {
      if (mainWindow === window) {
        mainWindow = null;
        windowReady = null;
      }
    });
    windowReady = window.loadURL(`${dashboard.url}/desktop.html`);
  }
  const window = mainWindow;
  await windowReady;
  if (window.isDestroyed() || isQuitting) return null;
  if (window.isMinimized()) window.restore();
  window.show();
  window.focus();
  return window;
}

function showWindowError(error: unknown): void {
  if (!isQuitting) {
    dialog.showErrorBox("0sec could not open", error instanceof Error ? error.message : String(error));
  }
}

function sendCommand(command: DesktopHostCommand): void {
  void showMainWindow().then(async (window) => {
    if (!window || !dashboard) return;
    if (new URL(window.webContents.getURL()).pathname !== "/desktop.html") {
      await window.loadURL(`${dashboard.url}/desktop.html`);
    }
    if (!window.isDestroyed()) window.webContents.send("osec:command", command);
  }).catch(showWindowError);
}

function installApplicationMenu(): void {
  const isMac = process.platform === "darwin";

  const template: MenuItemConstructorOptions[] = [
    // macOS application menu (About, Settings, Quit, etc.)
    ...(isMac
      ? [
          {
            label: app.name,
            submenu: [
              { role: "about" },
              { type: "separator" },
              {
                label: "Settings…",
                accelerator: "CmdOrCtrl+,",
                click: () => sendCommand("settings"),
              },
              { type: "separator" },
              { role: "services" },
              { type: "separator" },
              { role: "hide" },
              { role: "hideOthers" },
              { role: "unhide" },
              { type: "separator" },
              { role: "quit" },
            ],
          } satisfies MenuItemConstructorOptions,
        ]
      : []),

    // File: New Session, Open Folder, Close/Quit
    {
      label: "File",
      submenu: [
        {
          label: "New Session",
          accelerator: "CmdOrCtrl+N",
          click: () => sendCommand("new-thread"),
        },
        {
          label: "Open Folder…",
          accelerator: "CmdOrCtrl+O",
          click: () => sendCommand("open-folder"),
        },
        { type: "separator" },
        ...(isMac
          ? [{ role: "close" } satisfies MenuItemConstructorOptions]
          : [{ role: "quit" } satisfies MenuItemConstructorOptions]),
      ],
    } satisfies MenuItemConstructorOptions,

    // Standard Edit
    { role: "editMenu" } satisfies MenuItemConstructorOptions,

    // View: Toggle Sidebar, reload, zoom, fullscreen
    {
      label: "View",
      submenu: [
        {
          label: "Toggle Sidebar",
          accelerator: "CmdOrCtrl+B",
          click: () => sendCommand("toggle-sidebar"),
        },
        { type: "separator" },
        { role: "reload" },
        { role: "forceReload" },
        { role: "toggleDevTools" },
        { type: "separator" },
        { role: "resetZoom" },
        { role: "zoomIn" },
        { role: "zoomOut" },
        { type: "separator" },
        { role: "togglefullscreen" },
      ],
    } satisfies MenuItemConstructorOptions,

    // Window (macOS gets a standard window menu; non-mac gets Settings here)
    ...(isMac
      ? [
          { role: "windowMenu" } satisfies MenuItemConstructorOptions,
        ]
      : [
          {
            label: "Window",
            submenu: [
              {
                label: "Settings",
                accelerator: "CmdOrCtrl+,",
                click: () => sendCommand("settings"),
              },
              { type: "separator" },
              { role: "minimize" },
              { role: "zoom" },
            ],
          } satisfies MenuItemConstructorOptions,
        ]),

    {
      role: "help",
      submenu: [
        { label: "0sec Documentation", click: () => { void shell.openExternal("https://docs.0.security"); } },
      ],
    },
  ];

  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

function installPermissionPolicy(): void {
  const canWriteClipboard = (
    contents: Electron.WebContents | null,
    permission: string,
    origin: string,
  ) =>
    permission === "clipboard-sanitized-write" &&
    contents === mainWindow?.webContents &&
    contents.isFocused() &&
    isTrustedDashboardUrl(origin);
  session.defaultSession.setPermissionCheckHandler(
    (contents, permission, origin) =>
      canWriteClipboard(contents, permission, origin),
  );
  session.defaultSession.setPermissionRequestHandler(
    (contents, permission, callback, _details) =>
      callback(canWriteClipboard(contents, permission, _details.requestingUrl)),
  );
}

function isTrustedMainRenderer(event: Electron.IpcMainInvokeEvent): boolean {
  return mainWindow !== null &&
    event.sender === mainWindow.webContents &&
    event.senderFrame === mainWindow.webContents.mainFrame &&
    isTrustedDashboardUrl(event.senderFrame?.url ?? "");
}

function installIpcPolicy(): void {
  ipcMain.handle("osec:preferences:get", (event) => {
    if (!isTrustedMainRenderer(event) || !preferences) throw new Error("Desktop denied an untrusted preference request.");
    return preferences.snapshot();
  });
  ipcMain.handle("osec:preferences:set", (event, key: unknown, value: unknown) => {
    if (!isTrustedMainRenderer(event) || !preferences) throw new Error("Desktop denied an untrusted preference request.");
    return preferences.set(key, value);
  });
  ipcMain.handle("osec:open-external", async (event, candidate: unknown) => {
    if (
      !isTrustedMainRenderer(event) ||
      typeof candidate !== "string" ||
      !isExternalHttpsUrl(candidate)
    ) {
      throw new Error("Desktop denied an untrusted external navigation request.");
    }
    await shell.openExternal(candidate);
  });

  ipcMain.handle("osec:choose-directory", async (event) => {
    if (!isTrustedMainRenderer(event)) {
      throw new Error("Desktop denied an untrusted directory picker request.");
    }
    if (!mainWindow) throw new Error("No main window available.");
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ["openDirectory"],
    });
    return result.canceled ? null : (result.filePaths[0] ?? null);
  });
}

async function startApplication(): Promise<void> {
  if (isQuitting) return;
  if (!app.isPackaged && process.platform === "darwin") {
    app.dock?.setIcon(join(moduleDirectory, "../../build/icon.png"));
  }
  preferences = new DesktopPreferences(join(app.getPath("userData"), "workspace.json"));
  installApplicationMenu();
  installPermissionPolicy();
  installIpcPolicy();

  const assetDir = desktopAssetDirectory();
  const invocation = createDashboardSidecarInvocation({
    assetDir,
    cwd: sidecarWorkingDirectory(),
    packaged: app.isPackaged,
    resourcesPath: app.isPackaged ? process.resourcesPath : undefined,
    projectRoot: app.isPackaged
      ? undefined
      : findWorkspaceRoot(process.env.OSEC_DESKTOP_ROOT ?? moduleDirectory),
  });
  dashboard = await startDashboardSidecar(invocation);

  await showMainWindow();
}

async function stopApplication(): Promise<void> {
  // Quit can arrive while the sidecar is still announcing readiness.
  await applicationStart?.catch(() => undefined);
  const runningDashboard = dashboard;
  dashboard = null;
  await runningDashboard?.stop();
  await preferences?.flush();
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    void showMainWindow().catch(showWindowError);
  });

  app.whenReady().then(() => {
    applicationStart = startApplication();
    return applicationStart;
  }).catch((error: unknown) => {
    if (isQuitting) return;
    const message = error instanceof Error ? error.message : String(error);
    dialog.showErrorBox("0sec could not start", message);
    void stopApplication().finally(() => app.exit(1));
  });

  // macOS: closing the last window keeps the app and sidecar alive.
  // Non-mac: last-window close quits the app.
  app.on("window-all-closed", () => {
    if (process.platform !== "darwin") {
      app.quit();
    }
  });

  // macOS dock/activation: re-create a window without spawning a second sidecar.
  app.on("activate", () => {
    void showMainWindow().catch(showWindowError);
  });

  app.on("before-quit", (event) => {
    if (canQuit) return;
    event.preventDefault();
    if (isQuitting) return;
    isQuitting = true;
    void stopApplication().finally(() => {
      canQuit = true;
      app.quit();
    });
  });
}