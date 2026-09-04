import { app, BrowserWindow, dialog, ipcMain, Menu, session, shell } from "electron";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createDashboardSidecarInvocation,
  findWorkspaceRoot,
  startDashboardSidecar,
  type DashboardSidecar,
} from "./sidecar.js";
import { hasSameOrigin, isExternalHttpsUrl } from "./security.js";
import { parseDevelopmentDebugPort } from "./development.js";

const moduleDirectory = dirname(fileURLToPath(import.meta.url));
const developmentDebugPort = parseDevelopmentDebugPort(process.env.OSEC_DESKTOP_DEBUG_PORT);
if (!app.isPackaged && developmentDebugPort !== undefined) {
  // Loopback only. Remote inspection reaches this port through an SSH tunnel,
  // never by opening a Chromium debugger on the local network.
  app.commandLine.appendSwitch("remote-debugging-address", "127.0.0.1");
  app.commandLine.appendSwitch("remote-debugging-port", String(developmentDebugPort));
}


let mainWindow: BrowserWindow | null = null;
let dashboard: DashboardSidecar | null = null;
let isQuitting = false;

function desktopAssetDirectory(): string {
  if (app.isPackaged) return join(process.resourcesPath, "dashboard");
  const workspaceRoot = findWorkspaceRoot(process.env.OSEC_DESKTOP_ROOT ?? process.cwd());
  return join(workspaceRoot, "packages", "dashboard", "dist");
}

function sidecarWorkingDirectory(): string {
  if (!app.isPackaged) return findWorkspaceRoot(process.env.OSEC_DESKTOP_ROOT ?? process.cwd());
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
  const window = new BrowserWindow({
    width: 1440,
    height: 960,
    minWidth: 960,
    minHeight: 640,
    show: false,
    backgroundColor: "#09090b",
    title: "0sec",
    webPreferences: {
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      webviewTag: false,
      preload: join(moduleDirectory, "../preload/index.js"),
    },
  });

  installNavigationPolicy(window);
  window.webContents.setVisualZoomLevelLimits(1, 1).catch(() => undefined);
  window.once("ready-to-show", () => window.show());
  return window;
}

function installApplicationMenu(): void {
  Menu.setApplicationMenu(
    Menu.buildFromTemplate([
      { role: "appMenu" },
      { role: "fileMenu" },
      { role: "editMenu" },
      { role: "viewMenu" },
      { role: "windowMenu" },
    ]),
  );
}

function installPermissionPolicy(): void {
  session.defaultSession.setPermissionCheckHandler(() => false);
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
}

function installIpcPolicy(): void {
  ipcMain.handle("osec:open-external", async (event, candidate: unknown) => {
    if (!isTrustedDashboardUrl(event.senderFrame?.url ?? "") || typeof candidate !== "string" || !isExternalHttpsUrl(candidate)) {
      throw new Error("Desktop denied an untrusted external navigation request.");
    }
    await shell.openExternal(candidate);
  });
}

async function startApplication(): Promise<void> {
  installApplicationMenu();
  installPermissionPolicy();
  installIpcPolicy();

  const assetDir = desktopAssetDirectory();
  const invocation = createDashboardSidecarInvocation({
    assetDir,
    cwd: sidecarWorkingDirectory(),
    packaged: app.isPackaged,
    resourcesPath: app.isPackaged ? process.resourcesPath : undefined,
    projectRoot: app.isPackaged ? undefined : findWorkspaceRoot(process.env.OSEC_DESKTOP_ROOT ?? process.cwd()),
  });
  dashboard = await startDashboardSidecar(invocation);

  mainWindow = createWindow();
  mainWindow.on("closed", () => {
    mainWindow = null;
  });
  await mainWindow.loadURL(dashboard.url);
}

async function stopApplication(): Promise<void> {
  const runningDashboard = dashboard;
  dashboard = null;
  await runningDashboard?.stop();
}

if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  });

  app.whenReady().then(startApplication).catch((error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    dialog.showErrorBox("0sec could not start", message);
    app.exit(1);
  });

  app.on("window-all-closed", () => app.quit());
  app.on("before-quit", (event) => {
    if (isQuitting) return;
    event.preventDefault();
    isQuitting = true;
    void stopApplication().finally(() => app.quit());
  });
}
