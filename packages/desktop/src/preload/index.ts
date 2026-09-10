import { contextBridge, ipcRenderer } from "electron";
import type { DesktopHostBridge, DesktopHostCommand } from "@0sec/shared";

const VALID_COMMANDS = ["new-thread", "open-folder", "toggle-sidebar", "settings"] as const satisfies readonly DesktopHostCommand[];

const commandListeners = new Set<(command: DesktopHostCommand) => void>();
let pendingCommand: DesktopHostCommand | undefined;

function dispatchCommand(command: DesktopHostCommand): void {
  if (commandListeners.size === 0) {
    // The lazy conversation route may mount after did-finish-load.
    pendingCommand = command;
    return;
  }
  for (const listener of [...commandListeners]) listener(command);
}

ipcRenderer.on("osec:command", (_event, command: unknown) => {
  if (typeof command === "string" && VALID_COMMANDS.includes(command as DesktopHostCommand)) {
    dispatchCommand(command as DesktopHostCommand);
  }
});

contextBridge.exposeInMainWorld(
  "osecDesktop",
  Object.freeze({
    platform: process.platform,
    openExternal(url: string): Promise<void> {
      return ipcRenderer.invoke("osec:open-external", url) as Promise<void>;
    },
    chooseDirectory(): Promise<string | null> {
      return ipcRenderer.invoke("osec:choose-directory") as Promise<string | null>;
    },
    onCommand(listener: (command: DesktopHostCommand) => void): () => void {
      commandListeners.add(listener);
      if (pendingCommand !== undefined) {
        queueMicrotask(() => {
          if (pendingCommand === undefined || commandListeners.size === 0) return;
          const command = pendingCommand;
          pendingCommand = undefined;
          dispatchCommand(command);
        });
      }
      return () => {
        commandListeners.delete(listener);
      };
    },
  } satisfies DesktopHostBridge),
);