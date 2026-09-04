import { contextBridge, ipcRenderer } from "electron";

contextBridge.exposeInMainWorld(
  "osecDesktop",
  Object.freeze({
    openExternal(url: string): Promise<void> {
      return ipcRenderer.invoke("osec:open-external", url) as Promise<void>;
    },
  }),
);
