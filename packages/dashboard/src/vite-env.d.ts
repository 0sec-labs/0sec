/// <reference types="vite/client" />

import type { DesktopHostBridge } from "@0sec/shared";

declare global {
  interface Window {
    readonly osecDesktop?: DesktopHostBridge;
  }
}