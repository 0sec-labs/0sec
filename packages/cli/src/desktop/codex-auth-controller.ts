import {
  startCodexDeviceAuth,
  type CodexDeviceAuthSession,
  type CodexDeviceAuthUpdate,
  type StartCodexDeviceAuthOptions,
} from "../tui/codex-device-auth.js";
import type { DesktopCodexAuthStatus } from "@0sec/shared";

export type { DesktopCodexAuthStatus } from "@0sec/shared";

export interface DesktopCodexAuthControllerOptions {
  start?: (options: StartCodexDeviceAuthOptions) => CodexDeviceAuthSession;
}

/**
 * Daemon-owned adapter for Codex's official device OAuth flow. The browser
 * renderer sees phase/status text only; the Codex CLI writes and 0sec reads the
 * auth file inside the daemon process, so OAuth tokens never cross this API.
 */
export class DesktopCodexAuthController {
  readonly #start: (options: StartCodexDeviceAuthOptions) => CodexDeviceAuthSession;
  #status: DesktopCodexAuthStatus = {
    phase: "idle",
    message: "ChatGPT Codex is not connected.",
    lines: [],
  };
  #session: CodexDeviceAuthSession | null = null;

  constructor(options: DesktopCodexAuthControllerOptions = {}) {
    this.#start = options.start ?? startCodexDeviceAuth;
  }

  status(): DesktopCodexAuthStatus {
    return { ...this.#status, lines: [...this.#status.lines] };
  }

  start(): DesktopCodexAuthStatus {
    if (this.#status.phase === "running") return this.status();
    this.#session = this.#start({
      onUpdate: (update) => this.#apply(update),
      onConnected: () => undefined,
    });
    return this.status();
  }

  cancel(): DesktopCodexAuthStatus {
    this.#session?.cancel();
    return this.status();
  }

  #apply(update: CodexDeviceAuthUpdate): void {
    this.#status = {
      phase: update.phase,
      message: update.message,
      lines: [...update.lines],
    };
    if (update.phase !== "running") this.#session = null;
  }
}
