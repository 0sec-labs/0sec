import { loadCloudCredentials } from "@0sec/core";
import { hostedBrowserLoginFlow, type HostedBrowserLoginOptions, type HostedLoginPhase, type LoginResult } from "../commands/auth.js";

export interface HostedDeviceAuthUpdate {
  phase: HostedLoginPhase | "failed";
  message: string;
  loginUrl?: string;
}

export interface StartHostedDeviceAuthOptions extends Omit<HostedBrowserLoginOptions, "signal" | "onStatus"> {
  onUpdate: (update: HostedDeviceAuthUpdate) => void;
  /** Login persisted; this does not establish funds or service availability. */
  onConnected: () => void;
  onSettled?: (result: LoginResult) => void;
}

/** Return safe local metadata only. Presence is not authentication or funding proof. */
export function readHostedConnection(env: Record<string, string | undefined>, homeDir?: string): { configured: boolean; host?: string; warning?: string } {
  let warning: string | undefined;
  try {
    const credentials = loadCloudCredentials({ env, homeDir, warn: (message) => { warning = message; } });
    return { configured: true, host: credentials.host, warning };
  } catch {
    return { configured: false };
  }
}

/** The canonical helper owns polling and credential writes. This bridge owns UI cancellation. */
export function startHostedDeviceAuth(options: StartHostedDeviceAuthOptions): { cancel(): void } {
  const controller = new AbortController();
  const { onUpdate, onConnected, onSettled, ...loginOptions } = options;
  let phase: HostedDeviceAuthUpdate["phase"] = "opening";
  void hostedBrowserLoginFlow({
    ...loginOptions,
    signal: controller.signal,
    onStatus: (next, message, loginUrl) => {
      if (controller.signal.aborted) return;
      phase = next;
      onUpdate({ phase: next, message, loginUrl });
    },
  }).then((result) => {
    if (controller.signal.aborted) return;
    if (result.ok) onConnected();
    else if (phase !== "timeout") onUpdate({ phase: "failed", message: result.error });
    onSettled?.(result);
  }, () => {
    if (!controller.signal.aborted) onUpdate({ phase: "failed", message: "0sec Cloud sign-in could not complete. Use your own provider or try again." });
  });
  return { cancel: () => controller.abort() };
}
