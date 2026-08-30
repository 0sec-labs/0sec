import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import {
  startCodexDeviceAuth,
  type CodexDeviceAuthProcess,
} from "./codex-device-auth.js";

const directories: string[] = [];

function temporaryHome(): string {
  const home = mkdtempSync(join(tmpdir(), "0sec-codex-device-auth-"));
  directories.push(home);
  return home;
}

afterEach(() => {
  for (const directory of directories.splice(0)) {
    rmSync(directory, { recursive: true, force: true });
  }
});

function fakeProcess() {
  let stdout: ((chunk: Buffer) => void) | undefined;
  let stderr: ((chunk: Buffer) => void) | undefined;
  let error: ((value: Error) => void) | undefined;
  let close: ((code: number | null) => void) | undefined;
  const kills: NodeJS.Signals[] = [];
  const process: CodexDeviceAuthProcess = {
    stdout: { on: (_event, listener) => { stdout = listener; } },
    stderr: { on: (_event, listener) => { stderr = listener; } },
    on: (event, listener) => {
      if (event === "error") error = listener as (value: Error) => void;
      if (event === "close") close = listener as (code: number | null) => void;
    },
    kill: (signal) => {
      if (signal) kills.push(signal);
      return true;
    },
  };
  return {
    process,
    kills,
    stdout: (text: string) => stdout?.(Buffer.from(text)),
    stderr: (text: string) => stderr?.(Buffer.from(text)),
    error: (value: Error) => error?.(value),
    close: (code: number | null) => close?.(code),
  };
}

describe("startCodexDeviceAuth", () => {
  it("uses Codex device OAuth and replaces only stale in-process Codex tokens after success", () => {
    const home = temporaryHome();
    const authPath = join(home, "auth.json");
    writeFileSync(authPath, JSON.stringify({
      tokens: { access_token: "fresh-access", refresh_token: "fresh-refresh" },
    }));
    const env: NodeJS.ProcessEnv = {
      "0SEC_CHATGPT_AUTH_FILE": authPath,
      "0SEC_CHATGPT_ACCESS_TOKEN": "stale-access",
      "0SEC_CHATGPT_OAUTH_REFRESH_TOKEN": "stale-refresh",
    };
    const child = fakeProcess();
    const updates: string[] = [];
    let connected = 0;

    startCodexDeviceAuth({
      env,
      homeDir: home,
      spawn: (command, args) => {
        expect(command).toBe("codex");
        expect(args).toEqual(["login", "--device-auth"]);
        return child.process;
      },
      onUpdate: (update) => updates.push(update.phase),
      onConnected: () => { connected += 1; },
    });
    child.stdout("Open https://auth.openai.com/device\n");
    child.stderr("Enter code ABCD-EFGH\n");
    child.close(0);

    expect(env["0SEC_CHATGPT_ACCESS_TOKEN"]).toBe("fresh-access");
    expect(env["0SEC_CHATGPT_OAUTH_REFRESH_TOKEN"]).toBe("fresh-refresh");
    expect(updates).toEqual(["running", "running", "running", "connected"]);
    expect(connected).toBe(1);
  });

  it("cancels the device flow without treating it as an API-key failure", () => {
    const child = fakeProcess();
    const phases: string[] = [];
    const session = startCodexDeviceAuth({
      env: {},
      spawn: () => child.process,
      onUpdate: (update) => phases.push(update.phase),
      onConnected: () => {},
    });
    session.cancel();
    child.close(null);

    expect(child.kills).toEqual(["SIGTERM"]);
    expect(phases.at(-1)).toBe("cancelled");
  });
});
