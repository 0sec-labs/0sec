import { describe, expect, it } from "vitest";
import {
  createProcessPresentationOutput,
  installConsolePresentationBridge,
  installProcessPresentationStreamBridge,
} from "./process-output.js";

describe("createProcessPresentationOutput", () => {
  it("preserves bytes and emits ordered canonical records", () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const events: unknown[] = [];
    const output = createProcessPresentationOutput({
      stdout: { write(text) { stdout.push(String(text)); return true; } },
      stderr: { write(text) { stderr.push(String(text)); return true; } },
      now: () => "2026-08-26T00:00:00.000Z",
      onEvent(event) { events.push(event); },
    });

    output.stdout("answer", "console.assistant.delta");
    output.stderr("warning\n", "console.notice");

    expect(stdout).toEqual(["answer"]);
    expect(stderr).toEqual(["warning\n"]);
    expect(events).toEqual([
      expect.objectContaining({
        protocol: "0sec.presentation/v1",
        sequence: 1,
        eventType: "console.assistant.delta",
        payload: { channel: "stdout", text: "answer" },
      }),
      expect.objectContaining({
        protocol: "0sec.presentation/v1",
        sequence: 2,
        eventType: "console.notice",
        payload: { channel: "stderr", text: "warning\n" },
      }),
    ]);
  });
});

describe("installConsolePresentationBridge", () => {
  it("preserves console formatting while emitting canonical events", () => {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const events: unknown[] = [];
    const target: {
      log: (...args: unknown[]) => void;
      info: (...args: unknown[]) => void;
      warn: (...args: unknown[]) => void;
      error: (...args: unknown[]) => void;
    } = {
      log(...args) { stdout.push(String(args[0])); },
      info(...args) { stdout.push(`info:${String(args[0])}`); },
      warn(...args) { stderr.push(`warn:${String(args[0])}`); },
      error(...args) { stderr.push(String(args[0])); },
    };
    const bridge = installConsolePresentationBridge({
      target,
      now: () => "2026-08-26T00:00:00.000Z",
      onEvent(event) { events.push(event); },
    });

    target.log("answer %d", 7);
    target.warn("warning");
    bridge.restore();
    target.log("plain");

    expect(stdout).toEqual(["answer 7", "plain"]);
    expect(stderr).toEqual(["warn:warning"]);
    expect(events).toEqual([
      expect.objectContaining({
        eventType: "output.console.log",
        payload: { channel: "stdout", text: "answer 7" },
      }),
      expect.objectContaining({
        eventType: "output.console.warn",
        payload: { channel: "stderr", text: "warning" },
      }),
    ]);
  });
});


describe("installProcessPresentationStreamBridge", () => {
  it("observes raw stream bytes and suspends around terminal ownership", () => {
    const stdoutWrites: string[] = [];
    const stderrWrites: string[] = [];
    const events: unknown[] = [];
    const stdout = {
      write(chunk: unknown) {
        stdoutWrites.push(String(chunk));
        return true;
      },
    } as unknown as NodeJS.WriteStream;
    const stderr = {
      write(chunk: unknown) {
        stderrWrites.push(String(chunk));
        return true;
      },
    } as unknown as NodeJS.WriteStream;
    const bridge = installProcessPresentationStreamBridge({
      stdout,
      stderr,
      now: () => "2026-08-26T00:00:00.000Z",
      onEvent(event) { events.push(event); },
    });

    stdout.write("first");
    stderr.write("problem");
    bridge.suspend();
    stdout.write("terminal-frame");
    bridge.resume();
    stdout.write("last");
    bridge.restore();

    expect(stdoutWrites).toEqual(["first", "terminal-frame", "last"]);
    expect(stderrWrites).toEqual(["problem"]);
    expect(events).toEqual([
      expect.objectContaining({
        sequence: 1,
        eventType: "output.stream.stdout",
        payload: { channel: "stdout", text: "first" },
      }),
      expect.objectContaining({
        sequence: 2,
        eventType: "output.stream.stderr",
        payload: { channel: "stderr", text: "problem" },
      }),
      expect.objectContaining({
        sequence: 3,
        eventType: "output.stream.stdout",
        payload: { channel: "stdout", text: "last" },
      }),
    ]);
  });
});