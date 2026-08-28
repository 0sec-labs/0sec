import { format } from "node:util";

import {
  createPresentationEvent,
  type PresentationEvent,
  type PresentationSource,
} from "@0sec/shared";
import { presentationEventBus } from "./event-bus.js";

type WritableOutput = Pick<NodeJS.WriteStream, "write">;

export interface ProcessPresentationOutputOptions {
  stdout?: WritableOutput;
  stderr?: WritableOutput;
  source?: PresentationSource;
  now?: () => string;
  onEvent?: (event: PresentationEvent) => void;
}

export interface ProcessPresentationOutput {
  stdout(text: string, eventType?: string): PresentationEvent;
  stderr(text: string, eventType?: string): PresentationEvent;
}

export interface ConsolePresentationOutputOptions {
  log?: (text: string) => void;
  error?: (text: string) => void;
  source?: PresentationSource;
  now?: () => string;
  onEvent?: (event: PresentationEvent) => void;
}

type ConsoleMethod = (...args: unknown[]) => void;

export interface ConsolePresentationBridgeOptions {
  target?: {
    log: ConsoleMethod;
    info: ConsoleMethod;
    warn: ConsoleMethod;
    error: ConsoleMethod;
  };
  source?: PresentationSource;
  now?: () => string;
  onEvent?: (event: PresentationEvent) => void;
}

export interface ConsolePresentationBridge {
  restore(): void;
}

export interface ProcessPresentationStreamBridgeOptions {
  stdout?: NodeJS.WriteStream;
  stderr?: NodeJS.WriteStream;
  source?: PresentationSource;
  now?: () => string;
  onEvent?: (event: PresentationEvent) => void;
}

export interface ProcessPresentationStreamBridge {
  suspend(): void;
  resume(): void;
  restore(): void;
}

type StreamWrite = NodeJS.WriteStream["write"];
type BridgedStream = {
  channel: "stdout" | "stderr";
  stream: NodeJS.WriteStream;
  original: StreamWrite;
  patched: StreamWrite;
};

let streamBridgeSuppressionDepth = 0;
let activeStreamBridge: ProcessPresentationStreamBridge | null = null;

function currentPresentationTimestamp(): string {
  return new Date().toISOString();
}

/**
 * Preserve process-stream bytes while exposing every write as the canonical
 * presentation envelope. This is the Node/non-TTY adapter; it deliberately
 * does not add ANSI, newlines, buffering, or terminal ownership semantics.
 */
export function createProcessPresentationOutput(
  options: ProcessPresentationOutputOptions = {},
): ProcessPresentationOutput {
  const stdout = options.stdout ?? { write: process.stdout.write.bind(process.stdout) as WritableOutput["write"] };
  const stderr = options.stderr ?? { write: process.stderr.write.bind(process.stderr) as WritableOutput["write"] };
  const source = options.source ?? "cli";
  const now = options.now ?? currentPresentationTimestamp;
  let sequence = 0;

  const write = (
    channel: "stdout" | "stderr",
    target: WritableOutput,
    text: string,
    eventType: string,
  ): PresentationEvent => {
    const event = createPresentationEvent({
      source,
      sequence: ++sequence,
      at: now(),
      eventType,
      payload: { channel, text },
    });
    target.write(text);
    options.onEvent?.(event);
    return event;
  };

  return {
    stdout(text, eventType = "output.stdout") {
      return write("stdout", stdout, text, eventType);
    },
    stderr(text, eventType = "output.stderr") {
      return write("stderr", stderr, text, eventType);
    },
  };
}

/**
 * Console-method adapter for commands whose public/test contract is
 * `console.log`/`console.error` rather than raw stream writes.
 */
export function createConsolePresentationOutput(
  options: ConsolePresentationOutputOptions = {},
): ProcessPresentationOutput {
  const source = options.source ?? "cli";
  const now = options.now ?? currentPresentationTimestamp;
  let sequence = 0;

  const emit = (
    channel: "stdout" | "stderr",
    text: string,
    eventType: string,
  ): PresentationEvent => {
    const event = createPresentationEvent({
      source,
      sequence: ++sequence,
      at: now(),
      eventType,
      payload: { channel, text },
    });
    if (channel === "stdout") {
      (options.log ?? console.log)(text);
    } else {
      (options.error ?? console.error)(text);
    }
    options.onEvent?.(event);
    return event;
  };

  return {
    stdout(text, eventType = "output.stdout") {
      return emit("stdout", text, eventType);
    },
    stderr(text, eventType = "output.stderr") {
      return emit("stderr", text, eventType);
    },
  };
}

/** Default console-method adapter for human-oriented command output. */
export const consolePresentationOutput = createConsolePresentationOutput({
  onEvent(event) {
    presentationEventBus.emit(event);
  },
});

/**
 * Bridge legacy `console.*` writers at the CLI process boundary. The bridge
 * preserves Node's formatting/newline behavior by delegating to the original
 * console methods, while every line joins the canonical event stream.
 */
export function installConsolePresentationBridge(
  options: ConsolePresentationBridgeOptions = {},
): ConsolePresentationBridge {
  const target = options.target ?? console;
  const originals = {
    log: target.log,
    info: target.info,
    warn: target.warn,
    error: target.error,
  };
  const source = options.source ?? "cli";
  const now = options.now ?? currentPresentationTimestamp;
  let sequence = 0;
  const emit = (
    method: keyof typeof originals,
    channel: "stdout" | "stderr",
    args: unknown[],
    eventType: string,
  ): void => {
    const text = format(...args);
    const event = createPresentationEvent({
      source,
      sequence: ++sequence,
      at: now(),
      eventType,
      payload: { channel, text },
    });
    streamBridgeSuppressionDepth += 1;
    try {
      originals[method].call(target, text);
    } finally {
      streamBridgeSuppressionDepth -= 1;
    }
    presentationEventBus.emit(event);
    options.onEvent?.(event);
  };

  const bridgedLog: ConsoleMethod = (...args) => emit("log", "stdout", args, "output.console.log");
  const bridgedInfo: ConsoleMethod = (...args) => emit("info", "stdout", args, "output.console.info");
  const bridgedWarn: ConsoleMethod = (...args) => emit("warn", "stderr", args, "output.console.warn");
  const bridgedError: ConsoleMethod = (...args) => emit("error", "stderr", args, "output.console.error");
  target.log = bridgedLog;
  target.info = bridgedInfo;
  target.warn = bridgedWarn;
  target.error = bridgedError;

  return {
    restore() {
      if (target.log === bridgedLog) target.log = originals.log;
      if (target.info === bridgedInfo) target.info = originals.info;
      if (target.warn === bridgedWarn) target.warn = originals.warn;
      if (target.error === bridgedError) target.error = originals.error;
    },
  };
}


/**
 * Observe legacy raw process writes without changing their bytes. The bridge is
 * suspended while OpenTUI owns the terminal so renderer frames never become
 * presentation events.
 */
export function installProcessPresentationStreamBridge(
  options: ProcessPresentationStreamBridgeOptions = {},
): ProcessPresentationStreamBridge {
  if (activeStreamBridge) return activeStreamBridge;

  const source = options.source ?? "cli";
  const now = options.now ?? currentPresentationTimestamp;
  let sequence = 0;
  let suspended = false;
  const streams: BridgedStream[] = [];
  const emit = (channel: "stdout" | "stderr", chunk: unknown, encoding: unknown): void => {
    const text = typeof chunk === "string"
      ? chunk
      : chunk instanceof Uint8Array
        ? Buffer.from(chunk).toString(typeof encoding === "string" ? encoding as BufferEncoding : "utf8")
        : String(chunk ?? "");
    // Core has already emitted the corresponding canonical event. Preserve its
    // legacy cloud wire bytes without double-recording a generic stream event.
    if (channel === "stdout" && text.startsWith("0SEC_EVENT_")) return;

    const event = createPresentationEvent({
      source,
      sequence: ++sequence,
      at: now(),
      eventType: channel === "stdout" ? "output.stream.stdout" : "output.stream.stderr",
      payload: { channel, text },
    });
    presentationEventBus.emit(event);
    options.onEvent?.(event);
  };

  for (const [channel, stream] of [
    ["stdout", options.stdout ?? process.stdout],
    ["stderr", options.stderr ?? process.stderr],
  ] as const) {
    const original = stream.write as StreamWrite;
    const patched = ((chunk: unknown, encoding?: unknown, callback?: unknown): boolean => {
      const result = (original as unknown as (
        this: NodeJS.WriteStream,
        value: unknown,
        valueEncoding?: unknown,
        done?: unknown,
      ) => boolean).call(stream, chunk, encoding, callback);
      if (!suspended && streamBridgeSuppressionDepth === 0) emit(channel, chunk, encoding);
      return result;
    }) as StreamWrite;
    streams.push({ channel, stream, original, patched });
  }

  const bridge: ProcessPresentationStreamBridge = {
    suspend() {
      if (suspended) return;
      suspended = true;
      for (const item of streams) {
        if (item.stream.write === item.patched) item.stream.write = item.original;
      }
    },
    resume() {
      if (!suspended) return;
      suspended = false;
      for (const item of streams) {
        if (item.stream.write === item.original) item.stream.write = item.patched;
      }
    },
    restore() {
      for (const item of streams) {
        if (item.stream.write === item.patched) item.stream.write = item.original;
      }
      if (activeStreamBridge === bridge) activeStreamBridge = null;
    },
  };
  for (const item of streams) item.stream.write = item.patched;
  activeStreamBridge = bridge;
  return bridge;
}

export function suspendProcessPresentationStreamBridge(): void {
  activeStreamBridge?.suspend();
}

export function resumeProcessPresentationStreamBridge(): void {
  activeStreamBridge?.resume();
}
/** Default process writer shared by command adapters in this CLI process. */
export const processPresentationOutput = createProcessPresentationOutput({
  onEvent(event) {
    presentationEventBus.emit(event);
  },
});

/** Preserve console.log-style line output while emitting one semantic record. */
export function writePresentationLine(text: string, eventType = "output.stdout"): PresentationEvent {
  return processPresentationOutput.stdout(`${text}\n`, eventType);
}

/** Preserve console.error-style line output while emitting one semantic record. */
export function writePresentationErrorLine(text: string, eventType = "output.stderr"): PresentationEvent {
  return processPresentationOutput.stderr(`${text}\n`, eventType);
}
