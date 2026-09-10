import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { claimForProcessing, markProcessed, releaseClaim, type LensSynthesisResult } from "@0sec/core";
import { homeStateDir } from "@0sec/shared";

import { runLensSynthesisInput, watchLensSynthCommand } from "../commands/lens-synth.js";
import type {
  LensSynthWatchDeps,
  LensSynthWatchOptions,
} from "../commands/lens-synth.js";
import {
  getSettings,
  subscribeSettings,
} from "./settings-store.js";
import type { TuiSettings } from "./settings.js";

/** Shell-friendly override for the curated lens-synthesis input file. */
export const TUI_LENS_SYNTH_INPUT_ENV = "OSEC_TUI_LENS_SYNTH_INPUT";
/** Shell-friendly override for the watcher polling interval. */
export const TUI_LENS_SYNTH_POLL_INTERVAL_ENV = "OSEC_TUI_LENS_SYNTH_POLL_INTERVAL_MS";

export type TuiLensEvolutionPhase =
  | "disabled"
  | "watching"
  | "waiting_input"
  | "promoted"
  | "champion"
  | "error";

export interface TuiLensEvolutionStatus {
  phase: TuiLensEvolutionPhase;
  inputPath?: string;
  promote: boolean;
  message: string;
}

export interface TuiLensEvolutionController {
  getStatus(): TuiLensEvolutionStatus;
  subscribe(listener: (status: TuiLensEvolutionStatus) => void): () => void;
  stop(): void;
}

export interface TuiLensEvolutionDeps {
  settings?: () => TuiSettings;
  subscribeSettings?: (listener: (settings: TuiSettings) => void) => () => void;
  env?: NodeJS.ProcessEnv;
  watch?: (
    options: LensSynthWatchOptions,
    deps: LensSynthWatchDeps,
  ) => Promise<void>;
  /** Injected feedback-queue consumer for approved observations. Defaults to real impl. */
  consumeApprovedObservations?: (
    opts: { promote: boolean; pollIntervalMs: number },
    deps: {
      signal: AbortSignal;
      log: (msg: string) => void;
      onResult: (result: LensSynthesisResult) => void;
      onError: (error: Error) => void;
    },
  ) => Promise<void>;
}

/** The stable inbox a configured TUI watches when no explicit override exists. */
export function tuiLensSynthesisInputPath(homeDir?: string): string {
  return join(homeStateDir(homeDir), "lens-synthesis", "miss-input.json");
}

/** Compact, honest status-bar text. Disabled automation stays invisible. */
export function tuiLensEvolutionStatusLabel(status: TuiLensEvolutionStatus): string | undefined {
  switch (status.phase) {
    case "disabled":
      return undefined;
    case "watching":
      return status.promote ? "evolve:auto" : "evolve:dry-run";
    case "waiting_input":
      return "evolve:waiting input";
    case "promoted":
      return "evolve:promoted";
    case "champion":
      return status.promote ? "evolve:unchanged" : "evolve:champion";
    case "error":
      return "evolve:error";
  }
}

// Approved observations retain separate development and held-out corpora.
// Each is evaluated once; completed rejections and dry runs are retained too,
// rather than spending model budget on the same unchanged input every poll.
// Interrupted claims are released; process-crash claims require explicit recovery.
export async function consumeApprovedObservations(
  opts: { promote: boolean; pollIntervalMs: number },
  deps: {
    signal: AbortSignal;
    log: (msg: string) => void;
    onResult: (result: LensSynthesisResult) => void;
    onError: (error: Error) => void;
  },
): Promise<void> {
  const pollIntervalMs = Number.isFinite(opts.pollIntervalMs) ? Math.max(100, opts.pollIntervalMs) : 1000;
  const sleep = () => new Promise<void>((done) => {
    const finish = () => {
      clearTimeout(timer);
      deps.signal.removeEventListener("abort", finish);
      done();
    };
    const timer = setTimeout(finish, pollIntervalMs);
    deps.signal.addEventListener("abort", finish, { once: true });
    if (deps.signal.aborted) finish();
  });
  while (!deps.signal.aborted) {
    try {
      const claimed = claimForProcessing();
      const processedIds = new Set<string>();
      try {
        for (const observation of claimed) {
          if (deps.signal.aborted) break;
          try {
            if (!observation.consent) throw new Error("approved observation lacks source-access consent");
            const result = await runLensSynthesisInput({
              misses: { curatedCandidates: [{
                classHint: observation.classHint,
                sinkPattern: observation.sinkPattern,
                exampleFileLine: observation.exampleFileLine,
                whyMissed: observation.whyMissed,
                source: observation.source,
              }] },
              corpus: observation.approvedShape,
            }, { promote: opts.promote, signal: deps.signal });
            deps.signal.throwIfAborted();
            if (!markProcessed(observation.id, {
              registeredLensIds: result.registered.map((lens) => lens.id),
              registeredLenses: result.registered,
              validatedAt: new Date().toISOString(),
              validationReports: result.validations,
              warnings: result.warnings.length ? result.warnings : undefined,
              rejected: result.rejected.length ? result.rejected : undefined,
            }, observation.claimToken)) throw new Error("feedback processing claim was lost");
            processedIds.add(observation.id);
            deps.onResult(result);
          } catch (error) {
            deps.onError(error instanceof Error ? error : new Error(String(error)));
          }
        }
      } finally {
        for (const observation of claimed) {
          if (processedIds.has(observation.id)) continue;
          try { releaseClaim(observation.id, observation.claimToken); }
          catch (error) { deps.onError(error instanceof Error ? error : new Error(String(error))); }
        }
      }
    } catch (error) {
      deps.onError(error instanceof Error ? error : new Error(String(error)));
    }
    if (!deps.signal.aborted) await sleep();
  }
}

/**
 * Start the TUI-owned self-evolution worker. It is deliberately controlled by
 * two persisted Security settings: one permits autonomous model evaluation;
 * the other separately permits durable promotion. The watcher reads both the
 * curated inbox file AND the durable feedback queue's approved observations.
 *
 * The feedback queue provides consistent, retry-safe processing: approved
 * observations are claimed atomically, processed through the lens loop, and
 * marked processed on success. Crashes mid-processing leave entries recoverable.
 */
export function createTuiLensEvolutionController(
  deps: TuiLensEvolutionDeps = {},
): TuiLensEvolutionController {
  const settings = deps.settings ?? getSettings;
  const subscribeSettingsFn = deps.subscribeSettings ?? subscribeSettings;
  const env = deps.env ?? process.env;
  const watch = deps.watch ?? defaultWatch;
  const consumeApproved = deps.consumeApprovedObservations ?? consumeApprovedObservations;
  const listeners = new Set<(status: TuiLensEvolutionStatus) => void>();
  let current: TuiLensEvolutionStatus = {
    phase: "disabled",
    promote: false,
    message: "finder-lens evolution is disabled",
  };
  let abortController: AbortController | undefined;
  let activeKey: string | undefined;
  let stopped = false;
  let generation = 0;

  const publish = (next: TuiLensEvolutionStatus): void => {
    current = next;
    for (const listener of [...listeners]) {
      try {
        listener(current);
      } catch {
        // A status observer must never stop the improvement worker.
      }
    }
  };

  const reconcile = (nextSettings: TuiSettings): void => {
    if (stopped) return;
    const inputPath = env[TUI_LENS_SYNTH_INPUT_ENV]?.trim() || tuiLensSynthesisInputPath();
    const promote = nextSettings.autoPromoteFinderLenses;
    if (!nextSettings.autoEvolveFinderLenses) {
      generation += 1;
      abortController?.abort();
      abortController = undefined;
      activeKey = undefined;
      publish({
        phase: "disabled",
        promote: false,
        message: "finder-lens evolution is disabled",
      });
      return;
    }

    const rawPollInterval = Number.parseInt(env[TUI_LENS_SYNTH_POLL_INTERVAL_ENV] ?? "2000", 10);
    const pollIntervalMs = Number.isInteger(rawPollInterval) && rawPollInterval >= 100
      ? rawPollInterval
      : 2_000;
    const key = `${inputPath}\u0000${promote}\u0000${pollIntervalMs}`;
    if (activeKey === key && abortController) return;

    generation += 1;
    const ownGeneration = generation;
    abortController?.abort();
    const controller = new AbortController();
    abortController = controller;
    activeKey = key;
    publish({
      phase: "watching",
      inputPath,
      promote,
      message: promote
        ? "watching curated lens inbox and promoting validated champions"
        : "watching curated lens inbox in validation-only mode",
    });

    // Run both the file-based watcher and the approved-queue consumer in
    // parallel. The queue consumer provides retry-safe durable processing;
    // the file watcher provides backward compatibility with manual inbox imports.
    void Promise.all([
      watch(
        { missInput: inputPath, promote, pollIntervalMs },
        {
          signal: controller.signal,
          log: () => {},
          onResult: (result) => {
            if (stopped || generation !== ownGeneration) return;
            handleResult(result, controller.signal.aborted);
          },
          onError: (error) => {
            if (stopped || generation !== ownGeneration) return;
            const code = (error as NodeJS.ErrnoException).code;
            publish({
              phase: code === "ENOENT" ? "waiting_input" : "error",
              inputPath,
              promote,
              message: code === "ENOENT"
                ? "waiting for the curated lens inbox"
                : `lens evolution rejected the latest inbox revision: ${error.message}`,
            });
          },
        },
      ),
      consumeApproved(
        { promote, pollIntervalMs },
        {
          signal: controller.signal,
          log: () => {},
          onResult: (result) => {
            if (stopped || generation !== ownGeneration) return;
            handleResult(result, controller.signal.aborted);
          },
          onError: (error) => {
            if (stopped || generation !== ownGeneration) return;
            publish({
              phase: "error",
              inputPath,
              promote,
              message: `approved queue: ${error.message}`,
            });
          },
        },
      ),
    ]).catch((error: unknown) => {
      if (stopped || generation !== ownGeneration) return;
      publish({
        phase: "error",
        inputPath,
        promote,
        message: `lens evolution worker stopped: ${error instanceof Error ? error.message : String(error)}`,
      });
    });
  };

  // Shared handler for both the file watcher and queue consumer.
  function handleResult(result: LensSynthesisResult, aborted: boolean): void {
    if (stopped || aborted) return;
    if (result.registered.length > 0) {
      publish({
        phase: "promoted",
        inputPath: current.inputPath,
        promote: current.promote,
        message: `promoted ${result.registered.length} validated finder lens(es)`,
      });
      return;
    }
    const championCount = result.validations.filter((validation) => validation.passed).length;
    publish({
      phase: championCount > 0 ? "champion" : "watching",
      inputPath: current.inputPath,
      promote: current.promote,
      message: championCount > 0
        ? current.promote
          ? "validated champion already present; no registry change"
          : `${championCount} validated champion(s) awaiting promotion`
        : "latest curated revision produced no promotable lens",
    });
  }

  const unsubscribeSettings = subscribeSettingsFn(reconcile);
  reconcile(settings());

  return {
    getStatus: () => current,
    subscribe: (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    stop: () => {
      if (stopped) return;
      stopped = true;
      generation += 1;
      unsubscribeSettings();
      abortController?.abort();
      abortController = undefined;
      activeKey = undefined;
      listeners.clear();
    },
  };
}

// Default watcher — delegates to the lens-synth command's file watcher.
const defaultWatch = watchLensSynthCommand;