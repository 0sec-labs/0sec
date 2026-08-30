import { join } from "node:path";

import { homeStateDir } from "@0sec/shared";

import { watchLensSynthCommand } from "../commands/lens-synth.js";
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

/**
 * Start the TUI-owned self-evolution worker. It is deliberately controlled by
 * two persisted Security settings: one permits autonomous model evaluation;
 * the other separately permits durable promotion. The watcher reads only the
 * curated inbox, and an active deep review still captures its own immutable
 * finder snapshot before target preparation.
 */
export function createTuiLensEvolutionController(
  deps: TuiLensEvolutionDeps = {},
): TuiLensEvolutionController {
  const settings = deps.settings ?? getSettings;
  const subscribeSettingsFn = deps.subscribeSettings ?? subscribeSettings;
  const env = deps.env ?? process.env;
  const watch = deps.watch ?? watchLensSynthCommand;
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

    void watch(
      { missInput: inputPath, promote, pollIntervalMs },
      {
        signal: controller.signal,
        log: () => {},
        onResult: (result) => {
          if (stopped || generation !== ownGeneration) return;
          if (result.registered.length > 0) {
            publish({
              phase: "promoted",
              inputPath,
              promote,
              message: `promoted ${result.registered.length} validated finder lens(es)`,
            });
            return;
          }
          const championCount = result.validations.filter((validation) => validation.passed).length;
          publish({
            phase: championCount > 0 ? "champion" : "watching",
            inputPath,
            promote,
            message: championCount > 0
              ? promote
                ? "validated champion already present; no registry change"
                : `${championCount} validated champion(s) awaiting promotion`
              : "latest curated revision produced no promotable lens",
          });
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
    ).catch((error: unknown) => {
      if (stopped || generation !== ownGeneration) return;
      publish({
        phase: "error",
        inputPath,
        promote,
        message: `lens evolution worker stopped: ${error instanceof Error ? error.message : String(error)}`,
      });
    });
  };

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
