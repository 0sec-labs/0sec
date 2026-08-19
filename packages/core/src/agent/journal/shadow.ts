/**
 * Shadow-mode execution journal (#494, first additive slice).
 *
 * A crash-safe wrapper the live agent loop uses to ALSO record its steps to an
 * append-only journal while continuing to drive off its own in-memory
 * conversation window. Two hard guarantees make this safe to wire into the live
 * loop:
 *
 *   1. **Flag-gated, default OFF.** `createShadowJournal` returns a no-op when
 *      `features.executionJournal` is false, so a normal scan is byte-for-byte
 *      unchanged — no journal directory is even created.
 *   2. **Never throws.** Every method swallows its own errors (a full disk, a
 *      permissions problem, a serialization edge case must never abort a scan).
 *      The journal is a side-channel; the loop is the source of truth in this
 *      slice.
 *
 * Routing the loop OFF the journal (rehydrating fresh contexts via
 * `rehydrateContext`) is the next slice; see
 * `docs/research/agent-execution-journal-design.md`.
 */

import { features } from "../features.js";
import { createJournalWriter, type JournalWriter } from "./writer.js";
import type { JournalEntryInput } from "./types.js";

export interface ShadowJournalOptions {
  /** Run id; the agentic-scanner uses the scanId as the run id (run dir = `~/.0sec/runs/<scanId>`). */
  runId: string;
  /** Override the runs root (tests point this at a tmp dir). */
  rootDir?: string;
  /** Force-enable regardless of the feature flag (tests). */
  enabled?: boolean;
  /** Inject a writer factory (tests / alternate sinks). */
  writerFactory?: (runId: string, rootDir?: string) => JournalWriter;
}

export interface ShadowJournal {
  readonly enabled: boolean;
  append(entry: JournalEntryInput): void;
}

const NOOP: ShadowJournal = {
  enabled: false,
  append() {
    /* disabled: no-op */
  },
};

/**
 * Build a shadow journal for a run. Returns a no-op (no I/O, no directory
 * creation) unless the execution-journal feature is on or `enabled` is forced.
 */
export function createShadowJournal(options: ShadowJournalOptions): ShadowJournal {
  const on = options.enabled ?? features.executionJournal;
  if (!on) return NOOP;

  let writer: JournalWriter | null = null;
  try {
    const factory =
      options.writerFactory ??
      ((runId, rootDir) => createJournalWriter({ runId, rootDir }));
    writer = factory(options.runId, options.rootDir);
  } catch {
    // If we can't even open the journal, degrade to a no-op rather than risk
    // the loop. Shadow mode is best-effort by construction.
    return NOOP;
  }

  return {
    enabled: true,
    append(entry: JournalEntryInput): void {
      if (!writer) return;
      try {
        writer.append(entry);
      } catch {
        // Swallow: a failed shadow write must never abort a scan.
      }
    },
  };
}
