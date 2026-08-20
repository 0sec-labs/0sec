import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Per-user engine state directory (`~/.0sec`): scan DB, journals, kernel and
 * intel caches, cloud credentials.
 */
export function homeStateDir(home: string = homedir()): string {
  return join(home, ".0sec");
}

/**
 * Private mutable state for one engine execution. Every fresh run owns this
 * directory; only an explicit resume may reuse it.
 */
export function runStateDir(runId: string, home?: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(runId)) {
    throw new Error(`Invalid 0sec run id ${JSON.stringify(runId)}.`);
  }
  return join(homeStateDir(home), "runs", runId);
}
