import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Per-user engine state directory (`~/.0sec`): scan DB, journals, kernel and
 * intel caches, cloud credentials.
 */
export function homeStateDir(home: string = homedir()): string {
  return join(home, ".0sec");
}
