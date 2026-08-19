import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

/**
 * Per-user engine state directory (`~/.0sec`): scan DB, journals, kernel and
 * intel caches, cloud credentials.
 *
 * Renamed from `~/.pwnkit` in the 0sec rename (2026-08-19). If the legacy
 * directory exists and the new one does not, the legacy directory is used so
 * existing installs keep their scan history and credentials. Once both exist,
 * the new directory wins; no automatic migration is attempted.
 */
export function homeStateDir(home: string = homedir()): string {
  const current = join(home, ".0sec");
  const legacy = join(home, ".pwnkit");
  if (existsSync(current) || !existsSync(legacy)) return current;
  return legacy;
}
