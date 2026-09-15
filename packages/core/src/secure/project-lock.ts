import { mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

/**
 * Exclusive file-system lock for secure project runs.
 *
 * Uses POSIX-atomic `mkdir` — an uncontested mkdir of a non-existent
 * directory succeeds atomically on all Unix filesystems.  A lock directory
 * living under `stateDir/.lock` means stale-lock cleanup is naturally scoped
 * to its state directory.
 *
 * Cleanup: caller MUST release.  A SIGINT/SIGTERM handler on the main
 * process will try to release known locks, but the lock is *not* crash-safe
 * (a `kill -9` leaves a stale directory).  The caller can clear it manually
 * via {@link clearStale} or after confirming the previous PID is dead.
 */
export class ProjectLock {
  private readonly lockDir: string;
  private readonly pid: number;
  private held = false;

  constructor(stateDir: string) {
    this.lockDir = join(stateDir, ".lock");
    this.pid = process.pid;
  }

  acquire(): void {
    if (this.held) return;
    try {
      // Single-argument mkdir: atomic create-or-EEXIST, no options object.
      mkdirSync(this.lockDir);
    } catch (err: unknown) {
      if (isEexists(err)) {
        const holder = this.readHolder();
        if (holder === this.pid) {
          this.held = true;
          return;
        }
        throw new LockHeldError(
          holder != null
            ? `Secure project run already in progress (pid ${holder}). Use resume or clear stale lock.`
            : "Secure project run already in progress (unknown pid). Clear stale lock to proceed.",
        );
      }
      throw err;
    }
    try {
      writeFileSync(join(this.lockDir, "pid"), String(this.pid), "utf-8");
    } catch {
      // Best-effort.
    }
    this.held = true;
  }

  release(): void {
    if (!this.held) return;
    this.held = false;
    try {
      rmSync(this.lockDir, { recursive: true, force: true });
    } catch {
      // Already removed or permission denied.
    }
  }

  isHeld(): boolean {
    if (!existsSync(this.lockDir)) return false;
    const holder = this.readHolder();
    if (holder == null) return true;
    if (holder === this.pid) return false;
    try {
      process.kill(holder, 0);
      return true;
    } catch {
      return false;
    }
  }

  clearStale(): void {
    try {
      rmSync(this.lockDir, { recursive: true, force: true });
    } catch {
      // Not present or permission denied.
    }
    this.held = false;
  }

  private readHolder(): number | null {
    try {
      const pidPath = join(this.lockDir, "pid");
      if (!existsSync(pidPath)) return null;
      return Number(readFileSync(pidPath, "utf-8").trim());
    } catch {
      return null;
    }
  }

  registerSignalHandlers(): () => void {
    const release = () => this.release();
    const signals = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"] as const;
    for (const sig of signals) {
      process.once(sig, release);
    }
    return () => {
      for (const sig of signals) {
        process.off(sig, release);
      }
    };
  }
}

export class LockHeldError extends Error {
  override readonly name = "LockHeldError";
}

function isEexists(err: unknown): err is NodeJS.ErrnoException {
  return (
    err != null &&
    typeof err === "object" &&
    "code" in err &&
    (err as NodeJS.ErrnoException).code === "EEXIST"
  );
}