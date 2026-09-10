import { closeSync, constants, fstatSync, fsyncSync, lstatSync, openSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { ensureEvolutionDirectory, readEvolutionArtifact } from "./artifacts.js";

export class EvolutionControllerBusyError extends Error {}

/** Serialize entire evolution passes, not just individual registry transitions. */
export function acquireEvolutionController(storePath: string): () => void {
  ensureEvolutionDirectory(storePath);
  const path = join(storePath, "controller.lock");
  for (let attempt = 0; attempt < 2; attempt++) {
    let fd: number;
    try {
      fd = openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      let stat;
      try {
        stat = lstatSync(path);
      } catch (statError) {
        if ((statError as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw statError;
      }
      // A creator may still be writing its owner record.
      if (Date.now() - stat.mtimeMs < 1000) throw new EvolutionControllerBusyError("an evolution controller lease is being acquired");
      const owner = readEvolutionArtifact(path) as { pid?: unknown };
      if (!Number.isInteger(owner.pid) || Number(owner.pid) <= 0) throw new Error("invalid evolution controller lease; inspect controller.lock before recovery");
      try {
        process.kill(Number(owner.pid), 0);
        throw new EvolutionControllerBusyError(`an evolution controller is already running (pid ${owner.pid})`);
      } catch (probeError) {
        if ((probeError as NodeJS.ErrnoException).code !== "ESRCH") throw probeError;
      }
      const recoveryPath = `${path}.recovery`;
      let recoveryFd: number;
      try {
        recoveryFd = openSync(recoveryPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
      } catch (recoveryError) {
        if ((recoveryError as NodeJS.ErrnoException).code === "EEXIST") throw new EvolutionControllerBusyError("controller recovery is locked; inspect controller.lock.recovery if its owner stopped");
        throw recoveryError;
      }
      try {
        const current = lstatSync(path);
        if (current.ino === stat.ino && current.dev === stat.dev) unlinkSync(path);
      } catch (recoveryError) {
        if ((recoveryError as NodeJS.ErrnoException).code !== "ENOENT") throw recoveryError;
      } finally {
        closeSync(recoveryFd);
        unlinkSync(recoveryPath);
      }
      continue;
    }
    writeFileSync(fd, JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }));
    fsyncSync(fd);
    const identity = fstatSync(fd);
    closeSync(fd);
    return () => {
      const current = lstatSync(path);
      if (current.ino !== identity.ino || current.dev !== identity.dev) throw new Error("evolution controller lease ownership changed");
      unlinkSync(path);
    };
  }
  throw new Error("cannot acquire evolution controller lease");
}
