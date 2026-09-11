import { randomUUID } from "node:crypto";
import { closeSync, fsyncSync, openSync, realpathSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homeStateDir } from "@0sec/shared";
import { z } from "zod";
import { ensureEvolutionDirectory, readEvolutionArtifact } from "../improvement/artifacts.js";
import { acquireEvolutionController } from "../improvement/controller-lock.js";

const grantsSchema = z.object({ schema: z.literal(1), workspaces: z.record(z.boolean()) }).strict();
const storage = () => join(homeStateDir(), "harness-trust");

/** Operator-owned grant, never inferred from workspace contents or model permissions. */
export function getWorkspaceHarnessTrust(workspaceRoot: string): boolean {
  try {
    const root = realpathSync(workspaceRoot);
    const grants = grantsSchema.parse(readEvolutionArtifact(join(storage(), "grants.json")));
    return grants.workspaces[root] === true;
  } catch { return false; }
}

/** Host/UI only. Granting this permission allows arbitrary code with host privileges. */
export function setWorkspaceHarnessTrust(workspaceRoot: string, trusted: boolean): void {
  if (typeof trusted !== "boolean") throw new Error("Workspace trust must be boolean");
  const root = realpathSync(workspaceRoot);
  const directory = ensureEvolutionDirectory(storage());
  const release = acquireEvolutionController(directory);
  const temporary = join(directory, `.grants-${randomUUID()}.tmp`);
  try {
    let grants: z.infer<typeof grantsSchema> = { schema: 1, workspaces: {} };
    try { grants = grantsSchema.parse(readEvolutionArtifact(join(directory, "grants.json"))); }
    catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    if (trusted) grants.workspaces[root] = true;
    else delete grants.workspaces[root];
    const fd = openSync(temporary, "wx", 0o600);
    try { writeFileSync(fd, JSON.stringify(grants)); fsyncSync(fd); } finally { closeSync(fd); }
    renameSync(temporary, join(directory, "grants.json"));
    const directoryFd = openSync(directory, "r");
    try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
  } finally {
    try { unlinkSync(temporary); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    finally { release(); }
  }
}
