// Atomic file writes for the file-review store (deepsec atomic-file.ts
// pattern): temp file in the destination directory + rename, so a crash
// leaves either the old complete state or the new one — never a torn write.
// The temp name carries pid + random suffix so concurrent writers on the
// same host never collide.

import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

function temporaryPath(file: string): string {
  return `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString("hex")}`;
}

/** Write `contents` to `file` atomically (sync). Creates parent dirs. */
export function atomicWriteFileSync(file: string, contents: string): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temp = temporaryPath(file);
  try {
    fs.writeFileSync(temp, contents, { encoding: "utf8" });
    fs.renameSync(temp, file);
  } finally {
    if (fs.existsSync(temp)) {
      try {
        fs.unlinkSync(temp);
      } catch {
        // best-effort cleanup; the rename already won or the write failed
      }
    }
  }
}

/** Write `contents` to `file` atomically (async). Creates parent dirs. */
export async function atomicWriteFile(file: string, contents: string): Promise<void> {
  await fs.promises.mkdir(path.dirname(file), { recursive: true });
  const temp = temporaryPath(file);
  try {
    await fs.promises.writeFile(temp, contents, { encoding: "utf8" });
    await fs.promises.rename(temp, file);
  } finally {
    await fs.promises.unlink(temp).catch(() => undefined);
  }
}
