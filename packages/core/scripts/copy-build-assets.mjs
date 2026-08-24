// Copy non-TS runtime assets into dist/ after `tsc`. Replaces a chain of Unix
// `cp -R` / `mkdir -p` / glob commands that failed on Windows (cmd/PowerShell
// have no `cp -R`, `mkdir -p`, or `*.json` glob), so core could never build
// there. Pure Node fs — works on every platform.
import { cpSync, mkdirSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const root = new URL("..", import.meta.url).pathname;
const abs = (p) => join(root, p);

// Recursive directory copy: src/triage/kernel-vm -> dist/triage/kernel-vm
const copyDir = (from, to) => {
  if (!existsSync(abs(from))) return;
  mkdirSync(abs(to), { recursive: true });
  cpSync(abs(from), abs(to), { recursive: true });
};

// Copy every file with `ext` from a dir into a dest dir (mkdir -p + glob cp).
const copyByExt = (fromDir, ext, toDir) => {
  if (!existsSync(abs(fromDir))) return;
  mkdirSync(abs(toDir), { recursive: true });
  for (const name of readdirSync(abs(fromDir))) {
    if (name.endsWith(ext)) cpSync(abs(join(fromDir, name)), abs(join(toDir, name)));
  }
};

copyDir("src/triage/kernel-vm", "dist/triage/kernel-vm");
copyByExt("src/bench", ".json", "dist/bench");
copyByExt("src/xnu-fuzz/opener", ".c", "dist/xnu-fuzz/opener");
copyByExt("src/stages/data", ".json", "dist/stages/data");
copyByExt("src/review/data", ".json", "dist/review/data");
