// Copy non-TS runtime assets into dist/ after `tsc`. Replaces a chain of Unix
// `cp -R` / `mkdir -p` / glob commands that failed on Windows (cmd/PowerShell
// have no `cp -R`, `mkdir -p`, or `*.json` glob), so core could never build
// there. Pure Node fs — works on every platform.
import { cpSync, mkdirSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
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
copyByExt("src/stages", ".cjs", "dist/stages");

// JIT methodology skills: the loader (src/agent/skills/index.ts) walks its own
// module directory for *.yaml and validates each as a skill. Mirror the yaml
// tree into dist/agent/skills so a consumer importing the built @0sec/core (not
// the CLI bundle, which copies these separately in scripts/bundle-cli.mjs) also
// resolves every pack. Copy ONLY *.yaml — a stray non-skill yaml would fail
// validation. Recurses through frameworks/, techniques/, vulnerabilities/.
const copyYamlTree = (fromRel, toRel) => {
  if (!existsSync(abs(fromRel))) return;
  for (const entry of readdirSync(abs(fromRel), { withFileTypes: true })) {
    const from = join(fromRel, entry.name);
    const to = join(toRel, entry.name);
    if (entry.isDirectory()) {
      copyYamlTree(from, to);
    } else if (entry.name.endsWith(".yaml") || entry.name.endsWith(".yml")) {
      mkdirSync(abs(toRel), { recursive: true });
      cpSync(abs(from), abs(to));
    }
  }
};
copyYamlTree("src/agent/skills", "dist/agent/skills");
