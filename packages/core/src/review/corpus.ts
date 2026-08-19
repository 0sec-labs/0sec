/**
 * Corpus extraction for Tier-2 C/C++ harnesses.
 *
 * Tier-2 wants real-world seeds, not synthesized ones. This module
 * looks under the source tree for files in well-known seed locations
 * and copies them into a working corpus directory.
 *
 * Deliberately conservative: we do NOT generate, mutate, or synthesise
 * seeds. If a project has no fixtures, this returns an empty array and
 * the harness will run with libFuzzer's default empty corpus.
 */

import { copyFile, mkdir, readdir, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { basename, extname, join, resolve } from "node:path";

export interface ExtractCorpusOptions {
  /** Directory to copy collected seeds into. Created if missing. */
  outputDir: string;
  /**
   * Override the default seed directory list. Paths are resolved
   * against `sourceRoot`. Defaults to a tested set of conventional
   * locations (see `DEFAULT_SEED_DIRS`).
   */
  seedDirs?: string[];
  /**
   * Skip files whose size exceeds this (bytes). Defaults to 1 MiB —
   * libFuzzer truncates large seeds anyway, and the inflation is not
   * worth the extra IO. Set to `Infinity` to disable.
   */
  maxFileBytes?: number;
  /**
   * Extensions to include. Defaults to a broad allowlist of binary +
   * text test inputs. Match is case-insensitive.
   */
  allowedExtensions?: string[];
}

/**
 * Conventional seed directories — ordered by how strong a signal each
 * one is that the contents are libFuzzer-ready inputs.
 */
export const DEFAULT_SEED_DIRS = [
  "oss-fuzz/corpus",
  "oss-fuzz/seeds",
  "fuzz/corpus",
  "fuzz/seeds",
  "corpus",
  "seeds",
  "tests/corpus",
  "tests/seeds",
  "tests/fuzz",
  "tests/fuzzdata",
  "tests/inputs",
  "tests/regressions",
  "test/corpus",
  "test/seeds",
  "test/inputs",
];

const DEFAULT_ALLOWED_EXTENSIONS = new Set([
  // No extension is the libFuzzer default — many projects store
  // anonymous binary seeds.
  "",
  ".bin",
  ".dat",
  ".raw",
  ".pkt",
  ".pcap",
  ".pcapng",
  ".asn1",
  ".der",
  ".pem",
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".bmp",
  ".tiff",
  ".tif",
  ".ico",
  ".wav",
  ".mp3",
  ".ogg",
  ".flac",
  ".mp4",
  ".mkv",
  ".webm",
  ".pdf",
  ".zip",
  ".gz",
  ".tar",
  ".xml",
  ".json",
  ".html",
  ".txt",
  ".csv",
  ".tsv",
  ".yaml",
  ".yml",
]);

const DEFAULT_MAX_BYTES = 1024 * 1024;

/**
 * Collect existing corpus files into `outputDir`.
 *
 * Returns the absolute paths of the copied files. Returns an empty
 * array when nothing matches; this is not an error — many libraries
 * genuinely have no upstream corpus.
 */
export async function extractCorpus(
  sourceRoot: string,
  opts: ExtractCorpusOptions,
): Promise<string[]> {
  const root = resolve(sourceRoot);
  if (!existsSync(root)) {
    throw new Error(`extractCorpus: source root '${root}' does not exist`);
  }
  const outputDir = resolve(opts.outputDir);
  await mkdir(outputDir, { recursive: true });

  const seedDirs = opts.seedDirs ?? DEFAULT_SEED_DIRS;
  const maxBytes = opts.maxFileBytes ?? DEFAULT_MAX_BYTES;
  const allowed = opts.allowedExtensions
    ? new Set(opts.allowedExtensions.map((e) => e.toLowerCase()))
    : DEFAULT_ALLOWED_EXTENSIONS;

  const collected: string[] = [];
  const seenBasenames = new Set<string>();

  for (const rel of seedDirs) {
    const dir = resolve(root, rel);
    if (!existsSync(dir)) continue;
    const candidates = await listFiles(dir, maxBytes, allowed);
    for (const src of candidates) {
      // Disambiguate identical basenames coming from different
      // seed directories.
      const base = basename(src);
      let name = base;
      let n = 1;
      while (seenBasenames.has(name)) {
        name = `${n}-${base}`;
        n += 1;
      }
      seenBasenames.add(name);
      const dest = join(outputDir, name);
      await copyFile(src, dest);
      collected.push(dest);
    }
  }

  return collected.sort();
}

async function listFiles(
  dir: string,
  maxBytes: number,
  allowedExtensions: Set<string>,
): Promise<string[]> {
  const out: string[] = [];
  const queue: string[] = [dir];
  while (queue.length > 0) {
    const current = queue.shift()!;
    let entries: import("node:fs").Dirent[];
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (entry.name.startsWith(".")) continue; // skip dotfiles
      const full = join(current, entry.name);
      if (entry.isDirectory()) {
        queue.push(full);
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if (!allowedExtensions.has(ext)) continue;
        try {
          const st = await stat(full);
          if (st.size > maxBytes) continue;
          if (st.size === 0) continue; // libFuzzer rejects empty seeds
        } catch {
          continue;
        }
        out.push(full);
      }
    }
  }
  return out;
}
