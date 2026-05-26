import { describe, it, expect } from "vitest";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { extractCorpus, DEFAULT_SEED_DIRS } from "./corpus.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "__fixtures__");

describe("extractCorpus", () => {
  it("collects seeds from every conventional fixture location", async () => {
    const root = join(FIXTURES, "cpp-tier2-corpus");
    const outDir = await mkdtemp(join(tmpdir(), "pwnkit-corpus-"));
    try {
      const seeds = await extractCorpus(root, { outputDir: outDir });
      const names = seeds.map((p) => basename(p)).sort();
      expect(names).toContain("seed.bin");
      expect(names).toContain("sample.bin");
      expect(names).toContain("fuzz-input.bin");
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("returns an empty array gracefully when no conventional dirs exist", async () => {
    const root = await mkdtemp(join(tmpdir(), "pwnkit-corpus-empty-"));
    const outDir = await mkdtemp(join(tmpdir(), "pwnkit-corpus-out-"));
    try {
      const seeds = await extractCorpus(root, { outputDir: outDir });
      expect(seeds).toEqual([]);
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("skips empty files (libFuzzer rejects them)", async () => {
    const root = await mkdtemp(join(tmpdir(), "pwnkit-corpus-empty-files-"));
    const outDir = await mkdtemp(join(tmpdir(), "pwnkit-corpus-out-"));
    try {
      await mkdir(join(root, "corpus"), { recursive: true });
      await writeFile(join(root, "corpus", "empty.bin"), "");
      await writeFile(join(root, "corpus", "ok.bin"), "AAAA");
      const seeds = await extractCorpus(root, { outputDir: outDir });
      expect(seeds.map((p) => basename(p))).toEqual(["ok.bin"]);
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("honours a custom maxFileBytes ceiling", async () => {
    const root = await mkdtemp(join(tmpdir(), "pwnkit-corpus-big-"));
    const outDir = await mkdtemp(join(tmpdir(), "pwnkit-corpus-out-"));
    try {
      await mkdir(join(root, "corpus"), { recursive: true });
      await writeFile(join(root, "corpus", "small.bin"), Buffer.alloc(4, 1));
      await writeFile(join(root, "corpus", "big.bin"), Buffer.alloc(2048, 1));
      const seeds = await extractCorpus(root, {
        outputDir: outDir,
        maxFileBytes: 1024,
      });
      expect(seeds.map((p) => basename(p))).toEqual(["small.bin"]);
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("disambiguates identical basenames across multiple seed dirs", async () => {
    const root = await mkdtemp(join(tmpdir(), "pwnkit-corpus-dup-"));
    const outDir = await mkdtemp(join(tmpdir(), "pwnkit-corpus-out-"));
    try {
      await mkdir(join(root, "corpus"), { recursive: true });
      await mkdir(join(root, "seeds"), { recursive: true });
      await writeFile(join(root, "corpus", "input.bin"), "AAAA");
      await writeFile(join(root, "seeds", "input.bin"), "BBBB");
      const seeds = await extractCorpus(root, { outputDir: outDir });
      const names = seeds.map((p) => basename(p));
      expect(names.length).toBe(2);
      expect(new Set(names).size).toBe(2);
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("honours a custom seedDirs override", async () => {
    const root = await mkdtemp(join(tmpdir(), "pwnkit-corpus-custom-"));
    const outDir = await mkdtemp(join(tmpdir(), "pwnkit-corpus-out-"));
    try {
      await mkdir(join(root, "weird"), { recursive: true });
      await writeFile(join(root, "weird", "x.bin"), "AAAA");
      // Default dirs would miss this; custom override picks it up.
      expect(
        (await extractCorpus(root, { outputDir: outDir })).length,
      ).toBe(0);
      const seeds = await extractCorpus(root, {
        outputDir: outDir,
        seedDirs: ["weird"],
      });
      expect(seeds.map((p) => basename(p))).toEqual(["x.bin"]);
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("exposes a sensible default seed directory list", () => {
    expect(DEFAULT_SEED_DIRS).toContain("corpus");
    expect(DEFAULT_SEED_DIRS).toContain("tests/corpus");
    expect(DEFAULT_SEED_DIRS).toContain("oss-fuzz/corpus");
  });
});
