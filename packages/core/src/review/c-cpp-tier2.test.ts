import { describe, it, expect } from "vitest";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  buildTier2Harness,
  detectBuildSystem,
  discoverObjectSubset,
} from "./c-cpp-tier2.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "__fixtures__");

describe("detectBuildSystem", () => {
  it("returns the requested system when not 'auto'", async () => {
    expect(await detectBuildSystem(FIXTURES, "cmake")).toBe("cmake");
  });

  it("detects autotools from configure.ac / Makefile.am", async () => {
    expect(
      await detectBuildSystem(join(FIXTURES, "cpp-tier2-autotools"), "auto"),
    ).toBe("autotools");
  });

  it("detects cmake from CMakeLists.txt", async () => {
    expect(
      await detectBuildSystem(join(FIXTURES, "cpp-tier2-cmake"), "auto"),
    ).toBe("cmake");
  });

  it("detects meson from meson.build", async () => {
    expect(
      await detectBuildSystem(join(FIXTURES, "cpp-tier2-meson"), "auto"),
    ).toBe("meson");
  });

  it("falls back to autotools for unknown trees", async () => {
    const outDir = await mkdtemp(join(tmpdir(), "0sec-tier2-unknown-"));
    try {
      expect(await detectBuildSystem(outDir, "auto")).toBe("autotools");
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });
});

describe("discoverObjectSubset", () => {
  it("collects same-directory siblings for an autotools project", async () => {
    const root = join(FIXTURES, "cpp-tier2-autotools");
    const suspect = join(root, "src", "widget.c");
    const subset = await discoverObjectSubset({
      sourceRoot: root,
      suspectSourceFile: suspect,
      buildSystem: "autotools",
    });
    expect(subset).toContain(suspect);
    expect(subset).toContain(join(root, "src", "helper.c"));
  });

  it("collects siblings for a cmake project via grep-parse of CMakeLists.txt", async () => {
    const root = join(FIXTURES, "cpp-tier2-cmake");
    const suspect = join(root, "src", "gadget.c");
    const subset = await discoverObjectSubset({
      sourceRoot: root,
      suspectSourceFile: suspect,
      buildSystem: "cmake",
    });
    expect(subset).toContain(suspect);
    expect(subset).toContain(join(root, "src", "util.c"));
  });

  it("collects siblings for a meson project via grep-parse of meson.build", async () => {
    const root = join(FIXTURES, "cpp-tier2-meson");
    const suspect = join(root, "src", "sprocket.c");
    const subset = await discoverObjectSubset({
      sourceRoot: root,
      suspectSourceFile: suspect,
      buildSystem: "meson",
    });
    expect(subset).toContain(suspect);
    expect(subset).toContain(join(root, "src", "auxlib.c"));
  });
});

describe("buildTier2Harness", () => {
  it("emits harness.c, linker script, and Makefile fragment for an autotools tree", async () => {
    const root = join(FIXTURES, "cpp-tier2-autotools");
    const outDir = await mkdtemp(join(tmpdir(), "0sec-tier2-emit-"));
    try {
      const artifact = await buildTier2Harness({
        suspectFunction: {
          header: "widget.h",
          functionName: "widget_decode",
          declaration:
            "int widget_decode(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size);",
          inputShape: "bytesAndLenOut",
        },
        sourceRoot: root,
        buildSystem: "autotools",
        sanitizers: ["asan", "ubsan"],
        outputDir: outDir,
      });

      expect(artifact.harness_path).toBe(join(outDir, "harness.c"));
      expect(existsSync(artifact.harness_path)).toBe(true);
      expect(existsSync(artifact.linker_script_path)).toBe(true);
      expect(existsSync(artifact.makefile_fragment_path)).toBe(true);

      const harness = await readFile(artifact.harness_path, "utf8");
      // Round-trip: the function name has to appear in the harness body.
      expect(harness).toMatch(/widget_decode\(data, size, &out, &out_size\)/);
      expect(harness).toContain("LLVMFuzzerTestOneInput");
      expect(harness).toContain("// 0sec Tier-2");

      // Compile command should reference the discovered sibling and
      // enable both sanitizers + libFuzzer.
      expect(artifact.compile_command).toMatch(
        /-fsanitize=address,undefined,fuzzer/,
      );
      expect(artifact.compile_command).toContain(join(root, "src", "widget.c"));
      expect(artifact.compile_command).toContain(join(root, "src", "helper.c"));

      // Linker shell script should be runnable (mode 0o755) and
      // contain the compile command verbatim.
      const script = await readFile(artifact.linker_script_path, "utf8");
      expect(script).toContain("#!/usr/bin/env bash");
      expect(script).toContain(artifact.compile_command);

      // Makefile fragment should be non-empty and call out the sanitizers.
      const mk = await readFile(artifact.makefile_fragment_path, "utf8");
      expect(mk).toMatch(/0SEC_TIER2_HARNESS/);
      expect(mk).toContain(artifact.compile_command);
      expect(mk).toMatch(/Sanitizers: asan, ubsan/);

      expect(artifact.detected_build_system).toBe("autotools");
      expect(artifact.sanitizers_enabled).toEqual(["asan", "ubsan"]);
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("auto-detects the build system when 'auto' is passed", async () => {
    const root = join(FIXTURES, "cpp-tier2-cmake");
    const outDir = await mkdtemp(join(tmpdir(), "0sec-tier2-auto-"));
    try {
      const artifact = await buildTier2Harness({
        suspectFunction: {
          header: "gadget.h",
          functionName: "gadget_decode",
          declaration: "int gadget_decode(const uint8_t *data, size_t size);",
          inputShape: "bytesAndLen",
        },
        sourceRoot: root,
        buildSystem: "auto",
        outputDir: outDir,
      });
      expect(artifact.detected_build_system).toBe("cmake");
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("locates the suspect source file automatically when not provided", async () => {
    const root = join(FIXTURES, "cpp-tier2-meson");
    const outDir = await mkdtemp(join(tmpdir(), "0sec-tier2-locate-"));
    try {
      const artifact = await buildTier2Harness({
        suspectFunction: {
          header: "sprocket.h",
          functionName: "sprocket_decode",
          declaration: "int sprocket_decode(const uint8_t *data, size_t size);",
          inputShape: "bytesAndLen",
        },
        sourceRoot: root,
        buildSystem: "meson",
        outputDir: outDir,
      });
      expect(artifact.linked_objects).toContain(
        join(root, "src", "sprocket.c"),
      );
      expect(artifact.linked_objects).toContain(join(root, "src", "auxlib.c"));
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("includes corpus seed arguments in the run command when provided", async () => {
    const root = join(FIXTURES, "cpp-tier2-autotools");
    const outDir = await mkdtemp(join(tmpdir(), "0sec-tier2-corpus-"));
    try {
      const artifact = await buildTier2Harness({
        suspectFunction: {
          header: "widget.h",
          functionName: "widget_decode",
          declaration: "int widget_decode(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size);",
          inputShape: "bytesAndLenOut",
        },
        sourceRoot: root,
        buildSystem: "autotools",
        corpusSeeds: ["/tmp/seed-1.bin", "/tmp/seed-2.bin"],
        outputDir: outDir,
      });
      expect(artifact.run_command).toContain("/tmp/seed-1.bin");
      expect(artifact.run_command).toContain("/tmp/seed-2.bin");
      expect(artifact.run_command).toMatch(/-max_total_time=300/);
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("respects msan when explicitly requested", async () => {
    const root = join(FIXTURES, "cpp-tier2-autotools");
    const outDir = await mkdtemp(join(tmpdir(), "0sec-tier2-msan-"));
    try {
      const artifact = await buildTier2Harness({
        suspectFunction: {
          header: "widget.h",
          functionName: "widget_decode",
          declaration: "int widget_decode(const uint8_t *data, size_t size, uint8_t **out, size_t *out_size);",
          inputShape: "bytesAndLenOut",
        },
        sourceRoot: root,
        buildSystem: "autotools",
        sanitizers: ["msan"],
        outputDir: outDir,
      });
      expect(artifact.compile_command).toContain("memory");
      expect(artifact.compile_command).not.toMatch(
        /-fsanitize=[^"' ]*address/,
      );
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it("throws when sourceRoot does not exist", async () => {
    await expect(
      buildTier2Harness({
        suspectFunction: {
          header: "x.h",
          functionName: "f",
          declaration: "void f(const uint8_t *, size_t);",
        },
        sourceRoot: "/definitely/missing/tree",
        buildSystem: "auto",
        outputDir: "/tmp/whatever",
      }),
    ).rejects.toThrow(/does not exist/);
  });
});
