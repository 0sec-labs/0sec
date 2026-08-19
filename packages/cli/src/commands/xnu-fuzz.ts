/**
 * `0sec xnu-fuzz` — the IOKit user-client fuzzer mode (dynamic sibling to the
 * static `xnu-re` review profile). Design: docs/0sec-iokit-fuzzer.md.
 *
 * Subcommands (the buildable MVP loop — model + generate locally; the VM run
 * lane is built but must run on a beefier Apple-Silicon Mac, see harness):
 *
 *   enumerate  — §1: kext → target-model.json (dispatch-table → valid-input model)
 *   gen        — §2: target-model.json → gate-passing + structure-aware inputs
 *   harness-plan — §3: print what a single macOS-VM shard run needs to actually run
 *
 * This command is GLUE: all logic lives in `@0sec/core` `xnu-fuzz/`.
 */

import type { Command } from "commander";
import { readFileSync, writeFileSync } from "node:fs";
import {
  enumerateTargetModelFromKext,
  generateInputsForSelector,
  makeRng,
  selectorModelToLine,
  type TargetModel,
  type UserClientModel,
  planSingleShardRun,
} from "@0sec/core";

interface EnumerateOpts {
  kext: string;
  bundle?: string;
  out?: string;
  json?: boolean;
}

function enumerateAction(opts: EnumerateOpts): number {
  const bundle = opts.bundle ?? "com.apple.unknown";
  const model = enumerateTargetModelFromKext(opts.kext, { kext: bundle, source: opts.kext });
  if (opts.out) {
    writeFileSync(opts.out, JSON.stringify(model, null, 2) + "\n");
  }
  if (opts.json) {
    process.stdout.write(JSON.stringify(model, null, 2) + "\n");
    return model.userClients.length > 0 ? 0 : 1;
  }
  printModelSummary(model);
  return model.userClients.length > 0 ? 0 : 1;
}

function printModelSummary(model: TargetModel): void {
  process.stdout.write(`kext: ${model.kext}  (${model.abi})\n`);
  process.stdout.write(`source: ${model.source}\n`);
  if (model.userClients.length === 0) {
    process.stdout.write("no IOUserClient dispatch tables found (sMethods/sMethodDescs)\n");
    return;
  }
  for (const uc of model.userClients) {
    process.stdout.write(
      `\n${uc.class} :: ${uc.table} — ${uc.selectorCount} selectors, ` +
        `${uc.varSizeSelectorCount} variable-size (sentinel density)\n`,
    );
    for (const s of uc.selectors) process.stdout.write("  " + selectorModelToLine(s) + "\n");
  }
}

interface GenOpts {
  model: string;
  class?: string;
  selector?: string;
  seed?: string;
  json?: boolean;
}

function pickClient(model: TargetModel, name?: string): UserClientModel | undefined {
  if (name) return model.userClients.find((u) => u.class === name) ?? model.userClients[0];
  return model.userClients[0];
}

function genAction(opts: GenOpts): number {
  const model = JSON.parse(readFileSync(opts.model, "utf8")) as TargetModel;
  const uc = pickClient(model, opts.class);
  if (!uc) {
    process.stderr.write("no user client in model\n");
    return 3;
  }
  const seed = opts.seed ? parseInt(opts.seed, 10) : 1;
  const rng = makeRng(seed);
  const selFilter = opts.selector !== undefined ? parseInt(opts.selector, 10) : undefined;
  const targets = uc.selectors.filter((s) => selFilter === undefined || s.sel === selFilter);

  const summary = targets.map((s) => {
    const inputs = generateInputsForSelector(s, rng);
    return {
      sel: s.sel,
      inputs: inputs.length,
      sampleStructLens: inputs.slice(0, 8).map((i) => i.structureInput.byteLength),
      scalarInCnt: s.scalarInCnt,
      variable: s.structInSize === 0xffffffff || s.structOutSize === 0xffffffff,
    };
  });

  if (opts.json) {
    process.stdout.write(JSON.stringify({ class: uc.class, selectors: summary }, null, 2) + "\n");
    return 0;
  }
  process.stdout.write(`generation for ${uc.class} (seed ${seed})\n`);
  for (const s of summary) {
    process.stdout.write(
      `  sel ${String(s.sel).padStart(2)} — ${s.inputs} input(s)` +
        `${s.variable ? " [VAR sweep]" : ""}, struct lens [${s.sampleStructLens.join(", ")}]\n`,
    );
  }
  return 0;
}

interface HarnessPlanOpts {
  golden?: string;
  build?: string;
  shared?: string;
  oracle?: string;
}

function harnessPlanAction(opts: HarnessPlanOpts): number {
  const plan = planSingleShardRun({
    goldenImage: opts.golden ?? "<golden-macos-vm>",
    guestBuild: opts.build ?? "<macos-build-matching-kernelcache>",
    sharedDir: opts.shared ?? "/tmp/xnu-fuzz-shared",
    oracle: (opts.oracle as "release" | "kasan" | "kfence" | undefined) ?? "release",
  });
  process.stdout.write("xnu-fuzz §3 macOS-VM single-shard run plan\n\n");
  process.stdout.write("PREREQUISITES:\n");
  for (const p of plan.prerequisites) process.stdout.write("  - " + p + "\n");
  process.stdout.write("\nSTEPS:\n");
  for (const s of plan.steps) process.stdout.write("  " + s + "\n");
  process.stdout.write(`\nCHANNELS:\n  program: ${plan.artifacts.programChannel}\n`);
  process.stdout.write(`  result:  ${plan.artifacts.resultChannel}\n  panic:   ${plan.artifacts.panicLogs}\n`);
  process.stdout.write(`\n⚠ ${plan.warning}\n`);
  return 0;
}

export function registerXnuFuzzCommand(program: Command): void {
  const cmd = program
    .command("xnu-fuzz")
    .description(
      "IOKit user-client fuzzer (dynamic sibling to the xnu-re review profile). " +
        "Models the IOExternalMethodDispatch2022 gate per user client, generates " +
        "gate-passing + structure-aware inputs, and plans the disposable macOS-VM run lane.",
    );

  cmd
    .command("enumerate")
    .description("§1: kext → target-model.json (dispatch-table → valid-input model)")
    .requiredOption("--kext <path>", "Path to the extracted kext Mach-O (from xnu-re-extract.sh).")
    .option("--bundle <id>", "Kext bundle id recorded in the model (e.g. com.apple.iokit.IOSurface).")
    .option("--out <file>", "Write the full target-model.json to this path.")
    .option("--json", "Emit the model as JSON on stdout instead of a summary.")
    .action((opts: EnumerateOpts) => {
      try {
        process.exitCode = enumerateAction(opts);
      } catch (err) {
        process.stderr.write(`xnu-fuzz enumerate error: ${err instanceof Error ? err.message : String(err)}\n`);
        process.exitCode = 3;
      }
    });

  cmd
    .command("gen")
    .description("§2: target-model.json → gate-passing + structure-aware inputs")
    .requiredOption("--model <file>", "Path to a target-model.json from `enumerate`.")
    .option("--class <name>", "User-client class to generate for (default: largest).")
    .option("--selector <N>", "Only generate for this selector index.")
    .option("--seed <N>", "PRNG seed for reproducible generation (default 1).")
    .option("--json", "Emit the generation summary as JSON.")
    .action((opts: GenOpts) => {
      try {
        process.exitCode = genAction(opts);
      } catch (err) {
        process.stderr.write(`xnu-fuzz gen error: ${err instanceof Error ? err.message : String(err)}\n`);
        process.exitCode = 3;
      }
    });

  cmd
    .command("harness-plan")
    .description("§3: print what a single macOS-VM shard run needs to actually run")
    .option("--golden <image>", "Golden tart VM image name.")
    .option("--build <build>", "macOS build the golden image + kernelcache match.")
    .option("--shared <dir>", "Host-shared folder for the program/result/panic channel.")
    .option("--oracle <kind>", "Crash oracle: release | kasan | kfence (default release).")
    .action((opts: HarnessPlanOpts) => {
      process.exitCode = harnessPlanAction(opts);
    });
}
