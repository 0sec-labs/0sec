/**
 * `PackageProbe` implementations — the execution-isolation seam.
 *
 * `inProcessProbe` loads modules with `require` from a base dir: the single-host
 * analog of the prototype's `worker.js` (one dedicated Node process per package,
 * so a detector that mutates a live prototype cannot corrupt siblings). It is
 * what runs under the CLI on a trusted host and what the hermetic tests use via
 * `staticProbe`.
 *
 * PRODUCTION isolation is a sandbox-backed probe: the stage supplies a probe
 * whose `load` runs the harness INSIDE an e2b exec (`npm install
 * --ignore-scripts` in a throwaway dir, run the detector core, return structured
 * JSON). That probe is the integration seam wired at the cloud/worker layer via
 * the existing e2b template — it is intentionally NOT implemented here so this
 * module stays free of the sandbox transport. Any object satisfying
 * {@link PackageProbe} plugs in.
 */

import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import type { PackageProbe, PackageRef } from "./types.js";

/**
 * A probe that `require`s modules from `baseDir`. Untrusted-code caveat: only
 * use on a trusted host or inside an already-isolated sandbox exec — this does
 * NOT itself sandbox the loaded code.
 */
export function inProcessProbe(pkg: PackageRef, baseDir: string, note?: (msg: string) => void): PackageProbe {
  const req = createRequire(pathToFileURL(baseDir.endsWith("/") ? baseDir : `${baseDir}/`).href);
  return {
    pkg,
    baseDir,
    load(moduleId: string): unknown | undefined {
      try {
        return req(moduleId);
      } catch {
        return undefined;
      }
    },
    note,
  };
}

/**
 * A probe backed by a fixed module map — for hermetic tests and for callers
 * that already hold the loaded surface (no filesystem/require). `modules` maps a
 * module id (e.g. `es-toolkit`, `es-toolkit/compat`) to its loaded value.
 */
export function staticProbe(
  pkg: PackageRef,
  modules: Record<string, unknown>,
  note?: (msg: string) => void,
): PackageProbe {
  return {
    pkg,
    baseDir: "/dev/null",
    load(moduleId: string): unknown | undefined {
      return Object.prototype.hasOwnProperty.call(modules, moduleId) ? modules[moduleId] : undefined;
    },
    note,
  };
}
