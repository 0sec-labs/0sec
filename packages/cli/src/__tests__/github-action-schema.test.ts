/**
 * Schema test for .github/actions/0sec-scan/action.yml.
 *
 * This guards against accidental yaml syntax breakage or a drift between the
 * documented input/output names and the action contract. Pure parse + shape
 * assertions — no runtime invocation.
 *
 * Companion smoke test:
 *   .github/actions/0sec-scan/__tests__/smoke.test.sh
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parse as parseYaml } from "yaml";

const HERE = fileURLToPath(new URL(".", import.meta.url));
const ACTION_YML = resolve(HERE, "../../../../.github/actions/0sec-scan/action.yml");

interface ActionYml {
  name?: string;
  description?: string;
  author?: string;
  branding?: { icon?: string; color?: string };
  inputs?: Record<string, { description?: string; required?: boolean; default?: string }>;
  outputs?: Record<string, { description?: string; value?: string }>;
  runs?: { using?: string; steps?: unknown[] };
}

function loadAction(): ActionYml {
  const raw = readFileSync(ACTION_YML, "utf8");
  return parseYaml(raw) as ActionYml;
}

describe("github action: .github/actions/0sec-scan/action.yml", () => {
  it("parses as valid YAML", () => {
    expect(() => loadAction()).not.toThrow();
  });

  it("declares marketplace metadata (name, description, author, branding)", () => {
    const doc = loadAction();
    expect(doc.name).toBeTruthy();
    expect(doc.description).toBeTruthy();
    expect(doc.author).toBeTruthy();
    expect(doc.branding?.icon).toBe("shield");
    expect(doc.branding?.color).toBe("red");
  });

  it("is a composite action", () => {
    const doc = loadAction();
    expect(doc.runs?.using).toBe("composite");
  });

  it("declares the documented inputs with descriptions and defaults", () => {
    const doc = loadAction();
    const inputs = doc.inputs ?? {};
    const expected: Record<string, string> = {
      mode: "pr",
      profile: "web",
      "comment-on-pr": "true",
      "fail-on-confirmed": "true",
      "0sec-version": "latest",
    };
    for (const [name, defaultValue] of Object.entries(expected)) {
      expect(inputs[name], `missing input '${name}'`).toBeDefined();
      expect(inputs[name]?.description, `input '${name}' missing description`).toBeTruthy();
      expect(inputs[name]?.default, `input '${name}' wrong default`).toBe(defaultValue);
    }
  });

  it("declares the findings-confirmed and findings-hypothesis outputs", () => {
    const doc = loadAction();
    const outputs = doc.outputs ?? {};
    for (const name of ["findings-confirmed", "findings-hypothesis"]) {
      expect(outputs[name], `missing output '${name}'`).toBeDefined();
      expect(outputs[name]?.description, `output '${name}' missing description`).toBeTruthy();
      // The output value wires up to a step output via ${{ steps.<id>.outputs.<name> }}
      expect(outputs[name]?.value, `output '${name}' missing value expression`).toMatch(/^\$\{\{\s*steps\./);
    }
  });

  it("has a non-empty step list", () => {
    const doc = loadAction();
    expect(Array.isArray(doc.runs?.steps)).toBe(true);
    expect((doc.runs?.steps ?? []).length).toBeGreaterThan(0);
  });

  it("only allows documented values for the 'mode' and 'profile' inputs (defaults match the README)", () => {
    // The validation lives inside the first composite step (a bash case
    // statement). We assert the documented defaults here so that a contract
    // change forces a docs update.
    const doc = loadAction();
    expect(doc.inputs?.mode?.default).toBe("pr");
    expect(doc.inputs?.profile?.default).toBe("web");
  });
});
