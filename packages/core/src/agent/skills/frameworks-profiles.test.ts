import { describe, expect, it, beforeEach } from "vitest";
import { fileURLToPath } from "node:url";
import {
  clearSkillRegistry,
  loadSkillRegistry,
  getSkillById,
  matchTriggers,
} from "./index.js";

const __dirname = fileURLToPath(new URL(".", import.meta.url));

/**
 * Framework-specific methodology packs (nextjs / supabase / python-web).
 * These plug into the existing JIT skill loader by living under
 * skills/frameworks/, so the loader auto-discovers them. This test pins the
 * contract: they validate, they're uniquely IDed, and their triggers fire on
 * realistic framework signatures so a source review actually pulls them in.
 *
 * Note: matchTriggers requires >=2 distinct trigger hits to fire (the same
 * anti-noise threshold the playbook detector uses), so each snippet below is
 * written to contain at least two independent framework signatures.
 */
describe("framework methodology packs", () => {
  beforeEach(() => {
    clearSkillRegistry();
    loadSkillRegistry(__dirname);
  });

  const PACKS = ["nextjs-appsec", "supabase-appsec", "python-web-appsec"];

  it("all three packs load and validate", () => {
    for (const id of PACKS) {
      const skill = getSkillById(id);
      expect(skill, `skill ${id} should be registered`).toBeDefined();
      expect(skill!.content.length).toBeGreaterThan(400);
      expect(skill!.applicable_roles).toContain("review");
      expect(skill!.estimated_tokens).toBeGreaterThan(0);
    }
  });

  it.each([
    [
      "nextjs-appsec",
      'import { NextRequest, NextResponse } from "next/server"\nexport function GET(req: NextRequest) {}',
    ],
    [
      "nextjs-appsec",
      'async function save(formData: FormData) {\n  "use server"\n  return NextResponse.json({})\n}',
    ],
    [
      "supabase-appsec",
      'import { createClient } from "@supabase/supabase-js"\nconst supabase = createClient(url, key)\nawait supabase.from("orders").select("*")',
    ],
    [
      "supabase-appsec",
      "CREATE POLICY p ON orders FOR SELECT USING (auth.uid() = user_id);",
    ],
    [
      "python-web-appsec",
      "from django.db import models\nUser.objects.raw(request.GET['q'])",
    ],
    [
      "python-web-appsec",
      "from flask import Flask, request\n@app.route('/x')\ndef x():\n    return render_template(t)",
    ],
  ])("%s triggers on realistic framework code", (id, snippet) => {
    const registry = loadSkillRegistry(__dirname);
    const matched = matchTriggers([snippet], [...registry.values()]);
    expect(
      matched.has(id),
      `expected ${id} to match snippet:\n${snippet}\n(got: ${[...matched].join(", ")})`,
    ).toBe(true);
  });

  it("packs do not collide with an existing skill id", () => {
    // loadSkillRegistry throws on duplicate ids; reaching here means the
    // frameworks/ additions are uniquely named across the whole tree.
    const registry = loadSkillRegistry(__dirname);
    for (const id of PACKS) expect(registry.has(id)).toBe(true);
  });
});
