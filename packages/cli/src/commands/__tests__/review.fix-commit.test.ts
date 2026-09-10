import { Command } from "commander";
import { tmpdir } from "node:os";
import { expect, it, vi } from "vitest";

const { runUnified } = vi.hoisted(() => ({ runUnified: vi.fn() }));
vi.mock("../run.js", () => ({ runUnified }));
import { registerReviewCommand } from "../review.js";

it("rejects variants-only without a fix before starting a model-backed review", async () => {
  const program = new Command();
  program.exitOverride();
  registerReviewCommand(program);
  await expect(program.parseAsync(["node", "0sec", "review", tmpdir(), "--variants-only"]))
    .rejects.toThrow(/--fix-commit/);
  expect(runUnified).not.toHaveBeenCalled();
});
