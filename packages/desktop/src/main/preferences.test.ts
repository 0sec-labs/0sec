import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { DesktopPreferences } from "./preferences.js";

it("flushes the latest draft and preferences before reopening on a new sidecar origin", async () => {
  const directory = mkdtempSync(join(tmpdir(), "0sec-workspace-"));
  try {
    const path = join(directory, "workspace.json");
    const preferences = new DesktopPreferences(path);
    const writes = [
      preferences.set("0sec:drafts", { session: "unfinished" }),
      preferences.set("0sec:theme", "light"),
      preferences.set("0sec:drafts", { session: "final draft" }),
    ];
    await preferences.flush();
    await Promise.all(writes);
    const reopened = new DesktopPreferences(path).snapshot();
    expect(reopened["0sec:drafts"]).toEqual({ session: "final draft" });
    expect(reopened["0sec:theme"]).toBe("light");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
