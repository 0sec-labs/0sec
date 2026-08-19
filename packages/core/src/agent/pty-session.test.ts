import { afterEach, describe, expect, it } from "vitest";
import { PtySessionManager } from "./pty-session.js";

const managers: PtySessionManager[] = [];

afterEach(() => {
  for (const manager of managers.splice(0)) manager.cleanup();
});

describe("PtySessionManager credential isolation", () => {
  it("does not inherit process credentials into an interactive shell", async () => {
    const envName = "Z_AI_API_KEY";
    const previous = process.env[envName];
    const canary = "canary-zai-pty-must-not-leak";
    process.env[envName] = canary;

    try {
      const manager = new PtySessionManager();
      managers.push(manager);
      const session = manager.createSession("credential-isolation", {
        env: { SAFE_SESSION_VALUE: "present" },
      });
      manager.send(
        session.id,
        `printf 'credential=[%s] safe=[%s]\\n' "$${envName}" "$SAFE_SESSION_VALUE"; exit`,
      );

      let output = "";
      for (let attempt = 0; attempt < 20 && !output.includes("safe=[present]"); attempt++) {
        output += await manager.read(session.id, 100);
      }

      expect(output).toContain("credential=[]");
      expect(output).not.toContain(canary);
      expect(output).toContain("safe=[present]");
    } finally {
      if (previous === undefined) delete process.env[envName];
      else process.env[envName] = previous;
    }
  });
});
