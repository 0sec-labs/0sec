import { describe, expect, it, vi } from "vitest";
import { DesktopCodexAuthController } from "./codex-auth-controller.js";

describe("DesktopCodexAuthController", () => {
  it("keeps OAuth tokens daemon-side while publishing lifecycle status", () => {
    let onUpdate: ((update: { phase: "running" | "connected" | "cancelled" | "failed"; message: string; lines: readonly string[] }) => void) | undefined;
    const cancel = vi.fn();
    const controller = new DesktopCodexAuthController({
      start: (options) => {
        onUpdate = options.onUpdate;
        return { cancel };
      },
    });

    expect(controller.status()).toMatchObject({ phase: "idle" });
    controller.start();
    onUpdate?.({ phase: "running", message: "Open your browser.", lines: ["https://auth.example.test"] });
    expect(controller.status()).toEqual({
      phase: "running",
      message: "Open your browser.",
      lines: ["https://auth.example.test"],
    });

    controller.cancel();
    expect(cancel).toHaveBeenCalledOnce();
    onUpdate?.({ phase: "connected", message: "Connected.", lines: [] });
    expect(controller.status()).toMatchObject({ phase: "connected", message: "Connected." });
  });
});
