import { describe, it, expect } from "vitest";
import { createScanContext, normalizeTargetUrl } from "./context.js";

// ── normalizeTargetUrl ─────────────────────────────────────────────
//
// Bare hostnames as targets (`doruk.ch`, `nikin.ch`, ...) blow up
// every URL-using tool because `new URL(input, base)` requires the
// base to be absolute. Pin that the normalizer auto-prefixes
// `https://` for bare hostnames + leaves already-absolute URLs alone.

describe("normalizeTargetUrl", () => {
  it("prefixes https:// for a bare hostname", () => {
    expect(normalizeTargetUrl("doruk.ch")).toBe("https://doruk.ch");
  });

  it("prefixes https:// for a host:port", () => {
    expect(normalizeTargetUrl("doruk.ch:8443")).toBe("https://doruk.ch:8443");
  });

  it("prefixes https:// for a host/path", () => {
    expect(normalizeTargetUrl("doruk.ch/admin")).toBe("https://doruk.ch/admin");
  });

  it("leaves https:// URLs unchanged", () => {
    expect(normalizeTargetUrl("https://doruk.ch/")).toBe("https://doruk.ch/");
  });

  it("leaves http:// URLs unchanged", () => {
    expect(normalizeTargetUrl("http://localhost:3000")).toBe(
      "http://localhost:3000",
    );
  });

  it("returns empty / non-string input as-is so package targets keep flowing", () => {
    expect(normalizeTargetUrl("")).toBe("");
    // @ts-expect-error — runtime should be defensive even on wrong types
    expect(normalizeTargetUrl(undefined)).toBeUndefined();
  });

  it("trims whitespace before prefixing", () => {
    expect(normalizeTargetUrl("  doruk.ch  ")).toBe("https://doruk.ch");
  });
});

describe("createScanContext", () => {
  it("normalizes the bare-hostname target onto the URL field", () => {
    const ctx = createScanContext({
      target: "doruk.ch",
      depth: "default",
      runtime: "auto",
      format: "json",
    } as any);
    expect(ctx.target.url).toBe("https://doruk.ch");
    expect(ctx.target.type).toBe("unknown");
  });
});
