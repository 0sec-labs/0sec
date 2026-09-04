import { describe, expect, it } from "vitest";
import { hasSameOrigin, isExternalHttpsUrl } from "./security.js";

describe("desktop URL policy", () => {
  it("keeps renderer navigation on the dashboard origin", () => {
    const dashboard = "http://127.0.0.1:48123";

    expect(hasSameOrigin(dashboard, "http://127.0.0.1:48123/findings")).toBe(true);
    expect(hasSameOrigin(dashboard, "http://127.0.0.1:48124/findings")).toBe(false);
    expect(hasSameOrigin(dashboard, "https://127.0.0.1:48123/findings")).toBe(false);
    expect(hasSameOrigin(dashboard, "http://127.0.0.1:48123.evil.example/findings")).toBe(false);
    expect(hasSameOrigin(dashboard, "not a URL")).toBe(false);
  });

  it("allows only credential-free HTTPS links outside the shell", () => {
    expect(isExternalHttpsUrl("https://platform.openai.com/docs")).toBe(true);
    expect(isExternalHttpsUrl("http://127.0.0.1:48123")).toBe(false);
    expect(isExternalHttpsUrl("https://user:password@example.com")).toBe(false);
    expect(isExternalHttpsUrl("file:///etc/passwd")).toBe(false);
    expect(isExternalHttpsUrl("javascript:alert(1)")).toBe(false);
  });
});
