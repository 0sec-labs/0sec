import { describe, expect, it } from "vitest";
import { extractEndpointsFromJs } from "./js-endpoints.js";

describe("extractEndpointsFromJs", () => {
  it("extracts API-shaped path literals", () => {
    const body = `const u = "/api/v2/users"; loadProfile("/account/profile");`;
    const { endpoints } = extractEndpointsFromJs(body);
    const paths = endpoints.map((e) => e.path);
    expect(paths).toContain("/api/v2/users");
    expect(paths).toContain("/account/profile");
  });

  it("associates HTTP methods from fetch/axios call sites", () => {
    const body = `
      axios.post("/api/login", creds);
      fetch("/api/v1/orders");
      axios.delete("/api/sessions/42");
    `;
    const { endpoints } = extractEndpointsFromJs(body);
    const byPath = new Map(endpoints.map((e) => [e.path, e.method]));
    expect(byPath.get("/api/login")).toBe("POST");
    expect(byPath.get("/api/v1/orders")).toBe("GET");
    expect(byPath.get("/api/sessions/42")).toBe("DELETE");
  });

  it("captures absolute API base URLs and their paths", () => {
    const body = `const API = "https://api.example.com/v1"; fetch("https://api.example.com/v1/health");`;
    const { apiBaseUrls, endpoints } = extractEndpointsFromJs(body);
    expect(apiBaseUrls).toContain("https://api.example.com");
    expect(endpoints.map((e) => e.path)).toContain("/v1/health");
  });

  it("drops static assets and the bare root", () => {
    const body = `"/assets/app.123.js"; "/styles/main.css"; "/"; "/logo.png";`;
    const { endpoints } = extractEndpointsFromJs(body);
    expect(endpoints).toHaveLength(0);
  });

  it("dedupes paths and normalizes query/hash + trailing slash", () => {
    const body = `"/api/users?id=1"; "/api/users#x"; "/api/users/";`;
    const { endpoints } = extractEndpointsFromJs(body);
    const userPaths = endpoints.filter((e) => e.path === "/api/users");
    expect(userPaths).toHaveLength(1);
  });

  it("is bounded — never explodes on a huge body", () => {
    const body = Array.from({ length: 5000 }, (_, i) => `"/api/r${i}"`).join(";");
    const { endpoints } = extractEndpointsFromJs(body);
    expect(endpoints.length).toBeLessThanOrEqual(500);
  });
});
