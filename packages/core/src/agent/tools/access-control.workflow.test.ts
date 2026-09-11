import { afterEach, describe, expect, it, vi } from "vitest";
import { ToolExecutor } from "../tools.js";
import { SessionEngine } from "../session.js";
import type { ToolContext } from "../types.js";
import { fetchScoped } from "../../http.js";

vi.mock("../../http.js", async (importOriginal) => ({
  ...(await importOriginal<object>()),
  fetchScoped: vi.fn(),
}));

const target = "https://target.test";
const request = {
  allow_mutation: true, owner_identity: "owner", actor_identity: "actor",
  observation_url: `${target}/resource`, observation_json_pointer: "/marker", expected_state: "unique-marker",
  steps: [{ method: "POST", url: `${target}/resource`, body: '{"marker":"unique-marker"}' }],
};
function executor() {
  const session = new SessionEngine([
    { label: "owner", role: "admin", auth: { type: "bearer", token: "owner-secret" } },
    { label: "actor", role: "user", auth: { type: "bearer", token: "actor-secret" } },
  ]);
  const context: ToolContext = { target, scanId: "workflow", findings: [], attackResults: [], targetInfo: {}, session };
  return new ToolExecutor(context, null);
}
const response = (marker: unknown, status = 200) => new Response(JSON.stringify({ marker }), { status });
afterEach(() => vi.mocked(fetchScoped).mockReset());

describe("access_control_workflow", () => {
  it("confirms a real state transition with isolated owner and actor credentials", async () => {
    let marker = "before";
    const identities: string[] = [];
    vi.mocked(fetchScoped).mockImplementation(async (_url: unknown, init: RequestInit) => {
      identities.push(new Headers(init.headers).get("authorization") ?? "");
      if (init.method === "POST") marker = "unique-marker";
      return response(marker);
    });
    const result = await executor().execute({ name: "access_control_workflow", arguments: request });
    expect(result.output).toMatchObject({ verdict: "confirmed" });
    expect(identities).toEqual(["Bearer owner-secret", "Bearer actor-secret", "Bearer owner-secret"]);
    expect(JSON.stringify(result)).not.toContain("owner-secret");
    expect(JSON.stringify(result)).not.toContain("actor-secret");
  });

  it("does not treat successful HTTP status alone as an authorization break", async () => {
    vi.mocked(fetchScoped).mockImplementation(async () => response("before"));
    const result = await executor().execute({ name: "access_control_workflow", arguments: request });
    expect(result.output).toMatchObject({ verdict: "no_change" });
  });

  it("requires successful owner observations, even when an error body contains the marker", async () => {
    vi.mocked(fetchScoped)
      .mockResolvedValueOnce(response("before"))
      .mockResolvedValueOnce(response("ok"))
      .mockResolvedValueOnce(response("unique-marker", 403));
    const result = await executor().execute({ name: "access_control_workflow", arguments: request });
    expect(result.output).toMatchObject({ verdict: "inconclusive" });
  });

  it("rejects an invalid later step before sending an earlier mutating request", async () => {
    const result = await executor().execute({ name: "access_control_workflow", arguments: {
      ...request, steps: [...request.steps, { method: "POST", url: `${target}/resource`, headers: { Authorization: "Bearer owner-secret" } }],
    } });
    expect(result.success).toBe(false);
    expect(fetchScoped).not.toHaveBeenCalled();
  });

  it("requires mutation consent before making any request", async () => {
    const result = await executor().execute({ name: "access_control_workflow", arguments: { ...request, allow_mutation: false } });
    expect(result.success).toBe(false);
    expect(fetchScoped).not.toHaveBeenCalled();
  });

  it("stops a workflow after a transport failure and refuses to attribute a concurrent change", async () => {
    vi.mocked(fetchScoped)
      .mockResolvedValueOnce(response("before"))
      .mockRejectedValueOnce(new Error("connection reset"))
      .mockResolvedValueOnce(response("unique-marker"));
    const result = await executor().execute({ name: "access_control_workflow", arguments: {
      ...request, steps: [...request.steps, { method: "DELETE", url: `${target}/resource` }],
    } });
    expect(result.output).toMatchObject({ verdict: "inconclusive", steps: [{ error: "connection reset" }] });
    expect(fetchScoped).toHaveBeenCalledTimes(3);
  });

  it("does not coerce a number into the declared string marker", async () => {
    vi.mocked(fetchScoped)
      .mockResolvedValueOnce(response("before")).mockResolvedValueOnce(response("ok"))
      .mockResolvedValueOnce(response(42));
    const result = await executor().execute({ name: "access_control_workflow", arguments: { ...request, expected_state: "42" } });
    expect(result.output).toMatchObject({ verdict: "inconclusive" });
  });

  it("accepts null as a present baseline value, not a missing pointer", async () => {
    vi.mocked(fetchScoped)
      .mockResolvedValueOnce(response(null)).mockResolvedValueOnce(response("ok"))
      .mockResolvedValueOnce(response("unique-marker"));
    const result = await executor().execute({ name: "access_control_workflow", arguments: request });
    expect(result.output).toMatchObject({ verdict: "confirmed" });
  });

  it("does not mutate when the expected marker already exists", async () => {
    vi.mocked(fetchScoped).mockImplementation(async () => response("unique-marker"));
    const result = await executor().execute({ name: "access_control_workflow", arguments: request });
    expect(result.output).toMatchObject({ verdict: "no_change" });
    expect(fetchScoped).toHaveBeenCalledTimes(1);
  });
});
