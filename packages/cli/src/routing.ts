import { resolveEngagement } from "./engagement-plan.js";

export function detectAndRoute(target: string): string[] | null {
  const resolution = resolveEngagement(target);
  if (!resolution.ok) return null;
  const { plan } = resolution;

  if (plan.kind === "web") {
    return ["scan", "--target", plan.target];
  }
  if (plan.kind === "source") {
    return ["review", plan.target, "--depth", "deep"];
  }
  return ["audit", plan.target, "--ecosystem", plan.ecosystem ?? "npm"];
}
