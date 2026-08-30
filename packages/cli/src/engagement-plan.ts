import {
  expandHomePath,
  isExistingLocalTargetPath,
  isExplicitLocalTargetPath,
} from "@0sec/core";

export type EngagementKind = "web" | "source" | "package";
export type PackageEcosystem = "npm" | "pypi" | "cargo" | "oci";

export interface EngagementPlan {
  kind: EngagementKind;
  target: string;
  label: string;
  /** The unified runner's target type, kept out of the TUI presentation layer. */
  targetType: "url" | "source-code" | "npm-package" | "pypi-package" | "cargo-package" | "oci-image";
  /** Source engagements use validated finder lenses as a review strategy. */
  reviewStrategy?: "lenses";
  ecosystem?: PackageEcosystem;
}

export type EngagementResolution =
  | { ok: true; plan: EngagementPlan }
  | { ok: false; message: string };

const PACKAGE_PREFIXES: Readonly<Record<string, { ecosystem: PackageEcosystem; targetType: EngagementPlan["targetType"] }>> = {
  "npm:": { ecosystem: "npm", targetType: "npm-package" },
  "pypi:": { ecosystem: "pypi", targetType: "pypi-package" },
  "cargo:": { ecosystem: "cargo", targetType: "cargo-package" },
  "oci:": { ecosystem: "oci", targetType: "oci-image" },
};

/**
 * Produce one explicit engagement plan for the primary control plane. Bare
 * package names are intentionally rejected: a security harness must not turn
 * an ambiguous string into a networked or expensive operation invisibly.
 */
export function resolveEngagement(rawTarget: string): EngagementResolution {
  const raw = rawTarget.trim();
  if (raw.length === 0) return { ok: false, message: "Enter a URL, source path, git URL, or ecosystem-prefixed package." };

  for (const [prefix, packagePlan] of Object.entries(PACKAGE_PREFIXES)) {
    if (!raw.startsWith(prefix)) continue;
    const target = raw.slice(prefix.length).trim();
    if (target.length === 0) return { ok: false, message: `${prefix} requires a package name.` };
    return {
      ok: true,
      plan: {
        kind: "package",
        target,
        targetType: packagePlan.targetType,
        ecosystem: packagePlan.ecosystem,
        label: `${packagePlan.ecosystem} package ${target}`,
      },
    };
  }

  if (raw.startsWith("source:")) {
    const target = raw.slice("source:".length).trim();
    if (target.length === 0) return { ok: false, message: "source: requires a local path or git URL." };
    return {
      ok: true,
      plan: {
        kind: "source",
        target: expandHomePath(target),
        targetType: "source-code",
        reviewStrategy: "lenses",
        label: `source review ${target}`,
      },
    };
  }

  // Keep repository URLs ahead of generic HTTP routing. The core resolver
  // treats these as source scopes; sending them to `scan` would launch a web
  // engagement against GitHub instead of reviewing the repository.
  if (
    raw.startsWith("git@") ||
    raw.startsWith("git://") ||
    raw.endsWith(".git") ||
    raw.startsWith("https://github.com/")
  ) {
    return {
      ok: true,
      plan: {
        kind: "source",
        target: raw,
        targetType: "source-code",
        reviewStrategy: "lenses",
        label: `source review ${raw}`,
      },
    };
  }

  if (raw.startsWith("mcp://") || raw.startsWith("http://") || raw.startsWith("https://")) {
    return {
      ok: true,
      plan: {
        kind: "web",
        target: raw,
        targetType: "url",
        label: `web target ${raw}`,
      },
    };
  }

  if (isExplicitLocalTargetPath(raw) || isExistingLocalTargetPath(raw)) {
    const target = expandHomePath(raw);
    return {
      ok: true,
      plan: {
        kind: "source",
        target,
        targetType: "source-code",
        reviewStrategy: "lenses",
        label: `source review ${target}`,
      },
    };
  }

  return {
    ok: false,
    message: "Ambiguous target. Use https://…, ./path, source:…, npm:…, pypi:…, cargo:…, or oci:….",
  };
}
