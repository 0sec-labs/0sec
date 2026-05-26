import {
  expandHomePath,
  isExistingLocalTargetPath,
  isExplicitLocalTargetPath,
} from "@pwnkit/core";

function isExistingLocalPath(target: string): boolean {
  return isExistingLocalTargetPath(target);
}

export function detectAndRoute(target: string): string[] | null {
  if (target.startsWith("mcp://")) {
    return ["scan", "--target", target];
  }

  if (
    isExplicitLocalTargetPath(target) ||
    isExistingLocalPath(target)
  ) {
    return ["review", expandHomePath(target)];
  }

  if (target.startsWith("https://github.com/") || target.startsWith("git@")) {
    return ["review", target];
  }

  if (target.startsWith("http://") || target.startsWith("https://")) {
    return ["scan", "--target", target];
  }

  if (/^(@[a-z0-9-]+\/)?[a-z0-9][a-z0-9._-]*(@.*)?$/.test(target)) {
    return ["audit", target];
  }

  return null;
}
