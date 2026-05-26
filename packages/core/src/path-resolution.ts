import { statSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, resolve } from "node:path";

export interface LocalPathResolutionOptions {
  cwd?: string;
  homeDir?: string;
}

export function expandHomePath(input: string, homeDir = homedir()): string {
  if (input === "~") return homeDir;
  if (input.startsWith("~/")) return resolve(homeDir, input.slice(2));
  return input;
}

export function resolveLocalTargetPath(
  input: string,
  opts: LocalPathResolutionOptions = {},
): string {
  const expanded = expandHomePath(input, opts.homeDir);
  if (isAbsolute(expanded)) return resolve(expanded);
  return resolve(opts.cwd ?? process.cwd(), expanded);
}

export function isExplicitLocalTargetPath(input: string): boolean {
  return (
    input === "." ||
    input === ".." ||
    input === "~" ||
    input.startsWith("./") ||
    input.startsWith("../") ||
    input.startsWith("~/") ||
    isAbsolute(input)
  );
}

export function isExistingLocalTargetPath(
  input: string,
  opts: LocalPathResolutionOptions = {},
): boolean {
  try {
    return statSync(resolveLocalTargetPath(input, opts)).isDirectory();
  } catch {
    return false;
  }
}
