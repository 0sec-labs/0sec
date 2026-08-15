// Minimal glob matching for the file-review pipeline. Supports the subset
// deepsec's scanner/coverage layers use: `**`, `*`, `?`, `{a,b}`. No
// dependency added to @pwnkit/core for this — patterns compile to anchored
// regexes and matching is pure string work.

const GLOB_SPECIALS = /[.+^${}()|[\]\\]/g;

/** Compile one glob pattern to an anchored RegExp over POSIX paths. */
export function globToRegex(pattern: string): RegExp {
  const p = pattern.replaceAll("\\", "/").replace(/^\.\//, "");
  let out = "^";
  let i = 0;
  while (i < p.length) {
    const ch = p[i];
    if (ch === "*") {
      if (p[i + 1] === "*") {
        // `**/` crosses directory boundaries; bare `**` matches everything
        if (p[i + 2] === "/") {
          out += "(?:.*/)?";
          i += 3;
        } else {
          out += ".*";
          i += 2;
        }
      } else {
        out += "[^/]*";
        i += 1;
      }
    } else if (ch === "?") {
      out += "[^/]";
      i += 1;
    } else if (ch === "{") {
      const close = p.indexOf("}", i);
      if (close === -1) {
        out += "\\{";
        i += 1;
      } else {
        const alts = p
          .slice(i + 1, close)
          .split(",")
          .map((a) => a.replace(GLOB_SPECIALS, "\\$&"));
        out += `(?:${alts.join("|")})`;
        i = close + 1;
      }
    } else {
      out += ch.replace(GLOB_SPECIALS, "\\$&");
      i += 1;
    }
  }
  out += "$";
  return new RegExp(out);
}

export function matchGlob(filePath: string, pattern: string): boolean {
  const rel = filePath.replaceAll("\\", "/").replace(/^\.\//, "");
  return globToRegex(pattern).test(rel);
}

export function matchAnyGlob(filePath: string, patterns: readonly string[]): boolean {
  return patterns.some((p) => matchGlob(filePath, p));
}

/** Directories never scanned (build output, deps, VCS, caches). */
export const DEFAULT_IGNORE_DIR_GLOBS = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/target/**",
  "**/__pycache__/**",
  "**/.venv/**",
  "**/venv/**",
  "**/.tox/**",
  "**/vendor/**",
  "**/third_party/**",
  "**/deps/**",
  "**/.cache/**",
  "**/.next/**",
  "**/.nuxt/**",
  "**/coverage/**",
  "**/.turbo/**",
  "**/.vercel/**",
  "**/.deepsec/**",
] as const;

/** Files never scanned (minified bundles, lockfiles, images, archives). */
export const DEFAULT_IGNORE_FILE_GLOBS = [
  "**/*.min.js",
  "**/*.min.css",
  "**/*.map",
  "**/*.lock",
  "**/pnpm-lock.yaml",
  "**/package-lock.json",
  "**/yarn.lock",
  "**/*.png",
  "**/*.jpg",
  "**/*.jpeg",
  "**/*.gif",
  "**/*.svg",
  "**/*.ico",
  "**/*.woff",
  "**/*.woff2",
  "**/*.ttf",
  "**/*.eot",
  "**/*.pdf",
  "**/*.zip",
  "**/*.tar",
  "**/*.tar.gz",
  "**/*.tgz",
  "**/*.wasm",
  "**/*.pyc",
  "**/*.pyo",
] as const;

/** Normalize a relative path to POSIX form with no `./` prefix. */
export function normalizeRelPath(p: string): string {
  return p.replaceAll("\\", "/").replace(/^\.\//, "").trim();
}
