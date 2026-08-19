/**
 * Legacy environment-variable aliases (0sec rename, 2026-08-19).
 *
 * The engine's public env contract moved from `PWNKIT_*` to `0SEC_*`.
 * Existing deployments (0cloud worker-controller, operator scripts, CI) still
 * export the old names, so at CLI startup we copy any `PWNKIT_*` value onto
 * its `0SEC_*` equivalent **only when the new name is unset** — the new name
 * always wins.
 *
 * This module must be imported before any other engine module so the aliases
 * land before module-level `process.env.0SEC_*` reads evaluate. It is the
 * first import in `./index.ts`. The legacy names are also the permanent
 * shell-friendly path: POSIX shells reject digit-leading names, so operators
 * in bash/sh set `PWNKIT_*` while Docker/CI/systemd can use `0SEC_*`.
 */
for (const [key, value] of Object.entries(process.env)) {
  if (!key.startsWith("PWNKIT_") || value === undefined) continue;
  const renamed = `0SEC_${key.slice("PWNKIT_".length)}`;
  if (process.env[renamed] === undefined) {
    process.env[renamed] = value;
  }
}
