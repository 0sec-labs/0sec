import type { AuthConfig, NamedIdentity, IdentityRole } from "./types.js";

/**
 * Multi-identity access-control testing helpers (pwnkit#564).
 *
 * The engine reasons over a list of `NamedIdentity`, but the public config
 * surface still accepts the legacy singular `auth`. `resolveIdentities` is the
 * single back-compat shim that reconciles the two so the rest of the codebase
 * only ever deals with a normalized identity list.
 */

/** Default privilege tier for an identity with no explicit `role`. */
export function defaultRoleFor(auth?: AuthConfig): IdentityRole {
  return auth ? "user" : "anonymous";
}

/**
 * Reconcile the legacy singular `auth` field with the multi-identity
 * `identities` list into a single normalized list.
 *
 * Precedence:
 *  - `identities` present & non-empty → used verbatim (singular `auth` ignored).
 *  - only `auth` present → wrapped into a one-entry list labelled `"primary"`.
 *  - neither present → empty list (unauthenticated scan, behaviour unchanged).
 *
 * Every returned identity has a concrete `role` (defaulted from `auth`
 * presence when absent) and a unique `label` (de-duplicated with a numeric
 * suffix) so downstream cookie-jar keying and evidence labelling are stable.
 */
export function resolveIdentities(config: {
  auth?: AuthConfig;
  identities?: NamedIdentity[];
}): NamedIdentity[] {
  const raw: NamedIdentity[] =
    config.identities && config.identities.length > 0
      ? config.identities
      : config.auth
        ? [{ label: "primary", auth: config.auth }]
        : [];

  const seen = new Map<string, number>();
  return raw.map((idn, i) => {
    let label = (idn.label ?? "").trim() || `identity-${i + 1}`;
    // De-duplicate labels so jar keys + evidence never collide.
    const prior = seen.get(label);
    if (prior !== undefined) {
      const next = prior + 1;
      seen.set(label, next);
      label = `${label}-${next}`;
    } else {
      seen.set(label, 1);
    }
    return {
      label,
      role: idn.role ?? defaultRoleFor(idn.auth),
      auth: idn.auth,
    };
  });
}

/**
 * True when the scan is configured for access-control testing — i.e. it has
 * at least two distinct principals to diff against each other (or one
 * authenticated principal plus the implicit unauthenticated control).
 */
export function hasMultipleIdentities(identities: NamedIdentity[]): boolean {
  return identities.length >= 2;
}

/** Rough ordering of privilege tiers for vertical-privesc reasoning. */
const ROLE_RANK: Record<string, number> = { anonymous: 0, user: 1, admin: 2 };

/**
 * Compare two roles by privilege. Returns a negative number when `a` is
 * lower-privileged than `b`, 0 when equal/unknown, positive when higher.
 * Unknown (bespoke) roles rank as `user` so they never spuriously read as
 * admin.
 */
export function compareRoles(a?: IdentityRole, b?: IdentityRole): number {
  const ra = ROLE_RANK[(a ?? "user") as string] ?? ROLE_RANK.user;
  const rb = ROLE_RANK[(b ?? "user") as string] ?? ROLE_RANK.user;
  return ra - rb;
}
