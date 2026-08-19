import type { AuthConfig } from "@0sec/shared";

const REDACTED_AUTH_VALUE = "<REDACTED-AUTH>";

function isSensitiveHeader(name: string): boolean {
  const normalized = name.toLowerCase();
  return normalized === "authorization" ||
    normalized === "proxy-authorization" ||
    normalized === "cookie" ||
    normalized === "set-cookie" ||
    normalized === "x-api-key" ||
    normalized === "x-auth-token" ||
    normalized === "x-access-token" ||
    normalized === "x-amz-security-token" ||
    /^x-.*(?:api[-_]?key|auth|token|secret)$/i.test(normalized);
}

/**
 * Values supplied by the operator for target authentication. These must never
 * cross from target-bound HTTP into model input or persisted artifacts.
 */
export function authSecretValues(auth?: AuthConfig): string[] {
  if (!auth) return [];

  switch (auth.type) {
    case "bearer":
      return [auth.token, `Bearer ${auth.token}`];
    case "cookie":
      return [auth.value];
    case "basic": {
      const raw = `${auth.username}:${auth.password}`;
      return [auth.username, auth.password, raw, Buffer.from(raw).toString("base64"), `Basic ${Buffer.from(raw).toString("base64")}`];
    }
    case "header":
      return [auth.value];
  }
}

/** Redact configured or dynamically sent credential values from target data. */
export function redactAuthValues(value: string, secrets: Iterable<string>): string {
  let redacted = value;
  const uniqueSecrets = [...new Set(secrets)]
    .filter((secret) => secret.length > 0)
    .sort((a, b) => b.length - a.length);

  for (const secret of uniqueSecrets) {
    redacted = redacted.replaceAll(secret, REDACTED_AUTH_VALUE);
    const encoded = encodeURIComponent(secret);
    if (encoded !== secret) redacted = redacted.replaceAll(encoded, REDACTED_AUTH_VALUE);
  }
  return redacted;
}

/**
 * Return model- and artifact-safe HTTP headers. Standard credential-shaped
 * header names are always masked; configured custom authentication values are
 * masked even when the header name is not conventionally sensitive.
 */
export function redactAuthHeaders(
  headers: Record<string, string>,
  secrets: Iterable<string>,
): Record<string, string> {
  const secretSet = new Set(secrets);
  return Object.fromEntries(
    Object.entries(headers).map(([name, value]) => [
      name,
      isSensitiveHeader(name) || secretSet.has(value)
        ? REDACTED_AUTH_VALUE
        : redactAuthValues(value, secretSet),
    ]),
  );
}

/** Add values from sensitive outbound headers, including session cookies. */
export function sensitiveHeaderValues(headers: Record<string, string>): string[] {
  return Object.entries(headers)
    .filter(([name]) => isSensitiveHeader(name))
    .map(([, value]) => value);
}
