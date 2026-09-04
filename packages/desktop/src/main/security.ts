export function hasSameOrigin(expected: string, candidate: string): boolean {
  try {
    return new URL(candidate).origin === new URL(expected).origin;
  } catch {
    return false;
  }
}

export function isExternalHttpsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password;
  } catch {
    return false;
  }
}
