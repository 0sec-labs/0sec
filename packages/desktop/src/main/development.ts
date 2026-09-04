export function parseDevelopmentDebugPort(value: string | undefined): number | undefined {
  if (value === undefined || value.trim() === "") return undefined;
  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65535) {
    throw new Error("OSEC_DESKTOP_DEBUG_PORT must be an integer between 1024 and 65535.");
  }
  return port;
}
