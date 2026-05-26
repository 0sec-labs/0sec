import { VERSION } from "@pwnkit/shared";
import { RAIL } from "./theme.js";

// Lazy-loaded cfonts module (loaded once, cached)
let _cfonts: any = null;
let _cfontsLoaded = false;

/**
 * Pre-load cfonts so printBanner can be synchronous.
 * Call this early (e.g. during CLI startup) before Ink takes over.
 */
export async function preloadBanner(): Promise<void> {
  if (_cfontsLoaded) return;
  _cfontsLoaded = true;
  try {
    _cfonts = (await import("cfonts")).default;
  } catch {
    _cfonts = null;
  }
}

/**
 * Print the pwnkit banner. Must be synchronous — called right before
 * Ink takes over the terminal. Call preloadBanner() first if you want
 * the fancy font; otherwise falls back to plain text.
 */
export function printBanner(subtitle?: string): void {
  const p = `\x1b[38;2;250;178;131m`;
  const t = `\x1b[38;2;238;238;238m`;
  const m = `\x1b[38;2;128;128;128m`;
  const d = "\x1b[2m";
  const b = "\x1b[1m";
  const x = "\x1b[0m";

  console.log("");
  console.log(`  ${p}${RAIL}${x} ${t}${b}pwnkit${x} ${m}v${VERSION}${x}`);
  if (subtitle) {
    console.log(`    ${d}${subtitle}${x}`);
  } else {
    console.log(`    ${d}agentic security operations in a terminal-native shell${x}`);
  }
  console.log("");
}
