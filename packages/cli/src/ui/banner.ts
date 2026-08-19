// Lazy-loaded cfonts module (loaded once, cached)
let _cfonts: any = null;
let _cfontsLoaded = false;

/**
 * Pre-load cfonts so the banner can be rendered synchronously later.
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
