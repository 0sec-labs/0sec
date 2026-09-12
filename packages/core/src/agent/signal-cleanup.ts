type Cleanup = () => void | Promise<void>;

// Allows the host's 30-second disposal budget plus bounded shutdown overhead.
const CLEANUP_BUDGET_MS = 35_000;
const cleanups = new Set<Cleanup>();
let installed = false;
let stopping = false;
let exitRequested = false;

function finish(message?: string): void {
  if (exitRequested) return;
  exitRequested = true;
  if (message) {
    try { process.stderr.write(`[signal-cleanup] ${message}\n`); } catch { /* Exit even if stderr is unavailable. */ }
  }
  process.exit(1);
}

async function drainCleanups(): Promise<void> {
  const timer = setTimeout(() => finish("Cleanup deadline exceeded; resources may remain open (incomplete cleanup)."), CLEANUP_BUDGET_MS);
  const results = await Promise.allSettled([...cleanups].map(cleanup => {
    try { return Promise.resolve(cleanup()); }
    catch (error) { return Promise.reject(error); }
  }));
  clearTimeout(timer);
  const failed = results.filter(result => result.status === "rejected").length;
  finish(failed ? `${failed} cleanup callback(s) failed; resource cleanup may be incomplete.` : undefined);
}

function handleSignal(): void {
  if (stopping) {
    finish("Repeated signal forced exit; resource cleanup may be incomplete.");
    return;
  }
  stopping = true;
  void drainCleanups();
}

function install(): void {
  if (installed) return;
  process.on("SIGINT", handleSignal);
  process.on("SIGTERM", handleSignal);
  installed = true;
}

function uninstallIfIdle(): void {
  // Keep the force-exit listener while callbacks drain, even if they unregister.
  if (!installed || stopping || cleanups.size > 0) return;
  process.removeListener("SIGINT", handleSignal);
  process.removeListener("SIGTERM", handleSignal);
  installed = false;
}

export function registerSignalCleanup(cleanup: Cleanup): () => void {
  cleanups.add(cleanup);
  install();
  return () => {
    cleanups.delete(cleanup);
    uninstallIfIdle();
  };
}

export function signalCleanupListenerCountForTests(): number {
  return cleanups.size;
}
