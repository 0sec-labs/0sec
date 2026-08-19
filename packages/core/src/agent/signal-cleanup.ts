type SignalName = "SIGINT" | "SIGTERM";

type Cleanup = () => void;

const cleanups = new Set<Cleanup>();
let installed = false;

function handleSignal(): void {
  for (const cleanup of [...cleanups]) {
    try {
      cleanup();
    } catch {
      // Signal handlers must keep draining remaining cleanup callbacks.
    }
  }
  process.exit(1);
}

function install(): void {
  if (installed) return;
  process.on("SIGINT", handleSignal);
  process.on("SIGTERM", handleSignal);
  installed = true;
}

function uninstallIfIdle(): void {
  if (!installed || cleanups.size > 0) return;
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
