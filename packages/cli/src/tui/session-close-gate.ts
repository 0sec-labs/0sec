export interface SessionCloseGate {
  readonly closed: boolean;
  close(): boolean;
  wait(): Promise<void>;
}

/**
 * Coordinates a session UI closing before or after its owner starts waiting.
 * Multiple owners may wait; every waiter resolves exactly once on close.
 */
export function createSessionCloseGate(): SessionCloseGate {
  let closed = false;
  const resolvers = new Set<() => void>();

  return {
    get closed(): boolean {
      return closed;
    },
    close(): boolean {
      if (closed) return false;
      closed = true;
      for (const resolve of resolvers) resolve();
      resolvers.clear();
      return true;
    },
    wait(): Promise<void> {
      if (closed) return Promise.resolve();
      const deferred = Promise.withResolvers<void>();
      resolvers.add(deferred.resolve);
      return deferred.promise;
    },
  };
}
