import {
  createPresentationEvent,
  type PresentationEvent,
  type PresentationSource,
} from "@0sec/shared";

export interface PresentationEventListener {
  emit(event: PresentationEvent): void;
}

export interface PresentationEmitterOptions {
  source?: PresentationSource;
  now?: () => string;
  bus?: PresentationEventBus;
}

export interface PresentationEmitter {
  emit(
    eventType: string,
    payload: Record<string, unknown>,
    correlation?: { scanId?: string; sessionId?: string },
  ): PresentationEvent;
}

/**
 * Process-local fan-out for canonical presentation records. It has no retained
 * history: adapters that need replay own durable storage explicitly.
 */
export class PresentationEventBus {
  private listeners: PresentationEventListener[] = [];

  subscribe(listener: PresentationEventListener): () => void {
    this.listeners.push(listener);
    return () => {
      const index = this.listeners.indexOf(listener);
      if (index >= 0) this.listeners.splice(index, 1);
    };
  }

  emit(event: PresentationEvent): void {
    for (const listener of [...this.listeners]) {
      try {
        listener.emit(event);
      } catch {
        // Presentation observers must never change command output or exit state.
      }
    }
  }

  get size(): number {
    return this.listeners.length;
  }
}

export const presentationEventBus = new PresentationEventBus();

/** Create a monotonic producer-local emitter for one interactive adapter. */
export function createPresentationEmitter(
  options: PresentationEmitterOptions = {},
): PresentationEmitter {
  const source = options.source ?? "cli";
  const now = options.now ?? (() => new Date().toISOString());
  const bus = options.bus ?? presentationEventBus;
  let sequence = 0;

  return {
    emit(eventType, payload, correlation = {}) {
      const event = createPresentationEvent({
        source,
        sequence: ++sequence,
        at: now(),
        eventType,
        payload,
        ...(correlation.scanId ? { scanId: correlation.scanId } : {}),
        ...(correlation.sessionId ? { sessionId: correlation.sessionId } : {}),
      });
      bus.emit(event);
      return event;
    },
  };
}
