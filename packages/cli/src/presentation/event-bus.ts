import type { PresentationEvent } from "@0sec/shared";

export interface PresentationEventListener {
  emit(event: PresentationEvent): void;
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
