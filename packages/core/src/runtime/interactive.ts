/**
 * Interactive execution channel: a bidirectional stdio transport for
 * model-authored TypeScript running inside Docker/smolvm guests.
 *
 * The channel decouples frame transport from protocol semantics:
 * `onReady` provides a `write` function that sends data into the guest's
 * stdin, and `onData` delivers whatever the guest writes to stdout. The
 * caller (the executable plugin manager's protocol layer) frames JSON
 * messages over this transport without the channel needing to understand
 * the message shapes.
 *
 * When `initialInput` is set, it is written to stdin before `onReady`
 * fires — this lets a guest that expects handshake data on startup
 * receive it without the guest needing to wait for an explicit signal.
 */

/**
 * A bidirectional interactive execution channel for model-authored TS
 * running inside a Docker or smolvm guest.
 *
 * Transport contract — no protocol awareness:
 * - `onReady` fires once the target is accepting stdin data. The `write`
 *   callback sends bytes into the guest's stdin.
 * - `onData` delivers bounded stdout chunks from the guest. The guest's
 *   stdout delivers plugin-protocol JSON frames; the host's protocol layer
 *   decodes them.
 * - Callback propagation failures cancel the channel.
 * - Signals/deadlines/output caps/verified teardown remain enforced by
 *   the caller (the sandbox or plugin manager).
 * - The sandbox remains offline; there is NO host execution fallback.
 */
export interface InteractiveExecutionChannel {
  /**
   * Called once the guest process is ready to receive input. The `write`
   * function sends a string to the guest's stdin (appended with a newline
   * by the caller's framing layer — not by the channel).
   */
  onReady(write: (data: string) => void): void;

  /**
   * Called for each bounded stdout chunk from the guest. Chunks may be
   * partial frames; the caller's `FrameReader` reassembles them.
   * Callback failures propagate to cancellation.
   */
  onData(data: string): void;

  /**
   * Optional initial stdin content written before `onReady` fires, for
   * handshake or bootstrap data. Defaults to empty string (interactive
   * mode with no preamble).
   */
  initialInput?: string;
}