import { randomUUID } from "node:crypto";
import { createConsoleSession, type ConsoleSession, type ConsoleSessionConfig } from "@0sec/core";
import { osecDB } from "@0sec/db";
import { createConversationHistory } from "./conversation-history.js";

/** Local frontends share the findings store with history and own its connection. */
export function createLocalConsoleSession(
  config: Omit<ConsoleSessionConfig, "db">,
  dbPath?: string,
): ConsoleSession {
  const db = new osecDB(dbPath);
  const scanId = config.scanId ?? `console-${randomUUID()}`;
  let ownsScan = false;
  try {
    if (!db.getScan(scanId)) {
      db.createScan({
        target: config.target ?? "",
        depth: "default",
        format: "terminal",
        runtime: "api",
      }, scanId);
      ownsScan = true;
    }
    const session = createConsoleSession({
      ...config,
      scanId,
      db,
      conversationHistory: config.conversationHistory ?? createConversationHistory(),
    });
    const cleanup = session.cleanup;
    let closing: Promise<void> | undefined;
    session.cleanup = () => closing ??= (async () => {
      try {
        await cleanup();
        if (ownsScan) db.completeScan(scanId, { source: "console" });
      } finally {
        db.close();
      }
    })();
    return session;
  } catch (error) {
    try {
      if (ownsScan) db.failScan(scanId, error instanceof Error ? error.message : String(error));
    } finally {
      db.close();
    }
    throw error;
  }
}
