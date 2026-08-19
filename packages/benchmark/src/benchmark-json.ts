import express, { type ErrorRequestHandler, type Express } from "express";

/**
 * Install the benchmark API parser and normalize malformed JSON to a concise,
 * deterministic 400 response. Scanner probes can intentionally send invalid
 * JSON; the benchmark must not print an Express stack trace or lose its server.
 */
function isMalformedJsonError(err: unknown): err is SyntaxError & { status: number; type: string } {
  return err instanceof SyntaxError
    && "status" in err
    && err.status === 400
    && "type" in err
    && err.type === "entity.parse.failed";
}

const malformedJsonHandler: ErrorRequestHandler = (err, _req, res, next) => {
  if (!isMalformedJsonError(err)) return next(err);
  return res.status(400).json({ error: "malformed_json" });
};

export function installBenchmarkJsonHandling(app: Express): void {
  app.use(express.json());
  app.use(malformedJsonHandler);
}
