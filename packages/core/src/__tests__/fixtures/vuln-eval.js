// Fixture: an obvious eval(user_input) — both semgrep's `auto` config and
// foxguard's built-in `js/no-eval` rule must fire on this file. Used by
// `shared-analysis.foxguard.test.ts` to assert scanner parity (path,
// startLine, severity-within-one-tier).
//
// Do not refactor — the line numbers here are load-bearing for the test.
const express = require("express");
const app = express();

app.post("/run", (req, res) => {
  const code = req.body.code;
  // eslint-disable-next-line no-eval
  eval(code); // line 11 — taint sink
  res.send("ok");
});

module.exports = app;
