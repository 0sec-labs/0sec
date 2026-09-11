/** Split shell text for conservative inspection; this is not an execution sandbox. */
export function shellTokens(payload: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let started = false;
  let quote: '"' | "'" | null = null;
  const flush = () => {
    if (started) {
      tokens.push(current);
      current = "";
      started = false;
    }
  };
  for (let i = 0; i < payload.length; i++) {
    const ch = payload[i];
    if (quote) {
      if (ch === quote) { quote = null; continue; }
      if (quote === '"' && ch === "\\" && i + 1 < payload.length) { current += payload[++i]; started = true; continue; }
      current += ch;
      started = true;
      continue;
    }
    if (ch === '"' || ch === "'") { quote = ch; started = true; continue; }
    if (ch === "\n") { flush(); tokens.push("\n"); continue; }
    if (ch === " " || ch === "\t" || ch === "\r") { flush(); continue; }
    if (ch === "|" || ch === "&" || ch === ";") {
      flush();
      let op = ch;
      while (i + 1 < payload.length && payload[i + 1] === ch) { op += payload[++i]; }
      tokens.push(op);
      continue;
    }
    current += ch;
    started = true;
  }
  flush();
  return tokens;
}
