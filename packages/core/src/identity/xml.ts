// Minimal XML reader for SAML structural analysis.
//
// Hand-rolled on purpose: `@pwnkit/core` has no XML dependency, and pulling one
// in for a handful of structural checks would add a parser — and its attack
// surface — to every consumer of this package. This one is deliberately narrow:
// it handles exactly the subset SAML uses, has NO entity expansion, NO DTD
// processing (a DOCTYPE is refused outright), and NO external resolution, and it
// rejects anything it does not understand rather than recovering. It exists to
// answer structural questions about signature placement — which element does a
// `Reference` resolve to, is a signature enveloped, is an assertion buried
// inside a `ds:Object` — not to be a general XML parser, and it must never be
// used to make a security decision on its own.
//
// Total by construction: `parseXml` returns a reason, never throws. Callers in
// `tokens.ts` turn that into a `saml-malformed` finding.

export interface XmlElement {
  /** Local name with any namespace prefix stripped. */
  name: string;
  /** Name as written, prefix included. */
  qname: string;
  attrs: Record<string, string>;
  children: XmlElement[];
  parent?: XmlElement;
  /** Concatenated text of the element's direct text nodes. */
  text: string;
  /** True when a comment node appeared among this element's direct children. */
  hasComment: boolean;
  /** Count of non-empty direct text chunks. >1 alongside a comment is the truncation shape. */
  textChunks: number;
}

export type XmlParseResult =
  | { ok: true; root: XmlElement; all: XmlElement[] }
  | { ok: false; reason: string };

const MAX_XML_ELEMENTS = 20_000;
const MAX_XML_DEPTH = 200;

export function parseXml(input: string): XmlParseResult {
  const root = newElement("#document", "#document");
  const stack: XmlElement[] = [root];
  const all: XmlElement[] = [];
  let i = 0;

  while (i < input.length) {
    const open = stack[stack.length - 1];
    const lt = input.indexOf("<", i);
    if (lt === -1) {
      appendText(open, input.slice(i));
      break;
    }
    if (lt > i) appendText(open, input.slice(i, lt));

    if (input.startsWith("<!--", lt)) {
      const end = input.indexOf("-->", lt + 4);
      if (end === -1) return { ok: false, reason: "unterminated comment" };
      open.hasComment = true;
      i = end + 3;
      continue;
    }
    if (input.startsWith("<![CDATA[", lt)) {
      const end = input.indexOf("]]>", lt + 9);
      if (end === -1) return { ok: false, reason: "unterminated CDATA section" };
      appendText(open, input.slice(lt + 9, end));
      i = end + 3;
      continue;
    }
    if (input.startsWith("<?", lt)) {
      const end = input.indexOf("?>", lt + 2);
      if (end === -1) return { ok: false, reason: "unterminated processing instruction" };
      i = end + 2;
      continue;
    }
    if (input.startsWith("<!", lt)) {
      // A DTD is refused rather than skipped: entity expansion is the whole
      // reason SAML parsers get attacked, and this module has no business
      // pretending it can process one safely.
      if (/^<!doctype/i.test(input.slice(lt, lt + 9))) {
        return { ok: false, reason: "document contains a DOCTYPE declaration" };
      }
      const end = input.indexOf(">", lt + 2);
      if (end === -1) return { ok: false, reason: "unterminated declaration" };
      i = end + 1;
      continue;
    }

    const gt = findTagEnd(input, lt);
    if (gt === -1) return { ok: false, reason: "unterminated tag" };
    const raw = input.slice(lt + 1, gt);

    if (raw.startsWith("/")) {
      const closing = raw.slice(1).trim();
      if (stack.length <= 1) return { ok: false, reason: `unexpected closing tag </${closing}>` };
      const expected = stack[stack.length - 1].qname;
      if (expected !== closing) {
        return { ok: false, reason: `closing tag </${closing}> does not match <${expected}>` };
      }
      stack.pop();
      i = gt + 1;
      continue;
    }

    const selfClosing = raw.endsWith("/");
    const body = selfClosing ? raw.slice(0, -1) : raw;
    const nameMatch = /^([^\s/>]+)/.exec(body);
    if (nameMatch === null) return { ok: false, reason: "tag has no name" };
    const qname = nameMatch[1];

    if (all.length >= MAX_XML_ELEMENTS) {
      return { ok: false, reason: `document exceeds the ${MAX_XML_ELEMENTS}-element parser budget` };
    }
    if (stack.length >= MAX_XML_DEPTH) {
      return { ok: false, reason: `document exceeds the ${MAX_XML_DEPTH}-level nesting budget` };
    }

    const element = newElement(localName(qname), qname);
    element.attrs = parseAttributes(body.slice(qname.length));
    element.parent = open;
    open.children.push(element);
    all.push(element);
    if (!selfClosing) stack.push(element);
    i = gt + 1;
  }

  if (stack.length !== 1) {
    return { ok: false, reason: `unclosed element <${stack[stack.length - 1].qname}>` };
  }
  return { ok: true, root, all };
}

function newElement(name: string, qname: string): XmlElement {
  return { name, qname, attrs: {}, children: [], text: "", hasComment: false, textChunks: 0 };
}

function localName(qname: string): string {
  const colon = qname.lastIndexOf(":");
  return colon === -1 ? qname : qname.slice(colon + 1);
}

function appendText(element: XmlElement, chunk: string): void {
  const decoded = decodeXmlEntities(chunk);
  if (decoded.trim().length === 0) return;
  element.text += decoded;
  element.textChunks += 1;
}

/** Find the `>` that closes a tag, skipping any `>` inside a quoted value. */
function findTagEnd(input: string, from: number): number {
  let quote: string | undefined;
  for (let i = from + 1; i < input.length; i += 1) {
    const ch = input[i];
    if (quote !== undefined) {
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === ">") return i;
  }
  return -1;
}

const ATTRIBUTE_PATTERN = /([^\s=/<>]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g;

function parseAttributes(body: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  ATTRIBUTE_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = ATTRIBUTE_PATTERN.exec(body)) !== null) {
    const value = match[2] ?? match[3] ?? "";
    attrs[localName(match[1])] = decodeXmlEntities(value);
  }
  return attrs;
}

const NAMED_ENTITIES: Readonly<Record<string, string>> = {
  lt: "<", gt: ">", amp: "&", quot: '"', apos: "'",
};

function decodeXmlEntities(text: string): string {
  if (!text.includes("&")) return text;
  return text.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, body: string) => {
    if (body.startsWith("#x") || body.startsWith("#X")) {
      const code = Number.parseInt(body.slice(2), 16);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
    }
    if (body.startsWith("#")) {
      const code = Number.parseInt(body.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : whole;
    }
    return NAMED_ENTITIES[body] ?? whole;
  });
}

export function descendants(element: XmlElement): XmlElement[] {
  const out: XmlElement[] = [];
  const queue = [...element.children];
  while (queue.length > 0) {
    const next = queue.shift();
    if (next === undefined) break;
    out.push(next);
    queue.push(...next.children);
  }
  return out;
}

export function ancestors(element: XmlElement): XmlElement[] {
  const out: XmlElement[] = [];
  let current = element.parent;
  while (current !== undefined) {
    out.push(current);
    current = current.parent;
  }
  return out;
}

export function isDescendantOf(element: XmlElement, ancestor: XmlElement): boolean {
  return ancestors(element).includes(ancestor);
}
