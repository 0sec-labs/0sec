import {
  Children,
  isValidElement,
  memo,
  useCallback,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Check, Copy, X } from "lucide-react";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";

const REMARK_PLUGINS = [remarkGfm];

function childrenToText(children: ReactNode): string {
  let text = "";
  Children.forEach(children, (child) => {
    if (typeof child === "string" || typeof child === "number") {
      text += child;
    } else if (isValidElement<{ children?: ReactNode }>(child)) {
      text += childrenToText(child.props.children);
    }
  });
  return text;
}

function CodeBlockCopy({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<"idle" | "copied" | "failed">("idle");
  const resetRef = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(resetRef.current), []);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(childrenToText(children));
      setStatus("copied");
    } catch {
      setStatus("failed");
    } finally {
      window.clearTimeout(resetRef.current);
      resetRef.current = window.setTimeout(() => setStatus("idle"), 1500);
    }
  }, [children]);

  const Icon = status === "copied" ? Check : status === "failed" ? X : Copy;
  const label = status === "copied" ? "Copied" : status === "failed" ? "Copy failed" : "Copy code";

  return (
    <button type="button" onClick={copy} aria-label={label} title={label} className="desktop-code-copy">
      <Icon aria-hidden size={14} />
    </button>
  );
}

const COMPONENTS = {
  // Agent output must not fetch tracking images or other remote resources.
  img: ({ src, alt }) => <span>[{alt || src || "image"}]</span>,
  pre: ({ children }) => (
    <div className="desktop-code-block">
      <CodeBlockCopy>{children}</CodeBlockCopy>
      <pre>{children}</pre>
    </div>
  ),
  table: ({ children }) => (
    <div className="desktop-table">
      <table>{children}</table>
    </div>
  ),
  a: ({ children, href }) => (
    <a href={href} target="_blank" rel="noopener noreferrer">{children}</a>
  ),
} satisfies Components;

export const ChatMessage = memo(function ChatMessage({
  text,
  streaming = false,
}: {
  text: string;
  streaming?: boolean;
}) {
  return (
    <div className="desktop-markdown">
      <ReactMarkdown remarkPlugins={REMARK_PLUGINS} components={COMPONENTS}>{text}</ReactMarkdown>
      {streaming && <span className="desktop-stream-cursor" role="status" aria-label="Assistant is generating" />}
    </div>
  );
});
