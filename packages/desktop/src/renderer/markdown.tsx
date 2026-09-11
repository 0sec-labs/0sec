import {
  Children,
  isValidElement,
  memo,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import { Check, Copy } from "lucide-react";

function textContent(children: ReactNode): string {
  let text = "";
  Children.forEach(children, (child) => {
    if (typeof child === "string" || typeof child === "number") text += child;
    else if (isValidElement<{ children?: ReactNode }>(child))
      text += textContent(child.props.children);
  });
  return text;
}

function CodeBlock({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  useEffect(() => () => clearTimeout(timer.current), []);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(textContent(children));
      setStatus("copied");
    } catch {
      setStatus("failed");
    }
    clearTimeout(timer.current);
    timer.current = setTimeout(() => setStatus("idle"), 1800);
  };
  return (
    <div className="code-block-wrapper">
      <div className="code-block-header">
        <span>Code</span>
        <button
          type="button"
          className={`copy-btn ${status}`}
          onClick={() => void copy()}
          aria-label={
            status === "failed" ? "Copy failed; try again" : "Copy code"
          }
        >
          {status === "copied" ? <Check size={12} /> : <Copy size={12} />}
          <span aria-live="polite">
            {status === "copied"
              ? "Copied"
              : status === "failed"
                ? "Copy failed"
                : "Copy"}
          </span>
        </button>
      </div>
      <pre>{children}</pre>
    </div>
  );
}

function SafeLink({ href, children }: { href?: string; children: ReactNode }) {
  const [error, setError] = useState<string | null>(null);
  let safe = false;
  try {
    const url = new URL(href ?? "");
    safe = url.protocol === "https:" && !url.username && !url.password;
  } catch {
    // Agent-generated relative/file links must not navigate the privileged app.
  }
  if (!safe || !href) return <span>{children}</span>;
  return (
    <>
      <a
        href={href}
        target="_blank"
        rel="noopener noreferrer"
        onClick={(event) => {
          if (!window.osecDesktop) return;
          event.preventDefault();
          setError(null);
          void window.osecDesktop
            .openExternal(href)
            .catch((cause) =>
              setError(cause instanceof Error ? cause.message : String(cause)),
            );
        }}
      >
        {children}
      </a>
      {error && <span role="alert"> {error}</span>}
    </>
  );
}

const components: Components = {
  img: ({ alt }) => <span>{alt ? `[Image: ${alt}]` : "[Image]"}</span>,
  a: ({ href, children }) => <SafeLink href={href}>{children}</SafeLink>,
  pre: ({ children }) => <CodeBlock>{children}</CodeBlock>,
  table: ({ children }) => (
    <div style={{ overflowX: "auto" }}>
      <table>{children}</table>
    </div>
  ),
};
const plugins = [remarkGfm];

export const Markdown = memo(function Markdown({ text }: { text: string }) {
  return (
    <div className="message-body">
      <ReactMarkdown remarkPlugins={plugins} components={components} skipHtml>
        {text}
      </ReactMarkdown>
    </div>
  );
});
