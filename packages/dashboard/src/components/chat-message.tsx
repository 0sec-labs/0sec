import {
  memo,
  useCallback,
  useState,
  useEffect,
  useRef,
  Children,
  isValidElement,
  type ReactNode,
  type ComponentPropsWithoutRef,
} from "react";
import ReactMarkdown from "react-markdown";
import type { Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import { Copy, Check, X } from "lucide-react";
import { cn } from "@/lib/utils";

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
    const text = childrenToText(children);
    try {
      await navigator.clipboard.writeText(text);
      setStatus("copied");
    } catch {
      setStatus("failed");
    } finally {
      window.clearTimeout(resetRef.current);
      resetRef.current = window.setTimeout(() => setStatus("idle"), 1500);
    }
  }, [children]);

  const Icon = status === "copied" ? Check : status === "failed" ? X : Copy;
  const label =
    status === "copied"
      ? "Copied"
      : status === "failed"
        ? "Copy failed"
        : "Copy code";

  return (
    <button
      type="button"
      onClick={copy}
      aria-label={label}
      className={cn(
        "absolute right-2 top-2 z-10 flex size-6 items-center justify-center rounded",
        "text-[#8d8984] transition-colors",
        "hover:bg-[#f7f5f2]/8 hover:text-[#e4e0dc]",
        "focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-[#f7f5f2]/30",
      )}
    >
      <Icon aria-hidden className="size-3" />
    </button>
  );
}


const COMPONENTS = {
  // Images remain inert text; no remote resources are fetched.
  img: ({ src, alt, ..._rest }: ComponentPropsWithoutRef<"img">) => (
    <span className="inline text-[#8d8984]">
      {" ["}
      <span className="italic">{alt || src || "image"}</span>
      {"]"}
    </span>
  ),

  /* Fenced code → scrollable block with copy button */
  pre: ({ children, className, ..._rest }: ComponentPropsWithoutRef<"pre">) => (
    <div className="relative my-3 group/code">
      <CodeBlockCopy>{children}</CodeBlockCopy>
      <pre
        className={cn(
          "overflow-x-auto whitespace-pre break-normal rounded-lg border border-[#f7f5f2]/10 bg-[#f7f5f2]/[0.03] p-4 pr-10 [&>code]:block [&>code]:bg-transparent [&>code]:p-0 [&>code]:whitespace-pre",
          "text-[13px] leading-6",
          className,
        )}
      >
        {children}
      </pre>
    </div>
  ),

  /* Inline code */
  code: ({ className, children }: ComponentPropsWithoutRef<"code">) => (
    <code className={cn("rounded bg-[#f7f5f2]/8 px-1 py-0.5 font-mono text-[13px] text-[#e4e0dc]", className)}>
      {children}
    </code>
  ),

  /* GFM tables → horizontally scrollable */
  table: ({ children, ..._rest }: ComponentPropsWithoutRef<"table">) => (
    <div className="my-3 overflow-x-auto">
      <table className="min-w-full border-collapse text-sm leading-6">
        {children}
      </table>
    </div>
  ),
  thead: ({ children, ..._rest }: ComponentPropsWithoutRef<"thead">) => (
    <thead className="border-b border-[#f7f5f2]/10">
      {children}
    </thead>
  ),
  th: ({ children, ..._rest }: ComponentPropsWithoutRef<"th">) => (
    <th className="px-3 py-2 text-left text-[11px] font-medium tracking-wider text-[#8d8984] uppercase">
      {children}
    </th>
  ),
  td: ({ children, ..._rest }: ComponentPropsWithoutRef<"td">) => (
    <td className="border-b border-[#f7f5f2]/6 px-3 py-2 text-[#e4e0dc]/90">
      {children}
    </td>
  ),

  /* Headings */
  h1: ({ children, ..._rest }: ComponentPropsWithoutRef<"h1">) => (
    <h1 className="mb-2 mt-5 text-base font-medium text-[#f7f5f2]">{children}</h1>
  ),
  h2: ({ children, ..._rest }: ComponentPropsWithoutRef<"h2">) => (
    <h2 className="mb-2 mt-4 text-[15px] font-medium text-[#f7f5f2]">{children}</h2>
  ),
  h3: ({ children, ..._rest }: ComponentPropsWithoutRef<"h3">) => (
    <h3 className="mb-1.5 mt-3.5 text-sm font-medium text-[#f7f5f2]">{children}</h3>
  ),
  h4: ({ children, ..._rest }: ComponentPropsWithoutRef<"h4">) => (
    <h4 className="mb-1 mt-3 text-[13px] font-medium text-[#f7f5f2]">{children}</h4>
  ),

  /* Paragraphs */
  p: ({ children, ..._rest }: ComponentPropsWithoutRef<"p">) => (
    <p className="mb-3 last:mb-0 text-sm leading-7">{children}</p>
  ),

  /* Lists */
  ul: ({ children, ..._rest }: ComponentPropsWithoutRef<"ul">) => (
    <ul className="mb-3 list-disc pl-5 text-sm leading-7 text-[#e4e0dc] space-y-1">{children}</ul>
  ),
  ol: ({ children, ..._rest }: ComponentPropsWithoutRef<"ol">) => (
    <ol className="mb-3 list-decimal pl-5 text-sm leading-7 text-[#e4e0dc] space-y-1">{children}</ol>
  ),
  li: ({ children, ..._rest }: ComponentPropsWithoutRef<"li">) => (
    <li className="pl-1">{children}</li>
  ),

  /* Blockquotes */
  blockquote: ({ children, ..._rest }: ComponentPropsWithoutRef<"blockquote">) => (
    <blockquote className="my-3 border-l-2 border-[#f7f5f2]/20 pl-4 text-sm leading-7 text-[#aaa59f] italic">
      {children}
    </blockquote>
  ),

  /* Horizontal rules */
  hr: (_props: ComponentPropsWithoutRef<"hr">) => (
    <hr className="my-4 border-[#f7f5f2]/10" />
  ),

  /* Links */
  a: ({ children, href, ..._rest }: ComponentPropsWithoutRef<"a">) => (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-[#e4e0dc] underline decoration-white/30 underline-offset-2 transition-colors hover:decoration-white/70 focus-visible:outline-2 focus-visible:outline-[#b6b2ad]"
    >
      {children}
    </a>
  ),
} satisfies Components;

/* ─── streaming cursor ─────────────────────────────────────── */

function StreamingCursor() {
  return (
    <span
      className="inline-flex items-center"
      role="status"
      aria-label="Assistant is generating"
    >
      <span className="ml-0.5 inline-block h-[1em] w-[2px] rounded-full bg-[#8d8984] motion-safe:animate-pulse motion-reduce:opacity-60" />
    </span>
  );
}

/* ─── ChatMessage ─────────────────────────────────────────── */

export const ChatMessage = memo(function ChatMessage({
  text,
  streaming = false,
}: {
  text: string;
  streaming?: boolean;
}) {
  return (
    <div className="text-sm leading-7 text-[#e4e0dc]">
      <ReactMarkdown
        remarkPlugins={REMARK_PLUGINS}
        components={COMPONENTS}
      >
        {text}
      </ReactMarkdown>
      {streaming && <StreamingCursor />}
    </div>
  );
});