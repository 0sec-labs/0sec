import { unified } from "@astrojs/markdown-remark";
import starlight from "@astrojs/starlight";
import { defineConfig } from "astro/config";
import rehypeMermaid from "rehype-mermaid";

export default defineConfig({
  output: "static",
  outDir: "./dist",
  site: "https://docs.0.security",
  // Allow previewing the dev server over Tailscale (dev-only; ignored by the static build).
  vite: { server: { allowedHosts: [".ts.net"] } },
  markdown: {
    // Render ```mermaid code blocks as SVG at build time.
    syntaxHighlight: { type: "shiki", excludeLangs: ["mermaid"] },
    processor: unified({
      rehypePlugins: [
        [rehypeMermaid, { strategy: "img-svg", dark: true }],
      ],
    }),
  },
  integrations: [
    starlight({
      title: "0sec",
      favicon: "/favicon.svg",
      head: [
        { tag: "link", attrs: { rel: "icon", href: "/favicon.ico", sizes: "32x32" } },
        { tag: "link", attrs: { rel: "apple-touch-icon", href: "/apple-touch-icon.png" } },
        { tag: "link", attrs: { rel: "preconnect", href: "https://0.security", crossorigin: "anonymous" } },
      ],
      description:
        "Run the 0sec harness, choose model access, and understand executable self-evolution, authorization, and evidence.",
      logo: {
        dark: "./src/assets/0sec-aperture-white.svg",
        light: "./src/assets/0sec-aperture-dark.svg",
        alt: "0sec",
        replacesTitle: true,
      },
      social: [
        {
          icon: "github",
          label: "GitHub",
          href: "https://github.com/0sec-labs/0sec",
        },
        {
          icon: "external",
          label: "Website",
          href: "https://0.security/",
        },
      ],
      defaultLocale: "root",
      editLink: { baseUrl: "https://github.com/0sec-labs/0sec/edit/main/docs/" },
      components: {
        Header: "./src/components/DocsHeader.astro",
        Hero: "./src/components/DocsHero.astro",
        MobileMenuToggle: "./src/components/DocsMenuToggle.astro",
      },
      expressiveCode: {
        themes: ["github-dark", "github-light"],
      },
      sidebar: [
        {
          label: "Documentation overview",
          slug: "index",
        },
        {
          label: "Start with 0sec",
          items: [
            { label: "Install & first run", slug: "getting-started" },
            { label: "Persistent chat & settings", slug: "console" },
            { label: "Scan & review evidence", slug: "scan-workflows" },
            { label: "Scope & authorization", slug: "scope" },
            { label: "Recipes", slug: "recipes" },
            { label: "Capabilities", slug: "features" },
            { label: "Troubleshooting", slug: "troubleshooting" },
          ],
        },
        {
          label: "0sec Cloud · hosted models",
          badge: { text: "Draft", class: "docs-status" },
          items: [
            { label: "Account & model journey", link: "/getting-started/#hosted-models-draft" },
            { label: "Credentials & availability", link: "/api-keys/#hosted-inference-draft" },
            { label: "Charging & interruptions", link: "/api-keys/#charging-and-interrupted-requests" },
            { label: "Provider selection", link: "/configuration/#hosted-configuration-draft" },
          ],
        },
        {
          label: "Self-evolving agents",
          items: [
            { label: "Mechanisms & status", slug: "improvement-plane" },
            { label: "Executable plugin evolution", link: "/improvement-plane/#executable-plugin-evolution" },
            { label: "Live driver & UI contract", link: "/improvement-plane/#live-harness-component-contract" },
            { label: "Autonomy & workspace trust", link: "/configuration/#self-extension-and-workspace-trust" },
            { label: "Long-horizon goals", link: "/improvement-plane/#long-horizon-self-evolution" },
            { label: "Integrations & plugins", slug: "integrations" },
          ],
        },
        {
          label: "Reference & advanced workflows",
          collapsed: true,
          items: [
            { label: "CLI commands", slug: "commands" },
            { label: "Configuration", slug: "configuration" },
            { label: "API keys & BYOK", slug: "api-keys" },
            { label: "Budget management", slug: "budget-management" },
            { label: "Authorized engagements", slug: "engagements" },
            { label: "White-box mode", slug: "white-box-mode" },
            { label: "GitHub CI", slug: "ci/github-action" },
          ],
        },
        {
          label: "Architecture & evidence",
          collapsed: true,
          items: [
            { label: "Architecture", slug: "architecture" },
            { label: "Agent loop", slug: "agent-loop" },
            { label: "Finding Triage", slug: "triage" },
            { label: "Blind Verification", slug: "blind-verification" },
            { label: "Verification Results", slug: "verification-result" },
            { label: "Adversarial Evals", slug: "adversarial-evals" },
          ],
        },
        {
          label: "Benchmarks",
          collapsed: true,
          items: [
            { label: "Results", slug: "benchmark" },
            { label: "Methodology", slug: "methodology" },
            { label: "XBOW Analysis", slug: "research/xbow-analysis" },
            { label: "Competitive Landscape", slug: "research/competitive-landscape" },
          ],
        },
        {
          label: "Research",
          collapsed: true,
          items: [
            { label: "Overview", slug: "research" },
            { label: "Research Workflows", slug: "research-workflows" },
            { label: "Kernel VM Verification", slug: "kernel-vm" },
            {
              label: "Essays & Rationale",
              collapsed: true,
              items: [
                { label: "Shell-First Rationale", slug: "research/shell-first" },
                { label: "Agent Techniques", slug: "research/agent-techniques" },
                { label: "Model Comparison", slug: "research/model-comparison" },
                { label: "FP Reduction Moat", slug: "research/fp-reduction-moat" },
                { label: "TypeScript/Rust Boundary", slug: "research/typescript-rust-boundary" },
              ],
            },
            {
              label: "Triage ML",
              collapsed: true,
              items: [
                { label: "Finding Triage ML", slug: "research/finding-triage-ml" },
                { label: "Dynamic Routing Design", slug: "research/dynamic-routing-design" },
                { label: "Triage Dataset", slug: "research/triage-dataset" },
                { label: "Feature Extractor", slug: "research/feature-extractor" },
                { label: "Dynamic Triage Routing", slug: "research/dynamic-triage-routing" },
                { label: "Journal & Orchestrator", slug: "research/journal-orchestrator-design" },
              ],
            },
            {
              label: "Experiment Logs",
              collapsed: true,
              items: [
                { label: "2026-05-09 Control Flow, Not Prompts", slug: "research/2026-05-09-control-flow-not-prompts" },
                { label: "2026-05-08 Cost per Flag", slug: "research/2026-05-08-cost-per-flag" },
                { label: "2026-05-06 H1 Program Audit", slug: "research/2026-05-06-h1-ai-readiness" },
                { label: "2026-04-11 Ablation", slug: "research/2026-04-11-ablation" },
                { label: "XBEN-099 Investigation", slug: "research/xben-099-investigation" },
                { label: "Unsolved Eight Investigation", slug: "research/unsolved-eight-investigation" },
                { label: "Strix Implementation Comparison", slug: "research/strix-implementation-comparison" },
              ],
            },
          ],
        },
        {
          label: "Roadmap",
          slug: "roadmap",
        },
      ],
      customCss: ["./src/styles/custom.css"],
    }),
  ],
});
