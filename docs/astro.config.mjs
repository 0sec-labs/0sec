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
        "Documentation for the 0sec CLI and managed cloud engagements: getting started, scope, workflows, and verification.",
      logo: {
        dark: "./src/assets/0sec-aperture-white.svg",
        light: "./src/assets/0sec-aperture-dark.svg",
        alt: "0sec",
        replacesTitle: true,
      },
      social: [
        {
          icon: "external",
          label: "Website",
          href: "https://0.security",
        },
      ],
      defaultLocale: "root",
      expressiveCode: {
        themes: ["github-dark", "github-light"],
      },
      sidebar: [
        {
          label: "Start Here",
          slug: "index",
        },
        {
          label: "Use the CLI",
          items: [
            { label: "Getting Started", slug: "getting-started" },
            { label: "Scan Workflows", slug: "scan-workflows" },
            { label: "Console", slug: "console" },
            { label: "Desktop", slug: "desktop" },
            { label: "Recipes", slug: "recipes" },
            { label: "Features", slug: "features" },
            { label: "Troubleshooting", slug: "troubleshooting" },
          ],
        },
        {
          label: "Reference & setup",
          items: [
            { label: "Commands", slug: "commands" },
            { label: "Configuration", slug: "configuration" },
            { label: "API Keys", slug: "api-keys" },
            { label: "Scope & Authorization", slug: "scope" },
            { label: "Budget Management", slug: "budget-management" },
            { label: "Authorized Engagements", slug: "engagements" },
            { label: "White-Box Mode", slug: "white-box-mode" },
            { label: "Integrations", slug: "integrations" },
            { label: "GitHub CI", slug: "ci/github-action" },
          ],
        },
        {
          label: "Cloud",
          items: [
            { label: "Overview", slug: "cloud" },
            { label: "Getting Started", slug: "cloud/getting-started" },
            { label: "Scope & Access", slug: "cloud/scope-and-access" },
            { label: "Review Evidence", slug: "cloud/review-evidence" },
          ],
        },
        {
          label: "Understand the engine",
          items: [
            { label: "Architecture", slug: "architecture" },
            { label: "Agent Loop", slug: "agent-loop" },
            { label: "Improvement Plane", slug: "improvement-plane" },
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
