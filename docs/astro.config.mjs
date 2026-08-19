import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";
import rehypeMermaid from "rehype-mermaid";

export default defineConfig({
  output: "static",
  outDir: "./dist",
  site: "https://docs.0sec.ai",
  markdown: {
    // Render ```mermaid code blocks as SVG at build time
    syntaxHighlight: { type: "shiki", excludeLangs: ["mermaid"] },
    rehypePlugins: [
      [rehypeMermaid, { strategy: "img-svg", dark: true }],
    ],
  },
  integrations: [
    starlight({
      title: "0sec",
      description:
        "Open-source security research harness for authorized targets. The technical project and CLI are named pwnkit.",
      logo: {
        src: "./src/assets/0sec-aperture-white.svg",
        alt: "0sec",
      },
      social: [
        {
          icon: "external",
          label: "Website",
          href: "https://0sec.ai",
        },
      ],
      defaultLocale: "root",
      expressiveCode: {
        themes: ["dracula"],
      },
      sidebar: [
        {
          label: "Getting Started",
          slug: "getting-started",
        },
        {
          label: "Usage",
          items: [
            { label: "Commands", slug: "commands" },
            { label: "Configuration", slug: "configuration" },
            { label: "Recipes", slug: "recipes" },
            { label: "Features", slug: "features" },
            { label: "White-Box Mode", slug: "white-box-mode" },
            { label: "Kernel VM Verification", slug: "kernel-vm" },
            { label: "Budget Management", slug: "budget-management" },
            { label: "API Keys", slug: "api-keys" },
            { label: "Cloud", slug: "cloud" },
            { label: "Authorized Engagements", slug: "engagements" },
            { label: "GitHub Action (PR scans)", slug: "ci/github-action" },
            { label: "Enterprise readiness", slug: "enterprise" },
          ],
        },
        {
          label: "How It Works",
          items: [
            { label: "Architecture", slug: "architecture" },
            { label: "Agent Loop", slug: "agent-loop" },
            { label: "Finding Triage", slug: "triage" },
            { label: "Blind Verification", slug: "blind-verification" },
            { label: "Verification Results", slug: "verification-result" },
            { label: "Adversarial Evals", slug: "adversarial-evals" },
          ],
        },
        {
          label: "Benchmarks",
          items: [
            { label: "Results", slug: "benchmark" },
            { label: "Methodology", slug: "methodology" },
            { label: "XBOW Analysis", slug: "research/xbow-analysis" },
            { label: "Competitive Landscape", slug: "research/competitive-landscape" },
          ],
        },
        {
          label: "Research",
          items: [
            { label: "Overview", slug: "research" },
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
                { label: "XBEN-099 Investigation", slug: "research/xben-099-investigation" },
                { label: "Unsolved Eight Investigation", slug: "research/unsolved-eight-investigation" },
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
