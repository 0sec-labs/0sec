# syntax=docker/dockerfile:1.7
#
# pwnkit-cli — pre-built distribution image
#
# Multi-stage build:
#   stage 1 (builder): node:20 + pnpm, builds the bundled CLI in /app/dist
#   stage 2 (runtime): ubuntu:24.04 + Node 20 + pentest tooling + Playwright
#
# Usage:
#   docker run --rm -e AZURE_OPENAI_API_KEY=$KEY \
#     ghcr.io/peaktwilight/pwnkit:latest scan --target https://example.com
#
# Build args:
#   INSTALL_SECLISTS=1   include SecLists wordlists (~1GB extra, off by default)

# ---------- Stage 1: builder ----------
FROM node:20-bookworm AS builder

ENV PNPM_HOME=/root/.local/share/pnpm \
    PATH=/root/.local/share/pnpm:$PATH \
    CI=1

RUN corepack enable && corepack prepare pnpm@9 --activate

WORKDIR /app

# Copy manifests first for better layer caching
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY tsconfig.base.json ./
COPY scripts ./scripts
COPY packages ./packages
COPY assets ./assets

# Pull in any other workspace files referenced by package.json globs
COPY LICENSE README.md ./

RUN pnpm install --frozen-lockfile
RUN pnpm build

# Install runtime production deps that the bundle externalizes
# (better-sqlite3, drizzle-orm, cfonts) into dist/node_modules.
# playwright is installed in the runtime stage via apt + pip-less npm install.
WORKDIR /app/dist
RUN npm install --omit=dev --no-audit --no-fund

# ---------- Stage 2: runtime ----------
FROM ubuntu:24.04 AS runtime

ARG INSTALL_SECLISTS=0
ARG DEBIAN_FRONTEND=noninteractive

ENV NODE_ENV=production \
    PWNKIT_DOCKER=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PATH=/usr/local/bin:/usr/bin:/bin

# Base system + Node 20 + pentest tooling.
# `ripgrep` is included because the audit/scan agent's discovery loop
# defaults to `rg` for fast source-tree searches across npm/cargo/oci
# packages — without it, every audit run logs `spawnSync rg ENOENT`
# and the agent falls back to slower `find` + per-file reads, hurting
# scan quality. Cheap to add (a few MB) and the agent has been
# expecting it since the audit subcommand shipped.
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl wget gnupg jq git unzip xz-utils \
        ripgrep \
        skopeo \
        python3 python3-requests python3-bs4 \
        sqlmap nmap nikto gobuster hydra john ffuf wfuzz \
        whatweb wafw00f dirb \
    && rm -rf /var/lib/apt/lists/*

# Node.js from builder stage (no remote script execution)
COPY --from=builder /usr/local/bin/node /usr/local/bin/node
COPY --from=builder /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -sf ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -sf ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# Optional: SecLists wordlists (large)
RUN if [ "$INSTALL_SECLISTS" = "1" ]; then \
        apt-get update && apt-get install -y --no-install-recommends seclists \
        && rm -rf /var/lib/apt/lists/*; \
    fi

WORKDIR /app

# Copy the bundled CLI + its production node_modules from the builder
COPY --from=builder /app/dist /app/dist

# Install Playwright + Chromium with system deps.
# Pinning to whatever the bundle's package.json expects via the workspace
# isn't necessary — playwright is externalized, so any recent version works.
RUN npm install -g playwright@1.48.0 \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/* /root/.npm

# Make the bundled CLI globally invocable as `pwnkit-cli` too
RUN ln -s /app/dist/pwnkit.js /usr/local/bin/pwnkit-cli \
    && chmod +x /app/dist/pwnkit.js

# Drop privileges by reusing the default ubuntu user (uid 1000) shipped with
# ubuntu:24.04. Runtime code and browser assets are read-only to this user;
# only the working directory needs ownership. Avoid recursively chowning the
# large Playwright tree here: overlayfs metadata rewrites can take many minutes
# on self-hosted runners and do not change runtime access.
RUN install -d -o ubuntu -g ubuntu /work
USER ubuntu
WORKDIR /work

ENTRYPOINT ["node", "/app/dist/pwnkit.js"]
CMD ["--help"]
