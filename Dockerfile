# syntax=docker/dockerfile:1.7
#
# pwnkit — pre-built distribution image
#
# Multi-stage build:
#   stage 1 (builder): node:20 + pnpm, builds the bundled CLI in /app/dist
#   stage 2 (runtime): ubuntu:24.04 + Node 20 + pentest tooling + Playwright
#
# Usage:
#   docker run --rm -e AZURE_OPENAI_API_KEY=$KEY \
#     ghcr.io/0sec-labs/pwnkit:latest scan --target https://example.com --scope /work/scope.json
# Build args:
#   INSTALL_SECLISTS=1     include SecLists wordlists (~1GB extra, off by default)
#   AZUREHOUND_VERSION=vX  pin the AzureHound release (checksum-verified, see below)

# ---------- Stage 1: builder ----------
FROM node:24-bookworm AS builder

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

# Install the bundle's locked runtime dependencies without lifecycle scripts.
WORKDIR /app/dist
RUN npm ci --omit=dev --ignore-scripts

# ---------- Stage 2: runtime ----------
FROM ubuntu:24.04 AS runtime

ARG INSTALL_SECLISTS=0
ARG DEBIAN_FRONTEND=noninteractive

ENV NODE_ENV=production \
    PWNKIT_DOCKER=1 \
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

# ---------- Active Directory / cloud-identity tooling ----------
# Kept as its own block (rather than folded into the base apt line above) so it
# lands before the app COPY: iterating on engine code doesn't re-run any of it.
#
#   ldap-utils   ldapsearch — raw LDAP enumeration, the cheap first probe before
#                committing to a full graph collection
#   krb5-user    kinit/klist/kdestroy — ticket handling for Kerberos-auth runs
#                and for feeding TGTs to the impacket scripts below
#   python3-venv ubuntu:24.04 ships python3 without ensurepip; needed for the
#                venv created in the next layer
RUN apt-get update && apt-get install -y --no-install-recommends \
        ldap-utils krb5-user python3-venv \
    && rm -rf /var/lib/apt/lists/*

# Impacket + Certipy + the BloodHound CE collector come from PyPI, not apt.
#
# ubuntu:24.04 marks the system interpreter EXTERNALLY-MANAGED (PEP 668), so a
# bare `pip install` aborts. The two escapes are `--break-system-packages` and a
# venv; this uses a venv. `--break-system-packages` would let these packages'
# deep, tightly-pinned dependency trees (certipy-ad pins cryptography and
# impacket to exact minor ranges) overwrite the apt-managed python3-requests /
# python3-bs4 that the agent's own helper scripts import — a silent way to break
# unrelated scanning.
#
# The venv is deliberately NOT added to PATH: its bin/ contains a `python3` that
# would shadow the system interpreter and hide those same apt-installed modules.
# The console scripts are symlinked into /usr/local/bin instead — their shebangs
# hardcode the venv interpreter's absolute path, so they resolve correctly when
# invoked through the symlink.
#
# Impacket declares its examples via setuptools `scripts=`, so they install
# under their original filenames (secretsdump.py, GetUserSPNs.py, GetNPUsers.py,
# psexec.py, wmiexec.py, ntlmrelayx.py, ...) — hence the *.py symlink loop.
# bloodhound-ce is the CE-format collector whose JSON the `adgraph` analyzer
# ingests; the legacy `bloodhound` package emits the old pre-CE schema.
RUN python3 -m venv /opt/ad-tools \
    && /opt/ad-tools/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/ad-tools/bin/pip install --no-cache-dir \
        impacket==0.13.1 \
        certipy-ad==5.1.0 \
        bloodhound-ce==1.9.1 \
    && for f in /opt/ad-tools/bin/*.py; do ln -sf "$f" /usr/local/bin/; done \
    && ln -sf /opt/ad-tools/bin/certipy /usr/local/bin/certipy \
    && ln -sf /opt/ad-tools/bin/bloodhound-ce-python /usr/local/bin/bloodhound-ce-python \
    && rm -rf /root/.cache/pip

# AzureHound — the Azure/Entra collector. It's a Go binary shipped as a GitHub
# release asset, so there's no apt/pip package to pin; instead the tag is pinned
# and the download is checked against a SHA-256 recorded here. These two digests
# are the vendor-published `.sha256` sidecars, independently reproduced by
# downloading and hashing both archives (2026-07-27) — not copied on trust. If
# SpecterOps ever replaces the assets behind the tag, this build fails loudly
# instead of silently shipping different code.
#
# Default-on (unlike INSTALL_SECLISTS) because it's ~13MB and verifiable; the
# opt-in pattern is reserved for heavy or unverifiable additions.
ARG AZUREHOUND_VERSION=v3.0.0
ARG TARGETARCH
RUN set -eux; \
    arch="${TARGETARCH:-amd64}"; \
    case "$arch" in \
        amd64) sha256=d4bc8a09d90a5e6f0a1c8850ac732e6eeee93767edb13c1bdb85082156821d39 ;; \
        arm64) sha256=40811a96fc95022e49186de14b5defeabbb21e27d9300382b0405057c2f66365 ;; \
        *) echo "AzureHound ${AZUREHOUND_VERSION}: no pinned checksum for TARGETARCH=${arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/azurehound.zip \
        "https://github.com/SpecterOps/AzureHound/releases/download/${AZUREHOUND_VERSION}/AzureHound_${AZUREHOUND_VERSION}_linux_${arch}.zip"; \
    echo "${sha256}  /tmp/azurehound.zip" | sha256sum -c -; \
    unzip -j /tmp/azurehound.zip azurehound -d /usr/local/bin; \
    chmod +x /usr/local/bin/azurehound; \
    rm -f /tmp/azurehound.zip

WORKDIR /app

# Copy the bundled CLI + its production node_modules from the builder
COPY --from=builder /app/dist /app/dist


# Make the bundled CLI globally invocable as `pwnkit`.
RUN ln -s /app/dist/pwnkit.js /usr/local/bin/pwnkit \
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
