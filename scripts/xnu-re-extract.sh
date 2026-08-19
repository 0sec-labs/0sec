#!/usr/bin/env bash
#
# xnu-re-extract.sh — kernelcache -> kext -> decompiled pseudo-C, for the
# 0sec `xnu-re` review profile (closed Apple kext review).
#
# The open XNU source tree is hardened; the high-value LPE surface lives in
# the CLOSED kexts (AppleAVE, AGX/IOGPU, APFS, ...) that ship only as binaries
# inside the kernelcache. This script turns one of those kexts into
# decompiled pseudo-C an agent (the xnu-re profile) can review.
#
# Toolchain (all free): ipsw (kext split), radare2 + r2ghidra (decompile).
# macOS ships the kernel collections UNENCRYPTED on disk, so no IPSW download
# is needed to review the host's own kernel:
#   /System/Library/KernelCollections/{Boot,System}KernelExtensions.kc
#
# Verified on macOS 26.x arm64e with ipsw 3.1.x + radare2 6.1.x + r2ghidra.
#
# Usage:
#   xnu-re-extract.sh list   <kernelcache.kc>
#   xnu-re-extract.sh decomp <kernelcache.kc> <kext-bundle-id> <out-dir> [func-vaddr-or-name]
#
# Notes / gotchas baked in from the feasibility spike:
#   * Seek by VADDR, not by `sym.<name>` — name-seek mis-resolves to a neighbour.
#   * Cross-kext calls only resolve when analysing in-place against the full .kc;
#     single-kext extraction blinds the call graph. We extract for isolation but
#     ALSO emit an in-place decomp when a target vaddr is given.
#   * Debug-build stack poison (0xaa.../0x55...) and r2ghidra //WARNING lines are
#     stripped so they don't mislead the reviewing agent into fake findings.
set -euo pipefail

die() { echo "xnu-re-extract: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing tool: $1 (brew install $2)"; }

need ipsw blacktop/tap/ipsw
need r2 radare2
[ -f "$HOME/.local/share/radare2/plugins/core_ghidra.dylib" ] \
  || die "r2ghidra not installed — run: r2pm -U && r2pm -ci r2ghidra"

# Strip noise that produces hallucinated findings, keep everything else verbatim.
preprocess() {
  sed -E \
    -e 's/0x[aA]{8,16}/UNINIT/g' \
    -e 's/-?0x5{8,15}[0-9a-fA-F]?/UNINIT/g' \
    -e '/\/\/WARNING: /d'
}

cmd="${1:-}"; shift || true
case "$cmd" in
  list)
    kc="${1:?usage: list <kernelcache.kc>}"
    [ -f "$kc" ] || die "no such kernelcache: $kc"
    ipsw kernel kexts "$kc"
    ;;

  decomp)
    kc="${1:?kernelcache}"; bundle="${2:?kext-bundle-id}"; out="${3:?out-dir}"
    target="${4:-}"
    [ -f "$kc" ] || die "no such kernelcache: $kc"
    mkdir -p "$out"

    echo "[*] extracting $bundle from $(basename "$kc") ..."
    ipsw kernel extract "$kc" "$bundle" --output "$out" --force >/dev/null 2>&1 \
      || die "extract failed for '$bundle' (merged-into-parent kexts show 0x7fff.. in 'list' and cannot be extracted standalone)"
    kext="$(/bin/ls "$out"/* 2>/dev/null | grep -v '\.c$' | head -1)"
    [ -n "$kext" ] || die "no kext binary produced in $out"
    echo "[*] kext binary: $kext"

    if [ -n "$target" ]; then
      # Single function. Seek by vaddr if it looks like one; else resolve via 'is'.
      case "$target" in
        0x*) seek="$target" ;;
        *)   seek="$(r2 -e log.quiet=true -qc "is~$target" "$kext" | awk '{print $3}' | head -1)"
             [ -n "$seek" ] || die "symbol '$target' not found in $bundle" ;;
      esac
      echo "[*] decompiling $target @ $seek (in-place against full .kc for call-graph)"
      r2 -e log.quiet=true -e scr.color=0 -qc "s $seek; af; pdg" "$kc" \
        | preprocess > "$out/${bundle##*.}_${target//[^A-Za-z0-9_]/_}.c"
    else
      echo "[*] decompiling ALL functions in $bundle (this can be large) ..."
      r2 -e log.quiet=true -e scr.color=0 -qc "aaa; pdg @@f" "$kext" \
        | preprocess > "$out/${bundle##*.}_all.c"
    fi

    # Manifest: the dispatch-table map is what makes selector/count bugs mechanical.
    {
      echo "# xnu-re manifest for $bundle"
      echo "kernelcache: $kc"
      echo "extracted:   $kext"
      echo "## symbols (externalMethod / dispatch / copyin surface):"
      r2 -e log.quiet=true -qc "is~+externalMethod,Method,sMethods,getTargetAndMethod,clientMemoryForType" "$kext" 2>/dev/null || true
    } > "$out/${bundle}.manifest.txt"

    echo "[+] done. review artifacts in: $out"
    /bin/ls -la "$out"
    ;;

  *)
    die "usage:\n  xnu-re-extract.sh list   <kernelcache.kc>\n  xnu-re-extract.sh decomp <kernelcache.kc> <bundle-id> <out-dir> [func]"
    ;;
esac
