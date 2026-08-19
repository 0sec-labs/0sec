#!/usr/bin/env bash
set -euo pipefail

OUT="pwnkit-arxiv-source.tar.gz"

rm -f "$OUT"

tar -czf "$OUT" \
  "pwnkit-submission.tex" \
  "pwnkit-submission.bbl" \
  "refs.bib"

echo "Wrote $(pwd)/$OUT"
