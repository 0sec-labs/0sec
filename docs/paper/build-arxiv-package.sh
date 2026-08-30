#!/usr/bin/env bash
set -euo pipefail

OUT="0sec-arxiv-source.tar.gz"

rm -f "$OUT"

tar -czf "$OUT" \
  "0sec-submission.tex" \
  "0sec-submission.bbl" \
  "refs.bib"

echo "Wrote $(pwd)/$OUT"
