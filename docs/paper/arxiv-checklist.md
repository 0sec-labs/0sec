# arXiv submission checklist (0sec)

Use this checklist right before uploading source to arXiv.

## 1) Files included in upload package

- `0sec-submission.tex`
- `0sec-submission.bbl`
- `refs.bib`

Current draft has no external figures. If figures are added later, include only
the exact files referenced by `\includegraphics`.

## 2) Files excluded from upload package

- `*.aux`
- `*.log`
- `*.out`
- `*.blg`
- `0sec-submission.pdf` (optional; usually not needed in source upload)

## 3) Metadata and claim hygiene checks

1. Confirm title and author block are final.
2. Ensure all headline numbers include an as-of date.
3. Ensure retained artifact-backed claims are not mixed with historical mixed
   publication claims.
4. Re-run table numbers against latest ledger before final upload.

## 4) Local compile checks

```bash
pdflatex -interaction=nonstopmode 0sec-submission.tex
bibtex 0sec-submission
pdflatex -interaction=nonstopmode 0sec-submission.tex
pdflatex -interaction=nonstopmode 0sec-submission.tex
```

Pass criteria:

- no missing reference/citation errors
- no missing file errors
