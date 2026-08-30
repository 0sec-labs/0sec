# 0sec paper workspace

This folder mirrors the noeris paper workflow pattern:

- one living narrative draft (`0sec.md`)
- one submission-oriented LaTeX draft (`0sec-submission.tex`)
- split support notes for evaluation and related work

## Files

- `0sec.md` - canonical long-form draft with repo-grounded claims
- `0sec-submission.tex` - arXiv-style LaTeX draft
- `evaluation.md` - canonical table/numbers source for paper text
- `related_work.md` - comparison/citation notes with caveats
- `refs.bib` - bibliography database for LaTeX draft
- `arxiv-checklist.md` - pre-upload checklist
- `build-arxiv-package.sh` - creates minimal source tarball

## Build

From this directory:

```bash
pdflatex -interaction=nonstopmode "0sec-submission.tex"
pdflatex -interaction=nonstopmode "0sec-submission.tex"
```

With bibliography:

```bash
pdflatex -interaction=nonstopmode "0sec-submission.tex"
bibtex "0sec-submission"
pdflatex -interaction=nonstopmode "0sec-submission.tex"
pdflatex -interaction=nonstopmode "0sec-submission.tex"
```

Create arXiv source package:

```bash
bash "build-arxiv-package.sh"
```

## Claim hygiene

Before any public submission:

1. Re-validate all numbers against latest benchmark artifacts.
2. Stamp every headline number with an as-of date.
3. Keep retained artifact-backed claims separate from historical mixed claims.
4. Avoid cross-project leaderboard comparisons without protocol caveats.
