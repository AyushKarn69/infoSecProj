# RiskShare research paper (LaTeX)

IEEE conference-format paper drafted from `docs/`, the source code, and the recorded experiment results.

## Files

- `main.tex`: paper source (IEEEtran). Diagrams are TikZ, and charts are pgfplots that read `data/*.dat`.
- `references.bib`: bibliography (30 entries).
- `data/*.dat`: tables aggregated from `docs/experiments/results/riskshare-experiments.csv`.
- `scripts/aggregate_results.py`: regenerates `data/` (standard library only).
- `figures/ui-*.png`: Control Room screenshots, captured from a local demo run with simulated events.
- `main.pdf`: compiled output.

## Build

```bash
python paper/scripts/aggregate_results.py
cd paper && tectonic main.tex
```

Alternatively, run `pdflatex main && bibtex main && pdflatex main && pdflatex main`, or upload the `paper/` folder to Overleaf.

## Before submission

- Check the bibliography entries against the publishers' records. The Boneh–Partap–Rotem (CRYPTO 2024) entry has no page numbers.
- If you rerun `scripts/run_experiments.py`, rerun the aggregation script and update the numbers quoted in the text and in Tables III–IV.
