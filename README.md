# Data Privacy — Skill Spec & Tuning Guide

A skill with two PII workflows over local files:

1. **Quarantine** — find files that *are* personal-information files and move
   them into one folder (default `~/Desktop/Personal-Information`), behind a
   dry-run-then-confirm gate.
2. **Mask** — write PII-masked *copies* of markdown files for safe AI
   ingestion (RAG, fine-tuning, prompts), leaving originals untouched.

Detection stack: Microsoft Presidio + spaCy NER (`en_core_web_lg`) + regex /
Luhn recognizers + Tesseract OCR for images. A custom Luhn-validated Canadian
SIN recognizer is included alongside Presidio's built-ins.

---

## One-time setup

```bash
python scripts/setup_env.py
```

Installs the Python dependencies, downloads the spaCy model, and checks for
Tesseract. On macOS, if Tesseract is missing: `brew install tesseract`.
Add `--small-model` to install the lighter (less accurate) `en_core_web_sm`,
or `--break-system-packages` if your Python environment requires it.

---

## Function 1 — Quarantine PII files

```bash
# 1) dry run — reads files, writes a report, MOVES NOTHING
python scripts/quarantine_pii.py scan "<DIRECTORY>" --out pii_report.json

# 2) review the printed preview / edit pii_report.json to drop false positives

# 3) move the flagged files (requires --yes)
python scripts/quarantine_pii.py apply pii_report.json --yes
```

Files move with their relative paths preserved, collisions are auto-suffixed,
and `_quarantine_manifest_<timestamp>.json` logs every move.

## Function 2 — Mask markdown for AI ingestion

```bash
python scripts/mask_markdown.py "<FILE_OR_DIR>" --out "<OUTPUT_DIR>"
```

Originals are never modified. Output mirrors the input tree.
`_mask_manifest_<timestamp>.json` records redaction counts per type (never the
values themselves).

---

## How to adjust things

All knobs are command-line flags — no code editing required.

### Sensitivity (Function 1: how eagerly files get flagged)
`--sensitivity {low,medium,high}` (default `medium`)

| Preset   | A file is flagged when…                                        |
|----------|----------------------------------------------------------------|
| `low`    | a HIGH-tier identifier is present (SSN, SIN, card, passport…)  |
| `medium` | a HIGH-tier hit, OR ≥2 distinct LOW types, OR ≥4 LOW instances |
| `high`   | any single PII hit of any tier                                 |

Getting false positives on ordinary business docs? Use `low`. Need to catch
files that contain only a name or single email? Use `high`.

### Detector confidence
`--min-score 0.4` (0–1) on either script. Raise it for fewer false positives,
lower it for higher recall.

### Ignore specific PII types
`--exclude DATE_TIME PHONE_NUMBER …` on either script. `DATE_TIME` is the
common one to exclude, since it matches ordinary dates, not just dates of
birth.

### Mask style (Function 2)
- `--style asterisks` (default) → replaces each span with `*****`
- `--style tokens` → replaces with `[REDACTED_<TYPE>]`, preserving sentence
  structure for downstream models (recommended when the output feeds an AI)
- `--mask "<STRING>"` → custom replacement for the asterisks style

### Destinations / output
- Function 1: `--dest "<PATH>"` (default `~/Desktop/Personal-Information`)
- Function 2: `--out "<PATH>"` (default `~/Desktop/Masked-Markdown`)

### Unit Testing / output 
- Function 1: `--dest "<PATH>"` (test directory `test/Personal-Information`)
- Function 2: `--out "<PATH>"` (test directory `test/Masked-Markdown`)

### Tuning the tiers themselves
To change which entity types count as HIGH vs LOW, or the exact thresholds in
each preset, edit `HIGH_TIER`, `LOW_TIER`, and `SENSITIVITY_PRESETS` near the
top of `scripts/pii_engine.py`. See `references/pii-taxonomy.md` for the full
entity table and rationale.

---

## Supported file types

Text (`.txt`, `.md`, `.csv`, `.json`, `.yaml`, `.html`, …), `.docx`, `.xlsx`,
`.pptx`, `.pdf` (text-based), and images (`.png`, `.jpg`, `.tiff`, …) via OCR.
Scanned/image-only PDFs are flagged for manual review rather than guessed.

## Limitations

- Name/address detection depends on the spaCy model; without `en_core_web_lg`
  recall on PERSON/LOCATION drops (structured PII still works).
- Detection is probabilistic — no tool catches 100% of PII. The dry-run
  preview and never-overwrite design make a miss or false positive
  recoverable. Always review the preview before moving and spot-check masked
  output before ingestion.
