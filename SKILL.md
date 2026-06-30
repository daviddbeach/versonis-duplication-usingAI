---
name: data-privacy
description: >-
  Detect, quarantine, and mask personally identifiable information (PII) in
  local files. Use whenever the user wants to find, locate, scan for, isolate,
  move, redact, mask, scrub, sanitize, or anonymize personal data — names,
  emails, phone numbers, SSNs/SINs, credit cards, addresses, passports, bank
  or government IDs. Two capabilities: (1) scan a directory tree, identify
  which files are "personal information files", and move them to a quarantine
  folder (default ~/Desktop/Personal-Information) behind a dry-run-and-confirm
  gate; (2) produce PII-masked COPIES of markdown files so they can be safely
  ingested into an AI pipeline (RAG, fine-tuning, prompts) without leaking
  personal data. Trigger even on informal phrasings like "clean up the PII in
  this folder", "redact this note before I feed it to the model", or "make
  these markdown files safe for ingestion". Prefer this over ad-hoc
  grep/regex whenever the task involves personal data, privacy, or
  AI-ingestion safety.
---

# Data Privacy

Two PII workflows over local files, both built on the same detection engine
(Microsoft Presidio + spaCy NER + regex/Luhn recognizers + Tesseract OCR):

1. **Quarantine** — find files that *are* personal-information files and move
   them into one folder. (`scripts/quarantine_pii.py`)
2. **Mask** — write PII-masked copies of markdown files for safe AI ingestion,
   leaving the originals untouched. (`scripts/mask_markdown.py`)

The engine and scoring logic live in `scripts/pii_engine.py`. The PII
categories and sensitivity tiers are documented in
`references/pii-taxonomy.md` — read that file when you need to explain a
result or tune behavior.

## Before anything else: setup

The skill needs Python packages, a spaCy NER model, and (for images)
Tesseract. Run once:

```bash
python scripts/setup_env.py
```

If you see `ModelNotInstalled` at runtime, the spaCy model is missing — run
setup. On macOS, if image scanning is skipped, install Tesseract with
`brew install tesseract`.

## Core safety principles

These are the point of the skill. Do not shortcut them.

- **Moving is destructive; confirm first.** Function 1 is split into `scan`
  (read-only, writes a report) and `apply` (moves files). NEVER run `apply`
  until you've shown the user the scan preview and they've explicitly
  approved. `apply` refuses to run without `--yes`.
- **Masking never touches originals.** Function 2 only writes new files into
  a separate output folder.
- **Manifests, not values.** Both functions write a manifest. The masking
  manifest records only *counts per PII type*, never the redacted values —
  writing the values back out would re-leak exactly what you removed. Never
  print discovered PII values back to the user beyond the minimum needed to
  confirm a detection.
- **Detection is probabilistic.** Always review before acting. Tune
  `--sensitivity` and `--min-score` rather than assuming the defaults are
  perfect for the user's data.

---

## Function 1 — Quarantine PII files

Walk a directory recursively, score each supported file, and move the
personal-information files to a quarantine folder, preserving their relative
paths.

### Step 1 — Scan (read-only)

```bash
python scripts/quarantine_pii.py scan "<DIRECTORY>" \
    --sensitivity medium \
    --out pii_report.json
```

This reads every supported file (text, `.docx`, `.xlsx`, `.pptx`, `.pdf`,
and images via OCR), detects PII, and writes `pii_report.json`. It moves
nothing. Show the user the printed preview: how many files were flagged,
which ones, and why.

Useful flags:
- `--sensitivity {low,medium,high}` — how eagerly to flag. Default `medium`.
  See the taxonomy reference for exact thresholds. Lower it if ordinary
  business docs are getting flagged; raise it to catch single-name files.
- `--min-score 0.4` — detector confidence floor (0–1).
- `--exclude DATE_TIME` — ignore specific entity types.
- `--dest "<PATH>"` — quarantine destination (default
  `~/Desktop/Personal-Information`).

### Step 2 — Get explicit confirmation

Present the flagged list and ask the user to confirm. Tell them they can
**edit the report's `flagged` array** to drop false positives before
applying — `apply` only moves what's listed there. This is the moment to
catch mistakes.

### Step 3 — Apply the move

After the user confirms:

```bash
python scripts/quarantine_pii.py apply pii_report.json --yes
```

Files move to the destination with their relative paths preserved (so
`hr/roster.xlsx` lands at `Personal-Information/hr/roster.xlsx`), name
collisions are auto-suffixed, and a `_quarantine_manifest_<timestamp>.json`
records every move. Report the result and the manifest path to the user.

---

## Function 2 — Mask markdown for AI ingestion

Produce masked copies of markdown files so personal data never reaches an
AI pipeline.

```bash
python scripts/mask_markdown.py "<FILE_OR_DIR>" \
    --out "<OUTPUT_DIR>" \
    --style asterisks
```

- Input may be a single `.md`/`.markdown` file or a directory (searched
  recursively). Markdown structure (headings, lists, links) is preserved.
- Output defaults to `~/Desktop/Masked-Markdown`, mirroring the input tree.
  **Originals are never modified.**
- `--style asterisks` (default) replaces each PII span with `*****`.
  `--style tokens` instead emits `[REDACTED_<TYPE>]`, which keeps the
  sentence structure so a downstream model still understands "an email went
  here" — often better for RAG/prompting. Offer this option when the masked
  text will be read by another model.
- `--mask "<STRING>"` customizes the asterisk replacement.
- `--exclude DATE_TIME` / `--min-score` behave as in Function 1.

A `_mask_manifest_<timestamp>.json` records per-file redaction counts by
type (values are never stored). After running, suggest the user spot-check a
masked file before ingestion.

---

## Choosing the right function

**Example 1:**
User: "Go through my Downloads folder and pull out anything with personal info into one place."
Action: Function 1 — `scan` Downloads, show the preview, confirm, then `apply`.

**Example 2:**
User: "I'm about to load my Obsidian vault into a RAG system — scrub the PII first."
Action: Function 2 — `mask_markdown.py` over the vault into a separate output
folder. Recommend `--style tokens` since the output feeds a model.

**Example 3:**
User: "Find files with SSNs or card numbers but leave anything that just has a name."
Action: Function 1 with `--sensitivity low` (HIGH-tier identifiers only).

## Limitations to communicate

- Name/address detection depends on the spaCy model; without
  `en_core_web_lg`, recall on PERSON/LOCATION drops (structured PII still
  works). See the taxonomy reference.
- `DATE_TIME` is broad and will mask ordinary dates unless excluded.
- Scanned/image-only PDFs are flagged for manual review rather than guessed.
- No tool catches 100% of PII. The dry-run preview and the masked-copy
  (never-overwrite) design exist precisely so a miss or a false positive is
  recoverable.
