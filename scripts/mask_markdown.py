#!/usr/bin/env python3
"""
mask_markdown.py — Function 2 of the Data Privacy skill.

Produce PII-masked COPIES of markdown files so they can be safely ingested
into an AI pipeline (RAG, fine-tuning, prompts) without leaking personal data.

Key safety properties:
  * Originals are never modified. Masked copies are written to a separate
    output folder (default: ~/Desktop/Masked-Markdown), preserving the input
    tree structure.
  * Default masking replaces each PII span with literal "*****". Use
    --style tokens to instead emit [REDACTED_<TYPE>] markers, which keep the
    sentence structure intact for downstream models.
  * The manifest records only COUNTS per PII type, never the PII values
    themselves — writing the values back out would re-leak what we redacted.

Examples
--------
    python mask_markdown.py ~/vault/notes
    python mask_markdown.py ~/vault/notes --out ~/Desktop/Masked --style tokens
    python mask_markdown.py single_note.md
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pii_engine as pe  # noqa: E402

DEFAULT_OUT = "~/Desktop/Masked-Markdown"
MD_EXTS = {".md", ".markdown"}


def _now() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def _collect_markdown(target: Path):
    if target.is_file():
        return [target] if target.suffix.lower() in MD_EXTS else []
    return sorted(p for p in target.rglob("*")
                  if p.is_file() and p.suffix.lower() in MD_EXTS)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Mask PII in markdown files, writing masked copies.")
    p.add_argument("input", help="markdown file, or directory to search recursively")
    p.add_argument("--out", default=DEFAULT_OUT,
                   help=f"output folder for masked copies (default: {DEFAULT_OUT})")
    p.add_argument("--style", choices=["asterisks", "tokens"], default="asterisks",
                   help="asterisks -> '*****' (default); tokens -> [REDACTED_TYPE]")
    p.add_argument("--mask", default="*****",
                   help="replacement string when --style asterisks (default: *****)")
    p.add_argument("--min-score", type=float, default=0.4,
                   help="minimum detector confidence (0-1)")
    p.add_argument("--exclude", nargs="*", default=[],
                   help="PII entity types to ignore, e.g. --exclude DATE_TIME")
    args = p.parse_args(argv)

    target = Path(os.path.expanduser(args.input)).resolve()
    if not target.exists():
        print(f"error: not found: {target}", file=sys.stderr)
        return 2

    files = _collect_markdown(target)
    if not files:
        print("No markdown (.md/.markdown) files found.", file=sys.stderr)
        return 1

    out_root = Path(os.path.expanduser(args.out)).resolve()
    base = target if target.is_dir() else target.parent

    try:
        analyzer = pe.build_analyzer()
    except pe.ModelNotInstalled as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    model = getattr(analyzer, "_dp_model_name", None)

    items, errors = [], []
    total_redactions = 0

    for src in files:
        try:
            text = src.read_text(encoding="utf-8", errors="ignore")
            entities = [e for e in pe.DEFAULT_ENTITIES if e not in set(args.exclude)]
            results = pe.analyze_text(analyzer, text, min_score=args.min_score,
                                      entities=entities)
            masked = pe.mask_text(text, results, style=args.style, mask=args.mask)

            try:
                rel = src.relative_to(base)
            except ValueError:
                rel = Path(src.name)
            dest = out_root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(masked, encoding="utf-8")

            counts: dict[str, int] = {}
            for r in results:
                counts[r.entity_type] = counts.get(r.entity_type, 0) + 1
            total_redactions += len(results)
            items.append({"source": str(src), "masked_copy": str(dest),
                          "redactions": len(results), "by_type": counts})
        except Exception as e:
            errors.append({"path": str(src), "error": f"{type(e).__name__}: {e}"})

    manifest = {
        "generated_at": _now(),
        "input": str(target),
        "output_root": str(out_root),
        "style": args.style,
        "model": model,
        "summary": {"files_masked": len(items), "total_redactions": total_redactions,
                    "errors": len(errors)},
        "items": items,        # counts only — never the redacted values
        "errors": errors,
    }
    manifest_path = out_root / f"_mask_manifest_{dt.datetime.now():%Y%m%d_%H%M%S}.json"
    out_root.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print("=" * 70)
    print("MARKDOWN PII MASKING — masked copies written")
    print("=" * 70)
    print(f"Input:   {target}")
    print(f"Output:  {out_root}  (originals untouched)")
    print(f"Style:   {args.style}    NER model: {model}")
    print(f"Masked {len(items)} file(s), {total_redactions} redaction(s) total.")
    for it in items:
        bits = ", ".join(f"{k}:{v}" for k, v in sorted(it["by_type"].items()))
        print(f"  {Path(it['source']).name}: {it['redactions']} "
              f"({bits or 'none'})")
    if errors:
        print(f"{len(errors)} error(s):")
        for e in errors:
            print(f"  {e['path']}  ({e['error']})")
    print(f"Manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
