#!/usr/bin/env python3
"""
quarantine_pii.py — Function 1 of the Data Privacy skill.

Find files that are "personal information files" inside a directory tree and
move them to a quarantine folder (default: ~/Desktop/Personal-Information).

Moving files is destructive, so this is a TWO-STEP, confirmation-gated flow:

    1) scan   -> read every supported file, detect PII, score each file,
                 write a JSON report and print a preview. NOTHING is moved.
    2) apply  -> read the report and move the flagged files, writing a
                 manifest of every move. Refuses to run without --yes.

Examples
--------
    python quarantine_pii.py scan  ~/Documents/intake --sensitivity medium
    # review the preview, then:
    python quarantine_pii.py apply report.json --yes

The scan never modifies anything. apply only moves files listed as flagged
in the report you pass it, so you can hand-edit the report to drop any
false positives before applying.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shutil
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pii_engine as pe  # noqa: E402

DEFAULT_DEST = "~/Desktop/Personal-Information"


def _now() -> str:
    return dt.datetime.now().isoformat(timespec="seconds")


def _iter_files(root: Path, dest: Path):
    """Yield supported files under root, skipping the quarantine dest tree."""
    dest_resolved = dest.resolve()
    for dirpath, dirnames, filenames in os.walk(root):
        # never descend into the quarantine folder
        dirnames[:] = [d for d in dirnames
                       if (Path(dirpath) / d).resolve() != dest_resolved]
        for name in filenames:
            yield Path(dirpath) / name


def cmd_scan(args) -> int:
    root = Path(os.path.expanduser(args.directory)).resolve()
    if not root.is_dir():
        print(f"error: not a directory: {root}", file=sys.stderr)
        return 2
    dest = Path(os.path.expanduser(args.dest))

    try:
        analyzer = pe.build_analyzer()
    except pe.ModelNotInstalled as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    model = getattr(analyzer, "_dp_model_name", None)

    flagged, skipped, errors = [], [], []
    scanned = 0

    for path in _iter_files(root, dest):
        ext = path.suffix.lower()
        if ext not in pe.SCANNABLE_EXTS:
            skipped.append({"path": str(path), "reason": f"unsupported {ext}"})
            continue
        try:
            text = pe.extract_text(str(path))
            scanned += 1
            if "__DP_SCANNED_PDF__" in text:
                skipped.append({"path": str(path),
                                "reason": "scanned/image-only PDF; review manually"})
            entities = [e for e in pe.DEFAULT_ENTITIES if e not in set(args.exclude)]
            results = pe.analyze_text(analyzer, text, min_score=args.min_score,
                                      entities=entities)
            verdict = pe.score_file(str(path), results,
                                    sensitivity=args.sensitivity)
            if verdict.flagged:
                flagged.append({
                    "path": str(path),
                    "reason": verdict.reason,
                    "entity_counts": verdict.entity_counts,
                    "high_hits": verdict.high_hits,
                    "size_bytes": path.stat().st_size,
                })
        except Exception as e:  # keep going; record the failure
            errors.append({"path": str(path), "error": f"{type(e).__name__}: {e}"})

    report = {
        "scanned_root": str(root),
        "dest": str(dest),
        "sensitivity": args.sensitivity,
        "min_score": args.min_score,
        "model": model,
        "generated_at": _now(),
        "summary": {"scanned": scanned, "flagged": len(flagged),
                    "skipped": len(skipped), "errors": len(errors)},
        "flagged": sorted(flagged, key=lambda x: x["path"]),
        "skipped": skipped,
        "errors": errors,
    }
    out = Path(os.path.expanduser(args.out))
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")

    _print_preview(report, out)
    return 0


def _print_preview(report: dict, out_path: Path) -> None:
    s = report["summary"]
    print("\n" + "=" * 70)
    print("PII SCAN — DRY RUN (no files moved)")
    print("=" * 70)
    print(f"Root:        {report['scanned_root']}")
    print(f"Destination: {report['dest']}  (would be created if missing)")
    print(f"Sensitivity: {report['sensitivity']}   NER model: {report['model']}")
    print(f"Scanned {s['scanned']} files | flagged {s['flagged']} | "
          f"skipped {s['skipped']} | errors {s['errors']}")
    print("-" * 70)
    if not report["flagged"]:
        print("No personal-information files identified at this sensitivity.")
    else:
        print(f"{'FILE':52}  WHY")
        for item in report["flagged"]:
            rel = item["path"]
            if len(rel) > 50:
                rel = "…" + rel[-49:]
            print(f"{rel:52}  {item['reason']}")
    if report["errors"]:
        print("-" * 70)
        print("Could not read (left in place):")
        for e in report["errors"][:10]:
            print(f"  {e['path']}  ({e['error']})")
    print("-" * 70)
    print(f"Report written to: {out_path}")
    print("To move the flagged files, review the list above, then run:")
    print(f"    python quarantine_pii.py apply {out_path} --yes")
    print("(Edit the report's \"flagged\" list first to drop any false "
          "positives.)\n")


def cmd_apply(args) -> int:
    report_path = Path(os.path.expanduser(args.report))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    dest = Path(os.path.expanduser(args.dest or report.get("dest", DEFAULT_DEST)))
    root = Path(report["scanned_root"])
    flagged = report.get("flagged", [])

    if not flagged:
        print("Nothing to move — no flagged files in the report.")
        return 0

    if not args.yes:
        print(f"Refusing to move {len(flagged)} file(s) without --yes.")
        print("Re-run with --yes once you've reviewed the report.")
        return 1

    dest.mkdir(parents=True, exist_ok=True)
    moved, failures = [], []

    for item in flagged:
        src = Path(item["path"])
        try:
            # preserve provenance: recreate the path relative to the scan root
            try:
                rel = src.resolve().relative_to(root.resolve())
            except ValueError:
                rel = Path(src.name)
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            # collision-safe
            if target.exists():
                stem, suf = target.stem, target.suffix
                i = 1
                while target.exists():
                    target = target.with_name(f"{stem}__{i}{suf}")
                    i += 1
            if not src.exists():
                failures.append({"path": str(src), "error": "missing at apply time"})
                continue
            shutil.move(str(src), str(target))
            moved.append({"original": str(src), "new": str(target),
                          "reason": item.get("reason", ""),
                          "size_bytes": item.get("size_bytes")})
        except Exception as e:
            failures.append({"path": str(src), "error": f"{type(e).__name__}: {e}"})

    manifest = {
        "moved_at": _now(),
        "scanned_root": str(root),
        "dest": str(dest),
        "summary": {"moved": len(moved), "failures": len(failures)},
        "items": moved,
        "failures": failures,
    }
    manifest_path = dest / f"_quarantine_manifest_{dt.datetime.now():%Y%m%d_%H%M%S}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Moved {len(moved)} file(s) to {dest}")
    if failures:
        print(f"{len(failures)} failure(s):")
        for f in failures:
            print(f"  {f['path']}  ({f['error']})")
    print(f"Manifest: {manifest_path}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Identify and quarantine PII files.")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="dry-run: detect PII files, write a report")
    sp.add_argument("directory", help="directory to scan (recursively)")
    sp.add_argument("--dest", default=DEFAULT_DEST,
                    help=f"quarantine folder (default: {DEFAULT_DEST})")
    sp.add_argument("--sensitivity", choices=list(pe.SENSITIVITY_PRESETS),
                    default="medium")
    sp.add_argument("--min-score", type=float, default=0.4,
                    help="minimum detector confidence (0-1)")
    sp.add_argument("--exclude", nargs="*", default=[],
                    help="PII entity types to ignore, e.g. --exclude DATE_TIME")
    sp.add_argument("--out", default="pii_report.json",
                    help="where to write the JSON report")
    sp.set_defaults(func=cmd_scan)

    ap = sub.add_parser("apply", help="move the files a report flagged")
    ap.add_argument("report", help="path to the JSON report from `scan`")
    ap.add_argument("--dest", default=None,
                    help="override destination from the report")
    ap.add_argument("--yes", action="store_true",
                    help="required: confirm the move actually happens")
    ap.set_defaults(func=cmd_apply)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
