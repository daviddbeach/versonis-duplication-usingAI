#!/usr/bin/env python3
"""
setup_env.py — install everything the Data Privacy skill needs.

Run this once before first use (and any time the spaCy model is missing):

    python setup_env.py

It will:
  1. pip install the Python dependencies (requirements.txt).
  2. Download the spaCy NER model en_core_web_lg (needed for PERSON / address
     detection). Falls back to en_core_web_sm if the large model fails.
  3. Check for the Tesseract OCR binary (needed to read PII out of images)
     and print install instructions if it's missing.

Use --break-system-packages only if your environment requires it (some
Linux setups do; a normal venv or macOS Homebrew Python does not).
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def run(cmd: list[str]) -> int:
    print("›", " ".join(cmd))
    return subprocess.call(cmd)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--break-system-packages", action="store_true",
                    help="pass through to pip (only if your env needs it)")
    ap.add_argument("--small-model", action="store_true",
                    help="install en_core_web_sm instead of the large model")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    reqs = here / "requirements.txt"

    pip = [sys.executable, "-m", "pip", "install"]
    if args.break_system_packages:
        pip.append("--break-system-packages")

    print("== Installing Python dependencies ==")
    if run(pip + ["-r", str(reqs)]) != 0:
        print("pip install failed.", file=sys.stderr)
        return 1

    print("\n== Installing spaCy NER model ==")
    model = "en_core_web_sm" if args.small_model else "en_core_web_lg"
    if run([sys.executable, "-m", "spacy", "download", model]) != 0:
        print(f"Could not download {model}; trying en_core_web_sm…")
        run([sys.executable, "-m", "spacy", "download", "en_core_web_sm"])

    print("\n== Checking Tesseract OCR (for image scanning) ==")
    if shutil.which("tesseract"):
        print("✓ tesseract found:", shutil.which("tesseract"))
    else:
        print("✗ tesseract NOT found. Image scanning will be skipped until "
              "you install it:")
        print("    macOS:         brew install tesseract")
        print("    Debian/Ubuntu: sudo apt-get install tesseract-ocr")

    print("\nSetup complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
