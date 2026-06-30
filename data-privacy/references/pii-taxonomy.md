# PII Taxonomy & Sensitivity Tiers

This reference explains what the engine detects and how files get scored.
Read it when you need to explain a result, tune sensitivity, or decide
whether a detection is a false positive.

## Detected entity types

Detection combines spaCy NER (for unstructured PII) with Presidio's
regex/checksum recognizers (for structured PII), plus a custom
Luhn-validated Canadian SIN recognizer.

| Entity type        | Tier | How it's found                          |
|--------------------|------|-----------------------------------------|
| US_SSN             | HIGH | regex + context                         |
| CA_SIN             | HIGH | regex + Luhn check (custom recognizer)  |
| CREDIT_CARD        | HIGH | regex + Luhn check                      |
| US_PASSPORT        | HIGH | regex + context                         |
| US_DRIVER_LICENSE  | HIGH | regex + context                         |
| US_BANK_NUMBER     | HIGH | regex + context                         |
| US_ITIN            | HIGH | regex + context                         |
| IBAN_CODE          | HIGH | regex + checksum                        |
| MEDICAL_LICENSE    | HIGH | regex                                   |
| CRYPTO             | HIGH | regex (wallet addresses)                |
| PERSON             | LOW  | spaCy NER                               |
| EMAIL_ADDRESS      | LOW  | regex                                   |
| PHONE_NUMBER       | LOW  | libphonenumber                          |
| LOCATION           | LOW  | spaCy NER (cities, addresses)           |
| IP_ADDRESS         | LOW  | regex                                   |
| DATE_TIME          | LOW  | spaCy/regex (broad — see note)          |
| NRP                | LOW  | nationality/religion/political group    |

`URL` is deliberately NOT detected — URLs are rarely PII and the recognizer
needs a network call for the public-suffix list.

## Why two tiers?

Almost every business document contains a name or a single email. If a lone
name quarantined a file, you'd move your entire Documents folder. So:

- **HIGH-tier** identifiers (an SSN, a card number, a passport) are
  sensitive enough on their own that a single confident hit flags the file.
- **LOW-tier** items only flag a file when they co-occur or reach a density
  threshold, per the sensitivity preset.

## Sensitivity presets (Function 1 — quarantine)

| Preset   | A file is flagged when…                                          |
|----------|------------------------------------------------------------------|
| `low`    | a HIGH-tier identifier is present (nothing else flags)           |
| `medium` | a HIGH-tier hit, OR ≥2 distinct LOW types, OR ≥4 LOW instances   |
| `high`   | any single PII hit of any tier                                   |

Default is `medium`. Move toward `low` if you're getting false positives on
ordinary business docs; move toward `high` if you need to catch files that
contain only a name or a single email.

## Notes & known limitations

- **DATE_TIME is broad.** It matches meeting dates, not just dates of birth.
  If date redaction is too aggressive, pass `--exclude DATE_TIME` to either
  script.
- **Names need the model.** PERSON and LOCATION come from the spaCy model.
  If only `en_core_web_sm` (or no model) is installed, name/address recall
  drops. Install `en_core_web_lg` via `setup_env.py` for best results.
- **Scanned/image-only PDFs** yield little text via normal extraction; the
  scanner marks them for manual review rather than guessing. (Images proper —
  PNG/JPG/etc. — go through OCR.)
- **Detection is probabilistic.** Always review the dry-run preview before
  moving files, and spot-check masked output before ingestion. Tune
  `--min-score` (default 0.4) to trade precision vs. recall.
