# Usage Report

Ghost Data Still Exists, HackerRank Orchestrate October 2026.

This report covers the final full dataset run that produced `output.csv` at the repository root.

---

## 1. Model providers and model names used at run time

**None.**

The submitted agent is a deterministic auditor. It reads `dataset/`, parses all 94 evidence
artifacts, reconciles every record against `deletion_rules.csv`, and writes `output.csv` without
calling any language model and without any network access.

| Item | Value |
|---|---|
| Provider | none configured (`AUDIT_MODEL_PROVIDER` unset) |
| Model | none configured (`AUDIT_MODEL_NAME` unset) |
| API key present | no |
| Network calls | 0 |

There is an optional model hook in `code/audit_agent/intent.py`. It is used only when a request
text contains no deletion marker in any supported language and no withdrawal or confirmation
phrase. It is disabled unless `AUDIT_MODEL_PROVIDER`, `AUDIT_MODEL_NAME` and `AUDIT_MODEL_API_KEY`
are all present in the environment, and it reads the base URL from `AUDIT_MODEL_BASE_URL`. No key
is embedded anywhere in the code or in this report.

The hook would not have fired on this dataset even if a key had been supplied. Measured over all
518 requests:

| Classification path | Requests |
|---|---|
| Deletion marker present in the request text | 508 |
| Explicit withdrawal of the deletion mandate | 10 |

Every request is decided deterministically, so the model branch is dead code for this corpus. It
exists for requests that arrive in a language the marker list does not cover.

---

## 2. Token and cost accounting for the final run

Measured by the pipeline itself, which prints these counters at the end of the run:

```text
wrote 518 rows to ...\output.csv
model calls: 0  prompt tokens: 0  completion tokens: 0
```

| Measure | Value |
|---|---|
| Requests processed | 518 |
| Model calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request | 0.0 |
| Estimated cost per request | USD 0.00 |
| Estimated total cost | USD 0.00 |
| Wall clock time for the full run | 5.1 s |

Per model totals are not repeated here because only one execution path exists, the deterministic
one, and it accounts for 100 percent of the run.

The cost is zero by construction rather than by a free tier: there is no provider, no request and no
token to bill.

---

## 3. What did use a model, and why that is not in the run time numbers

Two things outside the inference path did involve a language model, and both are auditable.

1. **Coding.** The solution was written with an AI coding agent, as the challenge permits. The full
   transcript of that work is in `log.txt` at the repository root, which is also a required
   submission artifact.
2. **Screenshot transcription.** Eleven supplied PNGs have no text layer. Reading them once produced
   `code/vision_cache.json`, ten entries of which are used: the file id, the focal record, the
   visible identifiers and the state the screen establishes. That file is committed with the
   solution, so the run itself reads a fixed transcription and makes no model call. The eleventh
   screenshot (an object storage browser listing) shows no record that can be tied to any case, so
   it is not in the cache.

Neither activity is part of the 518 case run. A fresh clone produces `output.csv` from `dataset/`
alone, with zero tokens and zero cost, and produces the identical file every time.

---

## 4. Reproduction

```bash
python code/main.py                     # writes output.csv, prints the token counters
python evaluation/main.py          # sample set metrics
python evaluation/custom_cases.py  # participant authored cases
python evaluation/validate_output.py
```

Requirements: Python 3.10 or newer, standard library only, plus `pymupdf` for the four PDF artifacts.
No API key, no GPU, no external service.
