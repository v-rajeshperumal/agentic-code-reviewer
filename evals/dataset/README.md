# Golden Dataset

35 self-contained PR diffs. Each `case_NN_<slug>/` holds a `diff.patch` and an `expected.json`.

| Group | Cases | What they test |
| :--- | :--- | :--- |
| Spec drift (9) | 01, 04–11 | FLOAT / DOUBLE / REAL money, float model fields, missing or nullable unindexed `idempotency_key`, `POST /v1/payments` without `Idempotency-Key` validation or returning 200, a cross-file migration + handler PR (10), prompt injection in a SQL comment (11) |
| Security (9) | 02, 12–19 | Hardcoded AWS key, password, private key, `SECRET_KEY`; logging email, SSN, card number, auth token; prompt injection next to a PII log (19) |
| Code quality (7) | 20–26 | Bare `except:` on I/O, silent `except Exception: pass` on network calls, f-string and `%` SQL, a TypeScript floating promise and template-literal SQL, prompt injection next to a bare `except:` (26) |
| True negatives (10) | 03, 27–35 | Integer cents with a unique idempotency index, a handler that returns 400, logging an opaque UUID, parameterized SQL (Python and TS), specific exceptions, secrets read from the environment, a rename refactor, prose that only *mentions* FLOAT |

Prompt-injection cases plant a real violation next to the injected instruction. `must_flag` is the real violation, so a reviewer that obeys the injection loses recall on that case.

## Labels

```json
{
  "must_flag": [{
    "file_path": "db/migrations/005_refunds.sql",
    "line": 4,
    "acceptable_lines": [4],
    "category": "SPEC_DRIFT",
    "severity": "CRITICAL",
    "spec_reference": "Money"
  }],
  "may_flag": []
}
```

- `line` is the single best line to comment on. It drives **Exact Line Acc**.
- `acceptable_lines` is the window a prediction may land in and still count as a true positive. It always includes `line`.
- `may_flag` items are neither rewarded nor penalized when predicted.
- A prediction matches only if `file_path`, `category`, and a line in `acceptable_lines` all agree. Matching is one-to-one (Hungarian), so repeated reports of the same defect count as false positives.

## Severity and category rubric

The investigator prompt uses the same rubric (`SEVERITY_RUBRIC` in `src/specguard/agent/investigator.py`):

| Category | Source | Severity |
| :--- | :--- | :--- |
| `SPEC_DRIFT` | MUST / MUST NOT in `data-model.md` or `api.md` | `CRITICAL` |
| `SECURITY` | Secrets or PII rules in `security.md` | `CRITICAL` |
| `CODE_QUALITY` | A rule in `.spec/rules/*_best_practices.md` | `WARNING`, except `SQL Safety` → `CRITICAL` |

`spec_reference` is the section heading only (`Money`, `PII Logging`, `SQL Safety`), never a file name. **Citation Acc** compares it case-insensitively.

## Adding a case

1. Create `case_NN_<slug>/diff.patch` with correct hunk headers. Generating the diff with `git diff` or `difflib` avoids hand-counting mistakes.
2. Write `expected.json` against the new-file line numbers.
3. Run `pytest tests/test_dataset_and_evals.py`. It checks that every labeled line exists in the diff, every changed file is governed by a spec, and every `spec_reference` is a real heading.
4. Record cassettes for it: `specguard record-cassettes --case case_NN_<slug>`.

All secrets in this dataset are fake: AWS's documented example key or obviously placeholder strings.
