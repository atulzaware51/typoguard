# TypoGuard Evaluation Benchmark

A lightweight, reproducible, offline evaluation framework for assessing the heuristic detection accuracy, structural typo classification, and URL parsing behavior of **TypoGuard**.

---

## 1. Purpose and Scope

The TypoGuard Evaluation Harness benchmarks the in-process heuristic detection engine against a curated dataset of synthetic test URLs, legitimate domain baselines, structural typos, homoglyphs, and malformed inputs.

### Scope & Guarantees
* **100% Offline**: Executes entirely in-memory and in-process. No live DNS resolutions or HTTP network calls are made.
* **Database & Dataset Preservation**: Does not modify, truncate, or touch `backend/typoguard.db` or `dataset/trusted_domains.csv`.
* **Deterministic & Repeatable**: Given the same cases file, runs produce identical metrics, classifications, and score distributions.
* **Exploratory Isolation**: Edge cases without confident ground truth are tracked separately and excluded from headline precision/recall metrics.

> **Important Disclaimer**: This benchmark is a regression and functional evaluation suite covering documented heuristics and known attack patterns. It is **not** a guarantee of real-world safety or maliciousness, nor is it a statistically representative sample of all phishing campaigns on the internet.

---

## 2. Benchmark Dataset Structure (`cases.json`)

The test suite is defined in [`cases.json`](./cases.json) as a JSON array of case objects.

### Case Schema

```json
{
  "id": "CASE-005",
  "url": "https://g00gle.com/",
  "group": "typosquatting_synthetic",
  "expected_valid": true,
  "expected_risk_level": "Moderate",
  "expected_suspicious": true,
  "expected_signals": ["high_domain_similarity", "character_changes"],
  "exploratory": false,
  "rationale": "Obvious synthetic typosquat with double digit substitution (00 for oo) mimicking google.com."
}
```

### Fields
| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique identifier (e.g., `CASE-001`). Duplicate IDs are rejected during schema validation. |
| `url` | `string` | Target URL to test. Must be synthetic or benign documentation examples. |
| `group` | `string` | One of the 9 benchmark categories. |
| `expected_valid` | `boolean` | `true` if the URL is valid RFC syntax and accepted by `parse_url`; `false` if expected to be rejected with `ValueError`. |
| `expected_risk_level` | `string \| null` | Expected risk level (`Low`, `Moderate`, `High`, `Critical`), or `null` if `expected_valid` is `false`. |
| `expected_suspicious` | `boolean \| null` | Ground truth for headline binary classification (`true` for suspicious/typo >= 25, `false` for benign < 25, `null` for malformed or exploratory). |
| `expected_signals` | `string[]` | Codes of risk signals expected in the assessment (e.g., `["high_domain_similarity"]`). |
| `exploratory` | `boolean` | If `true`, the case is tracked and reported, but excluded from headline precision/recall metrics. |
| `rationale` | `string` | Architectural and security justification for the expected behavior. |

### Evaluation Groups (9 Categories)
1. `trusted_domain_baseline`: Legitimate root and internal paths of known trusted domains (e.g., Google, Apple, GitHub).
2. `typosquatting_synthetic`: Classic visual and phonetic character substitutions (e.g., `g00gle.com`, `paypa1.com`).
3. `typo_structural_variations`: Structural mutations including omissions, additions, and adjacent swaps.
4. `suspicious_path_and_keywords`: Authentication and credential harvest paths/queries with HTTP transport checks.
5. `normalization_and_parsing_edge_cases`: Normalization of schemes, ports, uppercase casing, trailing dots, and fragments.
6. `punycode_and_homoglyphs`: Internationalized domain names (IDN), Cyrillic lookalikes, and deceptive subdomain prefixes.
7. `benign_lookalike_probes`: Unrelated domains and RFC 2606 example domains to probe and prevent false positives.
8. `malformed_and_invalid_inputs`: Invalid hostnames, credentials, non-HTTP schemes, and out-of-range ports.
9. `exploratory_insufficient_evidence`: Unknown new TLDs and intranet domains without sufficient threat evidence.

---

## 3. Running the Benchmark

### Basic Command (Windows PowerShell)

Run from the project root using the backend virtual environment:

```powershell
backend\venv\Scripts\python.exe evaluation\run_evaluation.py
```

### With Strict Enforcement and JSON Report Output

```powershell
backend\venv\Scripts\python.exe evaluation\run_evaluation.py `
  --strict-pass `
  --output evaluation\results\latest_report.json
```

### CLI Arguments
* `--cases-file <path>`: Path to a custom cases JSON file (default: `evaluation/cases.json`).
* `--output <path>`: Path to write the full JSON benchmark report.
* `--strict-pass`: Exits with return code `1` if any non-exploratory classification mismatch occurs.

---

## 4. Metric Definitions and Calculations

Headline metrics use a decision threshold of **risk score >= 25** (`Moderate`, `High`, `Critical`):

* **True Positive (TP)**: Expected suspicious (`expected_suspicious: true`) and detector classified as elevated risk.
* **True Negative (TN)**: Expected benign (`expected_suspicious: false`) and detector classified as `Low` risk.
* **False Positive (FP)**: Expected benign (`expected_suspicious: false`) but detector classified as elevated risk.
* **False Negative (FN)**: Expected suspicious (`expected_suspicious: true`) but detector classified as `Low` risk.

$$\text{Accuracy} = \frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}}$$

$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$

$$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$

$$\text{F1 Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

> **Zero Denominator Protection**: If a denominator is zero, the harness outputs `null` rather than `0.0` or raising an error.

### Input Validation Metric
* **Malformed Rejection Rate**: Ratio of malformed cases (`expected_valid: false`) correctly rejected by `parse_url` with a `ValueError`.

---

## 5. Current Baseline Results

Measured execution on the current codebase (`v1.0.0`):

```text
=================================================================
 TypoGuard Evaluation Benchmark v1.0.0
=================================================================
Execution Time:  ~21 ms
Total Cases:     30
Evaluated:       28
Exploratory:     2
Malformed:       5
-----------------------------------------------------------------
BINARY CLASSIFICATION (Headline Metrics, threshold >= 25):
  Cases:         23
  TP: 11   TN: 12   FP: 0   FN: 0
  Accuracy:      1.0 (100.0%)
  Precision:     1.0 (100.0%)
  Recall:        1.0 (100.0%)
  F1 Score:      1.0 (100.0%)
-----------------------------------------------------------------
MALFORMED INPUT REJECTION:
  Total:         5
  Rejected:      5
  Rate:          1.0 (100.0%)
-----------------------------------------------------------------
SCORE DISTRIBUTION (Valid URLs):
  Min: 0 | Max: 58 | Mean: 19.92 | Median: 10
-----------------------------------------------------------------
GROUPS BREAKDOWN:
  trusted_domain_baseline                4/4 passed
  typosquatting_synthetic                3/3 passed
  typo_structural_variations             4/4 passed
  suspicious_path_and_keywords           3/3 passed
  normalization_and_parsing_edge_cases   3/3 passed
  punycode_and_homoglyphs                3/3 passed
  benign_lookalike_probes                3/3 passed
  malformed_and_invalid_inputs           5/5 passed
  exploratory_insufficient_evidence      2/2 passed
=================================================================
Final Status: PASS (exit code: 0)
```

---

## 6. How to Add a New Test Case

1. Open [`evaluation/cases.json`](./cases.json).
2. Assign the next sequential case ID (e.g., `CASE-031`).
3. Select an appropriate `group`.
4. Define `expected_valid`, `expected_risk_level`, `expected_suspicious`, and `rationale`.
5. Run the evaluation harness to verify:
   ```powershell
   backend\venv\Scripts\python.exe evaluation\run_evaluation.py --strict-pass
   ```
6. Run the automated harness unit tests:
   ```powershell
   cd backend
   .\venv\Scripts\python.exe -m pytest tests\test_evaluation_harness.py -v
   ```

---

## 7. Guidelines for Interpreting Discrepancies

* **False Positives (FP)**: The detector flagged a harmless URL as suspicious. Investigate whether an overly aggressive similarity threshold or keyword matching rule caused the issue.
* **False Negatives (FN)**: An actual typosquat was scored `< 25`. Investigate whether the target domain is present in `trusted_domains.csv` or whether the edit distance exceeded the RapidFuzz window.
* **Comparing Versions Fairly**: Always run benchmark comparisons using the same `cases.json` dataset and the same trusted domain seed. Never adjust test labels retroactively to inflate benchmark scores.
