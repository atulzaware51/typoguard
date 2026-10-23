#!/usr/bin/env python3
"""
TypoGuard Deterministic Evaluation Harness
------------------------------------------
Executes an offline, in-process evaluation of TypoGuard's URL risk detection logic
against a version-controlled benchmark dataset (evaluation/cases.json).

Guarantees:
- Completely offline: zero external network calls.
- Read-only data safety: does NOT touch or mutate backend/typoguard.db.
- Strict schema validation and duplicate ID rejection.
- Explicit metric calculation handling zero denominators cleanly (returns None/null).
"""

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean, median
from typing import Any

# Ensure backend modules are importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = PROJECT_ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

try:
    from app.services.url_parser import parse_url, normalize_domain
    from app.services.similarity import find_similar_domains
    from app.services.typo_detector import detect_typo
    from app.services.risk_scoring import calculate_risk
except ImportError as err:
    sys.stderr.write(f"Failed to import backend detection services: {err}\n")
    sys.exit(1)

BENCHMARK_VERSION = "1.0.0"
VALID_RISK_LEVELS = {"Low", "Moderate", "High", "Critical"}
DATASET_PATH = PROJECT_ROOT / "dataset" / "trusted_domains.csv"


def load_trusted_domains(csv_path: Path = DATASET_PATH) -> list[str]:
    """Load trusted domains from the version-controlled CSV dataset."""
    if not csv_path.is_file():
        raise FileNotFoundError(f"Trusted domains dataset missing at: {csv_path}")
    domains: list[str] = []
    with csv_path.open("r", encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            raw = (row.get("domain") or "").strip()
            if raw:
                try:
                    domains.append(normalize_domain(raw))
                except Exception:
                    continue
    return sorted(list(set(domains)))


def validate_dataset_schema(cases_data: Any) -> list[dict]:
    """Validate the benchmark cases schema and reject malformed entries or duplicates."""
    if not isinstance(cases_data, list):
        raise ValueError("Benchmark dataset must be a JSON array of case objects.")
    if not cases_data:
        raise ValueError("Benchmark dataset cannot be empty.")

    seen_ids: set[str] = set()
    validated_cases: list[dict] = []

    for idx, case in enumerate(cases_data):
        if not isinstance(case, dict):
            raise ValueError(f"Case at index {idx} must be a JSON object.")

        case_id = case.get("id")
        if not case_id or not isinstance(case_id, str):
            raise ValueError(f"Case at index {idx} missing valid 'id' string.")
        if case_id in seen_ids:
            raise ValueError(f"Duplicate case ID detected: {case_id}")
        seen_ids.add(case_id)

        url = case.get("url")
        if not isinstance(url, str):
            raise ValueError(f"Case {case_id} missing valid 'url' string.")

        group = case.get("group")
        if not group or not isinstance(group, str):
            raise ValueError(f"Case {case_id} missing valid 'group' string.")

        expected_valid = case.get("expected_valid")
        if not isinstance(expected_valid, bool):
            raise ValueError(f"Case {case_id} 'expected_valid' must be a boolean.")

        rationale = case.get("rationale")
        if not rationale or not isinstance(rationale, str):
            raise ValueError(f"Case {case_id} missing valid 'rationale' string.")

        expected_risk_level = case.get("expected_risk_level")
        if expected_valid:
            if expected_risk_level not in VALID_RISK_LEVELS:
                raise ValueError(
                    f"Case {case_id} 'expected_risk_level' must be one of {VALID_RISK_LEVELS}, "
                    f"got: {expected_risk_level}"
                )
        else:
            if expected_risk_level is not None:
                raise ValueError(
                    f"Malformed case {case_id} (expected_valid=False) must have null 'expected_risk_level'."
                )

        validated_cases.append(case)

    # Sort deterministically by case ID
    return sorted(validated_cases, key=lambda c: str(c["id"]))


def evaluate_single_case(case: dict, trusted_domains: list[str]) -> dict:
    """Evaluate one URL case against the detection pipeline."""
    url = case["url"]
    expected_valid = case["expected_valid"]

    # Result template
    result = {
        "id": case["id"],
        "url": url,
        "group": case["group"],
        "exploratory": bool(case.get("exploratory", False)),
        "expected_valid": expected_valid,
        "actual_valid": True,
        "validation_passed": True,
        "expected_risk_level": case.get("expected_risk_level"),
        "actual_risk_level": None,
        "level_matched": True,
        "expected_suspicious": case.get("expected_suspicious"),
        "actual_suspicious": None,
        "classification_matched": True,
        "risk_score": None,
        "is_trusted": False,
        "signals": [],
        "signals_matched": True,
        "missing_expected_signals": [],
        "error": None,
        "rationale": case["rationale"],
    }

    try:
        parsed = parse_url(url)
    except (ValueError, TypeError) as parse_err:
        result["actual_valid"] = False
        result["error"] = f"{type(parse_err).__name__}: {str(parse_err)}"
        if expected_valid:
            result["validation_passed"] = False
            result["classification_matched"] = False
            result["level_matched"] = False
        else:
            # Expected rejection
            result["validation_passed"] = True
            result["classification_matched"] = True
            result["level_matched"] = True
        return result

    if not expected_valid:
        # Expected parser rejection, but parse succeeded
        result["validation_passed"] = False
        result["classification_matched"] = False
        result["level_matched"] = False
        result["error"] = "Expected parser rejection, but URL parsed successfully."
        return result

    # Valid URL: proceed with domain comparison and risk scoring
    submitted_domain = normalize_domain(parsed["hostname"])
    is_trusted = submitted_domain in trusted_domains
    result["is_trusted"] = is_trusted

    matches = find_similar_domains(
        domain=submitted_domain,
        trusted_domains=trusted_domains,
        limit=5,
    )
    for match in matches:
        match["typo_analysis"] = detect_typo(submitted_domain, match["trusted_domain"])

    assessment = calculate_risk(
        domain=submitted_domain,
        is_trusted=is_trusted,
        similar_domains=matches,
        scheme=parsed["scheme"],
        path=parsed["path"],
        query=parsed["query"],
        trusted_domains=trusted_domains,
    )

    score = assessment["risk_score"]
    level = assessment["risk_level"]
    actual_signals = [s["code"] for s in assessment.get("signals", [])]

    # Binary suspicious definition: risk score >= 25 (Moderate, High, Critical)
    actual_suspicious = level in ("Moderate", "High", "Critical")

    result["risk_score"] = score
    result["actual_risk_level"] = level
    result["actual_suspicious"] = actual_suspicious
    result["signals"] = actual_signals

    # Level match check
    if case.get("expected_risk_level") is not None:
        result["level_matched"] = (level == case["expected_risk_level"])
    else:
        result["level_matched"] = True

    # Binary classification match check (if defined and non-exploratory)
    expected_suspicious = case.get("expected_suspicious")
    if expected_suspicious is not None and not result["exploratory"]:
        result["classification_matched"] = (actual_suspicious == expected_suspicious)
    else:
        result["classification_matched"] = True

    # Expected signals check
    expected_signals = case.get("expected_signals") or []
    missing_signals = [sig for sig in expected_signals if sig not in actual_signals]
    result["missing_expected_signals"] = missing_signals
    result["signals_matched"] = (len(missing_signals) == 0)

    return result


def compute_metrics(case_results: list[dict]) -> dict:
    """Compute benchmark statistics and binary confusion metrics."""
    total_cases = len(case_results)
    exploratory_cases = [c for c in case_results if c["exploratory"]]
    malformed_cases = [c for c in case_results if not c["expected_valid"]]
    valid_benchmark_cases = [
        c for c in case_results
        if c["expected_valid"] and not c["exploratory"] and c["expected_suspicious"] is not None
    ]

    # Binary metrics calculation
    tp = sum(1 for c in valid_benchmark_cases if c["expected_suspicious"] is True and c["actual_suspicious"] is True)
    tn = sum(1 for c in valid_benchmark_cases if c["expected_suspicious"] is False and c["actual_suspicious"] is False)
    fp = sum(1 for c in valid_benchmark_cases if c["expected_suspicious"] is False and c["actual_suspicious"] is True)
    fn = sum(1 for c in valid_benchmark_cases if c["expected_suspicious"] is True and c["actual_suspicious"] is False)

    total_binary = tp + tn + fp + fn
    accuracy = ((tp + tn) / total_binary) if total_binary > 0 else None
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else None
    f1 = (
        (2 * precision * recall / (precision + recall))
        if (precision is not None and recall is not None and (precision + recall) > 0)
        else None
    )

    # Malformed rejection verification
    malformed_total = len(malformed_cases)
    malformed_correctly_rejected = sum(1 for c in malformed_cases if not c["actual_valid"])
    malformed_rejection_rate = (
        (malformed_correctly_rejected / malformed_total) if malformed_total > 0 else None
    )

    # Risk score distribution for all valid evaluated URLs
    valid_scores = [c["risk_score"] for c in case_results if c["actual_valid"] and c["risk_score"] is not None]
    score_dist = {
        "count": len(valid_scores),
        "min": min(valid_scores) if valid_scores else None,
        "max": max(valid_scores) if valid_scores else None,
        "mean": round(mean(valid_scores), 2) if valid_scores else None,
        "median": round(median(valid_scores), 2) if valid_scores else None,
    }

    # Signal frequency
    signal_counts: dict[str, int] = {}
    for c in case_results:
        for sig in c.get("signals", []):
            signal_counts[sig] = signal_counts.get(sig, 0) + 1

    # Per-group breakdown
    groups: dict[str, dict[str, Any]] = {}
    for c in case_results:
        grp = c["group"]
        if grp not in groups:
            groups[grp] = {"total": 0, "passed": 0, "failed": 0}
        groups[grp]["total"] += 1
        is_pass = c["validation_passed"] and c["level_matched"] and c["classification_matched"]
        if is_pass:
            groups[grp]["passed"] += 1
        else:
            groups[grp]["failed"] += 1

    return {
        "total_cases": total_cases,
        "evaluated_cases": total_cases - len(exploratory_cases),
        "exploratory_cases_count": len(exploratory_cases),
        "malformed_cases_count": len(malformed_cases),
        "binary_classification": {
            "evaluated_count": total_binary,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "accuracy": round(accuracy, 4) if accuracy is not None else None,
            "precision": round(precision, 4) if precision is not None else None,
            "recall": round(recall, 4) if recall is not None else None,
            "f1_score": round(f1, 4) if f1 is not None else None,
        },
        "input_validation": {
            "total_malformed_cases": malformed_total,
            "correctly_rejected": malformed_correctly_rejected,
            "rejection_rate": round(malformed_rejection_rate, 4) if malformed_rejection_rate is not None else None,
        },
        "score_distribution": score_dist,
        "signal_frequency": signal_counts,
        "group_summary": groups,
    }


def run_evaluation(
    cases_path: Path,
    output_path: Path | None = None,
    strict_pass: bool = False,
) -> tuple[int, dict]:
    """Execute the evaluation benchmark and emit output."""
    start_time = time.perf_counter()

    if not cases_path.is_file():
        sys.stderr.write(f"Error: Cases file not found: {cases_path}\n")
        return 1, {}

    try:
        with cases_path.open("r", encoding="utf-8") as file:
            raw_cases = json.load(file)
        cases = validate_dataset_schema(raw_cases)
    except Exception as exc:
        sys.stderr.write(f"Dataset schema error: {exc}\n")
        return 1, {}

    try:
        trusted_domains = load_trusted_domains()
    except Exception as exc:
        sys.stderr.write(f"Failed to load trusted domains: {exc}\n")
        return 1, {}

    case_results = [evaluate_single_case(c, trusted_domains) for c in cases]
    metrics = compute_metrics(case_results)
    duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

    report = {
        "benchmark_version": BENCHMARK_VERSION,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "cases_file": str(cases_path),
        "trusted_domains_count": len(trusted_domains),
        "duration_ms": duration_ms,
        "summary": metrics,
        "case_results": case_results,
    }

    if output_path is not None:
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with output_path.open("w", encoding="utf-8") as out_file:
                json.dump(report, out_file, indent=2)
        except Exception as exc:
            sys.stderr.write(f"Failed to write output report to {output_path}: {exc}\n")
            return 1, report

    # Determine exit code
    # Fail if malformed rejection rate is not 1.0 or if strict_pass fails on non-exploratory cases
    has_validation_failures = any(not c["validation_passed"] for c in case_results)
    has_mismatches = any(
        (not c["level_matched"] or not c["classification_matched"] or not c["signals_matched"])
        for c in case_results
        if not c["exploratory"]
    )

    exit_code = 0
    if has_validation_failures:
        exit_code = 1
    elif strict_pass and has_mismatches:
        exit_code = 1

    return exit_code, report


def print_cli_summary(report: dict, exit_code: int) -> None:
    """Print clean, formatted benchmark results to stdout."""
    summary = report.get("summary", {})
    binary = summary.get("binary_classification", {})
    validation = summary.get("input_validation", {})
    dist = summary.get("score_distribution", {})

    print("\n" + "=" * 65)
    print(f" TypoGuard Evaluation Benchmark v{report.get('benchmark_version')} ")
    print("=" * 65)
    print(f"Timestamp:       {report.get('timestamp_utc')}")
    print(f"Execution Time:  {report.get('duration_ms')} ms")
    print(f"Total Cases:     {summary.get('total_cases')}")
    print(f"Evaluated:       {summary.get('evaluated_cases')}")
    print(f"Exploratory:     {summary.get('exploratory_cases_count')}")
    print(f"Malformed:       {summary.get('malformed_cases_count')}")
    print("-" * 65)
    print("BINARY CLASSIFICATION (Headline Metrics, threshold >= 25):")
    print(f"  Cases:         {binary.get('evaluated_count')}")
    print(f"  TP: {binary.get('true_positives')}   TN: {binary.get('true_negatives')}   FP: {binary.get('false_positives')}   FN: {binary.get('false_negatives')}")
    print(f"  Accuracy:      {binary.get('accuracy')}")
    print(f"  Precision:     {binary.get('precision')}")
    print(f"  Recall:        {binary.get('recall')}")
    print(f"  F1 Score:      {binary.get('f1_score')}")
    print("-" * 65)
    print("MALFORMED INPUT REJECTION:")
    print(f"  Total:         {validation.get('total_malformed_cases')}")
    print(f"  Rejected:      {validation.get('correctly_rejected')}")
    print(f"  Rate:          {validation.get('rejection_rate')}")
    print("-" * 65)
    print("SCORE DISTRIBUTION (Valid URLs):")
    print(f"  Min: {dist.get('min')} | Max: {dist.get('max')} | Mean: {dist.get('mean')} | Median: {dist.get('median')}")
    print("-" * 65)
    print("GROUPS BREAKDOWN:")
    for grp, st in summary.get("group_summary", {}).items():
        print(f"  {grp:<38} {st['passed']}/{st['total']} passed")
    print("=" * 65)
    print(f"Final Status: {'PASS' if exit_code == 0 else 'FAIL'} (exit code: {exit_code})\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="TypoGuard Deterministic Evaluation Harness")
    parser.add_argument(
        "--cases-file",
        type=Path,
        default=PROJECT_ROOT / "evaluation" / "cases.json",
        help="Path to cases.json dataset",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path to save output JSON report",
    )
    parser.add_argument(
        "--strict-pass",
        action="store_true",
        help="Return exit code 1 if any non-exploratory classification mismatch occurs",
    )

    args = parser.parse_args()
    exit_code, report = run_evaluation(
        cases_path=args.cases_file,
        output_path=args.output,
        strict_pass=args.strict_pass,
    )
    if report:
        print_cli_summary(report, exit_code)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
