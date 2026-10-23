"""
Unit tests for the TypoGuard Evaluation Harness
------------------------------------------------
Verifies:
- Dataset schema validation & duplicate case-ID rejection
- Empty and malformed dataset handling
- Metric calculations with known ground truth
- Zero-denominator handling (returns None, never crashes or reports 0)
- Exclusion of exploratory cases from headline metrics
- Stable result ordering
- Output JSON report generation
- Offline guarantee (no external network connections)
- Data preservation guarantee (no mutations to database or CSV)
"""

import hashlib
import json
import socket
import sys
from pathlib import Path
import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.run_evaluation import (
    load_trusted_domains,
    validate_dataset_schema,
    evaluate_single_case,
    compute_metrics,
    run_evaluation,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
REAL_DB_PATH = PROJECT_ROOT / "backend" / "typoguard.db"
REAL_CSV_PATH = PROJECT_ROOT / "dataset" / "trusted_domains.csv"
REAL_CASES_PATH = PROJECT_ROOT / "evaluation" / "cases.json"


def test_schema_validation_valid_cases():
    sample = [
        {
            "id": "CASE-100",
            "url": "https://example.com",
            "group": "sample_group",
            "expected_valid": True,
            "expected_risk_level": "Low",
            "expected_suspicious": False,
            "rationale": "Valid test case",
        }
    ]
    validated = validate_dataset_schema(sample)
    assert len(validated) == 1
    assert validated[0]["id"] == "CASE-100"


def test_schema_validation_rejects_duplicate_id():
    sample = [
        {
            "id": "CASE-001",
            "url": "https://a.com",
            "group": "g",
            "expected_valid": True,
            "expected_risk_level": "Low",
            "rationale": "First",
        },
        {
            "id": "CASE-001",
            "url": "https://b.com",
            "group": "g",
            "expected_valid": True,
            "expected_risk_level": "Low",
            "rationale": "Duplicate",
        },
    ]
    with pytest.raises(ValueError, match="Duplicate case ID detected: CASE-001"):
        validate_dataset_schema(sample)


def test_schema_validation_rejects_empty_dataset():
    with pytest.raises(ValueError, match="Benchmark dataset cannot be empty"):
        validate_dataset_schema([])


def test_schema_validation_rejects_non_list():
    with pytest.raises(ValueError, match="Benchmark dataset must be a JSON array"):
        validate_dataset_schema({"key": "val"})


def test_schema_validation_rejects_invalid_risk_level():
    sample = [
        {
            "id": "CASE-002",
            "url": "https://example.com",
            "group": "g",
            "expected_valid": True,
            "expected_risk_level": "ExtremeRisk",
            "rationale": "Invalid level",
        }
    ]
    with pytest.raises(ValueError, match="expected_risk_level"):
        validate_dataset_schema(sample)


def test_schema_validation_rejects_malformed_case_with_risk_level():
    sample = [
        {
            "id": "CASE-003",
            "url": "not a url",
            "group": "g",
            "expected_valid": False,
            "expected_risk_level": "Low",
            "rationale": "Should have null risk level",
        }
    ]
    with pytest.raises(ValueError, match="must have null 'expected_risk_level'"):
        validate_dataset_schema(sample)


def test_metric_calculations_known_truth():
    case_results = [
        # 2 TP
        {"group": "g1", "exploratory": False, "expected_valid": True, "expected_suspicious": True, "actual_suspicious": True, "actual_valid": True, "validation_passed": True, "level_matched": True, "classification_matched": True, "risk_score": 60, "signals": ["sigA"]},
        {"group": "g1", "exploratory": False, "expected_valid": True, "expected_suspicious": True, "actual_suspicious": True, "actual_valid": True, "validation_passed": True, "level_matched": True, "classification_matched": True, "risk_score": 50, "signals": ["sigA"]},
        # 1 TN
        {"group": "g1", "exploratory": False, "expected_valid": True, "expected_suspicious": False, "actual_suspicious": False, "actual_valid": True, "validation_passed": True, "level_matched": True, "classification_matched": True, "risk_score": 0, "signals": []},
        # 1 FP
        {"group": "g2", "exploratory": False, "expected_valid": True, "expected_suspicious": False, "actual_suspicious": True, "actual_valid": True, "validation_passed": True, "level_matched": False, "classification_matched": False, "risk_score": 35, "signals": ["sigB"]},
        # 1 FN
        {"group": "g2", "exploratory": False, "expected_valid": True, "expected_suspicious": True, "actual_suspicious": False, "actual_valid": True, "validation_passed": True, "level_matched": False, "classification_matched": False, "risk_score": 10, "signals": []},
        # 1 Exploratory (should be excluded from binary headline metrics)
        {"group": "exploratory", "exploratory": True, "expected_valid": True, "expected_suspicious": None, "actual_suspicious": False, "actual_valid": True, "validation_passed": True, "level_matched": True, "classification_matched": True, "risk_score": 0, "signals": []},
        # 1 Malformed
        {"group": "malformed", "exploratory": False, "expected_valid": False, "expected_suspicious": None, "actual_suspicious": None, "actual_valid": False, "validation_passed": True, "level_matched": True, "classification_matched": True, "risk_score": None, "signals": []},
    ]

    metrics = compute_metrics(case_results)
    bin_m = metrics["binary_classification"]

    assert bin_m["evaluated_count"] == 5  # 2 TP + 1 TN + 1 FP + 1 FN (exploratory & malformed excluded)
    assert bin_m["true_positives"] == 2
    assert bin_m["true_negatives"] == 1
    assert bin_m["false_positives"] == 1
    assert bin_m["false_negatives"] == 1
    # Accuracy = (2 + 1) / 5 = 0.6
    assert bin_m["accuracy"] == 0.6
    # Precision = 2 / (2 + 1) = 2/3 = 0.6667
    assert bin_m["precision"] == round(2 / 3, 4)
    # Recall = 2 / (2 + 1) = 2/3 = 0.6667
    assert bin_m["recall"] == round(2 / 3, 4)
    # F1 = 2 * (2/3) * (2/3) / (4/3) = 2/3 = 0.6667
    assert bin_m["f1_score"] == round(2 / 3, 4)

    assert metrics["exploratory_cases_count"] == 1
    assert metrics["malformed_cases_count"] == 1
    assert metrics["input_validation"]["rejection_rate"] == 1.0


def test_metric_calculations_zero_denominator_returns_none():
    empty_cases = [
        {"group": "g", "exploratory": True, "expected_valid": True, "expected_suspicious": None, "actual_suspicious": False, "actual_valid": True, "validation_passed": True, "level_matched": True, "classification_matched": True, "risk_score": 0, "signals": []}
    ]
    metrics = compute_metrics(empty_cases)
    bin_m = metrics["binary_classification"]

    assert bin_m["evaluated_count"] == 0
    assert bin_m["accuracy"] is None
    assert bin_m["precision"] is None
    assert bin_m["recall"] is None
    assert bin_m["f1_score"] is None


def test_dataset_stable_ordering():
    unsorted_sample = [
        {"id": "CASE-010", "url": "https://c.com", "group": "g", "expected_valid": True, "expected_risk_level": "Low", "rationale": "r"},
        {"id": "CASE-001", "url": "https://a.com", "group": "g", "expected_valid": True, "expected_risk_level": "Low", "rationale": "r"},
        {"id": "CASE-005", "url": "https://b.com", "group": "g", "expected_valid": True, "expected_risk_level": "Low", "rationale": "r"},
    ]
    sorted_cases = validate_dataset_schema(unsorted_sample)
    ids = [c["id"] for c in sorted_cases]
    assert ids == ["CASE-001", "CASE-005", "CASE-010"]


def test_json_report_generation(tmp_path):
    out_file = tmp_path / "report.json"
    exit_code, report = run_evaluation(
        cases_path=REAL_CASES_PATH,
        output_path=out_file,
        strict_pass=True,
    )
    assert exit_code == 0
    assert out_file.is_file()

    with out_file.open("r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["benchmark_version"] == "1.0.0"
    assert "summary" in data
    assert "case_results" in data
    assert len(data["case_results"]) == 30


def test_offline_guarantee_no_external_network(monkeypatch):
    """Ensure evaluation runner makes zero network connections."""
    def guarded_connect(*args, **kwargs):
        raise AssertionError("Evaluation harness attempted external network connection!")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)

    exit_code, report = run_evaluation(
        cases_path=REAL_CASES_PATH,
        output_path=None,
        strict_pass=True,
    )
    assert exit_code == 0


def test_database_and_csv_preservation_guarantee():
    """Verify evaluation harness does not mutate typoguard.db or trusted_domains.csv."""
    def file_hash(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    db_hash_before = file_hash(REAL_DB_PATH)
    csv_hash_before = file_hash(REAL_CSV_PATH)

    exit_code, report = run_evaluation(
        cases_path=REAL_CASES_PATH,
        output_path=None,
        strict_pass=True,
    )
    assert exit_code == 0

    db_hash_after = file_hash(REAL_DB_PATH)
    csv_hash_after = file_hash(REAL_CSV_PATH)

    assert db_hash_before == db_hash_after, "Database file was mutated during evaluation!"
    assert csv_hash_before == csv_hash_after, "Trusted domains CSV was mutated during evaluation!"
