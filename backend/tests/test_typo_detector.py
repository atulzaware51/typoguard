
import pytest

from app.services.typo_detector import detect_typo


def test_exact_match():
    result = detect_typo("google.com", "google.com")
    assert result["edit_distance"] == 0
    assert result["changes"] == []


def test_missing_character():
    result = detect_typo("gogle.com", "google.com")
    assert any(
        change["type"] == "missing_character"
        for change in result["changes"]
    )


def test_extra_character():
    result = detect_typo("gooogle.com", "google.com")
    assert any(
        change["type"] == "extra_character"
        for change in result["changes"]
    )


def test_character_substitution():
    result = detect_typo("g00gle.com", "google.com")
    assert any(
        change["type"] == "character_substitution"
        for change in result["changes"]
    )


def test_transposed_characters():
    result = detect_typo("googel.com", "google.com")
    assert any(
        change["type"] == "transposed_characters"
        for change in result["changes"]
    )


@pytest.mark.parametrize(
    ("submitted", "trusted", "expected_type"),
    [
        ("google.com", "google.com", "exact_match"),
        ("gogle.com", "google.com", "missing_character"),
        ("gooogle.com", "google.com", "extra_character"),
        ("g00gle.com", "google.com", "character_substitution"),
        ("goolge.com", "google.com", "transposed_characters"),
        ("g00gle.net", "google.com", "multiple_or_complex_changes"),
    ],
)
def test_comparison_record_reports_type_score_and_explanation(
    submitted, trusted, expected_type
):
    result = detect_typo(submitted, trusted)
    assert result["typo_type"] == expected_type
    assert 0 <= result["similarity_score"] <= 100
    assert result["trusted_domain"] == "google.com"
    assert "explanation" in result
    assert "changed_characters" in result
    if expected_type != "exact_match":
        assert "not proof of malicious intent" in result["explanation"]


def test_empty_comparison_input_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        detect_typo(None, "google.com")