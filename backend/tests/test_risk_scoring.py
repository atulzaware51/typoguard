
"""Edge-case tests for TypoGuard risk scoring."""

import pytest

from app.services.risk_scoring import calculate_risk, risk_level_for_score
from app.services.typo_detector import detect_typo


def test_trusted_domain_without_other_signals_is_low_risk():
    result = calculate_risk(
        domain="google.com",
        is_trusted=True,
        similar_domains=[],
        scheme="https",
    )

    assert result["is_trusted"] is True
    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"


def test_lookalike_with_two_substitutions_is_highlighted():
    result = calculate_risk(
        domain="g00gle.com",
        is_trusted=False,
        similar_domains=[
            {
                "trusted_domain": "google.com",
                "similarity_score": 96,
                "typo_analysis": {
                    "changes": [
                        {"type": "character_substitution"}
                    ]
                },
            }
        ],
        scheme="https",
    )

    assert result["risk_score"] == 50
    assert result["risk_level"] == "High"

    signals = {reason["signal"] for reason in result["reasons"]}
    assert "high_domain_similarity" in signals
    assert "character_changes" in signals


def test_punycode_hostname_adds_a_reason():
    result = calculate_risk(
        domain="xn--example-ova.com",
        is_trusted=False,
        similar_domains=[],
        scheme="https",
    )

    assert result["risk_score"] == 20
    assert any(
        reason["signal"] == "punycode_hostname"
        for reason in result["reasons"]
    )


def test_suspicious_path_adds_a_reason():
    result = calculate_risk(
        domain="example.com",
        is_trusted=False,
        similar_domains=[],
        scheme="https",
        path="/login",
    )

    assert result["risk_score"] == 5
    assert any(
        reason["signal"] == "suspicious_path_or_query"
        for reason in result["reasons"]
    )


def test_http_adds_a_reason():
    result = calculate_risk(
        domain="example.com",
        is_trusted=False,
        similar_domains=[],
        scheme="http",
    )

    assert result["risk_score"] == 5
    assert any(
        reason["signal"] == "unencrypted_http"
        for reason in result["reasons"]
    )


def test_score_never_exceeds_100():
    result = calculate_risk(
        domain="secure-login-wallet.example.com",
        is_trusted=False,
        similar_domains=[
            {
                "trusted_domain": "example.net",
                "similarity_score": 99,
                "typo_analysis": {
                    "changes": [{"type": "character_substitution"}]
                },
            }
        ],
        scheme="http",
        path="/login/verify/account/wallet",
        query="password=reset",
    )

    assert 0 <= result["risk_score"] <= 100


def test_trusted_exact_match_does_not_receive_similarity_penalties():
    result = calculate_risk(
        domain="google.com",
        is_trusted=True,
        similar_domains=[{
            "trusted_domain": "google.com",
            "similarity_score": 100,
            "typo_analysis": {"changes": [{"type": "character_substitution"}]},
        }],
    )
    assert result["risk_score"] == 0
    assert [signal["code"] for signal in result["signals"]] == [
        "no_configured_warning"
    ]


@pytest.mark.parametrize(
    ("similarity", "expected_points"),
    [(69.99, 0), (70, 10), (79.99, 10), (80, 18), (90, 28), (95, 35)],
)
def test_similarity_scoring_tiers(similarity, expected_points):
    result = calculate_risk(
        domain="example.net",
        is_trusted=False,
        similar_domains=[{
            "trusted_domain": "example.com",
            "similarity_score": similarity,
        }],
    )
    assert sum(signal["points"] for signal in result["signals"]) == expected_points


def test_repeated_keywords_are_counted_once_per_signal():
    result = calculate_risk(
        domain="login-login.example.com",
        is_trusted=False,
        similar_domains=[],
        path="/login/login",
        query="next=login",
    )
    points = {signal["code"]: signal["points"] for signal in result["signals"]}
    assert points["suspicious_hostname_keywords"] == 10
    assert points["suspicious_path_or_query"] == 5


def test_signals_reasons_and_capped_score_are_consistent():
    result = calculate_risk(
        domain="secure-login-wallet.xn--example.com",
        is_trusted=False,
        similar_domains=[{
            "trusted_domain": "example.com",
            "similarity_score": 99,
            "typo_analysis": {"changes": [{"type": "character_substitution"}]},
        }],
        scheme="http",
        path="/login/verify",
        query="account=wallet",
    )

    signals = result["signals"]
    assert len({signal["code"] for signal in signals}) == len(signals)
    assert result["raw_risk_score"] == sum(signal["points"] for signal in signals)
    assert result["risk_score"] == min(100, result["raw_risk_score"])
    assert result["score_capped"] is (result["raw_risk_score"] > 100)
    assert result["score_capped"] is True
    assert result["risk_score"] == 100
    assert [
        (reason["signal"], reason["points"], reason["description"])
        for reason in result["reasons"]
    ] == [
        (signal["code"], signal["points"], signal["description"])
        for signal in signals
    ]


def test_scoring_candidate_ties_are_deterministic():
    matches = [
        {"trusted_domain": "zeta.com", "similarity_score": 95},
        {"trusted_domain": "alpha.com", "similarity_score": 95},
    ]
    first = calculate_risk("example.com", False, matches)
    second = calculate_risk("example.com", False, list(reversed(matches)))
    assert first == second
    assert "alpha.com" in first["signals"][0]["description"]


@pytest.mark.parametrize(
    ("score", "expected_level"),
    [
        (0, "Low"),
        (24, "Low"),
        (25, "Moderate"),
        (49, "Moderate"),
        (50, "High"),
        (74, "High"),
        (75, "Critical"),
        (100, "Critical"),
    ],
)
def test_risk_level_boundaries(score, expected_level):
    """Exercise the production score classification helper."""
    assert risk_level_for_score(score) == expected_level



def test_many_differences_are_not_called_simple_substitutions():
    result = detect_typo("g00gle.com", "github.com")

    assert result["changes"][0]["type"] == "multiple_or_complex_changes"


def test_two_substitutions_are_reported():
    result = detect_typo("g00gle.com", "google.com")

    assert result["changes"][0]["type"] == "character_substitution"
    assert len(result["changes"][0]["details"]) == 2


def test_adjacent_swap_is_detected():
    result = detect_typo("goolge.com", "google.com")

    assert result["changes"][0]["type"] == "transposed_characters"


def test_empty_domain_is_rejected():
    import pytest

    with pytest.raises(ValueError):
        detect_typo("", "google.com")


def test_misleading_subdomain_prefix_triggers_signal():
    result = calculate_risk(
        domain="google.com.attacker.com",
        is_trusted=False,
        similar_domains=[],
        trusted_domains=["google.com"],
    )
    assert result["risk_score"] == 35
    assert result["risk_level"] == "Moderate"
    assert any(s["code"] == "misleading_subdomain" for s in result["signals"])


def test_punycode_unicode_lookalike_detected_and_elevated():
    # Cyrillic 'а' lookalike for apple.com
    result = calculate_risk(
        domain="xn--pple-43d.com",
        is_trusted=False,
        similar_domains=[],
        trusted_domains=["apple.com"],
    )
    assert result["risk_score"] == 35
    assert result["risk_level"] == "Moderate"
    assert any(s["code"] == "punycode_lookalike" for s in result["signals"])


def test_unrelated_domain_with_complex_diff_suppresses_lookalike_false_positive():
    # example.com has an 80% Levenshtein ratio with apple.com but multiple/complex changes
    similar = [{
        "trusted_domain": "apple.com",
        "similarity_score": 80.0,
        "typo_analysis": {
            "typo_type": "multiple_or_complex_changes",
            "changes": [{"type": "multiple_or_complex_changes"}],
        },
    }]
    result = calculate_risk(
        domain="example.com",
        is_trusted=False,
        similar_domains=similar,
        trusted_domains=["apple.com"],
    )
    # Both character_changes and high_domain_similarity are suppressed
    assert result["risk_score"] == 18
    assert result["risk_level"] == "Low"
    assert not any(s["code"] == "character_changes" for s in result["signals"])
