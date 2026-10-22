import pytest

from app.services.fingerprint import create_fingerprint


def test_fingerprint_counts_normalized_hostname_characters():
    fingerprint = create_fingerprint("google.com")

    assert fingerprint == {
        "normalized_domain": "google.com",
        "length": 10,
        "alphabetic_count": 9,
        "numeric_count": 0,
        "hyphen_count": 0,
        "has_digit": False,
        "has_hyphen": False,
        "subdomain_count": 0,
        "is_punycode": False,
    }


def test_fingerprint_normalizes_uppercase_www_and_trailing_dot():
    fingerprint = create_fingerprint("WWW.Example.COM.")
    assert fingerprint["normalized_domain"] == "example.com"
    assert fingerprint["length"] == len("example.com")


def test_fingerprint_counts_digits_and_hyphens():
    fingerprint = create_fingerprint("g00gle-login.com")
    assert fingerprint["numeric_count"] == 2
    assert fingerprint["hyphen_count"] == 1
    assert fingerprint["has_digit"] is True
    assert fingerprint["has_hyphen"] is True


@pytest.mark.parametrize(
    ("domain", "expected_count"),
    [
        ("a.b.google.com", 2),
        ("login.example.co.uk", 1),
        ("example.unknownsuffix", 0),
    ],
)
def test_fingerprint_counts_subdomains_with_conservative_suffix_rules(
    domain, expected_count
):
    assert create_fingerprint(domain)["subdomain_count"] == expected_count


def test_fingerprint_detects_punycode_labels():
    fingerprint = create_fingerprint("WWW.BÜCHER.de.")
    assert fingerprint["normalized_domain"] == "xn--bcher-kva.de"
    assert fingerprint["is_punycode"] is True


@pytest.mark.parametrize("domain", ["", "   ", "not a domain", "example..com", None])
def test_fingerprint_rejects_empty_or_invalid_domains(domain):
    with pytest.raises(ValueError):
        create_fingerprint(domain)
