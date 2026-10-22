"""Create deterministic structural fingerprints for normalized hostnames."""

import ipaddress

from app.services.url_parser import normalize_domain


# The fallback deliberately recognizes only common suffixes. Without a local
# Public Suffix List, unknown suffixes are not used to infer subdomain counts.
_SINGLE_LABEL_SUFFIXES = {
    "ai", "app", "au", "biz", "ca", "ch", "cn", "com", "de", "dev",
    "edu", "es", "fr", "gov", "info", "in", "int", "io", "it", "jp",
    "me", "mil", "net", "nl", "no", "nz", "org", "ru", "se", "uk",
    "us", "xyz",
}
_COMPOUND_PUBLIC_SUFFIXES = {
    "ac.uk", "co.in", "co.jp", "co.nz", "co.uk", "com.au", "com.br",
    "com.cn", "com.in", "com.jp", "gov.uk", "org.uk",
}


def _subdomain_count(domain: str) -> int:
    """Count leading labels only for suffixes known to this conservative fallback."""
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        return 0

    labels = domain.split(".")
    if len(labels) < 2:
        return 0

    suffix = ".".join(labels[-2:])
    if suffix in _COMPOUND_PUBLIC_SUFFIXES:
        return max(0, len(labels) - 3)
    if labels[-1] in _SINGLE_LABEL_SUFFIXES:
        return max(0, len(labels) - 2)
    return 0


def create_fingerprint(domain: str) -> dict:
    """
    Fingerprint a hostname after applying the URL parser's canonicalization.

    Length and character counts cover the complete normalized ASCII hostname,
    including dots. Subdomain counts use only the local suffix allowlist above;
    unknown public suffixes conservatively produce zero.
    """
    if not isinstance(domain, str) or not domain.strip():
        raise ValueError("Domain cannot be empty")

    try:
        normalized_domain = normalize_domain(domain)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid domain: {domain}") from exc

    labels = normalized_domain.split(".")
    return {
        "normalized_domain": normalized_domain,
        "length": len(normalized_domain),
        "alphabetic_count": sum(character.isalpha() for character in normalized_domain),
        "numeric_count": sum(character.isdigit() for character in normalized_domain),
        "hyphen_count": normalized_domain.count("-"),
        "has_digit": any(character.isdigit() for character in normalized_domain),
        "has_hyphen": "-" in normalized_domain,
        "subdomain_count": _subdomain_count(normalized_domain),
        "is_punycode": any(label.startswith("xn--") for label in labels),
    }
