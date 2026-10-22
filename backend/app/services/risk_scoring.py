"""TypoGuard: explainable, rule-based URL risk scoring."""

SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "password",
    "wallet",
    "banking",
    "confirm",
    "recovery",
    "authenticate",
    "update",
}


def risk_level_for_score(score: int) -> str:
    """Map a score in the documented range to its production risk level."""
    score = max(0, min(100, score))
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Moderate"
    return "Low"


import idna
from rapidfuzz import fuzz

CONFUSABLES = {
    "\u0430": "a", "\u0441": "c", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0455": "s", "\u0445": "x", "\u0443": "y", "\u0456": "i", "\u0458": "j",
    "\u03bf": "o", "\u03b1": "a", "\u03c1": "p", "\u03bd": "v",
}


def _decode_punycode_lookalike(domain: str) -> str:
    """Decode punycode labels and map common confusable homoglyphs to ASCII."""
    labels = []
    for label in domain.split("."):
        if label.startswith("xn--"):
            try:
                decoded = idna.decode(label)
                mapped = "".join(CONFUSABLES.get(ch, ch) for ch in decoded)
                labels.append(mapped)
            except Exception:
                labels.append(label)
        else:
            labels.append(label)
    return ".".join(labels)


def calculate_risk(
    domain: str,
    is_trusted: bool,
    similar_domains: list[dict],
    scheme: str = "https",
    path: str = "",
    query: str = "",
    trusted_domains: list[str] | None = None,
) -> dict:
    """
    Score visible URL strings and local trusted-domain comparisons only.

    Each returned signal is also the source record for its compatibility
    ``reasons`` entry; no submitted URL is fetched or resolved.
    """
    domain = domain.strip().lower().rstrip(".")
    scheme = scheme.strip().lower()
    signals = []
    raw_score = 0

    def add_signal(code: str, label: str, points: int, description: str) -> None:
        nonlocal raw_score
        signals.append({
            "code": code,
            "label": label,
            "points": points,
            "description": description,
        })
        raw_score += points

    # The best candidate is selected consistently if scores tie.
    if not is_trusted and similar_domains:
        best_match = min(
            similar_domains,
            key=lambda item: (
                -float(item.get("similarity_score", 0)),
                str(item.get("trusted_domain", "")),
            ),
        )
        similarity = float(best_match.get("similarity_score", 0))
        trusted_match = best_match.get("trusted_domain", "unknown")

        if similarity >= 95:
            points = 35
        elif similarity >= 90:
            points = 28
        elif similarity >= 80:
            points = 18
        elif similarity >= 70:
            points = 10
        else:
            points = 0

        if points:
            add_signal(
                "high_domain_similarity",
                "Similar to a trusted domain",
                points,
                (
                    f"{domain} closely resembles {trusted_match} "
                    f"(similarity: {similarity:.1f}%)."
                ),
            )

    # Character changes are flagged only for genuine single/double typos,
    # suppressing false positives on unrelated words with complex diffs.
    if not is_trusted:
        has_character_changes = any(
            float(match.get("similarity_score", 0)) >= 70
            and match.get("typo_analysis", {}).get("changes", [])
            and match.get("typo_analysis", {}).get("typo_type") != "multiple_or_complex_changes"
            for match in similar_domains
        )
        if has_character_changes:
            add_signal(
                "character_changes",
                "Lookalike character changes",
                15,
                "The submitted domain contains character changes compared with a similar trusted domain.",
            )

    # Detect misleading trusted domains embedded in subdomain prefixes (e.g. google.com.attacker.com).
    if not is_trusted and trusted_domains:
        domain_labels = domain.split(".")
        for t in trusted_domains:
            t_clean = t.strip().lower().rstrip(".")
            t_labels = t_clean.split(".")
            t_len = len(t_labels)
            if len(domain_labels) > t_len:
                for i in range(len(domain_labels) - t_len):
                    if domain_labels[i:i + t_len] == t_labels:
                        add_signal(
                            "misleading_subdomain",
                            "Misleading trusted-domain prefix",
                            35,
                            f"The domain embeds trusted domain \"{t_clean}\" as a subdomain prefix.",
                        )
                        break
            if any(s["code"] == "misleading_subdomain" for s in signals):
                break

    # Punycode hostname and Unicode lookalike detection
    if "xn--" in domain:
        punycode_lookalike_found = False
        if trusted_domains:
            decoded_domain = _decode_punycode_lookalike(domain)
            for t in trusted_domains:
                t_clean = t.strip().lower().rstrip(".")
                if decoded_domain == t_clean or fuzz.ratio(decoded_domain, t_clean) >= 88:
                    add_signal(
                        "punycode_lookalike",
                        "Punycode lookalike of trusted domain",
                        35,
                        f"The Punycode domain decodes to a lookalike of trusted domain \"{t_clean}\".",
                    )
                    punycode_lookalike_found = True
                    break

        if not punycode_lookalike_found:
            add_signal(
                "punycode_hostname",
                "Punycode hostname",
                20,
                "The hostname contains Punycode. Inspect the international characters for possible lookalikes.",
            )

    hostname_labels = domain.replace("-", ".").split(".")
    matched_host_words = sorted(
        word
        for word in SUSPICIOUS_KEYWORDS
        if any(word in label for label in hostname_labels)
    )
    if matched_host_words:
        points = min(20, 10 + (len(matched_host_words) - 1) * 5)
        add_signal(
            "suspicious_hostname_keywords",
            "Suspicious hostname keywords",
            points,
            "Suspicious hostname keywords found: " + ", ".join(matched_host_words) + ".",
        )

    url_text = f"{path} {query}".lower()
    matched_url_words = sorted(
        word for word in SUSPICIOUS_KEYWORDS if word in url_text
    )
    if matched_url_words:
        points = min(10, len(matched_url_words) * 5)
        add_signal(
            "suspicious_path_or_query",
            "Suspicious path or query keyword",
            points,
            "Suspicious words found in the URL path or query: "
            + ", ".join(matched_url_words)
            + ".",
        )

    if scheme == "http":
        add_signal(
            "unencrypted_http",
            "Unencrypted HTTP",
            5,
            "The URL uses HTTP instead of HTTPS.",
        )

    if not signals:
        signals.append({
            "code": "no_configured_warning",
            "label": "No configured warning",
            "points": 0,
            "description": (
                "No configured risk signals were detected. "
                "This does not guarantee the URL is safe."
            ),
        })

    score = min(100, raw_score)
    return {
        "risk_score": score,
        "risk_level": risk_level_for_score(score),
        "reasons": [
            {
                "signal": signal["code"],
                "points": signal["points"],
                "description": signal["description"],
            }
            for signal in signals
        ],
        "signals": signals,
        "raw_risk_score": raw_score,
        "score_capped": raw_score > 100,
        "is_trusted": is_trusted,
        "disclaimer": (
            "This is a heuristic assessment, not a malware verdict. "
            "A low score does not guarantee safety."
        ),
    }
