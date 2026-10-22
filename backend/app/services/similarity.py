
"""Compare a submitted domain against trusted domains."""

from rapidfuzz import fuzz, process


def find_similar_domains(
    domain: str,
    trusted_domains: list[str],
    limit: int = 5,
) -> list[dict]:
    """
    Return the closest trusted-domain matches.

    Similarity is a string-comparison score, not a security
    verdict or a calibrated probability of malicious activity.
    """

    # Standardize the submitted domain.
    domain = domain.strip().lower().rstrip(".")

    if domain.startswith("www."):
        domain = domain[4:]

    if not domain:
        return []

    # Remove duplicates and exclude an exact match.
    candidates = sorted({
        item.strip().lower().rstrip(".")
        for item in trusted_domains
        if item and item.strip().lower().rstrip(".") != domain
    })

    # Find the closest matching trusted domains.
    matches = process.extract(
        domain,
        candidates,
        scorer=fuzz.ratio,
        limit=limit,
        score_cutoff=50,
    )

    # Convert RapidFuzz results into API-friendly dictionaries.
    return [
        {
            "trusted_domain": matched_domain,
            "similarity_score": round(score, 2),
        }
        for matched_domain, score, _ in matches
    ]