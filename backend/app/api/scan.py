
"""API endpoint for scanning URLs against trusted domains."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.domain import TrustedDomain
from app.schemas.scan import URLScanRequest, URLScanResponse
from app.services.url_parser import parse_url, normalize_domain
from app.services.similarity import find_similar_domains
from app.services.typo_detector import detect_typo
from app.services.risk_scoring import calculate_risk
from app.services.fingerprint import create_fingerprint


router = APIRouter(prefix="/api/scan", tags=["URL Scanner"])


@router.post("/", response_model=URLScanResponse)
def scan_url(
    request: URLScanRequest,
    db: Session = Depends(get_db),
):
    """Parse a URL, compare its domain, and calculate a risk score."""

    # Step 1: Parse the URL without visiting the website.
    try:
        parsed = parse_url(request.url)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    # Step 2: Normalize the hostname for consistent comparisons.
    submitted_domain = normalize_domain(parsed["hostname"])

    # Step 3: Check for an exact match in the trusted-domain database.
    exact_match = (
        db.query(TrustedDomain)
        .filter(TrustedDomain.domain == submitted_domain)
        .first()
    )

    # Step 4: Load trusted domains from the local database.
    trusted_domains = [
        row[0]
        for row in db.query(TrustedDomain.domain).all()
    ]

    # Step 5: Find the closest trusted-domain matches.
    matches = find_similar_domains(
        domain=submitted_domain,
        trusted_domains=trusted_domains,
        limit=5,
    )

    # Step 6: Explain character changes for each similar match.
    for match in matches:
        analysis = detect_typo(
            submitted_domain,
            match["trusted_domain"],
        )
        match["typo_analysis"] = analysis
        match["typo_type"] = analysis["typo_type"]
        match["changed_characters"] = analysis["changed_characters"]
        match["explanation"] = analysis["explanation"]

    # Step 7: Calculate the risk score from the available signals.
    risk_assessment = calculate_risk(
        domain=submitted_domain,
        is_trusted=exact_match is not None,
        similar_domains=matches,
        scheme=parsed["scheme"],
        path=parsed["path"],
        query=parsed["query"],
    )

    # Step 8: Return all scan results.
    return {
        "valid": True,
        "original_url": parsed["original_url"],
        "scheme": parsed["scheme"],
        "hostname": parsed["hostname"],
        "normalized_domain": submitted_domain,
        "port": parsed["port"],
        "path": parsed["path"],
        "query": parsed["query"],
        "fragment": parsed["fragment"],
        "is_trusted": exact_match is not None,
        "similar_domains": matches,
        "domain_fingerprint": create_fingerprint(submitted_domain),
        "risk_assessment": risk_assessment,
    }
