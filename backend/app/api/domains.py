
# ============================================================
# File: app/api/domains.py
# Purpose:
# 1. Load trusted domains from a CSV dataset into SQLite.
# 2. Create and update domain fingerprints.
# 3. Provide API endpoints to import, list, and search domains.
# ============================================================

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.domain import TrustedDomain
from app.services.dataset_service import (
    DATASET_PATH,
    PROJECT_ROOT,
    load_trusted_domains,
)
from app.services.similarity import find_similar_domains
from app.services.url_parser import normalize_domain

# ------------------------------------------------------------
# 2. API ROUTER CONFIGURATION
# ------------------------------------------------------------

# All endpoints in this file will start with /api/domains.
# The tag groups them under "Trusted Domains" in Swagger UI.
router = APIRouter(
    prefix="/api/domains",
    tags=["Trusted Domains"],
)


# ------------------------------------------------------------
# 3. API ENDPOINT: IMPORT TRUSTED DOMAINS
# ------------------------------------------------------------

@router.post("/import")
def import_trusted_domains(
    db: Session = Depends(get_db),
):
    """
    Import or update trusted domains using the CSV dataset.

    Endpoint:
        POST /api/domains/import
    """

    try:
        # Call the CSV import service using the injected session.
        return load_trusted_domains(db)

    except (ValueError, FileNotFoundError) as exc:
        # Roll back pending changes after a validation or file error.
        db.rollback()

        # Return a clear client error instead of a server traceback.
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


# ------------------------------------------------------------
# 5. API ENDPOINT: LIST TRUSTED DOMAINS
# ------------------------------------------------------------

@router.get("/")
def list_trusted_domains(
    db: Session = Depends(get_db),
):
    """
    Return all trusted-domain records.

    Endpoint:
        GET /api/domains/
    """

    # Query all trusted-domain records from the database.
    records = (
        db.query(TrustedDomain)
        .order_by(TrustedDomain.domain)
        .all()
    )

    # FastAPI serializes the returned SQLAlchemy objects.
    return records


# ------------------------------------------------------------
# 6. API ENDPOINT: LOOK UP A TRUSTED DOMAIN
# ------------------------------------------------------------

@router.get("/{domain}")
def get_trusted_domain(

    domain: str,
    db: Session = Depends(get_db),
):
    """
    Look up a domain by its name.

    Endpoint example:
        GET /api/domains/google.com
    """

    # Normalize the requested domain before searching.
    normalized = normalize_domain(domain)

    # Look for an exact match in the trusted-domain table.
    record = (
        db.query(TrustedDomain)
        .filter(TrustedDomain.domain == normalized)
        .first()
    )

    # Return 404 if the domain is not in our trusted dataset.
    if record is None:
        raise HTTPException(
            status_code=404,
            detail=f"Trusted domain not found: {normalized}",
        )

    # Return the matching database record.
    return record



@router.get("/similar/{domain}")
def get_similar_domains(
    domain: str,
    db: Session = Depends(get_db),
):
    """Find trusted domains similar to the submitted domain."""

    # Load trusted domain names from the database.
    trusted_domains = [
        record[0]
        for record in db.query(TrustedDomain.domain).all()
    ]

    # Compare the submitted domain against the trusted dataset.
    matches = find_similar_domains(
        domain=domain,
        trusted_domains=trusted_domains,
        limit=5,
    )

    return {
        "submitted_domain": domain,
        "matches": matches,
    }

