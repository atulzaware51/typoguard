
"""Import trusted domains and their fingerprints from the local CSV."""

import csv
from pathlib import Path

from sqlalchemy.orm import Session

from app.models.domain import DomainFingerprint, TrustedDomain
from app.services.fingerprint import create_fingerprint
from app.services.url_parser import normalize_domain

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DATASET_PATH = PROJECT_ROOT / "dataset" / "trusted_domains.csv"


def load_trusted_domains(db: Session) -> dict:
    """Synchronize the CSV safely; blank-domain rows are skipped and reported."""
    if not DATASET_PATH.is_file():
        raise FileNotFoundError(
            f"Trusted-domain CSV is missing at {DATASET_PATH}. "
            "Restore dataset/trusted_domains.csv and retry."
        )

    inserted = updated = skipped = 0
    try:
        with DATASET_PATH.open("r", encoding="utf-8-sig", newline="") as file:
            reader = csv.DictReader(file, strict=True)
            required = {"domain", "organization", "category"}
            if not reader.fieldnames or not required.issubset(reader.fieldnames):
                raise ValueError(
                    "Trusted-domain CSV must contain domain, organization, and category headers."
                )
            seen = set()
            for row_number, row in enumerate(reader, start=2):
                if None in row:
                    raise ValueError(f"Malformed CSV row {row_number}: too many columns.")
                raw_domain = (row.get("domain") or "").strip()
                if not raw_domain:
                    skipped += 1
                    continue
                try:
                    domain = normalize_domain(raw_domain)
                except ValueError as exc:
                    raise ValueError(f"Invalid domain on CSV row {row_number}: {raw_domain}") from exc
                if "." not in domain or len(domain) > 253:
                    raise ValueError(f"Invalid domain on CSV row {row_number}: {raw_domain}")
                organization = (row.get("organization") or "").strip()
                category = (row.get("category") or "").strip()
                if not organization or not category:
                    raise ValueError(f"Missing organization/category on CSV row {row_number} ({domain}).")
                if domain in seen:
                    continue
                seen.add(domain)
                record = db.query(TrustedDomain).filter(TrustedDomain.domain == domain).first()
                if record is None:
                    record = TrustedDomain(domain=domain, organization=organization, category=category)
                    db.add(record)
                    db.flush()
                    inserted += 1
                elif (
                    record.organization != organization
                    or record.category != category
                ):
                    record.organization = organization
                    record.category = category
                    updated += 1
                features = create_fingerprint(domain)
                fingerprint = db.query(DomainFingerprint).filter(
                    DomainFingerprint.domain_id == record.id
                ).first()
                if fingerprint is None:
                    db.add(DomainFingerprint(domain_id=record.id, **features))
                else:
                    for key, value in features.items():
                        setattr(fingerprint, key, value)
        db.commit()
    except (csv.Error, UnicodeError) as exc:
        db.rollback()
        raise ValueError(f"Unable to read trusted-domain CSV: {exc}") from exc
    except Exception:
        db.rollback()
        raise

    return {
        "message": "Trusted domains imported successfully",
        "inserted": inserted,
        "updated": updated,
        "skipped": skipped,
        "dataset": str(DATASET_PATH),
    }
