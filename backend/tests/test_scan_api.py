from fastapi import HTTPException
from pydantic import ValidationError
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.scan import scan_url
from app.core.database import Base
from app.models.domain import TrustedDomain
from app.schemas.scan import URLScanRequest, URLScanResponse


def make_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'api-test.db'}")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)

    return session_factory(), engine


def test_invalid_scan_urls_return_400_and_empty_body_returns_422(tmp_path):
    session, engine = make_session(tmp_path)
    try:
        for url in [
            "https://example.com:99999",
            "https://bad_host.com",
            "https://not a valid host",
            "https://",
            "https://example.com:",
        ]:
            with pytest.raises(HTTPException) as error:
                scan_url(URLScanRequest(url=url), session)
            assert error.value.status_code == 400
        with pytest.raises(ValidationError):
            URLScanRequest(url="")
    finally:
        session.close()
        engine.dispose()


def test_scan_exact_and_similar_trusted_domains(tmp_path):
    session, engine = make_session(tmp_path)
    session.add(TrustedDomain(domain="google.com", organization="Google", category="Technology"))
    session.commit()
    try:
        exact = scan_url(URLScanRequest(url="https://www.google.com/"), session)
        assert exact["is_trusted"] is True
        assert exact["normalized_domain"] == "google.com"
        assert exact["risk_assessment"]["risk_score"] == 0
        assert exact["domain_fingerprint"]["normalized_domain"] == "google.com"
        assert exact["domain_fingerprint"]["length"] == 10
        URLScanResponse.model_validate(exact)
        legacy_response = {
            key: value
            for key, value in exact.items()
            if key != "domain_fingerprint"
        }
        assert URLScanResponse.model_validate(legacy_response).domain_fingerprint is None

        typo = scan_url(URLScanRequest(url="https://g00gle.com/login"), session)
        assert typo["is_trusted"] is False
        assert typo["similar_domains"][0]["trusted_domain"] == "google.com"
        assert typo["similar_domains"][0]["typo_analysis"]["changes"]
        assert typo["similar_domains"][0]["typo_type"] == "character_substitution"
        assert "not proof of malicious intent" in typo["similar_domains"][0]["explanation"]
        risk = typo["risk_assessment"]
        assert risk["risk_score"] == min(100, risk["raw_risk_score"])
        assert risk["raw_risk_score"] == sum(
            signal["points"] for signal in risk["signals"]
        )
        assert URLScanResponse.model_validate(typo).risk_assessment.risk_score == (
            risk["risk_score"]
        )
    finally:
        session.close()
        engine.dispose()
