import csv

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.domains import router as domains_router
from app.api.scan import router as scan_router
from app.core.database import Base, get_db
from app.models.domain import TrustedDomain
from app.services import dataset_service


@pytest.fixture
def client(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'admin-test.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    session.add(TrustedDomain(
        domain="google.com", organization="Google", category="Technology"
    ))
    session.commit()

    app = FastAPI()
    app.include_router(scan_router)
    app.include_router(domains_router)
    app.dependency_overrides[get_db] = lambda: session
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        session.close()
        engine.dispose()


@pytest.mark.parametrize("header", [None, "incorrect-secret"])
def test_import_rejects_missing_or_incorrect_secret_and_skips_service(
    client, monkeypatch, header
):
    monkeypatch.setenv("TYPOGUARD_ADMIN_SECRET", "test-admin-secret")
    called = []
    monkeypatch.setattr(
        "app.api.domains.load_trusted_domains",
        lambda _db: called.append(True),
    )
    headers = {} if header is None else {"X-Admin-Secret": header}
    response = client.post("/api/domains/import", headers=headers)

    assert response.status_code == 401
    assert response.json() == {"detail": "Admin authentication required"}
    assert called == []


@pytest.mark.parametrize("configured_secret", [None, ""])
def test_import_fails_closed_when_secret_is_unconfigured(
    client, monkeypatch, configured_secret
):
    if configured_secret is None:
        monkeypatch.delenv("TYPOGUARD_ADMIN_SECRET", raising=False)
    else:
        monkeypatch.setenv("TYPOGUARD_ADMIN_SECRET", configured_secret)

    called = []
    monkeypatch.setattr(
        "app.api.domains.load_trusted_domains",
        lambda _db: called.append(True),
    )
    response = client.post(
        "/api/domains/import", headers={"X-Admin-Secret": "test-admin-secret"}
    )

    assert response.status_code == 401
    assert called == []


def test_import_with_correct_secret_imports_dataset(
    client, monkeypatch, tmp_path
):
    monkeypatch.setenv("TYPOGUARD_ADMIN_SECRET", "test-admin-secret")
    csv_path = tmp_path / "domains.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(
            stream, fieldnames=["domain", "organization", "category"]
        )
        writer.writeheader()
        writer.writerow({
            "domain": "example.org",
            "organization": "Example",
            "category": "Other",
        })
    monkeypatch.setattr(dataset_service, "DATASET_PATH", csv_path)

    response = client.post(
        "/api/domains/import", headers={"X-Admin-Secret": "test-admin-secret"}
    )

    assert response.status_code == 200
    assert response.json()["inserted"] == 1
    assert client.get("/api/domains/example.org").status_code == 200


def test_public_scan_and_read_only_domain_routes_need_no_admin_secret(
    client, monkeypatch
):
    monkeypatch.delenv("TYPOGUARD_ADMIN_SECRET", raising=False)

    scan = client.post("/api/scan/", json={"url": "https://google.com"})
    listing = client.get("/api/domains/")
    lookup = client.get("/api/domains/google.com")
    similar = client.get("/api/domains/similar/gooogle.com")

    assert scan.status_code == 200
    assert listing.status_code == 200
    assert lookup.status_code == 200
    assert similar.status_code == 200
