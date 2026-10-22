import csv
from pathlib import Path

import pytest
from fastapi import HTTPException
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.domains import import_trusted_domains
from app.core.database import Base, migrate_domain_fingerprints
from app.models.domain import DomainFingerprint, TrustedDomain
from app.services import dataset_service


@pytest.fixture
def db_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def write_csv(path: Path, rows):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=["domain", "organization", "category"])
        writer.writeheader()
        writer.writerows(rows)


def test_dataset_path_resolves_to_project_dataset():
    assert dataset_service.DATASET_PATH == (
        Path(__file__).resolve().parents[2] / "dataset" / "trusted_domains.csv"
    )
    assert dataset_service.DATASET_PATH.is_file()


def test_real_dataset_imports_into_isolated_database(db_session):
    result = dataset_service.load_trusted_domains(db_session)
    assert result["inserted"] > 0
    assert db_session.query(TrustedDomain).count() == result["inserted"]
    assert db_session.query(DomainFingerprint).count() == result["inserted"]


def test_missing_csv_has_actionable_error(monkeypatch, tmp_path, db_session):
    monkeypatch.setattr(dataset_service, "DATASET_PATH", tmp_path / "missing.csv")
    with pytest.raises(FileNotFoundError, match="Restore dataset/trusted_domains.csv"):
        dataset_service.load_trusted_domains(db_session)


def test_missing_dataset_endpoint_returns_actionable_400(monkeypatch, tmp_path, db_session):
    monkeypatch.setattr(dataset_service, "DATASET_PATH", tmp_path / "missing.csv")

    with pytest.raises(HTTPException) as error:
        import_trusted_domains(db_session)

    assert error.value.status_code == 400
    assert "Restore dataset/trusted_domains.csv" in error.value.detail


@pytest.mark.parametrize(
    "content",
    ["wrong,headers\na,b\n", "domain,organization,category\nnot a domain,Org,Category\n"],
)
def test_malformed_csv_is_rejected_and_rolls_back(monkeypatch, tmp_path, db_session, content):
    path = tmp_path / "bad.csv"
    path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(dataset_service, "DATASET_PATH", path)
    with pytest.raises(ValueError):
        dataset_service.load_trusted_domains(db_session)
    assert db_session.query(TrustedDomain).count() == 0


def test_duplicate_rows_and_repeated_import_do_not_duplicate_records(monkeypatch, tmp_path, db_session):
    path = tmp_path / "domains.csv"
    write_csv(path, [
        {"domain": "Google.com", "organization": "Google", "category": "Tech"},
        {"domain": "google.com", "organization": "Duplicate", "category": "Duplicate"},
    ])
    monkeypatch.setattr(dataset_service, "DATASET_PATH", path)

    first = dataset_service.load_trusted_domains(db_session)
    second = dataset_service.load_trusted_domains(db_session)

    assert first["inserted"] == 1
    assert first["updated"] == 0
    assert second["inserted"] == 0
    assert second["updated"] == 0
    assert db_session.query(TrustedDomain).count() == 1
    assert db_session.query(DomainFingerprint).count() == 1
    record = db_session.query(TrustedDomain).one()
    assert record.organization == "Google"


def test_changed_domain_metadata_is_reported_once(monkeypatch, tmp_path, db_session):
    path = tmp_path / "domains.csv"
    write_csv(path, [
        {"domain": "google.com", "organization": "Google", "category": "Tech"},
    ])
    monkeypatch.setattr(dataset_service, "DATASET_PATH", path)
    db_session.add(TrustedDomain(
        domain="google.com",
        organization="Old name",
        category="Old category",
    ))
    db_session.commit()

    first = dataset_service.load_trusted_domains(db_session)
    second = dataset_service.load_trusted_domains(db_session)

    assert first["updated"] == 1
    assert second["updated"] == 0
    assert db_session.query(TrustedDomain).one().organization == "Google"


def test_blank_domain_rows_are_reported_as_skipped(monkeypatch, tmp_path, db_session):
    path = tmp_path / "domains.csv"
    write_csv(path, [
        {"domain": "", "organization": "No domain", "category": "Other"},
        {"domain": "google.com", "organization": "Google", "category": "Tech"},
    ])
    monkeypatch.setattr(dataset_service, "DATASET_PATH", path)

    result = dataset_service.load_trusted_domains(db_session)

    assert result["inserted"] == 1
    assert result["skipped"] == 1


def test_fingerprint_migration_adds_and_backfills_columns_idempotently(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as connection:
        connection.exec_driver_sql("""
            CREATE TABLE domain_fingerprints (
                id INTEGER PRIMARY KEY,
                domain_id INTEGER NOT NULL,
                normalized_domain VARCHAR(253) NOT NULL,
                length INTEGER NOT NULL,
                alphabetic_count INTEGER NOT NULL,
                numeric_count INTEGER NOT NULL,
                hyphen_count INTEGER NOT NULL,
                has_digit BOOLEAN NOT NULL,
                has_hyphen BOOLEAN NOT NULL
            )
        """)
        connection.exec_driver_sql(
            "INSERT INTO domain_fingerprints "
            "(id, domain_id, normalized_domain, length, alphabetic_count, "
            "numeric_count, hyphen_count, has_digit, has_hyphen) "
            "VALUES (1, 1, 'sub.xn--bcher-kva.com', 0, 0, 0, 0, 0, 0)"
        )

    try:
        migrate_domain_fingerprints(engine)
        migrate_domain_fingerprints(engine)
        with engine.connect() as connection:
            row = connection.exec_driver_sql(
                "SELECT subdomain_count, is_punycode "
                "FROM domain_fingerprints WHERE id = 1"
            ).one()
            assert tuple(row) == (1, 1)
            assert connection.exec_driver_sql(
                "SELECT COUNT(*) FROM domain_fingerprints"
            ).scalar_one() == 1
    finally:
        engine.dispose()
