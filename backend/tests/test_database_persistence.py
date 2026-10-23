import sqlite3

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import (
    BASE_DIR,
    Base,
    create_database_engine,
    database_path_from_env,
    migrate_domain_fingerprints,
)
from app.models.domain import TrustedDomain


def test_database_path_uses_environment_and_local_default(monkeypatch, tmp_path):
    monkeypatch.delenv("TYPOGUARD_SQLITE_PATH", raising=False)
    assert database_path_from_env() == BASE_DIR / "typoguard.db"

    configured = tmp_path / "persistent" / "typoguard.db"
    monkeypatch.setenv("TYPOGUARD_SQLITE_PATH", str(configured))
    assert database_path_from_env() == configured


def test_database_restart_initialization_and_backup_restore(tmp_path):
    database_path = tmp_path / "persistent.db"
    database_url = f"sqlite:///{database_path.as_posix()}"

    first_engine = create_database_engine(database_url)
    Base.metadata.create_all(first_engine)
    Session = sessionmaker(bind=first_engine)
    with Session() as session:
        session.add(TrustedDomain(
            domain="persist.example",
            organization="Persistence test",
            category="Test",
        ))
        session.commit()
    first_engine.dispose()

    # Simulate process restart: reopen the same file and repeat startup schema work.
    restarted_engine = create_database_engine(database_url)
    Base.metadata.create_all(restarted_engine)
    migrate_domain_fingerprints(restarted_engine)
    Base.metadata.create_all(restarted_engine)
    migrate_domain_fingerprints(restarted_engine)
    Session = sessionmaker(bind=restarted_engine)
    with Session() as session:
        assert session.query(TrustedDomain).filter_by(
            domain="persist.example"
        ).count() == 1
    restarted_engine.dispose()

    backup_path = tmp_path / "backup.db"
    with sqlite3.connect(database_path) as source, sqlite3.connect(backup_path) as backup:
        source.backup(backup)

    restored_path = tmp_path / "restored.db"
    with sqlite3.connect(backup_path) as backup, sqlite3.connect(restored_path) as restored:
        backup.backup(restored)

    restored_engine = create_engine(f"sqlite:///{restored_path.as_posix()}")
    Session = sessionmaker(bind=restored_engine)
    with Session() as session:
        record = session.query(TrustedDomain).filter_by(
            domain="persist.example"
        ).one()
        assert record.organization == "Persistence test"
    restored_engine.dispose()
