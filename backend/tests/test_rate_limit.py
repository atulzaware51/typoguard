import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.scan import router as scan_router
from app.core import rate_limit
from app.core.database import Base, get_db
from app.core.rate_limit import FixedWindowRateLimiter


def test_fixed_window_limiter_resets_and_returns_retry_time():
    limiter = FixedWindowRateLimiter(limit=2, window_seconds=10)

    assert limiter.retry_after("client", now=100) is None
    assert limiter.retry_after("client", now=101) is None
    assert limiter.retry_after("client", now=102) == 8
    assert limiter.retry_after("client", now=110) is None


def test_scan_api_returns_429_after_limit_and_includes_retry_after(
    monkeypatch, tmp_path
):
    engine = create_engine(f"sqlite:///{tmp_path / 'rate-limit.db'}")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = FastAPI()
    app.include_router(scan_router)
    app.dependency_overrides[get_db] = lambda: session
    monkeypatch.setattr(
        rate_limit, "scan_rate_limiter", FixedWindowRateLimiter(limit=2, window_seconds=60)
    )

    try:
        with TestClient(app) as client:
            first = client.post("/api/scan/", json={"url": "https://example.com"})
            second = client.post("/api/scan/", json={"url": "https://example.com"})
            limited = client.post("/api/scan/", json={"url": "https://example.com"})
    finally:
        session.close()
        engine.dispose()

    assert first.status_code == 200
    assert second.status_code == 200
    assert limited.status_code == 429
    assert limited.json()["detail"] == "Scan request limit exceeded. Try again shortly."
    assert int(limited.headers["retry-after"]) > 0


@pytest.mark.parametrize("limit,window,max_clients", [(0, 60, 1), (1, 0, 1), (1, 1, 0)])
def test_fixed_window_limiter_rejects_invalid_configuration(limit, window, max_clients):
    with pytest.raises(ValueError, match="must be positive"):
        FixedWindowRateLimiter(limit, window, max_clients)
