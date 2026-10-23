"""Authentication dependencies for privileged API operations."""

import os
import secrets

from fastapi import Header, HTTPException


def require_admin_secret(
    x_admin_secret: str | None = Header(default=None, alias="X-Admin-Secret"),
) -> None:
    """Fail closed unless the request supplies the configured admin secret."""
    expected = os.getenv("TYPOGUARD_ADMIN_SECRET", "")
    if (
        not expected
        or not x_admin_secret
        or not secrets.compare_digest(x_admin_secret, expected)
    ):
        raise HTTPException(status_code=401, detail="Admin authentication required")
