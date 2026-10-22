import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.scan import router as scan_router

from app.api.domains import router as domains_router

from app.core.database import Base,engine,migrate_domain_fingerprints

# import the modes so sqlalchemy register both tables
from app.models.domain import TrustedDomain,DomainFingerprint
Base.metadata.create_all(bind = engine )
migrate_domain_fingerprints(engine)


app = FastAPI(
    title="TypoGuard API",
    description="URL Typosquatting and Risk Scanner",
    version="0.2.0",
)

cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "TYPOGUARD_CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173,"
        "http://localhost:4173,http://127.0.0.1:4173",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)

app.include_router(scan_router)
app.include_router(domains_router)


@app.get("/")
def root():
    return {
        "project": "TypoGuard",
        "status": "running",
        "message": "URL Risk Scanner API"
    }