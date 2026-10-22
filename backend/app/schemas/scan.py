
"""Request and response models for URL scanning."""

from pydantic import BaseModel, Field


class URLScanRequest(BaseModel):
    # The URL submitted by the user.
    url: str = Field(..., min_length=3, max_length=2048)


class RiskSignal(BaseModel):
    code: str
    label: str
    points: int
    description: str


class RiskAssessment(BaseModel):
    risk_score: int
    risk_level: str
    reasons: list[dict]
    signals: list[RiskSignal]
    raw_risk_score: int
    score_capped: bool
    is_trusted: bool
    disclaimer: str


class DomainFingerprint(BaseModel):
    normalized_domain: str
    length: int
    alphabetic_count: int
    numeric_count: int
    hyphen_count: int
    has_digit: bool
    has_hyphen: bool
    subdomain_count: int
    is_punycode: bool


class URLScanResponse(BaseModel):
    # Basic URL parsing results.
    valid: bool
    original_url: str
    scheme: str
    hostname: str
    normalized_domain: str
    port: int | None
    path: str
    query: str
    fragment: str

    # Whether the exact normalized domain exists in our dataset.
    is_trusted: bool

    # Similar trusted domains and their typo analysis.
    similar_domains: list[dict] = Field(default_factory=list)

    # Optional for compatibility with older API consumers and stored responses.
    domain_fingerprint: DomainFingerprint | None = None

    # New: score, risk level, and reasons.
    risk_assessment: RiskAssessment
