export interface RiskSignal {
  code: string
  label: string
  points: number
  description: string
}

export interface RiskAssessment {
  risk_score: number
  risk_level: 'Low' | 'Moderate' | 'High' | 'Critical'
  reasons: Array<{
    signal: string
    points: number
    description: string
  }>
  signals: RiskSignal[]
  raw_risk_score: number
  score_capped: boolean
  is_trusted: boolean
  disclaimer: string
}

export interface SimilarDomain {
  trusted_domain: string
  similarity_score: number
  typo_type?: string
  changed_characters?: unknown
  explanation?: string
}

export interface DomainFingerprint {
  normalized_domain: string
  length: number
  alphabetic_count: number
  numeric_count: number
  hyphen_count: number
  has_digit: boolean
  has_hyphen: boolean
  subdomain_count: number
  is_punycode: boolean
}

export interface UrlScanResponse {
  valid: boolean
  original_url: string
  scheme: string
  hostname: string
  normalized_domain: string
  port: number | null
  path: string
  query: string
  fragment: string
  is_trusted: boolean
  similar_domains: SimilarDomain[]
  domain_fingerprint?: DomainFingerprint | null
  risk_assessment: RiskAssessment
}

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL?.trim().replace(/\/+$/, '') ||
  'http://127.0.0.1:8000'

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isString(value: unknown): value is string {
  return typeof value === 'string'
}

function isNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value)
}

function isInteger(value: unknown): value is number {
  return isNumber(value) && Number.isInteger(value)
}

function isRiskSignal(value: unknown): value is RiskSignal {
  return (
    isRecord(value) &&
    isString(value.code) &&
    isString(value.label) &&
    isInteger(value.points) &&
    isString(value.description)
  )
}

function isSimilarDomain(value: unknown): value is SimilarDomain {
  if (
    !isRecord(value) ||
    !isString(value.trusted_domain) ||
    !isNumber(value.similarity_score) ||
    value.similarity_score < 0 ||
    value.similarity_score > 100
  ) {
    return false
  }
  return (
    (value.typo_type === undefined || isString(value.typo_type)) &&
    (value.explanation === undefined || isString(value.explanation))
  )
}

function isDomainFingerprint(value: unknown): value is DomainFingerprint {
  return (
    isRecord(value) &&
    isString(value.normalized_domain) &&
    isInteger(value.length) &&
    value.length >= 0 &&
    isInteger(value.alphabetic_count) &&
    value.alphabetic_count >= 0 &&
    isInteger(value.numeric_count) &&
    value.numeric_count >= 0 &&
    isInteger(value.hyphen_count) &&
    value.hyphen_count >= 0 &&
    typeof value.has_digit === 'boolean' &&
    typeof value.has_hyphen === 'boolean' &&
    isInteger(value.subdomain_count) &&
    value.subdomain_count >= 0 &&
    typeof value.is_punycode === 'boolean'
  )
}

function isRiskAssessment(value: unknown): value is RiskAssessment {
  if (!isRecord(value)) return false
  const allowedLevels = ['Low', 'Moderate', 'High', 'Critical']
  const expectedLevel =
    isInteger(value.risk_score) && value.risk_score >= 75
      ? 'Critical'
      : isInteger(value.risk_score) && value.risk_score >= 50
        ? 'High'
        : isInteger(value.risk_score) && value.risk_score >= 25
          ? 'Moderate'
          : 'Low'
  const signals = value.signals
  const reasons = value.reasons
  const signalPoints =
    Array.isArray(signals) && signals.every(isRiskSignal)
      ? signals.reduce((total, signal) => total + signal.points, 0)
      : null

  return (
    isInteger(value.risk_score) &&
    value.risk_score >= 0 &&
    value.risk_score <= 100 &&
    isString(value.risk_level) &&
    allowedLevels.includes(value.risk_level) &&
    value.risk_level === expectedLevel &&
    Array.isArray(reasons) &&
    Array.isArray(signals) &&
    signals.every(isRiskSignal) &&
    new Set(signals.map((signal) => signal.code)).size === signals.length &&
    reasons.length === signals.length &&
    reasons.every(
      (reason, index) =>
        isRecord(reason) &&
        isString(reason.signal) &&
        isInteger(reason.points) &&
        isString(reason.description) &&
        reason.signal === signals[index].code &&
        reason.points === signals[index].points &&
        reason.description === signals[index].description,
    ) &&
    isInteger(value.raw_risk_score) &&
    value.raw_risk_score === signalPoints &&
    value.risk_score === Math.min(100, value.raw_risk_score) &&
    value.score_capped === (value.raw_risk_score > 100) &&
    typeof value.score_capped === 'boolean' &&
    typeof value.is_trusted === 'boolean' &&
    isString(value.disclaimer)
  )
}

export function isUrlScanResponse(value: unknown): value is UrlScanResponse {
  return (
    isRecord(value) &&
    value.valid === true &&
    isString(value.original_url) &&
    isString(value.scheme) &&
    isString(value.hostname) &&
    isString(value.normalized_domain) &&
    (value.port === null || isInteger(value.port)) &&
    isString(value.path) &&
    isString(value.query) &&
    isString(value.fragment) &&
    typeof value.is_trusted === 'boolean' &&
    Array.isArray(value.similar_domains) &&
    value.similar_domains.every(isSimilarDomain) &&
    (value.domain_fingerprint === undefined ||
      value.domain_fingerprint === null ||
      isDomainFingerprint(value.domain_fingerprint)) &&
    isRiskAssessment(value.risk_assessment) &&
    value.risk_assessment.is_trusted === value.is_trusted
  )
}

async function responseErrorMessage(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json()
    if (isRecord(body) && isString(body.detail)) return body.detail
  } catch {
    // Use a status-based message when the server returns no JSON error body.
  }
  return `The scan service returned an error (HTTP ${response.status}).`
}

export async function scanUrl(url: string): Promise<UrlScanResponse> {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}/api/scan/`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    })
  } catch {
    throw new Error(
      'Could not connect to the TypoGuard API. Check that the backend is running and try again.',
    )
  }

  if (!response.ok) {
    throw new Error(await responseErrorMessage(response))
  }

  let payload: unknown
  try {
    payload = await response.json()
  } catch {
    throw new Error('The scan service returned an unreadable response.')
  }
  if (!isUrlScanResponse(payload)) {
    throw new Error('The scan service returned an unexpected response format.')
  }

  return payload
}
