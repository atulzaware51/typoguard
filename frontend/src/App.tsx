import {
  useRef,
  useState,
  type CSSProperties,
  type FormEvent,
} from 'react'
import {
  scanUrl,
  type SimilarDomain,
  type UrlScanResponse,
} from './services/scan'
import {
  clearHistory,
  loadHistory,
  saveHistory,
  type HistoryRecord,
} from './services/history'
import { copyReportText, formatScanReport } from './services/report'
import './App.css'

function validateUrlInput(value: string): string | null {
  const candidate = value.trim()
  if (!candidate) return 'Enter a URL to begin the scan.'
  if (candidate.length < 3 || candidate.length > 2048) {
    return 'URL must be between 3 and 2,048 characters.'
  }
  if (
    /\s/.test(candidate) ||
    candidate.split('').some((character) => character.charCodeAt(0) < 32)
  ) {
    return 'URLs cannot contain spaces or control characters.'
  }

  try {
    const parsed = new URL(
      candidate.includes('://') ? candidate : `https://${candidate}`,
    )
    if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname) {
      return 'Enter a valid HTTP or HTTPS URL.'
    }
  } catch {
    return 'Enter a valid HTTP or HTTPS URL.'
  }

  return null
}

function severityClass(level: string): string {
  return level.toLowerCase()
}

function formatTypoType(value: string | undefined): string {
  if (!value) return 'No typo classification returned'
  if (value === 'exact_match') return 'Exact match'
  return value.replaceAll('_', ' ')
}

function ShieldMark() {
  return (
    <svg aria-hidden="true" viewBox="0 0 32 32" className="brand-mark">
      <path
        d="M16 3.5 26 7v7.2c0 6.3-4.1 11.5-10 14.3C10.1 25.7 6 20.5 6 14.2V7l10-3.5Z"
        fill="currentColor"
        opacity=".12"
      />
      <path
        d="M16 3.5 26 7v7.2c0 6.3-4.1 11.5-10 14.3C10.1 25.7 6 20.5 6 14.2V7l10-3.5Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.8"
      />
      <path
        d="m11.5 15.7 3 3 6.3-6.5"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.8"
      />
    </svg>
  )
}

function ArrowIcon() {
  return (
    <svg aria-hidden="true" viewBox="0 0 20 20" className="button-icon">
      <path
        d="M4 10h11m-4.5-4.5L15 10l-4.5 4.5"
        fill="none"
        stroke="currentColor"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeWidth="1.7"
      />
    </svg>
  )
}

function SimilarDomainCard({ candidate }: { candidate: SimilarDomain }) {
  return (
    <article className="comparison-card">
      <div className="comparison-topline">
        <div>
          <span className="eyebrow">Closest trusted match</span>
          <h3>{candidate.trusted_domain}</h3>
        </div>
        <span className="similarity-value">
          {candidate.similarity_score.toFixed(1)}%
        </span>
      </div>
      <div
        aria-label={`Similarity ${candidate.similarity_score.toFixed(1)} percent`}
        className="similarity-track"
        role="meter"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={candidate.similarity_score}
      >
        <span style={{ width: `${candidate.similarity_score}%` }} />
      </div>
      <div className="typo-detail">
        <span className="typo-type">{formatTypoType(candidate.typo_type)}</span>
        <p>
          {candidate.explanation ??
            'A similar trusted domain was found. Similarity is a warning signal, not proof of malicious intent.'}
        </p>
      </div>
    </article>
  )
}

function ScanResult({
  result,
  scannedAt,
  onCopy,
  copyMessage,
  copyFallback,
}: {
  result: UrlScanResponse
  scannedAt: string
  onCopy: () => void
  copyMessage: string | null
  copyFallback: string | null
}) {
  const assessment = result.risk_assessment
  const primaryMatch = result.similar_domains[0]
  const fingerprint = result.domain_fingerprint

  return (
    <section
      aria-labelledby="report-heading"
      className="report-section"
      id="scan-report"
    >
      <div className="section-heading report-heading">
        <div>
          <span className="eyebrow">Analysis report</span>
          <h2 id="report-heading">Scan results</h2>
        </div>
        <div className="report-actions">
          <span className="passive-note">
            <span className="status-dot" />
            Passive analysis
          </span>
          <button className="secondary-button" onClick={onCopy} type="button">
            Copy report
          </button>
        </div>
      </div>
      {copyMessage && (
        <p
          className={`copy-feedback ${copyFallback ? 'copy-failure' : ''}`}
          role="status"
        >
          {copyMessage}
        </p>
      )}
      {copyFallback && (
        <label className="copy-fallback">
          Report text (select and copy manually)
          <textarea aria-label="Report text to copy" readOnly value={copyFallback} />
        </label>
      )}

      <div className={`result-summary severity-${severityClass(assessment.risk_level)}`}>
        <div className="score-block">
          <div
            aria-label={`Risk score ${assessment.risk_score} out of 100`}
            className="score-ring"
            style={
              { '--score': `${assessment.risk_score}%` } as CSSProperties
            }
          >
            <span className="score-number">{assessment.risk_score}</span>
            <span className="score-out-of">/ 100</span>
          </div>
          <div className="score-copy">
            <span className="eyebrow">Risk score</span>
            <h3>{assessment.risk_level} risk</h3>
            {assessment.score_capped && (
              <p className="capped-note">
                Raw signal total: {assessment.raw_risk_score}; displayed score
                is capped at 100.
              </p>
            )}
          </div>
        </div>
        <div className="trust-summary">
          <span className={`trust-icon ${result.is_trusted ? 'is-trusted' : ''}`}>
            {result.is_trusted ? '✓' : '!'}
          </span>
          <div>
            <span className="eyebrow">Trusted-domain check</span>
            <strong>
              {result.is_trusted
                ? 'Exact trusted-domain match'
                : 'No exact trusted-domain match'}
            </strong>
            <p>
              {result.is_trusted
                ? `${result.normalized_domain} is present in the local trusted-domain dataset.`
                : `${result.normalized_domain} was not found in the local trusted-domain dataset.`}
            </p>
          </div>
        </div>
      </div>

      <div className="report-grid">
        <section aria-labelledby="comparison-heading" className="report-card">
          <div className="card-heading">
            <span className="card-icon comparison-icon" aria-hidden="true">
              ⇄
            </span>
            <div>
              <span className="eyebrow">Domain comparison</span>
              <h3 id="comparison-heading">Lookalike analysis</h3>
            </div>
          </div>
          {primaryMatch ? (
            <div className="comparison-list">
              {result.similar_domains.map((candidate) => (
                <SimilarDomainCard
                  key={candidate.trusted_domain}
                  candidate={candidate}
                />
              ))}
            </div>
          ) : (
            <p className="empty-note">
              No similar trusted domains were returned for this scan.
            </p>
          )}
        </section>

        <section aria-labelledby="fingerprint-heading" className="report-card">
          <div className="card-heading">
            <span className="card-icon fingerprint-icon" aria-hidden="true">
              #
            </span>
            <div>
              <span className="eyebrow">Structural details</span>
              <h3 id="fingerprint-heading">Domain fingerprint</h3>
            </div>
          </div>
          {fingerprint ? (
            <>
              <dl className="fingerprint-metrics">
                {[
                  ['Normalized hostname', fingerprint.normalized_domain],
                  ['Hostname length', fingerprint.length],
                  ['Alphabetic characters', fingerprint.alphabetic_count],
                  ['Numeric characters', fingerprint.numeric_count],
                  ['Hyphens', fingerprint.hyphen_count],
                  ['Subdomains', fingerprint.subdomain_count],
                  ['Contains digits', fingerprint.has_digit ? 'Yes' : 'No'],
                  ['Contains hyphens', fingerprint.has_hyphen ? 'Yes' : 'No'],
                  ['Punycode', fingerprint.is_punycode ? 'Yes' : 'No'],
                ].map(([label, value]) => (
                  <div className="fingerprint-metric" key={label}>
                    <dt>{label}</dt>
                    <dd>{value}</dd>
                  </div>
                ))}
              </dl>
              <p className="fingerprint-note">
                A hostname fingerprint describes structure; it does not determine
                whether a domain is malicious.
              </p>
            </>
          ) : (
            <div className="fingerprint-empty">
              <span aria-hidden="true">—</span>
              <p>Fingerprint attributes are not available for this scan.</p>
            </div>
          )}
        </section>
      </div>
      <p className="similarity-disclaimer">
        Similarity is a warning signal, not proof that a site is malicious.
      </p>

      <section aria-labelledby="signals-heading" className="report-card signals-card">
        <div className="signals-title-row">
          <div className="card-heading">
            <span className="card-icon signals-icon" aria-hidden="true">
              ≋
            </span>
            <div>
              <span className="eyebrow">Why this score</span>
              <h3 id="signals-heading">Risk signals</h3>
            </div>
          </div>
          <span className="signals-total">
            {assessment.raw_risk_score} {assessment.score_capped ? 'raw ' : ''}
            points
          </span>
        </div>
        <ul className="signal-list">
          {assessment.signals.map((signal) => (
            <li className="signal-row" key={signal.code}>
              <span className="signal-marker" aria-hidden="true" />
              <div className="signal-copy">
                <strong>{signal.label}</strong>
                <p>{signal.description}</p>
              </div>
              <span className="signal-points">
                +{signal.points}
                <span>pts</span>
              </span>
            </li>
          ))}
        </ul>
        <p className="disclaimer">{assessment.disclaimer}</p>
      </section>

      <section aria-labelledby="report-details-heading" className="report-card report-details">
        <div className="card-heading">
          <div>
            <span className="eyebrow">Scan metadata</span>
            <h3 id="report-details-heading">Report details</h3>
          </div>
        </div>
        <dl className="report-metadata">
          <div>
            <dt>Original URL</dt>
            <dd><code>{result.original_url}</code></dd>
          </div>
          <div>
            <dt>Normalized hostname</dt>
            <dd><code>{result.normalized_domain || 'Not available'}</code></dd>
          </div>
          <div>
            <dt>Scan timestamp</dt>
            <dd>{new Date(scannedAt).toLocaleString()}</dd>
          </div>
        </dl>
      </section>

      <section aria-labelledby="recommendations-heading" className="report-card recommendations-card">
        <div className="card-heading">
          <div>
            <span className="eyebrow">What to do next</span>
            <h3 id="recommendations-heading">Recommendations</h3>
          </div>
        </div>
        <ul>
          {result.is_trusted ? (
            <>
              <li>This hostname matches the local trusted-domain dataset.</li>
              <li>Confirm the address and context before sharing sensitive information; a match is not a safety guarantee.</li>
            </>
          ) : assessment.risk_score >= 50 ? (
            <>
              <li>Avoid entering credentials or payment details on this address.</li>
              <li>Navigate to the service using a known bookmark or its official address.</li>
            </>
          ) : (
            <>
              <li>Verify the hostname independently before signing in or sharing sensitive information.</li>
              <li>A low score is not proof that the URL is safe.</li>
            </>
          )}
        </ul>
      </section>
    </section>
  )
}

function App() {
  const [initialHistory] = useState(() => {
    try {
      return { records: loadHistory(), message: null as string | null }
    } catch {
      return {
        records: [] as HistoryRecord[],
        message: 'Local scan history could not be read in this browser.',
      }
    }
  })
  const [url, setUrl] = useState('')
  const [result, setResult] = useState<UrlScanResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [history, setHistory] = useState(initialHistory.records)
  const [historyMessage, setHistoryMessage] = useState(initialHistory.message)
  const [reportTimestamp, setReportTimestamp] = useState<string | null>(null)
  const [copyMessage, setCopyMessage] = useState<string | null>(null)
  const [copyFallback, setCopyFallback] = useState<string | null>(null)
  const submitLock = useRef(false)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (submitLock.current) return

    const validationError = validateUrlInput(url)
    if (validationError) {
      setError(validationError)
      setResult(null)
      return
    }

    submitLock.current = true
    setIsLoading(true)
    setError(null)
    setResult(null)
    setReportTimestamp(null)
    setCopyMessage(null)
    setCopyFallback(null)

    try {
      const scanResult = await scanUrl(url.trim())
      const scannedAt = new Date().toISOString()
      setResult(scanResult)
      setReportTimestamp(scannedAt)
      try {
        setHistory(saveHistory(scanResult, scannedAt))
        setHistoryMessage(null)
      } catch {
        setHistoryMessage('The scan completed, but local history could not be saved.')
      }
    } catch (scanError) {
      setError(
        scanError instanceof Error
          ? scanError.message
          : 'The scan could not be completed. Please try again.',
      )
    } finally {
      submitLock.current = false
      setIsLoading(false)
    }
  }

  function chooseExample(example: string) {
    setUrl(example)
    setResult(null)
    setError(null)
  }

  function reopenHistory(record: HistoryRecord) {
    setResult(record.result)
    setUrl(record.result.original_url)
    setReportTimestamp(record.scannedAt)
    setCopyMessage(null)
    setCopyFallback(null)
    setError(null)
  }

  function handleClearHistory() {
    if (history.length === 0 || !window.confirm('Clear all locally saved scan history?')) {
      return
    }
    try {
      clearHistory()
      setHistory([])
      setHistoryMessage(null)
    } catch {
      setHistoryMessage('Local scan history could not be cleared.')
    }
  }

  async function handleCopyReport() {
    if (!result || !reportTimestamp) return
    const report = formatScanReport(result, reportTimestamp)
    const copied = await copyReportText(report)
    setCopyFallback(copied ? null : report)
    setCopyMessage(
      copied
        ? 'Report copied to the clipboard.'
        : 'Clipboard access failed. Select the report text below and copy it manually.',
    )
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="TypoGuard home">
          <ShieldMark />
          <span>Typo<span className="brand-accent">Guard</span></span>
        </a>
        <nav aria-label="Main navigation" className="top-nav">
          <a aria-current="page" href="#scanner">Scanner</a>
          <a href="#scan-history">History</a>
          <a href="#how-it-works">How it works</a>
        </nav>
        <span className="header-status">
          <span className="status-dot" />
          Local analysis
        </span>
      </header>

      <main id="top">
        <section className="hero" id="scanner">
          <div className="hero-copy">
            <span className="hero-kicker">
              <span className="kicker-line" />
              URL THREAT ANALYSIS
            </span>
            <h1>Know before<br />you <span>click.</span></h1>
            <p>
              Spot suspicious lookalike domains and understand the signals
              behind every risk score.
            </p>
          </div>

          <div className="scanner-panel">
            <div className="scanner-panel-heading">
              <div className="input-icon" aria-hidden="true">
                <svg viewBox="0 0 24 24">
                  <circle cx="11" cy="11" r="6.5" />
                  <path d="m16 16 4.5 4.5M8.5 11h5M11 8.5v5" />
                </svg>
              </div>
              <div>
                <h2>Analyze a URL</h2>
                <p>We inspect the address only. We never visit the site.</p>
              </div>
            </div>
            <form className="scan-form" onSubmit={handleSubmit} noValidate>
              <label htmlFor="url-input">Website address</label>
              <div className={`url-input-wrap ${error ? 'has-error' : ''}`}>
                <input
                  autoComplete="url"
                  id="url-input"
                  inputMode="url"
                  maxLength={2048}
                  onChange={(event) => {
                    setUrl(event.target.value)
                    setResult(null)
                    setError(null)
                  }}
                  placeholder="https://example.com"
                  type="text"
                  value={url}
                  aria-describedby={error ? 'scan-error' : 'input-hint'}
                  aria-invalid={Boolean(error)}
                />
                <button
                  className="scan-button"
                  disabled={isLoading}
                  type="submit"
                >
                  {isLoading ? (
                    <>
                      <span className="spinner" aria-hidden="true" />
                      Scanning
                    </>
                  ) : (
                    <>
                      Scan URL
                      <ArrowIcon />
                    </>
                  )}
                </button>
              </div>
              {error ? (
                <p className="form-message error-message" id="scan-error" role="alert">
                  {error}
                </p>
              ) : (
                <p className="form-message" id="input-hint">
                  Accepts HTTP and HTTPS URLs, with or without a scheme.
                </p>
              )}
            </form>
            <div className="example-row">
              <span>Try an example</span>
              <button onClick={() => chooseExample('https://google.com/')} type="button">
                Trusted domain
              </button>
              <button onClick={() => chooseExample('https://g00gle.com/login')} type="button">
                Lookalike pattern
              </button>
            </div>
          </div>
          <div className="hero-decoration" aria-hidden="true">
            <div className="decoration-orbit orbit-one" />
            <div className="decoration-orbit orbit-two" />
            <div className="decoration-cross cross-one">+</div>
            <div className="decoration-cross cross-two">+</div>
            <div className="decoration-dot dot-one" />
            <div className="decoration-dot dot-two" />
          </div>
        </section>

        {isLoading && (
          <div className="loading-status" role="status" aria-live="polite">
            <span className="spinner" aria-hidden="true" />
            Comparing the domain with the local trusted-domain dataset…
          </div>
        )}
        {result && reportTimestamp && (
          <ScanResult
            result={result}
            scannedAt={reportTimestamp}
            onCopy={handleCopyReport}
            copyMessage={copyMessage}
            copyFallback={copyFallback}
          />
        )}

        <section aria-labelledby="history-heading" className="history-section" id="scan-history">
          <div className="section-heading">
            <div>
              <span className="eyebrow">This browser only</span>
              <h2 id="history-heading">Scan history</h2>
            </div>
            <button
              className="secondary-button"
              disabled={history.length === 0}
              onClick={handleClearHistory}
              type="button"
            >
              Clear history
            </button>
          </div>
          <p className="history-storage-note">
            Locally saved in this browser; it is not server-side history. URL credentials,
            query parameters, and fragments are omitted from saved records.
          </p>
          {historyMessage && <p className="history-message" role="alert">{historyMessage}</p>}
          {history.length === 0 ? (
            <p className="history-empty">No locally saved scans yet.</p>
          ) : (
            <ul className="history-list">
              {history.map((record, index) => (
                <li className="history-item" key={`${record.scannedAt}-${index}`}>
                  <div className="history-item-details">
                    <code>{record.result.original_url}</code>
                    {record.urlRedacted && (
                      <span className="history-redacted">
                        Sensitive URL components were omitted from local history.
                      </span>
                    )}
                    <span className="history-meta">
                      {new Date(record.scannedAt).toLocaleString()} ·{' '}
                      {record.result.risk_assessment.risk_score}/100 ·{' '}
                      {record.result.risk_assessment.risk_level}
                      {' · '}
                      {record.result.is_trusted ? 'Trusted match' : 'No trusted match'}
                    </span>
                  </div>
                  <button
                    className="secondary-button"
                    onClick={() => reopenHistory(record)}
                    type="button"
                  >
                    Reopen result
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="how-section" id="how-it-works">
          <div className="how-heading">
            <span className="eyebrow">A clearer way to assess a link</span>
            <h2>Signals, not scare tactics.</h2>
            <p>
              TypoGuard compares URL structure against a local list of trusted
              domains. It does not fetch, resolve, or open the submitted URL.
            </p>
          </div>
          <div className="how-steps">
            <article className="how-step">
              <span>01</span>
              <h3>Inspect the address</h3>
              <p>Hostname, URL structure, and risk patterns are parsed locally.</p>
            </article>
            <article className="how-step">
              <span>02</span>
              <h3>Compare domains</h3>
              <p>Lookalikes are compared against the trusted-domain dataset.</p>
            </article>
            <article className="how-step">
              <span>03</span>
              <h3>Explain the risk</h3>
              <p>Each configured signal is shown alongside its points.</p>
            </article>
          </div>
        </section>
      </main>

      <footer className="page-footer">
        <a className="brand footer-brand" href="#top">
          <ShieldMark />
          <span>Typo<span className="brand-accent">Guard</span></span>
        </a>
        <p>Heuristic URL analysis · No website visits · No safety guarantees</p>
      </footer>
    </div>
  )
}

export default App
