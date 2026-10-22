import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import App from './App'
import { scanUrl, type UrlScanResponse } from './services/scan'
import { copyReportText, formatScanReport } from './services/report'

vi.mock('./services/scan', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./services/scan')>()
  return { ...actual, scanUrl: vi.fn() }
})

const trustedResponse: UrlScanResponse = {
  valid: true,
  original_url: 'https://google.com/',
  scheme: 'https',
  hostname: 'google.com',
  normalized_domain: 'google.com',
  port: null,
  path: '/',
  query: '',
  fragment: '',
  is_trusted: true,
  similar_domains: [],
  risk_assessment: {
    risk_score: 0,
    risk_level: 'Low',
    reasons: [],
    signals: [
      {
        code: 'no_configured_warning',
        label: 'No configured warning',
        points: 0,
        description: 'No configured risk signals were detected.',
      },
    ],
    raw_risk_score: 0,
    score_capped: false,
    is_trusted: true,
    disclaimer: 'A low score does not guarantee safety.',
  },
}

const lookalikeResponse: UrlScanResponse = {
  ...trustedResponse,
  original_url: 'https://g00gle.com/login',
  hostname: 'g00gle.com',
  normalized_domain: 'g00gle.com',
  is_trusted: false,
  similar_domains: [
    {
      trusted_domain: 'google.com',
      similarity_score: 80,
      typo_type: 'character_substitution',
      explanation:
        '2 character substitution(s) detected. Similarity is a warning signal, not proof of malicious intent.',
    },
  ],
  risk_assessment: {
    ...trustedResponse.risk_assessment,
    risk_score: 38,
    risk_level: 'Moderate',
    is_trusted: false,
    raw_risk_score: 38,
    signals: [
      {
        code: 'high_domain_similarity',
        label: 'Similar to a trusted domain',
        points: 18,
        description: 'g00gle.com closely resembles google.com (similarity: 80.0%).',
      },
      {
        code: 'character_changes',
        label: 'Lookalike character changes',
        points: 15,
        description:
          'The submitted domain contains character changes compared with a similar trusted domain.',
      },
      {
        code: 'suspicious_path_or_query',
        label: 'Suspicious path or query keyword',
        points: 5,
        description: 'Suspicious words found in the URL path or query: login.',
      },
    ],
    reasons: [
      {
        signal: 'high_domain_similarity',
        points: 18,
        description: 'g00gle.com closely resembles google.com (similarity: 80.0%).',
      },
      {
        signal: 'character_changes',
        points: 15,
        description:
          'The submitted domain contains character changes compared with a similar trusted domain.',
      },
      {
        signal: 'suspicious_path_or_query',
        points: 5,
        description: 'Suspicious words found in the URL path or query: login.',
      },
    ],
  },
}

const mockedScanUrl = vi.mocked(scanUrl)

describe('TypoGuard dashboard', () => {
  beforeEach(() => {
    vi.resetAllMocks()
    localStorage.clear()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    Reflect.deleteProperty(navigator, 'clipboard')
  })

  it('renders a trusted-domain scan returned by the API', async () => {
    mockedScanUrl.mockResolvedValue(trustedResponse)
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Website address'), 'https://google.com/')
    await user.click(screen.getByRole('button', { name: 'Scan URL' }))

    expect(await screen.findByText('Exact trusted-domain match')).toBeInTheDocument()
    expect(screen.getByLabelText('Risk score 0 out of 100')).toBeInTheDocument()
    expect(
      screen.getByText(/Fingerprint attributes are not available/),
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Reopen result' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy report' })).toBeInTheDocument()
  })

  it('shows the actual lookalike comparison and risk signals', async () => {
    mockedScanUrl.mockResolvedValue(lookalikeResponse)
    const user = userEvent.setup()
    render(<App />)

    await user.type(
      screen.getByLabelText('Website address'),
      'https://g00gle.com/login',
    )
    await user.click(screen.getByRole('button', { name: 'Scan URL' }))

    expect(await screen.findByText('google.com')).toBeInTheDocument()
    expect(screen.getByText('80.0%')).toBeInTheDocument()
    expect(screen.getByText('character substitution')).toBeInTheDocument()
    expect(
      screen.getByText(/character substitution\(s\) detected/),
    ).toBeInTheDocument()
    expect(screen.getByText('Lookalike character changes')).toBeInTheDocument()
    expect(screen.getByText('Moderate risk')).toBeInTheDocument()
    expect(screen.getByText('+18')).toBeInTheDocument()
  })

  it('renders available fingerprint metrics and explains their limits', async () => {
    mockedScanUrl.mockResolvedValue({
      ...trustedResponse,
      domain_fingerprint: {
        normalized_domain: 'google.com',
        length: 10,
        alphabetic_count: 9,
        numeric_count: 0,
        hyphen_count: 0,
        has_digit: false,
        has_hyphen: false,
        subdomain_count: 0,
        is_punycode: false,
      },
    })
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Website address'), 'google.com')
    await user.click(screen.getByRole('button', { name: 'Scan URL' }))

    expect(await screen.findByText('Alphabetic characters')).toBeInTheDocument()
    expect(screen.getByText('Hostname length')).toBeInTheDocument()
    expect(
      screen.getByText(/does not determine whether a domain is malicious/),
    ).toBeInTheDocument()
  })

  it('restores locally saved history after reload and reopens its report', async () => {
    mockedScanUrl.mockResolvedValue({
      ...lookalikeResponse,
      original_url: 'https://user:password@g00gle.com/login?token=private#section',
      query: 'token=private',
      fragment: 'section',
    })
    const user = userEvent.setup()
    const firstRender = render(<App />)

    await user.type(
      screen.getByLabelText('Website address'),
      'https://g00gle.com/login?token=private#section',
    )
    await user.click(screen.getByRole('button', { name: 'Scan URL' }))
    expect(await screen.findByText('Moderate risk')).toBeInTheDocument()
    expect(screen.getByText(/Sensitive URL components were omitted/)).toBeInTheDocument()
    firstRender.unmount()

    render(<App />)
    expect(await screen.findByText('https://g00gle.com/login')).toBeInTheDocument()
    expect(screen.getByText(/This browser only/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Reopen result' }))
    expect(screen.getByText('Moderate risk')).toBeInTheDocument()
    expect(mockedScanUrl).toHaveBeenCalledTimes(1)
  })

  it('clears local history only after confirmation', async () => {
    mockedScanUrl.mockResolvedValue(trustedResponse)
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Website address'), 'google.com')
    await user.click(screen.getByRole('button', { name: 'Scan URL' }))
    expect(await screen.findByRole('button', { name: 'Reopen result' })).toBeInTheDocument()

    const confirm = vi.fn().mockReturnValue(false)
    vi.stubGlobal('confirm', confirm)
    await user.click(screen.getByRole('button', { name: 'Clear history' }))
    expect(confirm).toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Reopen result' })).toBeInTheDocument()

    confirm.mockReturnValue(true)
    await user.click(screen.getByRole('button', { name: 'Clear history' }))
    expect(screen.queryByRole('button', { name: 'Reopen result' })).not.toBeInTheDocument()
    expect(screen.getByText('No locally saved scans yet.')).toBeInTheDocument()
  })

  it('discards malformed stored history without breaking the scanner', async () => {
    localStorage.setItem('typoguard.scan-history.v1', '{not-json')
    render(<App />)
    expect(await screen.findByText('No locally saved scans yet.')).toBeInTheDocument()
    expect(localStorage.getItem('typoguard.scan-history.v1')).toBeNull()
    expect(screen.getByRole('button', { name: 'Scan URL' })).toBeEnabled()
  })

  it('copies a formatted report and exposes a manual fallback on clipboard failure', async () => {
    mockedScanUrl.mockResolvedValue(lookalikeResponse)
    const writeText = vi.fn().mockResolvedValue(undefined)
    const user = userEvent.setup()
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText },
    })
    expect(window.navigator.clipboard?.writeText).toBe(writeText)
    expect(await copyReportText('clipboard probe')).toBe(true)
    expect(writeText).toHaveBeenCalledWith('clipboard probe')
    writeText.mockClear()
    render(<App />)
    await user.type(screen.getByLabelText('Website address'), 'g00gle.com')
    await user.click(screen.getByRole('button', { name: 'Scan URL' }))
    await screen.findByText('Moderate risk')
    await user.click(screen.getByRole('button', { name: 'Copy report' }))
    expect(await screen.findByRole('status')).toHaveTextContent(
      'Report copied to the clipboard.',
    )
    await waitFor(() => expect(writeText).toHaveBeenCalledTimes(1))
    expect(writeText.mock.calls[0][0]).toContain('Risk score: 38/100 (Moderate)')
    expect(writeText.mock.calls[0][0]).toContain('Similar to a trusted domain: +18 points')

    writeText.mockRejectedValueOnce(new Error('clipboard denied'))
    await user.click(screen.getByRole('button', { name: 'Copy report' }))
    expect(await screen.findByRole('textbox', { name: 'Report text to copy' })).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('copy it manually')
  })

  it('shows a local validation error and does not submit malformed input', async () => {
    const user = userEvent.setup()
    render(<App />)

    await user.type(
      screen.getByLabelText('Website address'),
      'https://not a valid host',
    )
    await user.click(screen.getByRole('button', { name: 'Scan URL' }))

    expect(screen.getByRole('alert')).toHaveTextContent(
      'URLs cannot contain spaces',
    )
    expect(mockedScanUrl).not.toHaveBeenCalled()
  })

  describe('formatScanReport', () => {
    it('includes actual candidates, severity, signal points, and the similarity disclaimer', () => {
      const report = formatScanReport(lookalikeResponse, '2026-10-17T12:00:00.000Z')
      expect(report).toContain('URL: https://g00gle.com/login')
      expect(report).toContain('Trusted-domain status: No exact trusted-domain match')
      expect(report).toContain('google.com (80.0% similarity)')
      expect(report).toContain('character_substitution')
      expect(report).toContain('Risk score: 38/100 (Moderate)')
      expect(report).toContain('Lookalike character changes: +15 points')
      expect(report).toContain('Similarity is a warning signal, not proof')
    })
  })

  it('indicates loading and prevents duplicate submissions', async () => {
    let resolveScan!: (response: UrlScanResponse) => void
    mockedScanUrl.mockReturnValue(
      new Promise((resolve) => {
        resolveScan = resolve
      }),
    )
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Website address'), 'google.com')
    await user.click(screen.getByRole('button', { name: 'Scan URL' }))

    const form = screen.getByLabelText('Website address').closest('form')
    expect(screen.getByRole('button', { name: /Scanning/ })).toBeDisabled()
    expect(screen.getByRole('status')).toHaveTextContent('Comparing the domain')
    if (!form) throw new Error('Scan form was not rendered')
    fireEvent.submit(form)
    fireEvent.submit(form)
    expect(mockedScanUrl).toHaveBeenCalledTimes(1)

    resolveScan(trustedResponse)
    await screen.findByText('Exact trusted-domain match')
  })

  it('shows API failures in an accessible error state', async () => {
    mockedScanUrl.mockRejectedValue(new Error('Backend is unavailable.'))
    const user = userEvent.setup()
    render(<App />)

    await user.type(screen.getByLabelText('Website address'), 'example.com')
    await user.click(screen.getByRole('button', { name: 'Scan URL' }))

    expect(await screen.findByRole('alert')).toHaveTextContent(
      'Backend is unavailable.',
    )
    await waitFor(() => expect(mockedScanUrl).toHaveBeenCalledTimes(1))
  })
})
