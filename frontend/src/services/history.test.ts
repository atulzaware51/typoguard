import { beforeEach, describe, expect, it } from 'vitest'
import {
  clearHistory,
  loadHistory,
  saveHistory,
} from './history'
import type { UrlScanResponse } from './scan'

const scan: UrlScanResponse = {
  valid: true,
  original_url: 'https://user:password@example.com/path?token=secret#part',
  scheme: 'https',
  hostname: 'example.com',
  normalized_domain: 'example.com',
  port: null,
  path: '/path',
  query: 'token=secret',
  fragment: 'part',
  is_trusted: false,
  similar_domains: [],
  risk_assessment: {
    risk_score: 0,
    risk_level: 'Low',
    reasons: [
      {
        signal: 'no_configured_warning',
        points: 0,
        description: 'No configured warning.',
      },
    ],
    signals: [
      {
        code: 'no_configured_warning',
        label: 'No configured warning',
        points: 0,
        description: 'No configured warning.',
      },
    ],
    raw_risk_score: 0,
    score_capped: false,
    is_trusted: false,
    disclaimer: 'Not a safety guarantee.',
  },
}

describe('local scan history', () => {
  beforeEach(() => localStorage.clear())

  it('saves and restores validated records while redacting URL secrets', () => {
    const saved = saveHistory(scan, '2026-10-17T10:00:00.000Z')
    const restored = loadHistory()

    expect(saved).toHaveLength(1)
    expect(restored[0].scannedAt).toBe('2026-10-17T10:00:00.000Z')
    expect(restored[0].result.original_url).toBe('https://example.com/path')
    expect(restored[0].result.query).toBe('')
    expect(restored[0].result.fragment).toBe('')
    expect(restored[0].urlRedacted).toBe(true)
    expect(localStorage.getItem('typoguard.scan-history.v1')).not.toContain('secret')
    expect(loadHistory()[0].result.normalized_domain).toBe('example.com')
  })

  it('clears malformed JSON and filters invalid or outdated records', () => {
    localStorage.setItem('typoguard.scan-history.v1', '{broken')
    expect(loadHistory()).toEqual([])
    expect(localStorage.getItem('typoguard.scan-history.v1')).toBeNull()

    localStorage.setItem(
      'typoguard.scan-history.v1',
      JSON.stringify([{ scannedAt: 'yesterday', result: { original_url: 'old' } }]),
    )
    expect(loadHistory()).toEqual([])
  })

  it('removes saved history on clear', () => {
    saveHistory(scan, '2026-10-17T10:00:00.000Z')
    clearHistory()
    expect(loadHistory()).toEqual([])
  })
})
