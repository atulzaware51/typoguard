import { afterEach, describe, expect, it, vi } from 'vitest'
import { scanUrl } from './scan'

const responsePayload = {
  valid: true,
  original_url: 'https://g00gle.com/login',
  scheme: 'https',
  hostname: 'g00gle.com',
  normalized_domain: 'g00gle.com',
  port: null,
  path: '/login',
  query: '',
  fragment: '',
  is_trusted: false,
  similar_domains: [
    {
      trusted_domain: 'google.com',
      similarity_score: 80,
      typo_type: 'character_substitution',
      changed_characters: [
        {
          position: 1,
          submitted_character: '0',
          trusted_character: 'o',
        },
        {
          position: 2,
          submitted_character: '0',
          trusted_character: 'o',
        },
      ],
      explanation:
        '2 character substitution(s) detected. Similarity is a warning signal, not proof of malicious intent.',
      typo_analysis: {
        typo_type: 'character_substitution',
      },
    },
  ],
  risk_assessment: {
    risk_score: 38,
    risk_level: 'Moderate',
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
    raw_risk_score: 38,
    score_capped: false,
    is_trusted: false,
    disclaimer: 'This is a heuristic assessment, not a malware verdict.',
  },
}

describe('scanUrl', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('posts the submitted string only to the local scan API', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify(responsePayload), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    )
    vi.stubGlobal('fetch', fetchMock)

    const result = await scanUrl('https://g00gle.com/login')

    expect(fetchMock).toHaveBeenCalledWith(
      'http://127.0.0.1:8000/api/scan/',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ url: 'https://g00gle.com/login' }),
      }),
    )
    expect(result.similar_domains[0].trusted_domain).toBe('google.com')
  })

  it('surfaces API validation details for malformed URLs', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: 'Invalid URL: malformed hostname' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    )

    await expect(scanUrl('https://bad_host.com')).rejects.toThrow(
      'Invalid URL: malformed hostname',
    )
  })

  it('reports backend unavailability clearly', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('offline')))

    await expect(scanUrl('https://example.com')).rejects.toThrow(
      'Could not connect to the TypoGuard API.',
    )
  })

  it('rejects a successful response with an unexpected shape', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ valid: true }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    )

    await expect(scanUrl('https://example.com')).rejects.toThrow(
      'unexpected response format',
    )
  })

  it('rejects a response whose score does not match its signals', async () => {
    const inconsistent = structuredClone(responsePayload)
    inconsistent.risk_assessment.risk_score = 39
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(inconsistent), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        }),
      ),
    )

    await expect(scanUrl('https://g00gle.com/login')).rejects.toThrow(
      'unexpected response format',
    )
  })
})
