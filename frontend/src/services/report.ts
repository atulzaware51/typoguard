import type { UrlScanResponse } from './scan'

export function formatScanReport(
  result: UrlScanResponse,
  scannedAt: string,
): string {
  const assessment = result.risk_assessment
  const lines = [
    'TypoGuard scan report',
    `URL: ${result.original_url}`,
    `Scanned: ${new Date(scannedAt).toLocaleString()}`,
    `Normalized hostname: ${result.normalized_domain}`,
    `Trusted-domain status: ${result.is_trusted ? 'Trusted exact match' : 'No exact trusted-domain match'}`,
    `Risk score: ${assessment.risk_score}/100 (${assessment.risk_level})`,
  ]

  if (result.similar_domains.length > 0) {
    lines.push('Similar trusted-domain candidates:')
    result.similar_domains.forEach((candidate) => {
      lines.push(
        `- ${candidate.trusted_domain} (${candidate.similarity_score.toFixed(1)}% similarity)`,
      )
      if (candidate.typo_type) lines.push(`  Typo category: ${candidate.typo_type}`)
      if (candidate.explanation) lines.push(`  Explanation: ${candidate.explanation}`)
    })
  }

  lines.push('Risk signals:')
  assessment.signals.forEach((signal) => {
    lines.push(`- ${signal.label}: +${signal.points} points — ${signal.description}`)
  })
  lines.push(`Assessment: ${assessment.disclaimer}`)
  lines.push(
    'Similarity is a warning signal, not proof that a site is malicious.',
  )
  return lines.join('\n')
}

function legacyCopy(text: string): boolean {
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.setAttribute('readonly', '')
  textarea.style.position = 'fixed'
  textarea.style.opacity = '0'
  document.body.append(textarea)
  textarea.select()
  let copied = false
  try {
    copied = document.execCommand('copy')
  } finally {
    textarea.remove()
  }
  return copied
}

export async function copyReportText(text: string): Promise<boolean> {
  try {
    if (window.navigator.clipboard?.writeText) {
      await window.navigator.clipboard.writeText(text)
      return true
    }
  } catch {
    // Fall through to the legacy copy path when clipboard permission is denied.
  }

  try {
    return legacyCopy(text)
  } catch {
    return false
  }
}
