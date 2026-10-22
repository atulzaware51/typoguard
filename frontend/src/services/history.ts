import { isUrlScanResponse, type UrlScanResponse } from './scan'

const HISTORY_KEY = 'typoguard.scan-history.v1'
const MAX_HISTORY_ITEMS = 20

export interface HistoryRecord {
  scannedAt: string
  result: UrlScanResponse
  urlRedacted: boolean
}

type HistoryStorage = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>

function isHistoryRecord(value: unknown): value is HistoryRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }
  const record = value as Record<string, unknown>
  return (
    typeof record.scannedAt === 'string' &&
    Number.isFinite(Date.parse(record.scannedAt)) &&
    isUrlScanResponse(record.result) &&
    typeof record.urlRedacted === 'boolean'
  )
}

export function redactHistoryResult(result: UrlScanResponse): {
  result: UrlScanResponse
  urlRedacted: boolean
} {
  try {
    const hasScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(result.original_url)
    const url = new URL(
      hasScheme
        ? result.original_url
        : `${result.scheme}://${result.original_url}`,
    )
    const urlRedacted = Boolean(
      url.username || url.password || url.search || url.hash,
    )
    url.username = ''
    url.password = ''
    url.search = ''
    url.hash = ''
    const savedUrl = hasScheme
      ? url.toString()
      : `${url.host}${url.pathname}`
    return {
      result: {
        ...result,
        original_url: savedUrl,
        query: '',
        fragment: '',
      },
      urlRedacted,
    }
  } catch {
    return {
      result: {
        ...result,
        original_url: `${result.scheme}://${result.hostname}`,
        query: '',
        fragment: '',
      },
      urlRedacted: true,
    }
  }
}

export function loadHistory(
  storage: HistoryStorage = window.localStorage,
): HistoryRecord[] {
  const stored = storage.getItem(HISTORY_KEY)
  if (stored === null) return []

  let parsed: unknown
  try {
    parsed = JSON.parse(stored)
  } catch {
    storage.removeItem(HISTORY_KEY)
    return []
  }

  if (!Array.isArray(parsed)) {
    storage.removeItem(HISTORY_KEY)
    return []
  }
  return parsed.filter(isHistoryRecord).slice(0, MAX_HISTORY_ITEMS)
}

export function saveHistory(
  result: UrlScanResponse,
  scannedAt: string,
  storage: HistoryStorage = window.localStorage,
): HistoryRecord[] {
  const safeResult = redactHistoryResult(result)
  const record: HistoryRecord = {
    scannedAt,
    result: safeResult.result,
    urlRedacted: safeResult.urlRedacted,
  }
  const records = [record, ...loadHistory(storage)].slice(0, MAX_HISTORY_ITEMS)
  storage.setItem(HISTORY_KEY, JSON.stringify(records))
  return records
}

export function clearHistory(
  storage: HistoryStorage = window.localStorage,
): void {
  storage.removeItem(HISTORY_KEY)
}
