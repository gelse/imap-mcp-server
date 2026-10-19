import { vi } from 'vitest'

/**
 * Test helper — a tiny fake of the gateway's JSON API.
 *
 * The API client is exercised against the real `fetch` boundary: the mock
 * answers by (method, path) and records every call so the specs can assert
 * headers, bodies and URLs. No module is mocked out, so the CSRF wiring, the
 * error mapping and the session store are all covered end to end.
 */

export interface MockEndpoint {
  method: string
  /** Path below /api, e.g. '/admin/users'. */
  path: string
  status?: number
  body?: unknown
  headers?: Record<string, string>
  /** How often this answer may be served; unlimited when omitted. */
  times?: number
}

export interface RecordedCall {
  url: string
  method: string
  headers: Record<string, string>
  body: string | null
}

export interface FetchMock {
  calls: RecordedCall[]
  fetch: ReturnType<typeof vi.fn>
  /** Number of calls matching a (method, path) pair. */
  countOf(method: string, path: string): number
}

function headerRecord(init: RequestInit | undefined): Record<string, string> {
  const raw = init?.headers
  if (raw === undefined) return {}
  if (raw instanceof Headers) return Object.fromEntries(raw.entries())
  if (Array.isArray(raw)) return Object.fromEntries(raw)
  return { ...(raw as Record<string, string>) }
}

/** Pick the first endpoint that still has answers left for this call. */
function pickEndpoint(
  endpoints: MockEndpoint[],
  used: Map<MockEndpoint, number>,
  method: string,
  path: string,
): MockEndpoint | undefined {
  for (const endpoint of endpoints) {
    if (endpoint.method !== method || endpoint.path !== path) continue
    const count = used.get(endpoint) ?? 0
    if (endpoint.times !== undefined && count >= endpoint.times) continue
    used.set(endpoint, count + 1)
    return endpoint
  }
  return undefined
}

/** Install the fake `fetch` and return the recorder. */
export function installFetchMock(endpoints: MockEndpoint[]): FetchMock {
  const calls: RecordedCall[] = []
  const used = new Map<MockEndpoint, number>()

  const mock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = typeof input === 'string' ? input : String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    const body = typeof init?.body === 'string' ? init.body : null

    calls.push({ url, method, headers: headerRecord(init), body })

    const path = url.replace(/^\/api/, '')
    const match = pickEndpoint(endpoints, used, method, path)

    if (match === undefined) {
      return new Response(JSON.stringify({ error: 'not_found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      })
    }

    const status = match.status ?? 200
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(match.headers ?? {}),
    }
    const payload = status === 204 || match.body === undefined ? null : JSON.stringify(match.body)
    return new Response(payload, { status, headers })
  })

  vi.stubGlobal('fetch', mock)

  return {
    calls,
    fetch: mock,
    countOf(method: string, path: string): number {
      return calls.filter(
        (c) => c.method === method.toUpperCase() && c.url.replace(/^\/api/, '') === path,
      ).length
    },
  }
}
