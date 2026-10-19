import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { adminLogin, ApiError, request } from '@/lib/api'
import {
  bootstrap,
  csrfToken,
  forget,
  isAuthenticated,
  setSessionExpiredHandler,
} from '@/lib/session'
import { installFetchMock } from './helpers/fetch-mock'

/**
 * API client specs.
 *
 * Contract under test:
 *  - the CSRF token is attached to every mutation and to no read;
 *  - the admin login is form-encoded exactly and carries no CSRF header;
 *  - a 401 drops the session and notifies the app;
 *  - a 403 on a mutation re-bootstraps the CSRF token and retries exactly once;
 *  - errors are typed and carry the server's uniform body and Retry-After.
 */

const SESSION = { method: 'GET', path: '/admin/session', body: { csrf_token: 'csrf-token-1' } }

beforeEach(() => {
  forget()
})

afterEach(() => {
  vi.unstubAllGlobals()
  forget()
})

describe('api client — CSRF handling', () => {
  it('attaches the in-memory CSRF token to mutating requests', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'POST', path: '/admin/users', status: 201, body: { id: 'u1' } },
    ])

    await bootstrap('admin')
    await request('/admin/users', { method: 'POST', json: { name: 'Ada' } })

    const call = mock.calls.find((c) => c.method === 'POST')
    expect(call).toBeDefined()
    expect(call?.headers['X-CSRF-Token']).toBe('csrf-token-1')
    expect(call?.body).toBe('{"name":"Ada"}')
  })

  it('does not attach the CSRF token to reads', async () => {
    const mock = installFetchMock([SESSION, { method: 'GET', path: '/admin/users', body: [] }])

    await bootstrap('admin')
    await request('/admin/users')

    const call = mock.calls.find((c) => c.method === 'GET' && c.url.endsWith('/admin/users'))
    expect(call?.headers['X-CSRF-Token']).toBeUndefined()
  })

  it('form-encodes the admin login exactly and sends no CSRF header', async () => {
    const mock = installFetchMock([{ method: 'POST', path: '/admin/login', body: { status: 'ok' } }])

    await adminLogin('adm-secret-key')

    const call = mock.calls[0]
    expect(call?.method).toBe('POST')
    expect(call?.url).toBe('/api/admin/login')
    expect(call?.body).toBe('key=adm-secret-key')
    expect(call?.headers['Content-Type']).toBe('application/x-www-form-urlencoded')
    expect(call?.headers['X-CSRF-Token']).toBeUndefined()
  })

  it('never puts a secret in the URL', async () => {
    const mock = installFetchMock([{ method: 'POST', path: '/admin/login', body: { status: 'ok' } }])

    await adminLogin('adm-secret-key')

    expect(mock.calls[0]?.url).not.toContain('adm-secret-key')
    expect(mock.calls[0]?.url).not.toContain('?')
  })

  it('does not fire the 401 handler for a failed admin login', async () => {
    installFetchMock([{ method: 'POST', path: '/admin/login', status: 401, body: { error: 'unauthorized' } }])
    const expired = vi.fn()
    setSessionExpiredHandler(expired)

    await expect(adminLogin('wrong')).rejects.toBeInstanceOf(ApiError)
    expect(expired).not.toHaveBeenCalled()
  })
})

describe('api client — error handling', () => {
  it('maps a non-2xx answer to a typed error carrying the uniform body', async () => {
    installFetchMock([
      { method: 'GET', path: '/admin/users/u-missing', status: 404, body: { error: 'not_found' } },
    ])

    const error = await request('/admin/users/u-missing').catch((e: unknown) => e)

    expect(error).toBeInstanceOf(ApiError)
    const apiError = error as ApiError
    expect(apiError.status).toBe(404)
    expect(apiError.code).toBe('not_found')
    expect(apiError.isNotFound).toBe(true)
    expect(apiError.body).toEqual({ error: 'not_found' })
  })

  it('surfaces Retry-After for a rate-limited answer', async () => {
    installFetchMock([
      {
        method: 'POST',
        path: '/admin/login',
        status: 429,
        body: { error: 'rate_limited' },
        headers: { 'Retry-After': '42' },
      },
    ])

    const error = await adminLogin('k').catch((e: unknown) => e)

    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).code).toBe('rate_limited')
    expect((error as ApiError).retryAfter).toBe(42)
  })

  it('clears the session and notifies the app when a call answers 401', async () => {
    installFetchMock([
      SESSION,
      { method: 'GET', path: '/admin/users', status: 401, body: { error: 'unauthorized' } },
    ])
    const expired = vi.fn()
    setSessionExpiredHandler(expired)

    await bootstrap('admin')
    expect(csrfToken()).toBe('csrf-token-1')

    await expect(request('/admin/users')).rejects.toBeInstanceOf(ApiError)

    expect(csrfToken()).toBeNull()
    expect(isAuthenticated()).toBe(false)
    expect(expired).toHaveBeenCalledTimes(1)
  })

  it('re-bootstraps the CSRF token and retries a 403 mutation exactly once', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'POST', path: '/admin/users/u1/status', status: 403, body: { error: 'forbidden' } },
    ])
    const expired = vi.fn()
    setSessionExpiredHandler(expired)

    await bootstrap('admin')
    await expect(
      request('/admin/users/u1/status', { method: 'POST', json: { status: 'active' } }),
    ).rejects.toBeInstanceOf(ApiError)

    // One original attempt plus exactly one retry, and one re-bootstrap.
    expect(mock.countOf('POST', '/admin/users/u1/status')).toBe(2)
    expect(mock.countOf('GET', '/admin/session')).toBe(2)
    expect(expired).not.toHaveBeenCalled()
  })

  it('surfaces the error when the retried mutation fails with 403 again', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'POST', path: '/admin/users/u1/status', status: 403, body: { error: 'forbidden' } },
    ])

    await bootstrap('admin')
    const error = await request('/admin/users/u1/status', {
      method: 'POST',
      json: { status: 'active' },
    }).catch((e: unknown) => e)

    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).status).toBe(403)
    // Exactly one retry — never an unbounded loop.
    expect(mock.countOf('POST', '/admin/users/u1/status')).toBe(2)
  })

  it('reports a network failure as a typed error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('network down')
      }),
    )

    const error = await request('/admin/health').catch((e: unknown) => e)

    expect(error).toBeInstanceOf(ApiError)
    expect((error as ApiError).status).toBe(0)
    expect((error as ApiError).code).toBe('network_error')
  })
})
