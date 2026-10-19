import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  bootstrap,
  csrfToken,
  ensureSession,
  forget,
  isAuthenticated,
  sessionState,
} from '@/lib/session'
import { installFetchMock } from './helpers/fetch-mock'

/**
 * Session store specs.
 *
 * The load-bearing invariant: the CSRF token lives in memory ONLY. It is
 * never written to localStorage, sessionStorage or a cookie, and it is
 * re-fetched from the session endpoint after a reload.
 */

const SESSION = { method: 'GET', path: '/admin/session', body: { csrf_token: 'csrf-token-1' } }

beforeEach(() => {
  forget()
})

afterEach(() => {
  vi.unstubAllGlobals()
  forget()
})

describe('session store', () => {
  it('keeps the CSRF token in memory after a bootstrap', async () => {
    installFetchMock([SESSION])

    const ok = await bootstrap('admin')

    expect(ok).toBe(true)
    expect(csrfToken()).toBe('csrf-token-1')
    expect(isAuthenticated()).toBe(true)
    expect(sessionState().surface).toBe('admin')
  })

  it('never touches browser storage or cookies', async () => {
    installFetchMock([SESSION])
    const setItem = vi.spyOn(Storage.prototype, 'setItem')
    const getItem = vi.spyOn(Storage.prototype, 'getItem')
    const removeItem = vi.spyOn(Storage.prototype, 'removeItem')
    const cookie = vi.spyOn(Document.prototype, 'cookie', 'set')

    await bootstrap('admin')
    forget()

    expect(setItem).not.toHaveBeenCalled()
    expect(removeItem).not.toHaveBeenCalled()
    expect(getItem).not.toHaveBeenCalled()
    expect(cookie).not.toHaveBeenCalled()
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
  })

  it('drops every trace of the session on forget', async () => {
    installFetchMock([SESSION])
    await bootstrap('admin')

    forget()

    expect(csrfToken()).toBeNull()
    expect(isAuthenticated()).toBe(false)
    expect(sessionState().surface).toBeNull()
  })

  it('reports "no session" for a 401 without throwing', async () => {
    installFetchMock([{ method: 'GET', path: '/admin/session', status: 401, body: { error: 'unauthorized' } }])

    const ok = await bootstrap('admin')

    expect(ok).toBe(false)
    expect(csrfToken()).toBeNull()
    expect(isAuthenticated()).toBe(false)
  })

  it('reuses the in-memory token instead of re-fetching it', async () => {
    const mock = installFetchMock([SESSION])

    await bootstrap('admin')
    const ok = await ensureSession('admin')

    expect(ok).toBe(true)
    expect(mock.countOf('GET', '/admin/session')).toBe(1)
  })

  it('re-fetches the token after a reload dropped it', async () => {
    const mock = installFetchMock([SESSION])

    await bootstrap('admin')
    // A reload wipes the memory but not the cookie session.
    forget()
    const ok = await ensureSession('admin')

    expect(ok).toBe(true)
    expect(csrfToken()).toBe('csrf-token-1')
    expect(mock.countOf('GET', '/admin/session')).toBe(2)
  })
})
