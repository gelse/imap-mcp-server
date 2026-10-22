/**
 * Session store — the SPA's in-memory authentication state.
 *
 * Load-bearing invariants (M07 SPA UI milestone):
 *
 *  - The CSRF token lives in MEMORY ONLY. It is never written to
 *    localStorage, sessionStorage, a cookie, or the URL. After a reload the
 *    token is re-fetched from the session endpoint.
 *  - The one-time user key NEVER enters this store. It is rendered once by
 *    the KeyDisplay component and then discarded with the view.
 *  - The store owns the API client's CSRF provider and the global 401
 *    handler; the client itself never imports this module (that would be a
 *    cycle), it only calls the setters below.
 */

import { reactive } from 'vue'
import {
  request,
  setCsrfProvider,
  setCsrfRefreshHandler,
  setUnauthorizedHandler,
} from './api'

/** The two role surfaces of the SPA. */
export type Surface = 'admin' | 'user'

export interface SessionState {
  /** The session's CSRF token, in memory only. */
  csrfToken: string | null
  /** Which surface the current session belongs to. */
  surface: Surface | null
  /** Whether a session is currently established. */
  authenticated: boolean
}

const state = reactive<SessionState>({
  csrfToken: null,
  surface: null,
  authenticated: false,
})

const SESSION_ENDPOINTS: Record<Surface, string> = {
  admin: '/admin/session',
  user: '/me/session',
}

type SessionExpiredHandler = () => void
let sessionExpiredHandler: SessionExpiredHandler | null = null

/** Register the "the session is gone" callback (the router owns navigation). */
export function setSessionExpiredHandler(handler: SessionExpiredHandler | null): void {
  sessionExpiredHandler = handler
}

/** The reactive session state (read-only by convention). */
export function sessionState(): SessionState {
  return state
}

/** The current CSRF token, or null when there is no session. */
export function csrfToken(): string | null {
  return state.csrfToken
}

/** Whether a session is established. */
export function isAuthenticated(): boolean {
  return state.authenticated
}

/** Drop every trace of the session from memory. */
export function forget(): void {
  state.csrfToken = null
  state.surface = null
  state.authenticated = false
}

/**
 * Record a session established by a login response.
 *
 * The JSON user login answers with the session's CSRF token, so no second
 * round-trip is needed. The token goes straight into this in-memory store —
 * it is never written to browser storage.
 */
export function establish(surface: Surface, csrfToken: string): void {
  if (csrfToken.length === 0) {
    forget()
    return
  }
  state.csrfToken = csrfToken
  state.surface = surface
  state.authenticated = true
}

/**
 * Bootstrap the CSRF token for a surface.
 *
 * Returns true when a valid session exists (the token is now in memory) and
 * false otherwise. A 401 is NOT an error here — it simply means "no session",
 * and the caller decides what to render.
 */
export async function bootstrap(surface: Surface): Promise<boolean> {
  try {
    const body = await request<{ csrf_token: string }>(SESSION_ENDPOINTS[surface], {
      suppressUnauthorized: true,
      suppressCsrfRetry: true,
    })
    if (!body || typeof body.csrf_token !== 'string' || body.csrf_token.length === 0) {
      forget()
      return false
    }
    state.csrfToken = body.csrf_token
    state.surface = surface
    state.authenticated = true
    return true
  } catch {
    forget()
    return false
  }
}

/**
 * Ensure a session exists for a surface, bootstrapping only when needed.
 * Deep links and reloads land here: the cookie session survives, the in-memory
 * token does not.
 */
export async function ensureSession(surface: Surface): Promise<boolean> {
  if (state.authenticated && state.surface === surface && state.csrfToken !== null) {
    return true
  }
  return bootstrap(surface)
}

// --- wiring the API client --------------------------------------------------

setCsrfProvider(() => state.csrfToken)

setUnauthorizedHandler(() => {
  // A 401 on any call means the session is gone: drop the token and let the
  // router send the user to the login view.
  forget()
  sessionExpiredHandler?.()
})

setCsrfRefreshHandler(async () => {
  // A 403 on a mutation means the token went stale (e.g. the tab was
  // reloaded): re-bootstrap the current surface once.
  return bootstrap(state.surface ?? 'admin')
})
