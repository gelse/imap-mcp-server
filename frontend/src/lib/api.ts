/**
 * API client — the SPA's only HTTP boundary.
 *
 * Contract notes (all load-bearing, M07 SPA UI milestone):
 *
 *  - `fetch` only. No HTTP client library is in the dependency set.
 *  - Secrets NEVER travel in a URL. The admin key is posted as a form field,
 *    the CSRF token as a header. There is no query-string secret path.
 *  - The CSRF token is read from the in-memory session store through a
 *    provider callback (registered by lib/session.ts). It is never persisted.
 *  - The two login endpoints (admin, user) are the ONLY ones that are
 *    neither CSRF-protected nor allowed to trigger the global 401 handler (a
 *    wrong key must render the login form, not bounce the user to the login
 *    form with a notice).
 *  - Errors are mapped to a typed `ApiError` carrying `{status, code, body}`;
 *    the uniform backend bodies (`unauthorized`, `forbidden`, `rate_limited`,
 *    `invalid_request`, `not_found`, `internal_error`) are surfaced verbatim.
 *  - `Retry-After` is surfaced for 429 so the login view can count down.
 */

/** Base path of every JSON endpoint; the surface lives in the path prefix. */
export const API_BASE = '/api'

/** Uniform backend error codes (plus the client-side ones). */
export type ApiErrorCode =
  | 'unauthorized'
  | 'forbidden'
  | 'rate_limited'
  | 'invalid_request'
  | 'not_found'
  | 'internal_error'
  | 'network_error'
  | 'invalid_response'
  | 'request_failed'

/** A failed API call: HTTP status, the uniform error code, the raw body. */
export class ApiError extends Error {
  readonly status: number
  readonly code: ApiErrorCode | string
  readonly body: unknown
  /** Seconds to wait (429), or null when the server did not say. */
  readonly retryAfter: number | null

  constructor(status: number, code: ApiErrorCode | string, body: unknown, retryAfter: number | null = null) {
    super(`${code} (HTTP ${status})`)
    this.name = 'ApiError'
    this.status = status
    this.code = code
    this.body = body
    this.retryAfter = retryAfter
  }

  /** True for the uniform "no session" answer. */
  get isUnauthorized(): boolean {
    return this.status === 401
  }

  /** True for a missing resource. */
  get isNotFound(): boolean {
    return this.status === 404
  }
}

/** The metadata view every admin user endpoint returns. */
export interface AdminUser {
  id: string
  name: string
  status: 'active' | 'disabled'
  key_generation: number
  account_count: number
  created_at: string
}

/** The create response — the ONLY place a login key is ever disclosed. */
export interface AdminUserCreated {
  id: string
  name: string
  key_generation: number
  login_key: string
}

/** The rotate response — also a one-time disclosure. */
export interface AdminUserKeyRotated {
  id: string
  key_generation: number
  login_key: string
}

// --- user surface ----------------------------------------------------------

/**
 * One account as the `/api/me` listing returns it — metadata only.
 *
 * The view NEVER carries a credential: the IMAP password and the SMTP
 * user/password are write-only by construction (the store's own metadata
 * projection has no such fields). `smtp` carries only the coordination
 * fields `host`/`port`/`secure`.
 */
export interface UserAccountView {
  id: string
  name: string
  host: string
  port: number
  user: string
  tls: boolean
  allow_start_tls?: boolean
  email?: string
  smtp?: { host: string; port: number; secure: boolean }
  save_to_sent?: boolean
  sent_folder?: string
  default_bcc?: string | string[]
  allowed_from?: string[]
}

/** The profile half of `GET /api/me` plus the account listing. */
export interface UserProfile {
  id: string
  name: string
  created_at: string
  key_generation: number
  status: string
  /** Whether the account-encryption key is activated (M07-T01 extension). */
  aek_active: boolean
  account_count: number
  accounts: UserAccountView[]
}

/** The `smtp` block of an account request body. */
export interface SmtpAccountInput {
  host: string
  port: number
  secure: boolean
  /** Credential-adjacent: omitted means "keep the stored value". */
  user?: string
  /** Write-only: omitted means "keep the stored value", `''` means "no credential". */
  password?: string
}

/** The body of `POST /api/me/accounts` — the full upstream account shape. */
export interface CreateAccountPayload {
  name: string
  host: string
  port: number
  user: string
  password: string
  tls: boolean
  allow_start_tls?: boolean
  email?: string
  smtp?: SmtpAccountInput
  save_to_sent?: boolean
  sent_folder?: string
  default_bcc?: string | string[]
  allowed_from?: string[]
}

/**
 * The body of `PATCH /api/me/accounts/{id}` — a partial update.
 *
 * An omitted credential means "keep the stored value" (the sticky merge);
 * a non-credential optional field that IS present is applied verbatim, so a
 * blank `''`/`[]`/`false` is a deliberate erasure.
 */
export interface UpdateAccountPayload {
  name?: string
  host?: string
  port?: number
  user?: string
  password?: string
  tls?: boolean
  allow_start_tls?: boolean
  email?: string
  smtp?: SmtpAccountInput
  save_to_sent?: boolean
  sent_folder?: string
  default_bcc?: string | string[]
  allowed_from?: string[]
}

/** The create response — `account_encryption_key` appears ONLY on the first add. */
export interface UserAccountCreated {
  account: UserAccountView
  account_encryption_key?: string
}

/** The login response — the CSRF token of the fresh session. */
export interface UserLoginResponse {
  status: string
  csrf_token: string
}

/** The rotate response — also a one-time disclosure. */
export interface UserLoginKeyRotated {
  id: string
  key_generation: number
  login_key: string
}

const MUTATING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

type CsrfProvider = () => string | null
type UnauthorizedHandler = () => void
type CsrfRefreshHandler = () => Promise<boolean>

let csrfProvider: CsrfProvider = () => null
let unauthorizedHandler: UnauthorizedHandler | null = null
let csrfRefreshHandler: CsrfRefreshHandler | null = null

/**
 * Register the CSRF-token provider. lib/session.ts owns the token; the client
 * only asks for it at request time.
 */
export function setCsrfProvider(provider: CsrfProvider): void {
  csrfProvider = provider
}

/**
 * Register the global 401 handler. It is invoked for every failed request
 * EXCEPT the ones that opt out (the admin login, session bootstrap probes).
 */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler
}

/**
 * Register the "stale CSRF token" recovery: re-run the session bootstrap and
 * report whether a fresh token was obtained. The client retries the mutation
 * exactly once when this returns true.
 */
export function setCsrfRefreshHandler(handler: CsrfRefreshHandler | null): void {
  csrfRefreshHandler = handler
}

export interface ApiRequestOptions {
  /** HTTP method; defaults to GET. */
  method?: string
  /** JSON request body (sets the JSON content type). */
  json?: unknown
  /** Form-encoded request body (sets the form content type). */
  form?: Record<string, string>
  /** Extra request headers. */
  headers?: Record<string, string>
  /** Abort signal for cancellation. */
  signal?: AbortSignal | undefined
  /** Skip the CSRF header (the admin login endpoint). */
  withoutCsrf?: boolean
  /** Do not trigger the global 401 handler (login, session probes). */
  suppressUnauthorized?: boolean
  /** Do not attempt the CSRF-refresh retry (session probes). */
  suppressCsrfRetry?: boolean
}

/** Build the absolute (root-relative) URL for an API path. */
export function apiUrl(path: string): string {
  const suffix = path.startsWith('/') ? path : `/${path}`
  return `${API_BASE}${suffix}`
}

/** Encode a form body deterministically: `key=value&key2=value2`. */
export function encodeForm(form: Record<string, string>): string {
  return Object.entries(form)
    .map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`)
    .join('&')
}

function errorCodeFor(status: number, body: unknown): ApiErrorCode | string {
  if (body !== null && typeof body === 'object') {
    const code = (body as { error?: unknown }).error
    if (typeof code === 'string' && code.length > 0) return code
  }
  switch (status) {
    case 400:
      return 'invalid_request'
    case 401:
      return 'unauthorized'
    case 403:
      return 'forbidden'
    case 404:
      return 'not_found'
    case 429:
      return 'rate_limited'
    case 500:
      return 'internal_error'
    default:
      return 'request_failed'
  }
}

/** Parse a `Retry-After` header (delta-seconds form) into a number. */
export function parseRetryAfter(raw: string | null): number | null {
  if (raw === null) return null
  const seconds = Number.parseInt(raw.trim(), 10)
  if (!Number.isFinite(seconds) || seconds < 0) return null
  return seconds
}

async function readBody(response: Response): Promise<unknown> {
  let text: string
  try {
    text = await response.text()
  } catch {
    return null
  }
  if (text.length === 0) return null
  try {
    return JSON.parse(text) as unknown
  } catch {
    return text
  }
}

/**
 * Perform one API request. Non-2xx answers become `ApiError`s; the uniform
 * error bodies are never swallowed.
 */
export async function request<T = unknown>(
  path: string,
  options: ApiRequestOptions = {},
): Promise<T> {
  return execute<T>(path, options, false)
}

async function execute<T>(
  path: string,
  options: ApiRequestOptions,
  isRetry: boolean,
): Promise<T> {
  const method = (options.method ?? 'GET').toUpperCase()
  const headers: Record<string, string> = { Accept: 'application/json', ...options.headers }
  let body: string | undefined

  if (options.json !== undefined) {
    headers['Content-Type'] = 'application/json'
    body = JSON.stringify(options.json)
  } else if (options.form !== undefined) {
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    body = encodeForm(options.form)
  }

  const mutating = MUTATING_METHODS.has(method)
  if (mutating && !options.withoutCsrf) {
    const token = csrfProvider()
    if (token) headers['X-CSRF-Token'] = token
  }

  let response: Response
  try {
    const init: RequestInit = { method, headers, credentials: 'same-origin' }
    if (body !== undefined) init.body = body
    if (options.signal !== undefined) init.signal = options.signal
    response = await fetch(apiUrl(path), init)
  } catch {
    throw new ApiError(0, 'network_error', null)
  }

  const payload = await readBody(response)

  if (!response.ok) {
    const code = errorCodeFor(response.status, payload)
    const retryAfter = parseRetryAfter(response.headers.get('Retry-After'))

    if (response.status === 401 && !options.suppressUnauthorized) {
      unauthorizedHandler?.()
    }

    // A 403 on a mutation is, in practice, a stale CSRF token (the session
    // survived but the in-memory token did not). Re-bootstrap once and retry
    // the mutation exactly once; a second 403 surfaces to the caller.
    if (
      response.status === 403 &&
      mutating &&
      !options.suppressCsrfRetry &&
      !isRetry &&
      csrfRefreshHandler !== null
    ) {
      const refreshed = await csrfRefreshHandler()
      if (refreshed) return execute<T>(path, options, true)
    }

    throw new ApiError(response.status, code, payload, retryAfter)
  }

  if (response.status === 204 || payload === null) return undefined as T
  if (typeof payload === 'string') {
    throw new ApiError(response.status, 'invalid_response', payload)
  }
  return payload as T
}

// --- admin surface ----------------------------------------------------------

/**
 * Exchange the admin key for a session cookie.
 *
 * The endpoint's contract is unchanged: a form-encoded `key` field. This call
 * is deliberately exempt from the CSRF header (the session does not exist
 * yet) and from the global 401 handler (a wrong key must render the login
 * form, not redirect to it).
 */
export async function adminLogin(key: string): Promise<void> {
  await request<{ status: string }>('/admin/login', {
    method: 'POST',
    form: { key },
    withoutCsrf: true,
    suppressUnauthorized: true,
    suppressCsrfRetry: true,
  })
}

/** Invalidate the admin session cookie (CSRF-protected). */
export async function adminLogout(): Promise<void> {
  await request<{ status: string }>('/admin/logout', { method: 'POST' })
}

/** Fetch the session's CSRF token (the SPA's memory-only bootstrap). */
export async function adminSession(): Promise<{ csrf_token: string }> {
  return request<{ csrf_token: string }>('/admin/session', {
    suppressUnauthorized: true,
    suppressCsrfRetry: true,
  })
}

/** Authenticated liveness ping. */
export async function adminHealth(): Promise<{ status: string }> {
  return request<{ status: string }>('/admin/health')
}

/** Every registry user as a metadata view (never a key). */
export async function listAdminUsers(): Promise<AdminUser[]> {
  return request<AdminUser[]>('/admin/users')
}

/** One user's metadata view; 404 for an unknown id. */
export async function getAdminUser(userId: string): Promise<AdminUser> {
  return request<AdminUser>(`/admin/users/${encodeURIComponent(userId)}`)
}

/** Create a user; the response carries the one-time login key. */
export async function createAdminUser(name: string): Promise<AdminUserCreated> {
  return request<AdminUserCreated>('/admin/users', { method: 'POST', json: { name } })
}

/** Rotate a user's login key; the response carries the new one-time key. */
export async function rotateAdminUserKey(userId: string): Promise<AdminUserKeyRotated> {
  return request<AdminUserKeyRotated>(`/admin/users/${encodeURIComponent(userId)}/rotate-key`, {
    method: 'POST',
  })
}

/** Enable or disable a user; the response is the updated metadata view. */
export async function setAdminUserStatus(
  userId: string,
  status: 'active' | 'disabled',
): Promise<AdminUser> {
  return request<AdminUser>(`/admin/users/${encodeURIComponent(userId)}/status`, {
    method: 'POST',
    json: { status },
  })
}

/** Delete a user and their whole directory (204). */
export async function deleteAdminUser(userId: string): Promise<void> {
  await request<void>(`/admin/users/${encodeURIComponent(userId)}`, { method: 'DELETE' })
}

// --- user surface ----------------------------------------------------------

/**
 * Exchange the user login key for a session cookie (JSON body).
 *
 * The endpoint is the JSON twin of the old HTML form: the same per-IP login
 * budget, the same same-origin guard, the same HttpOnly cookie. It is exempt
 * from the CSRF header (the session does not exist yet) and from the global
 * 401 handler (a wrong key must render the login form, not bounce to it).
 *
 * The response carries the session's CSRF token — it is handed to the
 * in-memory session store by the caller and never persisted.
 */
export async function userLogin(key: string): Promise<UserLoginResponse> {
  return request<UserLoginResponse>('/me/login', {
    method: 'POST',
    json: { key },
    withoutCsrf: true,
    suppressUnauthorized: true,
    suppressCsrfRetry: true,
  })
}

/** Invalidate the user session cookie (CSRF-protected). */
export async function userLogout(): Promise<void> {
  await request<{ status: string }>('/me/logout', {
    method: 'POST',
    suppressUnauthorized: true,
  })
}

/** The authenticated user's profile and account listing — metadata only. */
export async function getUserProfile(): Promise<UserProfile> {
  return request<UserProfile>('/me')
}

/**
 * Create an account.
 *
 * The response carries `account_encryption_key` ONLY on the very first add
 * (the lazy AEK activation) — the one-time disclosure the KeyDisplay renders.
 */
export async function createUserAccount(body: CreateAccountPayload): Promise<UserAccountCreated> {
  return request<UserAccountCreated>('/me/accounts', { method: 'POST', json: body })
}

/** Partially update an account; credential fields are write-only. */
export async function updateUserAccount(
  accountId: string,
  body: UpdateAccountPayload,
): Promise<{ account: UserAccountView }> {
  return request<{ account: UserAccountView }>(
    `/me/accounts/${encodeURIComponent(accountId)}`,
    { method: 'PATCH', json: body },
  )
}

/** Remove an account (204). */
export async function deleteUserAccount(accountId: string): Promise<void> {
  await request<void>(`/me/accounts/${encodeURIComponent(accountId)}`, { method: 'DELETE' })
}

/** Activate the account-encryption key; the plaintext hex is shown exactly once. */
export async function activateAccountEncryption(): Promise<{ account_encryption_key: string }> {
  return request<{ account_encryption_key: string }>('/me/accounts/activate', { method: 'POST' })
}

/** Regenerate the login key; the new plaintext is shown exactly once. */
export async function rotateUserLoginKey(): Promise<UserLoginKeyRotated> {
  return request<UserLoginKeyRotated>('/me/rotate-key', { method: 'POST' })
}
