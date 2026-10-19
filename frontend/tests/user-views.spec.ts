import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createMemoryHistory, type Router } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import KeyDisplay from '@/components/KeyDisplay.vue'
import AccountAddView from '@/user/views/AccountAddView.vue'
import AccountEditView from '@/user/views/AccountEditView.vue'
import AccountsView from '@/user/views/AccountsView.vue'
import UserLoginView from '@/user/views/LoginView.vue'
import SettingsView from '@/user/views/SettingsView.vue'
import UserApp from '@/user/UserApp.vue'
import { createAppRouter } from '@/router'
import { forget, sessionState } from '@/lib/session'
import { userNotice } from '@/user/notice'
import { installFetchMock } from './helpers/fetch-mock'

/**
 * User-surface view specs.
 *
 * The views are mounted against the real router and the real API client; only
 * `fetch` is faked. The contracts under test:
 *  - the login posts JSON, stores the CSRF token in memory and shows one
 *    uniform failure message;
 *  - the account list renders the profile and deletes only behind the
 *    type-to-confirm dialog;
 *  - the edit view renders every credential input blank, prefills the
 *    non-credential fields and builds the exact PATCH body (blank credentials
 *    omitted, optional fields explicitly emptied, an explicit credential
 *    clearing sent as an empty string);
 *  - the add view shows the one-time key exactly once and never persists it,
 *    and the failure-safe disclosure states the failed save ALONGSIDE the
 *    revealed key;
 *  - the settings view hides the activation when the key is already active,
 *    handles the 409 and signs out;
 *  - a 401 mid-session routes the USER surface to the user login view.
 */

const SESSION = { method: 'GET', path: '/me/session', body: { csrf_token: 'csrf-token-1' } }

/** A synthetic 64-hex account-encryption key (built at runtime, never literal). */
const AEK = 'ab'.repeat(32)
const LOGIN_KEY = 'usr_' + 'C'.repeat(43)

const ACCOUNT = {
  id: 'a1',
  name: 'Work',
  host: 'imap.example.org',
  port: 993,
  user: 'ada',
  tls: true,
  allow_start_tls: false,
  email: 'ada@example.org',
  smtp: { host: 'smtp.example.org', port: 587, secure: false },
  save_to_sent: true,
  sent_folder: 'Sent',
  default_bcc: 'bcc@example.org',
  allowed_from: ['ada@example.org'],
}

function profile(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'u1',
    name: 'Ada',
    created_at: '2026-01-01T00:00:00Z',
    key_generation: 1,
    status: 'active',
    aek_active: true,
    account_count: 1,
    accounts: [ACCOUNT],
    ...overrides,
  }
}

let router: Router
const wrappers: VueWrapper[] = []

beforeEach(() => {
  forget()
  router = createAppRouter(createMemoryHistory())
})

afterEach(() => {
  for (const wrapper of wrappers) wrapper.unmount()
  wrappers.length = 0
  document.body.innerHTML = ''
  vi.unstubAllGlobals()
  forget()
  userNotice.value = null
})

function mountView(component: unknown): VueWrapper {
  const wrapper = mount(component as never, { global: { plugins: [router] } })
  wrappers.push(wrapper)
  return wrapper
}

async function go(path: string): Promise<void> {
  await router.push(path)
  await router.isReady()
  await flushPromises()
}

function buttonByText(wrapper: VueWrapper, label: string) {
  const button = wrapper.findAll('button').find((b) => b.text() === label)
  if (button === undefined) throw new Error(`button not found: ${label}`)
  return button
}

function bodyOf(mock: { calls: { method: string; url: string; body: string | null }[] }, method: string, path: string): Record<string, unknown> {
  const call = mock.calls.find((c) => c.method === method && c.url.endsWith(path))
  if (call === undefined || call.body === null) throw new Error(`no call: ${method} ${path}`)
  return JSON.parse(call.body) as Record<string, unknown>
}

describe('user — login', () => {
  it('posts the key as JSON and keeps the CSRF token in memory only', async () => {
    const mock = installFetchMock([
      { method: 'GET', path: '/me/session', status: 401, body: { error: 'unauthorized' }, times: 1 },
      { method: 'POST', path: '/me/login', body: { status: 'ok', csrf_token: 'csrf-token-1' } },
    ])

    await go('/user/login')
    const wrapper = mountView(UserLoginView)
    await flushPromises()

    await wrapper.get('#user-key').setValue('the-user-key')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    const call = mock.calls.find((c) => c.method === 'POST')
    expect(call?.url).toBe('/api/me/login')
    expect(call?.headers['Content-Type']).toBe('application/json')
    expect(call?.body).toBe('{"key":"the-user-key"}')
    // No secret ever travels in the URL.
    expect(call?.url).not.toContain('the-user-key')

    // The token is in memory only.
    expect(sessionState().csrfToken).toBe('csrf-token-1')
    expect(sessionState().surface).toBe('user')
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)
    expect(router.currentRoute.value.name).toBe('user-accounts')
  })

  it('renders one uniform failure message for a wrong key', async () => {
    installFetchMock([
      { method: 'GET', path: '/me/session', status: 401, body: { error: 'unauthorized' } },
      { method: 'POST', path: '/me/login', status: 401, body: { error: 'unauthorized' } },
    ])

    await go('/user/login')
    const wrapper = mountView(UserLoginView)
    await flushPromises()

    await wrapper.get('#user-key').setValue('wrong-key')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('Sign-in failed')
    // No cause distinction leaks into the UI.
    expect(wrapper.text()).not.toContain('unauthorized')
    expect(sessionState().csrfToken).toBeNull()
  })

  it('shows the retry countdown for a rate-limited answer', async () => {
    installFetchMock([
      { method: 'GET', path: '/me/session', status: 401, body: { error: 'unauthorized' } },
      {
        method: 'POST',
        path: '/me/login',
        status: 429,
        body: { error: 'rate_limited' },
        headers: { 'Retry-After': '30' },
      },
    ])

    await go('/user/login')
    const wrapper = mountView(UserLoginView)
    await flushPromises()

    await wrapper.get('#user-key').setValue('key')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('Try again in')
  })
})

describe('user — accounts', () => {
  it('renders the profile and every account', async () => {
    installFetchMock([SESSION, { method: 'GET', path: '/me', body: profile() }])

    await go('/user')
    const wrapper = mountView(AccountsView)
    await flushPromises()

    expect(wrapper.text()).toContain('Ada')
    expect(wrapper.text()).toContain('Work')
    expect(wrapper.text()).toContain('imap.example.org:993')
    expect(wrapper.text()).toContain('smtp.example.org')
    expect(wrapper.text()).toContain('Active')
  })

  it('deletes only after the exact account name is typed', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'GET', path: '/me', body: profile() },
      { method: 'DELETE', path: '/me/accounts/a1', status: 204 },
    ])

    await go('/user')
    const wrapper = mountView(AccountsView)
    await flushPromises()

    await buttonByText(wrapper, 'Delete').trigger('click')
    await flushPromises()

    const input = document.querySelector<HTMLInputElement>('#dialog-confirm-input')
    const confirm = document.querySelector<HTMLButtonElement>('.dialog__btn--confirm')
    expect(input).not.toBeNull()
    expect(confirm?.disabled).toBe(true)
    expect(mock.countOf('DELETE', '/me/accounts/a1')).toBe(0)

    if (input !== null) {
      input.value = 'work'
      input.dispatchEvent(new Event('input', { bubbles: true }))
    }
    await nextTick()
    expect(confirm?.disabled).toBe(true)

    if (input !== null) {
      input.value = 'Work'
      input.dispatchEvent(new Event('input', { bubbles: true }))
    }
    await nextTick()
    expect(confirm?.disabled).toBe(false)

    confirm?.click()
    await flushPromises()

    expect(mock.countOf('DELETE', '/me/accounts/a1')).toBe(1)
  })

  it('routes to the user login view when a call answers 401', async () => {
    installFetchMock([
      SESSION,
      { method: 'GET', path: '/me', status: 401, body: { error: 'unauthorized' } },
    ])

    await go('/user')
    mountView(AccountsView)
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('user-login')
    expect(router.currentRoute.value.query.reason).toBe('expired')
    expect(sessionState().csrfToken).toBeNull()
  })
})

describe('user — account edit', () => {
  it('renders every credential input blank and prefills the non-credential fields', async () => {
    installFetchMock([SESSION, { method: 'GET', path: '/me', body: profile() }])

    await go('/user/accounts/a1')
    const wrapper = mountView(AccountEditView)
    await flushPromises()

    // Credentials are never prefilled.
    expect((wrapper.get('#edit-account-password').element as HTMLInputElement).value).toBe('')
    expect((wrapper.get('#edit-account-smtp-password').element as HTMLInputElement).value).toBe('')
    expect((wrapper.get('#edit-account-smtp-user').element as HTMLInputElement).value).toBe('')

    // Non-credential fields are prefilled.
    expect((wrapper.get('#edit-account-name').element as HTMLInputElement).value).toBe('Work')
    expect((wrapper.get('#edit-account-host').element as HTMLInputElement).value).toBe('imap.example.org')
    expect((wrapper.get('#edit-account-port').element as HTMLInputElement).value).toBe('993')
    expect((wrapper.get('#edit-account-user').element as HTMLInputElement).value).toBe('ada')
    expect((wrapper.get('#edit-account-email').element as HTMLInputElement).value).toBe('ada@example.org')
    expect((wrapper.get('#edit-account-sent-folder').element as HTMLInputElement).value).toBe('Sent')
    expect((wrapper.get('#edit-account-default-bcc').element as HTMLInputElement).value).toBe('bcc@example.org')
    expect((wrapper.get('#edit-account-allowed-from').element as HTMLInputElement).value).toBe('ada@example.org')
    expect((wrapper.get('#edit-account-smtp-host').element as HTMLInputElement).value).toBe('smtp.example.org')
    expect((wrapper.get('#edit-account-smtp-port').element as HTMLInputElement).value).toBe('587')
    expect((wrapper.get('#edit-account-save-to-sent').element as HTMLInputElement).checked).toBe(true)
    expect((wrapper.get('#edit-account-tls').element as HTMLInputElement).checked).toBe(true)
  })

  it('omits blank credentials from the PATCH body and keeps the stored values', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'GET', path: '/me', body: profile() },
      { method: 'PATCH', path: '/me/accounts/a1', body: { account: ACCOUNT } },
    ])

    await go('/user/accounts/a1')
    const wrapper = mountView(AccountEditView)
    await flushPromises()

    await wrapper.get('form').trigger('submit')
    await flushPromises()

    const body = bodyOf(mock, 'PATCH', '/me/accounts/a1')
    expect(body).toEqual({
      name: 'Work',
      host: 'imap.example.org',
      port: 993,
      user: 'ada',
      tls: true,
      allow_start_tls: false,
      email: 'ada@example.org',
      save_to_sent: true,
      sent_folder: 'Sent',
      default_bcc: 'bcc@example.org',
      allowed_from: ['ada@example.org'],
      smtp: { host: 'smtp.example.org', port: 587, secure: false },
    })
    expect(body).not.toHaveProperty('password')
    expect((body.smtp as Record<string, unknown>)).not.toHaveProperty('password')
    expect((body.smtp as Record<string, unknown>)).not.toHaveProperty('user')
  })

  it('sends an emptied optional field as a deliberate erasure', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'GET', path: '/me', body: profile() },
      { method: 'PATCH', path: '/me/accounts/a1', body: { account: ACCOUNT } },
    ])

    await go('/user/accounts/a1')
    const wrapper = mountView(AccountEditView)
    await flushPromises()

    await wrapper.get('#edit-account-email').setValue('')
    await wrapper.get('#edit-account-sent-folder').setValue('')
    await wrapper.get('#edit-account-default-bcc').setValue('')
    await wrapper.get('#edit-account-allowed-from').setValue('')
    await wrapper.get('#edit-account-save-to-sent').setValue(false)
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    const body = bodyOf(mock, 'PATCH', '/me/accounts/a1')
    expect(body.email).toBe('')
    expect(body.sent_folder).toBe('')
    expect(body.default_bcc).toBe('')
    expect(body.allowed_from).toEqual([])
    expect(body.save_to_sent).toBe(false)
  })

  it('sends a typed credential and an explicit SMTP credential clearing', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'GET', path: '/me', body: profile() },
      { method: 'PATCH', path: '/me/accounts/a1', body: { account: ACCOUNT } },
    ])

    await go('/user/accounts/a1')
    const wrapper = mountView(AccountEditView)
    await flushPromises()

    await wrapper.get('#edit-account-password').setValue('new-secret')
    await wrapper.get('#edit-account-smtp-user').setValue('ada')
    await wrapper.get('#edit-account-clear-smtp-credential').setValue(true)
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    const body = bodyOf(mock, 'PATCH', '/me/accounts/a1')
    expect(body.password).toBe('new-secret')
    expect(body.smtp).toEqual({
      host: 'smtp.example.org',
      port: 587,
      secure: false,
      user: 'ada',
      password: '',
    })
  })

  it('sends an explicit IMAP credential clearing', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'GET', path: '/me', body: profile() },
      { method: 'PATCH', path: '/me/accounts/a1', body: { account: ACCOUNT } },
    ])

    await go('/user/accounts/a1')
    const wrapper = mountView(AccountEditView)
    await flushPromises()

    // The switch is off by default: a blank password keeps the stored one.
    expect((wrapper.get('#edit-account-clear-imap-credential').element as HTMLInputElement).checked).toBe(false)

    await wrapper.get('#edit-account-clear-imap-credential').setValue(true)
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    const body = bodyOf(mock, 'PATCH', '/me/accounts/a1')
    // Explicitly empty: the store's documented "no credential" value.
    expect(body.password).toBe('')
    // The SMTP credential is untouched by the IMAP switch.
    expect((body.smtp as Record<string, unknown>)).not.toHaveProperty('password')
  })

  it('renders the not-found state for an unknown account', async () => {
    installFetchMock([
      SESSION,
      { method: 'GET', path: '/me', body: profile({ accounts: [] }) },
    ])

    await go('/user/accounts/a-missing')
    const wrapper = mountView(AccountEditView)
    await flushPromises()

    expect(wrapper.text()).toContain('Account not found')
  })
})

describe('user — account add', () => {
  it('shows the one-time key exactly once and never persists it', async () => {
    const mock = installFetchMock([
      SESSION,
      {
        method: 'POST',
        path: '/me/accounts',
        status: 201,
        body: { account: { ...ACCOUNT, id: 'a2', name: 'New' }, account_encryption_key: AEK },
      },
    ])

    await go('/user/accounts/new')
    const wrapper = mountView(AccountAddView)
    await flushPromises()

    await wrapper.get('#account-name').setValue('New')
    await wrapper.get('#account-host').setValue('imap.example.org')
    await wrapper.get('#account-user').setValue('ada')
    await wrapper.get('#account-password').setValue('the-password')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.findComponent(KeyDisplay).exists()).toBe(true)
    expect(wrapper.get('[data-testid="key-value"]').text()).toBe(AEK)
    expect(wrapper.text()).toContain('never be shown again')

    // The plaintext is in no store, no storage and no route.
    expect(JSON.stringify(sessionState())).not.toContain(AEK)
    expect(JSON.stringify(router.currentRoute.value)).not.toContain(AEK)
    expect(window.localStorage.length).toBe(0)
    expect(window.sessionStorage.length).toBe(0)

    // The created account carries no credential back into the form.
    const body = bodyOf(mock, 'POST', '/me/accounts')
    expect(body.name).toBe('New')
    expect(body.password).toBe('the-password')

    // "Done" drops the key and moves on to the list.
    await wrapper.get('.key-display__done').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-testid="key-value"]').exists()).toBe(false)
    expect(router.currentRoute.value.name).toBe('user-accounts')
  })

  it('clears the one-time key when the view unmounts', async () => {
    installFetchMock([
      SESSION,
      {
        method: 'POST',
        path: '/me/accounts',
        status: 201,
        body: { account: { ...ACCOUNT, id: 'a2', name: 'New' }, account_encryption_key: AEK },
      },
    ])

    await go('/user/accounts/new')
    const wrapper = mountView(AccountAddView)
    await flushPromises()

    await wrapper.get('#account-name').setValue('New')
    await wrapper.get('#account-host').setValue('imap.example.org')
    await wrapper.get('#account-user').setValue('ada')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    const keyDisplay = wrapper.findComponent(KeyDisplay)
    const revealed = (keyDisplay.vm as unknown as { revealed: string }).revealed
    expect(revealed).toBe(AEK)

    wrapper.unmount()
    expect((keyDisplay.vm as unknown as { revealed: string }).revealed).toBe('')
  })

  it('states the failed save ALONGSIDE the failure-safe disclosed key', async () => {
    installFetchMock([
      SESSION,
      {
        method: 'POST',
        path: '/me/accounts',
        status: 500,
        body: { error: 'internal_error', account_encryption_key: AEK },
      },
    ])

    await go('/user/accounts/new')
    const wrapper = mountView(AccountAddView)
    await flushPromises()

    await wrapper.get('#account-name').setValue('New')
    await wrapper.get('#account-host').setValue('imap.example.org')
    await wrapper.get('#account-user').setValue('ada')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    // The key is disclosed — it is the only chance to copy it.
    expect(wrapper.get('[data-testid="key-value"]').text()).toBe(AEK)

    // ...and the honest error context is visible in the SAME branch.
    expect(wrapper.find('.error-banner').exists()).toBe(true)
    expect(wrapper.text()).toContain('The account was not saved')

    // The summary must never claim that the account exists.
    expect(wrapper.text()).not.toContain('created together with this account')

    // The key is still shown exactly once and dies with the view.
    const keyDisplay = wrapper.findComponent(KeyDisplay)
    const revealed = (keyDisplay.vm as unknown as { revealed: string }).revealed
    expect(revealed).toBe(AEK)
    wrapper.unmount()
    expect((keyDisplay.vm as unknown as { revealed: string }).revealed).toBe('')
  })

  it('does not show a key when the response carries none', async () => {
    installFetchMock([
      SESSION,
      {
        method: 'POST',
        path: '/me/accounts',
        status: 201,
        body: { account: { ...ACCOUNT, id: 'a2', name: 'New' } },
      },
      { method: 'GET', path: '/me', body: profile() },
    ])

    await go('/user/accounts/new')
    const wrapper = mountView(AccountAddView)
    await flushPromises()

    await wrapper.get('#account-name').setValue('New')
    await wrapper.get('#account-host').setValue('imap.example.org')
    await wrapper.get('#account-user').setValue('ada')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.findComponent(KeyDisplay).exists()).toBe(false)
    expect(router.currentRoute.value.name).toBe('user-accounts')

    // The success notice outlives the form: the list shows it.
    expect(userNotice.value?.message).toContain('was added')
    const list = mountView(AccountsView)
    await flushPromises()
    expect(list.text()).toContain('was added')
  })

  it('surfaces a 409 as an error and keeps the form usable', async () => {
    installFetchMock([
      SESSION,
      { method: 'POST', path: '/me/accounts', status: 409, body: { error: 'aek_already_active' } },
    ])

    await go('/user/accounts/new')
    const wrapper = mountView(AccountAddView)
    await flushPromises()

    await wrapper.get('#account-name').setValue('New')
    await wrapper.get('#account-host').setValue('imap.example.org')
    await wrapper.get('#account-user').setValue('ada')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('already active')
    expect(wrapper.findComponent(KeyDisplay).exists()).toBe(false)
    expect(router.currentRoute.value.name).toBe('user-account-add')
  })
})

describe('user — surface frame', () => {
  it('renders the navigation and signs out from the shell', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'GET', path: '/me', body: profile() },
      { method: 'POST', path: '/me/logout', body: { status: 'ok' } },
    ])

    await go('/user')
    const wrapper = mountView(UserApp)
    await flushPromises()

    expect(wrapper.text()).toContain('Accounts')
    expect(wrapper.text()).toContain('Settings')
    expect(wrapper.text()).toContain('Add account')

    await buttonByText(wrapper, 'Sign out').trigger('click')
    await flushPromises()

    expect(mock.countOf('POST', '/me/logout')).toBe(1)
    expect(sessionState().csrfToken).toBeNull()
    expect(sessionState().authenticated).toBe(false)
    expect(router.currentRoute.value.name).toBe('user-login')
  })
})

describe('user — settings', () => {
  it('hides the activation when the encryption key is already active', async () => {
    installFetchMock([SESSION, { method: 'GET', path: '/me', body: profile({ aek_active: true }) }])

    await go('/user/settings')
    const wrapper = mountView(SettingsView)
    await flushPromises()

    expect(wrapper.text()).toContain('Active')
    expect(wrapper.findAll('button').some((b) => b.text().includes('Activate account encryption'))).toBe(
      false,
    )
  })

  it('offers the activation while the key is not active and shows it once', async () => {
    installFetchMock([
      SESSION,
      { method: 'GET', path: '/me', body: profile({ aek_active: false }) },
      { method: 'POST', path: '/me/accounts/activate', body: { account_encryption_key: AEK } },
    ])

    await go('/user/settings')
    const wrapper = mountView(SettingsView)
    await flushPromises()

    await buttonByText(wrapper, 'Activate account encryption').trigger('click')
    await flushPromises()

    expect(wrapper.get('[data-testid="key-value"]').text()).toBe(AEK)
    expect(JSON.stringify(sessionState())).not.toContain(AEK)
  })

  it('handles the 409 of a second activation', async () => {
    installFetchMock([
      SESSION,
      { method: 'GET', path: '/me', body: profile({ aek_active: false }) },
      {
        method: 'POST',
        path: '/me/accounts/activate',
        status: 409,
        body: { error: 'aek_already_active' },
      },
    ])

    await go('/user/settings')
    const wrapper = mountView(SettingsView)
    await flushPromises()

    await buttonByText(wrapper, 'Activate account encryption').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('already active')
    expect(wrapper.find('[data-testid="key-value"]').exists()).toBe(false)
  })

  it('rotates the login key and shows the new one exactly once', async () => {
    installFetchMock([
      SESSION,
      { method: 'GET', path: '/me', body: profile() },
      {
        method: 'POST',
        path: '/me/rotate-key',
        body: { id: 'u1', key_generation: 2, login_key: LOGIN_KEY },
      },
    ])

    await go('/user/settings')
    const wrapper = mountView(SettingsView)
    await flushPromises()

    await buttonByText(wrapper, 'Regenerate login key').trigger('click')
    await flushPromises()

    expect(wrapper.get('[data-testid="key-value"]').text()).toBe(LOGIN_KEY)
    expect(wrapper.text()).toContain('no longer works')
    expect(JSON.stringify(sessionState())).not.toContain(LOGIN_KEY)
  })

  it('signs out: the session is cleared and the login view is shown', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'GET', path: '/me', body: profile() },
      { method: 'POST', path: '/me/logout', body: { status: 'ok' } },
    ])

    await go('/user/settings')
    const wrapper = mountView(SettingsView)
    await flushPromises()

    await buttonByText(wrapper, 'Sign out').trigger('click')
    await flushPromises()

    expect(mock.countOf('POST', '/me/logout')).toBe(1)
    expect(sessionState().csrfToken).toBeNull()
    expect(sessionState().authenticated).toBe(false)
    expect(router.currentRoute.value.name).toBe('user-login')
  })
})
