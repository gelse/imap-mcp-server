import { flushPromises, mount, type VueWrapper } from '@vue/test-utils'
import { createMemoryHistory, type Router } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import KeyDisplay from '@/components/KeyDisplay.vue'
import LoginView from '@/admin/views/LoginView.vue'
import UserCreateView from '@/admin/views/UserCreateView.vue'
import UserDetailView from '@/admin/views/UserDetailView.vue'
import UsersView from '@/admin/views/UsersView.vue'
import { createAppRouter } from '@/router'
import { forget, sessionState } from '@/lib/session'
import { installFetchMock } from './helpers/fetch-mock'

/**
 * Admin view specs.
 *
 * The views are mounted against the real router and the real API client; only
 * `fetch` is faked. The contracts under test:
 *  - create → the one-time key is rendered exactly once and then discarded;
 *  - rotate → a new key is shown once and the key generation bumps;
 *  - status → the exact request body is posted;
 *  - delete → the type-to-confirm dialog gates the DELETE;
 *  - 404 → the not-found state;
 *  - 401 → the login view with a "session expired" notice.
 */

const SESSION = { method: 'GET', path: '/admin/session', body: { csrf_token: 'csrf-token-1' } }

const USER = {
  id: 'u1',
  name: 'Ada',
  status: 'active',
  key_generation: 1,
  account_count: 2,
  created_at: '2026-01-01T00:00:00Z',
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

function detailValue(wrapper: VueWrapper, label: string): string {
  const pair = wrapper.findAll('.detail__pair').find((p) => p.get('dt').text() === label)
  if (pair === undefined) throw new Error(`detail pair not found: ${label}`)
  return pair.get('dd').text()
}

describe('admin — create user', () => {
  it('shows the one-time key exactly once and forgets it afterwards', async () => {
    const mock = installFetchMock([
      SESSION,
      {
        method: 'POST',
        path: '/admin/users',
        status: 201,
        body: { id: 'u1', name: 'Ada', key_generation: 1, login_key: 'usr_one_time_key' },
      },
    ])

    await go('/admin/users/new')
    const wrapper = mountView(UserCreateView)
    await flushPromises()

    await wrapper.get('#new-user-name').setValue('Ada')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    const keyDisplay = wrapper.findComponent(KeyDisplay)
    expect(keyDisplay.exists()).toBe(true)
    expect(wrapper.get('[data-testid="key-value"]').text()).toBe('usr_one_time_key')
    expect(wrapper.text()).toContain('never be shown again')

    // The plaintext is in no store and in no router state.
    expect(JSON.stringify(sessionState())).not.toContain('usr_one_time_key')
    expect(JSON.stringify(router.currentRoute.value)).not.toContain('usr_one_time_key')

    // "Done" drops the key and moves on to the created user.
    await wrapper.get('.key-display__done').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-testid="key-value"]').exists()).toBe(false)
    expect(router.currentRoute.value.name).toBe('admin-user-detail')
    expect(router.currentRoute.value.params.id).toBe('u1')
    expect(mock.countOf('POST', '/admin/users')).toBe(1)
  })

  it('clears the one-time key when the view unmounts', async () => {
    installFetchMock([
      SESSION,
      {
        method: 'POST',
        path: '/admin/users',
        status: 201,
        body: { id: 'u1', name: 'Ada', key_generation: 1, login_key: 'usr_one_time_key' },
      },
    ])

    await go('/admin/users/new')
    const wrapper = mountView(UserCreateView)
    await flushPromises()

    await wrapper.get('#new-user-name').setValue('Ada')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    const keyDisplay = wrapper.findComponent(KeyDisplay)
    const revealed = (keyDisplay.vm as unknown as { revealed: string }).revealed
    expect(revealed).toBe('usr_one_time_key')

    wrapper.unmount()
    expect((keyDisplay.vm as unknown as { revealed: string }).revealed).toBe('')
  })

  it('renders an error state when the create call fails', async () => {
    installFetchMock([
      SESSION,
      { method: 'POST', path: '/admin/users', status: 400, body: { error: 'invalid_request' } },
    ])

    await go('/admin/users/new')
    const wrapper = mountView(UserCreateView)
    await flushPromises()

    await wrapper.get('#new-user-name').setValue('Ada')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('could not be created')
    expect(wrapper.find('[data-testid="key-value"]').exists()).toBe(false)
  })
})

describe('admin — user detail', () => {
  it('rotates the login key: the new key is shown once and the generation bumps', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'GET', path: '/admin/users/u1', body: USER },
      {
        method: 'POST',
        path: '/admin/users/u1/rotate-key',
        body: { id: 'u1', key_generation: 2, login_key: 'usr_rotated_key' },
      },
    ])

    await go('/admin/users/u1')
    const wrapper = mountView(UserDetailView)
    await flushPromises()

    expect(wrapper.text()).toContain('Ada')
    expect(detailValue(wrapper, 'Key generation')).toBe('1')

    await buttonByText(wrapper, 'Rotate login key').trigger('click')
    await flushPromises()

    expect(wrapper.get('[data-testid="key-value"]').text()).toBe('usr_rotated_key')
    expect(detailValue(wrapper, 'Key generation')).toBe('2')
    expect(mock.countOf('POST', '/admin/users/u1/rotate-key')).toBe(1)

    // The key is not kept anywhere but the one-time display.
    expect(JSON.stringify(sessionState())).not.toContain('usr_rotated_key')
  })

  it('posts the exact status body and reflects the answer', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'GET', path: '/admin/users/u1', body: USER },
      {
        method: 'POST',
        path: '/admin/users/u1/status',
        body: { ...USER, status: 'disabled' },
      },
    ])

    await go('/admin/users/u1')
    const wrapper = mountView(UserDetailView)
    await flushPromises()

    await buttonByText(wrapper, 'Disable user').trigger('click')
    await flushPromises()

    const call = mock.calls.find((c) => c.method === 'POST' && c.url.endsWith('/status'))
    expect(call?.body).toBe('{"status":"disabled"}')
    expect(detailValue(wrapper, 'Status')).toBe('disabled')
  })

  it('deletes only after the exact name is typed into the confirmation dialog', async () => {
    const mock = installFetchMock([
      SESSION,
      { method: 'GET', path: '/admin/users/u1', body: USER },
      { method: 'DELETE', path: '/admin/users/u1', status: 204 },
    ])

    await go('/admin/users/u1')
    const wrapper = mountView(UserDetailView)
    await flushPromises()

    await buttonByText(wrapper, 'Delete user').trigger('click')
    await flushPromises()

    const input = document.querySelector<HTMLInputElement>('#dialog-confirm-input')
    const confirm = document.querySelector<HTMLButtonElement>('.dialog__btn--confirm')
    expect(input).not.toBeNull()
    expect(confirm).not.toBeNull()
    expect(confirm?.disabled).toBe(true)
    expect(mock.countOf('DELETE', '/admin/users/u1')).toBe(0)

    // A wrong name does not unlock the confirmation.
    if (input !== null) {
      input.value = 'ada'
      input.dispatchEvent(new Event('input', { bubbles: true }))
    }
    await nextTick()
    expect(confirm?.disabled).toBe(true)
    expect(mock.countOf('DELETE', '/admin/users/u1')).toBe(0)

    // The exact name does.
    if (input !== null) {
      input.value = 'Ada'
      input.dispatchEvent(new Event('input', { bubbles: true }))
    }
    await nextTick()
    expect(confirm?.disabled).toBe(false)

    confirm?.click()
    await flushPromises()

    expect(mock.countOf('DELETE', '/admin/users/u1')).toBe(1)
    expect(router.currentRoute.value.name).toBe('admin-users')
  })

  it('renders the not-found state for an unknown user', async () => {
    installFetchMock([
      SESSION,
      { method: 'GET', path: '/admin/users/u-missing', status: 404, body: { error: 'not_found' } },
    ])

    await go('/admin/users/u-missing')
    const wrapper = mountView(UserDetailView)
    await flushPromises()

    expect(wrapper.text()).toContain('User not found')
  })
})

describe('admin — user list', () => {
  it('renders every user with its status badge', async () => {
    installFetchMock([
      SESSION,
      {
        method: 'GET',
        path: '/admin/users',
        body: [USER, { ...USER, id: 'u2', name: 'Grace', status: 'disabled' }],
      },
    ])

    await go('/admin/users')
    const wrapper = mountView(UsersView)
    await flushPromises()

    expect(wrapper.text()).toContain('Ada')
    expect(wrapper.text()).toContain('Grace')
    expect(wrapper.text()).toContain('active')
    expect(wrapper.text()).toContain('disabled')
  })

  it('routes to the login view when a call answers 401', async () => {
    installFetchMock([
      SESSION,
      { method: 'GET', path: '/admin/users', status: 401, body: { error: 'unauthorized' } },
    ])

    await go('/admin/users')
    mountView(UsersView)
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('admin-login')
    expect(router.currentRoute.value.query.reason).toBe('expired')
    expect(sessionState().csrfToken).toBeNull()
  })
})

describe('admin — login', () => {
  it('renders one uniform failure message for a wrong key', async () => {
    installFetchMock([
      { method: 'POST', path: '/admin/login', status: 401, body: { error: 'unauthorized' } },
    ])

    await go('/admin/login')
    const wrapper = mountView(LoginView)
    await flushPromises()

    await wrapper.get('#admin-key').setValue('wrong-key')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('Sign-in failed')
    // No cause distinction leaks into the UI.
    expect(wrapper.text()).not.toContain('unauthorized')
    expect(wrapper.text()).not.toContain('invalid_request')
  })

  it('shows the retry countdown for a rate-limited answer', async () => {
    installFetchMock([
      {
        method: 'POST',
        path: '/admin/login',
        status: 429,
        body: { error: 'rate_limited' },
        headers: { 'Retry-After': '30' },
      },
    ])

    await go('/admin/login')
    const wrapper = mountView(LoginView)
    await flushPromises()

    await wrapper.get('#admin-key').setValue('key')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('Try again in')
  })

  it('signs in and moves on to the dashboard', async () => {
    installFetchMock([
      // The mount probe finds no session; the post-login bootstrap does.
      { method: 'GET', path: '/admin/session', status: 401, body: { error: 'unauthorized' }, times: 1 },
      { method: 'POST', path: '/admin/login', body: { status: 'ok' } },
      { method: 'GET', path: '/admin/session', body: { csrf_token: 'csrf-token-1' } },
    ])

    await go('/admin/login')
    const wrapper = mountView(LoginView)
    await flushPromises()

    await wrapper.get('#admin-key').setValue('good-key')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('admin-home')
    expect(sessionState().csrfToken).toBe('csrf-token-1')
  })
})
