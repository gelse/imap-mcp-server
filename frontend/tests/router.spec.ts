import { flushPromises, mount } from '@vue/test-utils'
import { createMemoryHistory } from 'vue-router'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createAppRouter } from '@/router'
import { forget } from '@/lib/session'
import { installFetchMock } from './helpers/fetch-mock'

/**
 * Router specs: the section prefixes, the session guard and the shared
 * not-found route.
 */

const SESSION = { method: 'GET', path: '/admin/session', body: { csrf_token: 'csrf-token-1' } }
const USER_SESSION = { method: 'GET', path: '/me/session', body: { csrf_token: 'csrf-token-2' } }

beforeEach(() => {
  forget()
})

afterEach(() => {
  vi.unstubAllGlobals()
  forget()
})

describe('router', () => {
  it('redirects the root to the admin dashboard', async () => {
    const router = createAppRouter(createMemoryHistory())
    installFetchMock([SESSION])

    await router.push('/')
    await router.isReady()
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('admin-home')
  })

  it('sends a visitor without a session to the login view', async () => {
    const router = createAppRouter(createMemoryHistory())
    installFetchMock([
      { method: 'GET', path: '/admin/session', status: 401, body: { error: 'unauthorized' } },
    ])

    await router.push('/admin/users')
    await router.isReady()
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('admin-login')
    expect(router.currentRoute.value.query.reason).toBe('required')
  })

  it('renders the shared not-found view for an unknown admin route', async () => {
    const router = createAppRouter(createMemoryHistory())
    installFetchMock([SESSION])

    await router.push('/admin/does-not-exist')
    await router.isReady()
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('admin-not-found')

    const wrapper = mount(router.currentRoute.value.matched[0]!.components!.default as never, {
      global: { plugins: [router] },
    })
    expect(wrapper.text()).toContain('Page not found')
    wrapper.unmount()
  })

  it('sends a visitor without a user session to the user login view', async () => {
    const router = createAppRouter(createMemoryHistory())
    installFetchMock([
      { method: 'GET', path: '/me/session', status: 401, body: { error: 'unauthorized' } },
    ])

    await router.push('/user')
    await router.isReady()
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('user-login')
    expect(router.currentRoute.value.query.reason).toBe('required')
  })

  it('lets a user deep link through once the session is bootstrapped', async () => {
    const router = createAppRouter(createMemoryHistory())
    installFetchMock([USER_SESSION])

    await router.push('/user/accounts/new')
    await router.isReady()
    await flushPromises()

    expect(router.currentRoute.value.name).toBe('user-account-add')
  })
})
