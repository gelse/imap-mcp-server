import { mount } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import KeyDisplay from '@/components/KeyDisplay.vue'

/**
 * KeyDisplay tests: warning is always shown, the value is select-all, copy uses
 * the fallback when navigator.clipboard is absent, and the secret is cleared
 * from memory on unmount.
 */

const SECRET = 'usr_' + 'Z'.repeat(43)

const source = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'components', 'KeyDisplay.vue'),
  'utf8',
)

beforeEach(() => {
  vi.restoreAllMocks()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('KeyDisplay', () => {
  it('renders the one-time warning and the secret', () => {
    const wrapper = mount(KeyDisplay, { props: { value: SECRET } })
    expect(wrapper.text()).toContain('never be shown again')
    expect(wrapper.get('[data-testid="key-value"]').text()).toBe(SECRET)
  })

  it('exposes a warning slot while always rendering the warning region', () => {
    const wrapper = mount(KeyDisplay, {
      props: { value: SECRET },
      slots: { warning: 'Custom one-time warning' },
    })
    expect(wrapper.get('.key-display__warning').text()).toBe('Custom one-time warning')
  })

  it('marks the value selectable with user-select: all plus the -webkit- fallback', () => {
    const wrapper = mount(KeyDisplay, { props: { value: SECRET } })
    expect(wrapper.get('[data-testid="key-value"]').classes()).toContain('key-display__value')
    // The CSS contract lives in the SFC's style block (classes only, no inline
    // styles under strict CSP style-src 'self').
    expect(source).toMatch(/user-select:\s*all/)
    expect(source).toMatch(/-webkit-user-select:\s*all/)
  })

  it('copies via the async clipboard API when available', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    const wrapper = mount(KeyDisplay, { props: { value: SECRET } })
    await wrapper.get('.key-display__copy').trigger('click')
    await Promise.resolve()
    await wrapper.vm.$nextTick()
    expect(writeText).toHaveBeenCalledWith(SECRET)
    expect(wrapper.text()).toContain('Copied')
    expect(wrapper.emitted('copied')).toBeTruthy()
  })

  it('falls back to execCommand when navigator.clipboard is absent', async () => {
    vi.stubGlobal('navigator', {})
    const execCommand = vi.fn().mockReturnValue(true)
    document.execCommand = execCommand

    const wrapper = mount(KeyDisplay, { props: { value: SECRET } })
    await wrapper.get('.key-display__copy').trigger('click')
    await Promise.resolve()
    await Promise.resolve()
    await wrapper.vm.$nextTick()

    expect(execCommand).toHaveBeenCalledWith('copy')
    expect(wrapper.text()).toContain('Copied')
  })

  it('reports a failure when neither path can copy', async () => {
    vi.stubGlobal('navigator', {})
    document.execCommand = vi.fn().mockReturnValue(false)
    const wrapper = mount(KeyDisplay, { props: { value: SECRET } })
    await wrapper.get('.key-display__copy').trigger('click')
    await Promise.resolve()
    await Promise.resolve()
    await wrapper.vm.$nextTick()
    expect(wrapper.text()).toContain('Copy failed')
  })

  it('clears the secret from memory on unmount', () => {
    const wrapper = mount(KeyDisplay, { props: { value: SECRET } })
    expect((wrapper.vm as unknown as { revealed: string }).revealed).toBe(SECRET)
    wrapper.unmount()
    expect((wrapper.vm as unknown as { revealed: string }).revealed).toBe('')
  })

  it('emits done and clears the secret when done is clicked', async () => {
    const wrapper = mount(KeyDisplay, { props: { value: SECRET } })
    await wrapper.get('.key-display__done').trigger('click')
    expect(wrapper.emitted('done')).toBeTruthy()
    expect((wrapper.vm as unknown as { revealed: string }).revealed).toBe('')
  })

  it('never persists or logs the secret', async () => {
    const setItem = vi.spyOn(Storage.prototype, 'setItem')
    const logSpy = vi.spyOn(console, 'log').mockImplementation(() => {})
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {})

    const wrapper = mount(KeyDisplay, { props: { value: SECRET } })
    await wrapper.get('.key-display__copy').trigger('click')
    await wrapper.get('.key-display__done').trigger('click')

    expect(setItem).not.toHaveBeenCalled()
    for (const spy of [logSpy, errorSpy, warnSpy]) {
      for (const call of spy.mock.calls) {
        expect(JSON.stringify(call)).not.toContain(SECRET)
      }
    }
  })
})
