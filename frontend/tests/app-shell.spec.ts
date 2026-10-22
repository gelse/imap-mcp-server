import { mount } from '@vue/test-utils'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import AppShell from '@/components/AppShell.vue'

const source = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'components', 'AppShell.vue'),
  'utf8',
)

describe('AppShell', () => {
  it('renders header/nav/main landmarks and the title', () => {
    const wrapper = mount(AppShell, {
      props: { title: 'Admin' },
      slots: { nav: '<a href="/admin/users">Users</a>', default: '<p>Body</p>' },
    })
    expect(wrapper.find('header').exists()).toBe(true)
    expect(wrapper.find('nav[aria-label="Primary"]').exists()).toBe(true)
    expect(wrapper.find('main').exists()).toBe(true)
    expect(wrapper.text()).toContain('Admin')
    expect(wrapper.text()).toContain('Body')
  })

  it('exposes a theme toggle with an accessible label', async () => {
    const wrapper = mount(AppShell, { props: { title: 'Admin' } })
    const toggle = wrapper.get('.shell__theme-toggle')
    expect(toggle.attributes('aria-label')).toBeTruthy()
    await toggle.trigger('click')
    // Toggling flips data-theme on <html>.
    expect(['light', 'dark']).toContain(document.documentElement.getAttribute('data-theme'))
  })

  it('actually flips data-theme on each click and persists it', async () => {
    localStorage.clear()
    document.documentElement.removeAttribute('data-theme')
    const wrapper = mount(AppShell, { props: { title: 'Admin' } })
    const toggle = wrapper.get('.shell__theme-toggle')

    await toggle.trigger('click')
    const first = document.documentElement.getAttribute('data-theme')
    expect(first).toBeTruthy()

    await toggle.trigger('click')
    const second = document.documentElement.getAttribute('data-theme')
    expect(second).not.toBe(first)
    expect(new Set([first, second])).toEqual(new Set(['light', 'dark']))
    expect(localStorage.getItem('imapgw.theme')).toBe(second)
  })

  it('renders the actions slot next to the toggle', () => {
    const wrapper = mount(AppShell, {
      props: { title: 'Admin' },
      slots: { actions: '<button>Sign out</button>' },
    })
    expect(wrapper.get('.shell__actions').text()).toContain('Sign out')
  })

  it('collapses the nav under the mobile breakpoint via CSS media query only', () => {
    // No JS toggling library: the compact strip is a max-width media query.
    expect(source).toMatch(/@media \(max-width: \d+px\)/)
    expect(source).toMatch(/grid-template-columns:\s*1fr/)
    expect(source).not.toMatch(/window\.matchMedia|addEventListener\('resize'/)
  })

  it('renders inline SVG icons in the theme toggle (no emoji, no icon fonts)', () => {
    const wrapper = mount(AppShell, { props: { title: 'Admin' } })
    const toggle = wrapper.get('.shell__theme-toggle')
    expect(toggle.find('svg').exists()).toBe(true)
    expect(toggle.text()).not.toMatch(/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u)
  })
})
