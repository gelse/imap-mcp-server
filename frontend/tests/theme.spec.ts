import { beforeEach, describe, expect, it } from 'vitest'
import {
  applyTheme,
  initTheme,
  persistPreference,
  readStoredPreference,
  resolveTheme,
  THEME_STORAGE_KEY,
  type ThemePreference,
} from '@/lib/theme'

function fakeStorage(initial: Record<string, string> = {}): Storage {
  const map = new Map(Object.entries(initial))
  return {
    get length() {
      return map.size
    },
    clear: () => map.clear(),
    getItem: (k: string) => (map.has(k) ? map.get(k)! : null),
    key: (i: number) => Array.from(map.keys())[i] ?? null,
    removeItem: (k: string) => void map.delete(k),
    setItem: (k: string, v: string) => void map.set(k, v),
  }
}

function fakeWindow(prefersDark: boolean): Window {
  return {
    matchMedia: (q: string) => ({ matches: prefersDark && q.includes('dark') }),
  } as unknown as Window
}

describe('theme resolution', () => {
  it('explicit preference wins over the OS scheme', () => {
    expect(resolveTheme('light', true)).toBe('light')
    expect(resolveTheme('dark', false)).toBe('dark')
  })

  it('system defers to prefers-color-scheme', () => {
    expect(resolveTheme('system', true)).toBe('dark')
    expect(resolveTheme('system', false)).toBe('light')
  })
})

describe('theme persistence', () => {
  let storage: Storage
  beforeEach(() => {
    storage = fakeStorage()
  })

  it('round-trips an explicit preference under the single storage key', () => {
    persistPreference('dark', storage)
    expect(storage.getItem(THEME_STORAGE_KEY)).toBe('dark')
    expect(readStoredPreference(storage)).toBe('dark')
    expect(storage.length).toBe(1)
  })

  it('stores nothing for system (removes the key)', () => {
    persistPreference('dark', storage)
    persistPreference('system', storage)
    expect(storage.getItem(THEME_STORAGE_KEY)).toBeNull()
    expect(readStoredPreference(storage)).toBe('system')
    expect(storage.length).toBe(0)
  })

  it('ignores unknown persisted values', () => {
    const s = fakeStorage({ [THEME_STORAGE_KEY]: 'chartreuse' })
    expect(readStoredPreference(s)).toBe('system')
  })

  it('only ever touches the theme key — no other storage use', () => {
    persistPreference('light', storage)
    const keys: string[] = []
    for (let i = 0; i < storage.length; i++) keys.push(storage.key(i)!)
    expect(keys).toEqual([THEME_STORAGE_KEY])
  })
})

describe('theme application', () => {
  it('stamps data-theme on the root element for explicit themes', () => {
    const root = document.createElement('div')
    applyTheme('dark', root)
    expect(root.getAttribute('data-theme')).toBe('dark')
    applyTheme('light', root)
    expect(root.getAttribute('data-theme')).toBe('light')
  })

  it('removes data-theme for the system preference so the media query governs', () => {
    const root = document.createElement('div')
    applyTheme('dark', root)
    applyTheme('system', root)
    expect(root.hasAttribute('data-theme')).toBe(false)
  })

  it('initTheme resolves, applies and returns the preference', () => {
    const root = document.createElement('div')
    const storage = fakeStorage({ [THEME_STORAGE_KEY]: 'dark' })
    const result = initTheme(root, storage, fakeWindow(false))
    expect(result).toEqual<{ preference: ThemePreference; theme: 'dark' }>({
      preference: 'dark',
      theme: 'dark',
    })
    expect(root.getAttribute('data-theme')).toBe('dark')
  })

  it('initTheme with system leaves data-theme unset and reports the OS theme', () => {
    const root = document.createElement('div')
    const result = initTheme(root, fakeStorage(), fakeWindow(true))
    expect(result.preference).toBe('system')
    expect(result.theme).toBe('dark')
    // No stamp: the prefers-color-scheme rule keeps governing live OS changes.
    expect(root.hasAttribute('data-theme')).toBe(false)
  })

  it('survives unavailable storage', () => {
    const storage = {
      getItem: () => {
        throw new Error('denied')
      },
      setItem: () => {
        throw new Error('denied')
      },
      removeItem: () => {
        throw new Error('denied')
      },
    } as unknown as Storage
    expect(readStoredPreference(storage)).toBe('system')
    expect(() => persistPreference('dark', storage)).not.toThrow()
  })

  it('prefersDarkScheme handles a window without matchMedia', () => {
    const win = {} as unknown as Window
    expect(initTheme(document.createElement('div'), fakeStorage(), win).theme).toBe('light')
  })
})
