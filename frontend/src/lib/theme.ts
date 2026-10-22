/**
 * Theme preference — resolve, apply, persist.
 *
 * The ONLY browser storage this application uses is the theme preference under
 * localStorage key "imapgw.theme" (see M07 design). No tokens, no secrets, no
 * session data ever touch storage.
 *
 * CSP note: script-src is 'self', so theme resolution is NOT bootstrapped by an
 * inline script. `initTheme()` runs from main.ts before mount. This can produce
 * a brief flash when the persisted choice disagrees with the OS preference; that
 * is accepted (documented compromise) rather than weakening the CSP.
 */

export type Theme = 'light' | 'dark'
export type ThemePreference = Theme | 'system'

export const THEME_STORAGE_KEY = 'imapgw.theme'

/** Round-trip only for the theme preference; nothing else is stored. */
export function readStoredPreference(storage?: Storage): ThemePreference {
  const store = storage ?? defaultStorage()
  if (!store) return 'system'
  try {
    const raw = store.getItem(THEME_STORAGE_KEY)
    if (raw === 'light' || raw === 'dark') return raw
    return 'system'
  } catch {
    return 'system'
  }
}

export function persistPreference(pref: ThemePreference, storage?: Storage): void {
  const store = storage ?? defaultStorage()
  if (!store) return
  try {
    if (pref === 'system') {
      store.removeItem(THEME_STORAGE_KEY)
    } else {
      store.setItem(THEME_STORAGE_KEY, pref)
    }
  } catch {
    /* Storage can be unavailable (private mode); preference is then session-only. */
  }
}

/**
 * Resolve the effective theme. An explicit preference wins; "system" defers to
 * the prefers-color-scheme media query.
 */
export function resolveTheme(pref: ThemePreference, prefersDark: boolean): Theme {
  if (pref === 'light' || pref === 'dark') return pref
  return prefersDark ? 'dark' : 'light'
}

/** Read prefers-color-scheme if a window/matchMedia is available. */
export function prefersDarkScheme(win?: Window): boolean {
  const w = win ?? defaultWindow()
  if (!w || typeof w.matchMedia !== 'function') return false
  return w.matchMedia('(prefers-color-scheme: dark)').matches
}

/**
 * Apply a theme preference to a root element. Explicit preferences stamp
 * data-theme so themes.css selects the matching palette; "system" removes the
 * attribute so the prefers-color-scheme media query stays in charge and the
 * page continues to follow live OS theme changes.
 */
export function applyTheme(preference: ThemePreference, root?: HTMLElement): void {
  const el = root ?? defaultRoot()
  if (!el) return
  if (preference === 'system') {
    el.removeAttribute('data-theme')
  } else {
    el.setAttribute('data-theme', preference)
  }
}

/**
 * One-shot bootstrap called from main.ts: resolve from storage + OS, apply the
 * stored preference, and return both the preference and the resolved theme.
 * Applying the *preference* (not the resolved theme) keeps the
 * prefers-color-scheme fallback live for "system" users.
 */
export function initTheme(
  root?: HTMLElement,
  storage?: Storage,
  win?: Window,
): { preference: ThemePreference; theme: Theme } {
  const preference = readStoredPreference(storage)
  const theme = resolveTheme(preference, prefersDarkScheme(win))
  applyTheme(preference, root)
  return { preference, theme }
}

function defaultStorage(): Storage | undefined {
  try {
    return typeof localStorage !== 'undefined' ? localStorage : undefined
  } catch {
    return undefined
  }
}

function defaultWindow(): Window | undefined {
  return typeof window !== 'undefined' ? window : undefined
}

function defaultRoot(): HTMLElement | undefined {
  return typeof document !== 'undefined' ? document.documentElement : undefined
}
