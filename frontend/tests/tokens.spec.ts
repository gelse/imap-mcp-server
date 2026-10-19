import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { describe, expect, it } from 'vitest'

/**
 * Token + theme contrast tests.
 *
 * We parse the actual token stylesheets and assert that every text/surface pair
 * meets WCAG 2.x 4.5:1 (normal text) in BOTH themes, using the relative
 * luminance formula. This is the accessibility contract the milestone requires.
 */

const here = dirname(fileURLToPath(import.meta.url))
const stylesDir = join(here, '..', 'src', 'styles')

function parseVars(css: string): Record<string, string> {
  const vars: Record<string, string> = {}
  const re = /--([a-z0-9-]+)\s*:\s*([^;]+);/gi
  let m
  while ((m = re.exec(css)) !== null) {
    const name = m[1]
    const value = m[2]
    if (name && value) vars[`--${name}`] = value.trim()
  }
  return vars
}

function extractBlock(css: string, selector: string): string {
  const idx = css.indexOf(selector)
  if (idx === -1) return ''
  const open = css.indexOf('{', idx)
  const close = css.indexOf('}', open)
  return css.slice(open + 1, close)
}

function hexToRgb(hex: string): [number, number, number] {
  const h = hex.trim().replace('#', '')
  const full = h.length === 3 ? h.split('').map((c) => c + c).join('') : h
  return [
    parseInt(full.slice(0, 2), 16),
    parseInt(full.slice(2, 4), 16),
    parseInt(full.slice(4, 6), 16),
  ]
}

function luminance(hex: string): number {
  const [r, g, b] = hexToRgb(hex).map((v) => {
    const s = v / 255
    return s <= 0.03928 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4)
  }) as [number, number, number]
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function contrast(a: string, b: string): number {
  const la = luminance(a)
  const lb = luminance(b)
  const [hi, lo] = la > lb ? [la, lb] : [lb, la]
  return (hi + 0.05) / (lo + 0.05)
}

const tokensCss = readFileSync(join(stylesDir, 'tokens.css'), 'utf8')
const themesCss = readFileSync(join(stylesDir, 'themes.css'), 'utf8')

// Light theme: :root block in themes.css (the first plain :root rule).
const lightBlock = extractBlock(themesCss, ':root {')
const darkBlock = extractBlock(themesCss, "[data-theme='dark'] {")

const light = parseVars(lightBlock)
const dark = parseVars(darkBlock)
const tokens = parseVars(tokensCss)

describe('design tokens', () => {
  it('defines the full spacing ramp and radii/shadows', () => {
    for (let i = 1; i <= 8; i++) expect(tokens[`--space-${i}`]).toBeDefined()
    expect(tokens['--radius-sm']).toBeDefined()
    expect(tokens['--radius-md']).toBeDefined()
    expect(tokens['--radius-lg']).toBeDefined()
    expect(tokens['--shadow-1']).toBeDefined()
    expect(tokens['--shadow-2']).toBeDefined()
  })

  it('defines the typography scale and system font stacks only', () => {
    for (const t of ['--text-xs', '--text-sm', '--text-base', '--text-lg', '--text-xl']) {
      expect(tokens[t]).toBeDefined()
    }
    expect(tokens['--font-sans']).toContain('system-ui')
    expect(tokens['--font-mono']).toContain('ui-monospace')
    // No bundled/remote fonts: no url()/@font-face anywhere in tokens.
    expect(tokens['--font-sans']).not.toMatch(/url\(/)
    expect(tokens['--font-mono']).not.toMatch(/url\(/)
  })

  it('defines a focus ring token (never outline:none without replacement)', () => {
    expect(tokens['--focus-ring']).toBeDefined()
    expect(tokens['--focus-ring']).toMatch(/solid/)
  })
})

describe.each([
  ['light', light],
  ['dark', dark],
])('%s theme contrast (WCAG 4.5:1)', (_name, theme) => {
  const pairs: Array<[string, string, string]> = [
    ['text on bg', '--color-text', '--color-bg'],
    ['text on surface', '--color-text', '--color-surface'],
    ['text on surface-alt', '--color-text', '--color-surface-alt'],
    ['muted on surface', '--color-muted', '--color-surface'],
    ['muted on bg', '--color-muted', '--color-bg'],
    ['on-primary on primary', '--color-on-primary', '--color-primary'],
    ['on-danger on danger', '--color-on-danger', '--color-danger'],
    ['success on surface', '--color-success', '--color-surface'],
    ['warning on surface', '--color-warning', '--color-surface'],
    ['danger on surface', '--color-danger', '--color-surface'],
    // Badge status text sits on its own tinted background, not the plain
    // surface — assert those exact pairings too.
    ['success on success-bg', '--color-success', '--color-success-bg'],
    ['warning on warning-bg', '--color-warning', '--color-warning-bg'],
    ['danger on danger-bg', '--color-danger', '--color-danger-bg'],
    ['primary on info-bg', '--color-primary', '--color-info-bg'],
  ]

  it.each(pairs)('%s >= 4.5', (_label, fg, bg) => {
    const fgVal = theme[fg]
    const bgVal = theme[bg]
    expect(fgVal, `${fg} missing`).toBeDefined()
    expect(bgVal, `${bg} missing`).toBeDefined()
    const ratio = contrast(fgVal!, bgVal!)
    expect(ratio, `${fg}=${fgVal} on ${bg}=${bgVal} => ${ratio.toFixed(2)}`).toBeGreaterThanOrEqual(4.5)
  })
})
