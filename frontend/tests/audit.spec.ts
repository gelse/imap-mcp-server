import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
// eslint-disable-next-line import/extensions -- Node ESM script has no extension-less resolution
import {
  auditDist,
  findInlineScriptHits,
  isSecretBearingFile,
  scanTextForExternal,
  scanTextForSecrets,
  walkFiles,
} from '@audit'

/**
 * Audit-script tests. The critical one proves the detector actually fails the
 * build when a synthetic secret artifact appears in src — mirroring the
 * backend's test_leak_sweep_detectors_catch_every_real_secret_artifact.
 */

const SYNTHETIC_USER_TOKEN = 'usr_' + 'A'.repeat(43)
const SYNTHETIC_ADMIN_TOKEN = 'adm_' + 'B'.repeat(43)
const SYNTHETIC_HEX64 = 'f'.repeat(64)

describe('secret detectors', () => {
  it('catches every real secret artifact shape', () => {
    expect(scanTextForSecrets(SYNTHETIC_USER_TOKEN)).toContain('user-token')
    expect(scanTextForSecrets(SYNTHETIC_ADMIN_TOKEN)).toContain('admin-token')
    expect(scanTextForSecrets(SYNTHETIC_HEX64)).toContain('hex64')
    expect(scanTextForSecrets('scrypt$abc$def')).toContain('scrypt')
    expect(scanTextForSecrets('{"login_key_hash":"x"}')).toContain('login_key_hash')
    expect(scanTextForSecrets('{"aek":"..."}')).toContain('aek-literal')
  })

  it('does not false-positive on innocent substrings', () => {
    expect(scanTextForSecrets('this is a weak break of the week')).toEqual([])
    expect(scanTextForSecrets('https://example.com/not-a-secret')).not.toContain('hex64')
  })

  it('flags hex runs of 64 or more, in either case', () => {
    expect(scanTextForSecrets('a'.repeat(65))).toContain('hex64')
    expect(scanTextForSecrets('f'.repeat(64))).toContain('hex64')
    expect(scanTextForSecrets('ABCDEF01'.repeat(8))).toContain('hex64')
    expect(scanTextForSecrets('a'.repeat(63))).not.toContain('hex64')
  })
})

describe('external-reference detectors', () => {
  it('flags protocol URLs, protocol-relative and cdn references', () => {
    expect(scanTextForExternal('x https://evil.example y')).toContain('protocol-url')
    expect(scanTextForExternal('(//cdn.example.com/a.js)')).toContain('protocol-relative')
    expect(scanTextForExternal('//cdn/js')).toContain('cdn')
  })

  it('is case-insensitive so upper-case schemes cannot evade the gate', () => {
    expect(scanTextForExternal('src=HTTP://cdn.example/x.js')).toContain('protocol-url')
    expect(scanTextForExternal('src=HTTPS://cdn.example/x.js')).toContain('protocol-url')
    expect(scanTextForExternal('//CDN.example/x.js')).toContain('cdn')
  })

  it('passes clean local asset references', () => {
    expect(scanTextForExternal('/assets/index-abc123.js')).toEqual([])
  })

  it('ignores inert XML-namespace and Vue-error-reference literals', () => {
    expect(scanTextForExternal("<rect xmlns='http://www.w3.org/2000/svg'/>")).toEqual([])
    expect(scanTextForExternal('https://vuejs.org/error-reference/#runtime-x')).toEqual([])
    expect(scanTextForExternal('http://www.w3.org/1998/Math/MathML')).toEqual([])
  })

  it('still flags a genuine external URL alongside an inert literal', () => {
    const text = "xmlns='http://www.w3.org/2000/svg' import 'https://evil.example/x.js'"
    expect(scanTextForExternal(text)).toContain('protocol-url')
  })
})

describe('inline-script detectors', () => {
  it('flags a script with a body and no src', () => {
    expect(findInlineScriptHits('<script>var a=1</script>').length).toBeGreaterThan(0)
  })

  it('allows a src-referenced script', () => {
    expect(findInlineScriptHits('<script type="module" src="/assets/index.js"></script>')).toEqual(
      [],
    )
  })

  it('flags inline on* handlers', () => {
    expect(findInlineScriptHits('<button onclick="go()">x</button>').length).toBeGreaterThan(0)
  })

  it('flags on* handlers regardless of attribute-name case', () => {
    expect(findInlineScriptHits('<input onFocus="x()">').length).toBeGreaterThan(0)
    expect(findInlineScriptHits('<body onLoad="x()">').length).toBeGreaterThan(0)
    expect(findInlineScriptHits('<img onClick="x()">').length).toBeGreaterThan(0)
  })
})

describe('auditDist end to end', () => {
  let root: string
  let dist: string
  let src: string

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'audit-'))
    dist = join(root, 'dist')
    src = join(root, 'src')
    mkdirSync(dist)
    mkdirSync(src)
    writeFileSync(
      join(dist, 'index.html'),
      '<!doctype html><html><head><title>t</title></head><body><div id="app"></div><script type="module" src="/assets/app.js"></script></body></html>',
    )
    mkdirSync(join(dist, 'assets'))
    writeFileSync(join(dist, 'assets', 'app.js'), 'console.log("clean")')
  })

  afterEach(() => {
    rmSync(root, { recursive: true, force: true })
  })

  it('passes on a clean dist', () => {
    const result = auditDist(dist, src)
    expect(result.ok, result.errors.join('; ')).toBe(true)
  })

  it('FAILS when a synthetic secret fixture is placed in src', () => {
    // A token-shaped string in a source file must fail the build.
    writeFileSync(join(src, 'leak.ts'), `export const t = '${SYNTHETIC_USER_TOKEN}'`)
    const result = auditDist(dist, src)
    expect(result.ok).toBe(false)
    expect(result.errors.join(' ')).toContain('user-token')
    expect(result.errors.join(' ')).toContain('src/leak.ts')
  })

  it('FAILS on a 64-hex fixture placed in src', () => {
    writeFileSync(join(src, 'hex.ts'), `export const h = '${SYNTHETIC_HEX64}'`)
    const result = auditDist(dist, src)
    expect(result.ok).toBe(false)
    expect(result.errors.join(' ')).toContain('hex64')
  })

  it('refuses a secret-bearing .env placed in src by name', () => {
    writeFileSync(join(src, '.env'), 'SECRET=1')
    const result = auditDist(dist, src)
    expect(result.ok).toBe(false)
    expect(result.errors.join(' ')).toContain('.env')
  })

  it('FAILS when the dist bundle carries secret-shaped material', () => {
    writeFileSync(
      join(dist, 'assets', 'app.js'),
      `export const key = '${SYNTHETIC_USER_TOKEN}';`,
    )
    const result = auditDist(dist, src)
    expect(result.ok).toBe(false)
    expect(result.errors.join(' ')).toContain('user-token')
  })

  it('FAILS when the dist bundle references an external URL', () => {
    writeFileSync(
      join(dist, 'assets', 'app.js'),
      `import 'https://cdn.example.com/lib.js';`,
    )
    const result = auditDist(dist, src)
    expect(result.ok).toBe(false)
    expect(result.errors.join(' ')).toContain('external reference')
  })

  it('FAILS when index.html contains an inline script', () => {
    writeFileSync(
      join(dist, 'index.html'),
      '<!doctype html><html><body><script>window.x=1</script></body></html>',
    )
    const result = auditDist(dist, src)
    expect(result.ok).toBe(false)
    expect(result.errors.join(' ')).toContain('inline <script>')
  })

  it('refuses secret-bearing files by name', () => {
    expect(isSecretBearingFile('/x/.env.production')).toBe(true)
    expect(isSecretBearingFile('/x/server.key')).toBe(true)
    expect(isSecretBearingFile('/x/main.ts')).toBe(false)
  })
})

describe('audit against the real repository tree', () => {
  // Guards the shipped source, not a hand-written fixture: every real file
  // under frontend/src must pass both the secret and external-reference scans.
  const realSrc = join(process.cwd(), 'src')

  it('finds no secret-shaped material in any real src file', () => {
    const offenders: string[] = []
    for (const file of walkFiles(realSrc)) {
      const text = readFileSync(file, 'utf8')
      for (const hit of scanTextForSecrets(text)) {
        offenders.push(`${file}: ${hit}`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('finds no external network references in any real src file', () => {
    const offenders: string[] = []
    for (const file of walkFiles(realSrc)) {
      const text = readFileSync(file, 'utf8')
      for (const hit of scanTextForExternal(text)) {
        offenders.push(`${file}: ${hit}`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('finds no inline style attributes in any component (strict CSP style-src)', () => {
    // Classes + CSS custom properties only; :style="..." would compile to an
    // inline style attribute and break CSP style-src 'self'.
    const offenders: string[] = []
    for (const file of walkFiles(realSrc)) {
      if (!file.endsWith('.vue')) continue
      const text = readFileSync(file, 'utf8')
      if (/\sstyle\s*=/.test(text)) offenders.push(file)
    }
    expect(offenders).toEqual([])
  })

  it('finds no emoji used as UI chrome in any component', () => {
    const offenders: string[] = []
    const emoji = /[\u{1F300}-\u{1FAFF}\u{2190}-\u{21FF}\u{2300}-\u{23FF}\u{25A0}-\u{27BF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/u
    for (const file of walkFiles(realSrc)) {
      if (!file.endsWith('.vue')) continue
      const text = readFileSync(file, 'utf8')
      // Strip comments first: em-dashes in docblocks are prose, not UI chrome.
      const code = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/<!--[\s\S]*?-->/g, '')
      if (emoji.test(code)) offenders.push(file)
    }
    expect(offenders).toEqual([])
  })
})
