#!/usr/bin/env node
/**
 * Build-time audit for frontend/dist.
 *
 * Runs as the final leg of `npm run build`. Non-zero exit on ANY hit. It is
 * deliberately dependency-free and also exported as functions so Vitest can
 * exercise the detectors directly (see tests/audit.spec.ts).
 *
 * Three classes of check:
 *  1. Secret-shaped material anywhere in dist/ (token prefixes, 64-hex runs,
 *     scrypt markers, "aek" string-literal markers).
 *  2. External references + inline scripts/handlers in index.html and every
 *     emitted .js/.css — the CSP `script-src 'self'` / no-CDN contract.
 *  3. Secret-bearing FILES anywhere under src/ at build time (.env*, *.key).
 */

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'

// --- detectors -------------------------------------------------------------

/**
 * Secret-shaped patterns. Each is a real marker the backend emits; none of them
 * belongs in a client bundle.
 */
export const SECRET_PATTERNS = [
  { name: 'user-token', re: /usr_[A-Za-z0-9_-]{43}/ },
  { name: 'admin-token', re: /adm_[A-Za-z0-9_-]{43}/ },
  // 64-or-more hex chars, case-insensitive, matching the backend redactor's
  // contract (a run LONGER than 64 is still key material). Lookarounds stop
  // matches inside a longer alphanumeric run from being mis-anchored.
  { name: 'hex64', re: /(?<![0-9A-Fa-f])[0-9A-Fa-f]{64,}(?![0-9A-Fa-f])/ },
  { name: 'scrypt', re: /scrypt\$/ },
  { name: 'login_key_hash', re: /login_key_hash/ },
  // String-literal "aek" markers only — a bare substring like "weak"/"break"
  // must NOT match. We look for quoted occurrences of the exact token.
  { name: 'aek-literal', re: /["']aek["']/ },
]

/**
 * External-reference patterns applied to index.html and .js/.css bundles.
 * `https://` / `http://` are allowed in comments only when they name an
 * obviously non-network string, but to stay strict we flag every occurrence and
 * keep intentional URLs out of shipped source.
 */
export const EXTERNAL_PATTERNS = [
  { name: 'protocol-url', re: /https?:\/\//i },
  { name: 'protocol-relative', re: /(?:^|["'(=\s])\/\/[a-zA-Z0-9]/i },
  { name: 'cdn', re: /\/\/cdn/i },
]

/**
 * Allow-list of known-INERT absolute-URL literals. These never cause a network
 * request: they are XML namespace identifiers and the Vue.js error-reference
 * string that Vue's own production bundle embeds. They are matched here — and
 * only here — so the strict `protocol-url` rule above still flags any other
 * absolute URL a future change might introduce.
 *
 *   - http://www.w3.org/2000/svg       XML namespace (SVG)
 *   - http://www.w3.org/1998/Math/MathML  XML namespace (MathML)
 *   - http://www.w3.org/1999/xlink     XML namespace (xlink)
 *   - https://vuejs.org/error-reference/  Vue production warning string
 */
export const INERT_URL_ALLOWLIST = [
  'http://www.w3.org/2000/svg',
  'http://www.w3.org/1998/Math/MathML',
  'http://www.w3.org/1999/xlink',
  'https://vuejs.org/error-reference/',
]

function stripAllowlistedUrls(text) {
  let out = text
  for (const allowed of INERT_URL_ALLOWLIST) {
    out = out.split(allowed).join('')
  }
  return out
}

/** Inline <script> bodies and inline on*= handlers in HTML. */
export function findInlineScriptHits(html) {
  const hits = []
  // <script ...>BODY</script> where BODY is non-empty and there is no src attr.
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi
  let m
  while ((m = scriptRe.exec(html)) !== null) {
    const attrs = m[1] ?? ''
    const body = (m[2] ?? '').trim()
    if (body.length > 0 && !/\bsrc\s*=/.test(attrs)) {
      hits.push('inline <script> body (no src)')
    }
  }
  // Inline event handlers on tags.
  const handlerRe = /\son[a-z]+\s*=\s*["']/gi
  if (handlerRe.test(html)) hits.push('inline on*= event handler')
  return hits
}

export function scanTextForSecrets(text) {
  const hits = []
  for (const { name, re } of SECRET_PATTERNS) {
    if (re.test(text)) hits.push(name)
  }
  return hits
}

export function scanTextForExternal(text) {
  const hits = []
  const scrubbed = stripAllowlistedUrls(text)
  for (const { name, re } of EXTERNAL_PATTERNS) {
    if (re.test(scrubbed)) hits.push(name)
  }
  return hits
}

const SKIP_DIRS = new Set(['node_modules', '.git'])

export function walkFiles(root, { skipDirs = SKIP_DIRS } = {}) {
  const out = []
  const visit = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue
        visit(join(dir, entry.name))
      } else if (entry.isFile()) {
        out.push(join(dir, entry.name))
      }
    }
  }
  visit(root)
  return out
}

const TEXT_EXT = /\.(js|mjs|cjs|ts|vue|css|html|json|txt|svg|map)$/i

export function isTextFile(path) {
  return TEXT_EXT.test(path)
}

/** Files that look secret-bearing and must never be built. */
export function isSecretBearingFile(path) {
  const base = path.split('/').pop() ?? path
  return (
    /^\.env/.test(base) || base.endsWith('.key') || base.endsWith('.pem') || base.endsWith('.p12')
  )
}

// --- orchestration ---------------------------------------------------------

/**
 * Audit `distDir` and `srcDir`. Returns { ok, errors, checked }.
 * Pure with respect to the filesystem except for reads.
 */
export function auditDist(distDir, srcDir) {
  const errors = []

  let distFiles
  try {
    distFiles = walkFiles(distDir)
  } catch (err) {
    return { ok: false, errors: [`dist directory not found or unreadable: ${distDir}`], checked: 0 }
  }

  const indexHtml = join(distDir, 'index.html')
  let htmlSeen = false

  for (const file of distFiles) {
    const rel = relative(distDir, file)
    if (!isTextFile(file)) continue
    let text
    try {
      text = readFileSync(file, 'utf8')
    } catch {
      continue
    }

    for (const hit of scanTextForSecrets(text)) {
      errors.push(`secret-shaped material (${hit}) in dist/${rel}`)
    }

    if (rel === 'index.html') {
      htmlSeen = true
      for (const hit of findInlineScriptHits(text)) {
        errors.push(`violation in dist/index.html: ${hit}`)
      }
    }

    if (rel.endsWith('.js') || rel.endsWith('.css') || rel === 'index.html') {
      for (const hit of scanTextForExternal(text)) {
        errors.push(`external reference (${hit}) in dist/${rel}`)
      }
    }
  }

  // Sanity: the build must have produced an index.html.
  try {
    statSync(indexHtml)
  } catch {
    errors.push('dist/index.html missing')
  }

  // Secret-bearing files must never reach src/ — neither by name NOR by
  // content. A synthetic token placed in a source file must fail the build.
  try {
    for (const file of walkFiles(srcDir)) {
      const rel = relative(srcDir, file)
      if (isSecretBearingFile(file)) {
        errors.push(`secret-bearing file present in src: ${rel}`)
        continue
      }
      if (!isTextFile(file)) continue
      let text
      try {
        text = readFileSync(file, 'utf8')
      } catch {
        continue
      }
      for (const hit of scanTextForSecrets(text)) {
        errors.push(`secret-shaped material (${hit}) in src/${rel}`)
      }
    }
  } catch {
    /* src may be absent in exotic invocations; not fatal here. */
  }

  return { ok: errors.length === 0, errors, checked: distFiles.length, htmlSeen }
}

function main() {
  const distDir = process.argv[2] ?? 'dist'
  const srcDir = process.argv[3] ?? 'src'
  const result = auditDist(distDir, srcDir)

  if (result.ok) {
    console.log(
      `audit-dist: OK — ${result.checked} file(s) checked; no secrets, no external refs, no inline scripts.`,
    )
    process.exit(0)
  }

  console.error('audit-dist: FAILED')
  for (const e of result.errors) console.error(`  - ${e}`)
  process.exit(1)
}

// Run only when invoked directly (not when imported by tests).
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main()
}

export { main }
