/**
 * Types for the dependency-free build audit script (scripts/audit-dist.mjs).
 *
 * The script is authored as plain ESM so it runs under bare `node` in the build
 * pipeline; this declaration lets TypeScript consumers (Vitest specs via the
 * `@audit` path alias) type-check its exports without `allowJs`.
 */

export const SECRET_PATTERNS: ReadonlyArray<{ name: string; re: RegExp }>
export const EXTERNAL_PATTERNS: ReadonlyArray<{ name: string; re: RegExp }>
export const INERT_URL_ALLOWLIST: readonly string[]

export function findInlineScriptHits(html: string): string[]
export function scanTextForSecrets(text: string): string[]
export function scanTextForExternal(text: string): string[]
export function walkFiles(root: string, opts?: { skipDirs?: Set<string> }): string[]
export function isTextFile(path: string): boolean
export function isSecretBearingFile(path: string): boolean
export function auditDist(
  distDir: string,
  srcDir: string,
): { ok: boolean; errors: string[]; checked: number; htmlSeen?: boolean }
export function main(): void
