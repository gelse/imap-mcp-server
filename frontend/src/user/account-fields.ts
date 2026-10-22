/**
 * Account form field helpers — the shared parsing rules of the account forms.
 *
 * These mirror the semantics of the retired HTML account form exactly: the
 * SPA has to round-trip the stored values the same way the old form did,
 * otherwise every edit would silently erase what the user had configured.
 *
 *  - `default_bcc` is a `str | list[str]` in the store. The form edits it as
 *    one comma-separated text field: a single address stays a string, several
 *    addresses become a list (a bare string is NOT coerced to a list by the
 *    API, so a single entry must arrive as a list where the model wants one).
 *  - `allowed_from` is always a list.
 *  - A blank text field is "not provided" on create and "erase the stored
 *    value" on edit — the callers decide which body they build.
 */

/** Parse a comma-separated text field into the store's `str | list[str]` shape. */
export function parseMultiValue(raw: string): string | string[] | null {
  const value = raw.trim()
  if (value.length === 0) return null
  const parts = value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
  if (parts.length === 0) return null
  if (value.includes(',')) return parts
  return value
}

/** Parse a comma-separated text field into a list of strings. */
export function parseListValue(raw: string): string[] {
  return raw
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
}

/** Render a stored `str | list[str]` value for a text input. */
export function displayMulti(value: string | string[] | undefined): string {
  if (value === undefined) return ''
  if (Array.isArray(value)) return value.join(', ')
  return value
}

/** Parse a numeric text field; NaN when the text is not a number. */
export function parsePort(raw: string): number {
  const trimmed = raw.trim()
  if (trimmed.length === 0) return Number.NaN
  const parsed = Number(trimmed)
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 65535) return Number.NaN
  return parsed
}
