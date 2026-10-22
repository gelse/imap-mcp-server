/**
 * Clipboard helper — copy text with a graceful fallback.
 *
 * The modern async Clipboard API is only available in secure contexts (HTTPS or
 * localhost). The gateway can be reached over plain HTTP on a LAN host, so we
 * fall back to the legacy `document.execCommand('copy')` path via a temporary
 * off-screen textarea when `navigator.clipboard` is missing or rejects.
 *
 * This helper never logs or persists the copied value.
 */

export async function copyText(text: string, doc?: Document): Promise<boolean> {
  const document_ = doc ?? defaultDocument()

  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      /* fall through to the legacy path */
    }
  }

  return legacyCopy(text, document_)
}

/** Exposed for tests: the execCommand-based fallback in isolation. */
export function legacyCopy(text: string, doc?: Document): boolean {
  const document_ = doc ?? defaultDocument()
  if (!document_ || typeof document_.execCommand !== 'function') return false
  if (!document_.body) return false

  const textarea = document_.createElement('textarea')
  textarea.value = text
  textarea.className = 'clipboard-copy-source'
  textarea.setAttribute('readonly', '')
  textarea.setAttribute('aria-hidden', 'true')

  try {
    document_.body.appendChild(textarea)
    textarea.select()
    return document_.execCommand('copy')
  } catch {
    return false
  } finally {
    textarea.remove()
  }
}

function defaultDocument(): Document | undefined {
  return typeof document !== 'undefined' ? document : undefined
}
