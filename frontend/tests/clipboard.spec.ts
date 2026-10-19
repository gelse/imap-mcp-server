import { afterEach, describe, expect, it, vi } from 'vitest'
import { copyText, legacyCopy } from '@/lib/clipboard'

/**
 * Clipboard helper tests: the async Clipboard API path, the
 * document.execCommand('copy') fallback used on plain-HTTP LAN deployments,
 * and the never-persist contract (no storage writes).
 */

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('copyText', () => {
  it('uses navigator.clipboard.writeText when available', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    expect(await copyText('secret')).toBe(true)
    expect(writeText).toHaveBeenCalledWith('secret')
  })

  it('falls back to execCommand when navigator.clipboard is absent', async () => {
    vi.stubGlobal('navigator', {})
    const execCommand = vi.fn().mockReturnValue(true)
    document.execCommand = execCommand

    expect(await copyText('secret')).toBe(true)
    expect(execCommand).toHaveBeenCalledWith('copy')
  })

  it('falls back to execCommand when writeText rejects (insecure context)', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('denied'))
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    const execCommand = vi.fn().mockReturnValue(true)
    document.execCommand = execCommand

    expect(await copyText('secret')).toBe(true)
    expect(execCommand).toHaveBeenCalledWith('copy')
  })

  it('returns false when neither path works', async () => {
    vi.stubGlobal('navigator', {})
    document.execCommand = vi.fn().mockReturnValue(false)
    expect(await copyText('secret')).toBe(false)
  })

  it('never writes to web storage', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', { clipboard: { writeText } })
    const setItem = vi.spyOn(Storage.prototype, 'setItem')
    await copyText('secret')
    expect(setItem).not.toHaveBeenCalled()
  })
})

describe('legacyCopy', () => {
  it('creates a temporary textarea and removes it afterwards', async () => {
    const execCommand = vi.fn().mockReturnValue(true)
    document.execCommand = execCommand

    expect(legacyCopy('secret')).toBe(true)
    expect(document.querySelector('textarea')).toBeNull()
    expect(document.body.textContent).not.toContain('secret')
  })

  it('returns false without a usable document.execCommand', () => {
    const doc = {} as Document
    expect(legacyCopy('secret', doc)).toBe(false)
  })
})
