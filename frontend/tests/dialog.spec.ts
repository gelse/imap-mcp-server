import { mount, type VueWrapper } from '@vue/test-utils'
import { afterEach, describe, expect, it } from 'vitest'
import { nextTick } from 'vue'
import Dialog from '@/components/Dialog.vue'

/**
 * Dialog tests: type-to-confirm gating, Escape to close, focus trap and restore.
 *
 * Dialog teleports its content to <body>, so assertions query `document`
 * rather than the wrapper root.
 */

let wrapper: VueWrapper | undefined

afterEach(() => {
  wrapper?.unmount()
  wrapper = undefined
  document.body.innerHTML = ''
})

function mountOpen(props: Record<string, unknown> = {}): VueWrapper {
  wrapper = mount(Dialog, {
    props: { modelValue: true, title: 'Delete', ...props },
    attachTo: document.body,
  })
  return wrapper
}

function q<T extends Element = Element>(selector: string): T {
  const el = document.querySelector<T>(selector)
  if (!el) throw new Error(`not found: ${selector}`)
  return el
}

/** Sets a native input value and dispatches the events Vue's v-model listens to. */
async function typeInto(selector: string, value: string): Promise<void> {
  const input = q<HTMLInputElement>(selector)
  input.value = value
  input.dispatchEvent(new Event('input', { bubbles: true }))
  await nextTick()
}

describe('Dialog', () => {
  it('renders nothing when closed', () => {
    wrapper = mount(Dialog, { props: { modelValue: false, title: 'Delete' } })
    expect(document.querySelector('[role="dialog"]')).toBeNull()
  })

  it('renders a labelled modal dialog when open', () => {
    mountOpen({ title: 'Delete account' })
    const dialog = q('[role="dialog"]')
    expect(dialog.getAttribute('aria-modal')).toBe('true')
    const labelId = dialog.getAttribute('aria-labelledby')
    expect(labelId).toBeTruthy()
    expect(document.getElementById(labelId!)).toBeTruthy()
  })

  it('requires the exact confirmation phrase before enabling confirm', async () => {
    mountOpen({ confirmLabel: 'DELETE' })
    expect(q<HTMLButtonElement>('.dialog__btn--confirm').disabled).toBe(true)

    await typeInto('#dialog-confirm-input', 'delete') // wrong case
    expect(q<HTMLButtonElement>('.dialog__btn--confirm').disabled).toBe(true)

    await typeInto('#dialog-confirm-input', 'DELETE')
    expect(q<HTMLButtonElement>('.dialog__btn--confirm').disabled).toBe(false)
  })

  it('emits confirm only when the phrase matches', async () => {
    const w = mountOpen({ confirmLabel: 'DELETE' })
    // Disabled button cannot fire the handler.
    expect(w.emitted('confirm')).toBeFalsy()

    await typeInto('#dialog-confirm-input', 'DELETE')
    q<HTMLButtonElement>('.dialog__btn--confirm').click()
    await nextTick()
    expect(w.emitted('confirm')).toBeTruthy()
  })

  it('closes on Escape', async () => {
    const w = mountOpen()
    q('.dialog-overlay').dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
    await nextTick()
    expect(w.emitted('update:modelValue')).toEqual([[false]])
    expect(w.emitted('cancel')).toBeTruthy()
  })

  it('traps Tab focus within the dialog', async () => {
    mountOpen({ confirmLabel: 'DELETE' })
    await nextTick()
    const focusables = Array.from(
      document.querySelectorAll<HTMLElement>(
        '.dialog button:not([disabled]), .dialog input:not([disabled])',
      ),
    )
    expect(focusables.length).toBeGreaterThan(0)
    const last = focusables[focusables.length - 1]!
    last.focus()
    expect(document.activeElement).toBe(last)
    q('.dialog-overlay').dispatchEvent(
      new KeyboardEvent('keydown', { key: 'Tab', bubbles: true, cancelable: true }),
    )
    await nextTick()
    // Tab from the last enabled control wraps back to the first.
    expect(document.activeElement).toBe(focusables[0])
  })

  it('restores focus to the previously focused element on close', async () => {
    const trigger = document.createElement('button')
    document.body.appendChild(trigger)
    trigger.focus()

    wrapper = mount(Dialog, {
      props: { modelValue: false, title: 'Delete' },
      attachTo: document.body,
    })
    await wrapper.setProps({ modelValue: true })
    await nextTick()
    await wrapper.setProps({ modelValue: false })
    await nextTick()
    expect(document.activeElement).toBe(trigger)
  })
})
