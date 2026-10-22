<script setup lang="ts">
/**
 * Dialog — an accessible modal with an optional type-to-confirm gate.
 *
 * Props:
 *   - modelValue: open state (required). Use with v-model.
 *   - title (required): the accessible name of the dialog.
 *   - confirmLabel: when set, the dialog enters type-to-confirm mode — the user
 *     must type this exact phrase before the confirm button enables. This is the
 *     affordance used by every destructive operation.
 *   - confirmText / cancelText: button labels.
 *   - destructive: style the confirm button as danger.
 *   - busy: disable both buttons while an action is in flight.
 *
 * Emits: update:modelValue, confirm, cancel.
 *
 * Behaviour:
 *   - Focus trap: Tab/Shift+Tab cycle within the dialog.
 *   - Escape closes (unless busy).
 *   - Focus is moved into the dialog on open and restored to the previously
 *     focused element on close.
 *   - The dialog is labelled by its title and described by its body.
 */
import { nextTick, ref, watch } from 'vue'

const props = withDefaults(
  defineProps<{
    modelValue: boolean
    title: string
    confirmLabel?: string
    confirmText?: string
    cancelText?: string
    destructive?: boolean
    busy?: boolean
  }>(),
  {
    confirmLabel: '',
    confirmText: 'Confirm',
    cancelText: 'Cancel',
    destructive: false,
    busy: false,
  },
)

const emit = defineEmits<{
  'update:modelValue': [value: boolean]
  confirm: []
  cancel: []
}>()

const dialogEl = ref<HTMLDivElement | null>(null)
const typed = ref('')
const typedInput = ref<HTMLInputElement | null>(null)
let previouslyFocused: HTMLElement | null = null

const confirmEnabled = () =>
  !props.busy && (!props.confirmLabel || typed.value === props.confirmLabel)

function close(): void {
  emit('update:modelValue', false)
  emit('cancel')
}

function onConfirm(): void {
  if (!confirmEnabled()) return
  emit('confirm')
}

function focusable(): HTMLElement[] {
  if (!dialogEl.value) return []
  const selector =
    'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'
  return Array.from(dialogEl.value.querySelectorAll<HTMLElement>(selector))
}

function onKeydown(event: KeyboardEvent): void {
  if (event.key === 'Escape') {
    event.stopPropagation()
    if (!props.busy) close()
    return
  }
  if (event.key !== 'Tab') return

  const items = focusable()
  if (items.length === 0) {
    event.preventDefault()
    return
  }
  const first = items[0]
  const last = items[items.length - 1]
  if (!first || !last) return

  const active = document.activeElement
  const outside = !dialogEl.value?.contains(active)
  if (event.shiftKey) {
    if (active === first || outside) {
      event.preventDefault()
      last.focus()
    }
  } else if (active === last || outside) {
    event.preventDefault()
    first.focus()
  }
}

watch(
  () => props.modelValue,
  async (open) => {
    if (open) {
      previouslyFocused = (document.activeElement as HTMLElement) ?? null
      typed.value = ''
      await nextTick()
      // Prefer the confirmation input, else the first focusable control.
      if (typedInput.value) typedInput.value.focus()
      else focusable()[0]?.focus()
    } else if (previouslyFocused && typeof previouslyFocused.focus === 'function') {
      previouslyFocused.focus()
      previouslyFocused = null
    }
  },
)
</script>

<template>
  <Teleport to="body">
    <div
      v-if="props.modelValue"
      class="dialog-overlay"
      @keydown="onKeydown"
    >
      <div
        ref="dialogEl"
        class="dialog"
        role="dialog"
        aria-modal="true"
        :aria-labelledby="`${props.title.replace(/\s+/g, '-').toLowerCase()}-title`"
      >
        <header class="dialog__header">
          <h2 :id="`${props.title.replace(/\s+/g, '-').toLowerCase()}-title`" class="dialog__title">
            {{ props.title }}
          </h2>
        </header>

        <div class="dialog__body">
          <slot />

          <div v-if="props.confirmLabel" class="dialog__confirm">
            <label class="dialog__confirm-label" for="dialog-confirm-input">
              Type <strong>{{ props.confirmLabel }}</strong> to continue:
            </label>
            <input
              id="dialog-confirm-input"
              ref="typedInput"
              v-model="typed"
              class="dialog__confirm-input"
              type="text"
              autocomplete="off"
              @keyup.enter="onConfirm"
            />
          </div>
        </div>

        <footer class="dialog__footer">
          <button type="button" class="dialog__btn" :disabled="props.busy" @click="close">
            {{ props.cancelText }}
          </button>
          <button
            type="button"
            class="dialog__btn dialog__btn--confirm"
            :class="{ 'dialog__btn--danger': props.destructive }"
            :disabled="!confirmEnabled()"
            @click="onConfirm"
          >
            {{ props.confirmText }}
          </button>
        </footer>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
.dialog-overlay {
  position: fixed;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--space-4);
  background-color: rgba(15, 23, 42, 0.55);
  z-index: 100;
}

.dialog {
  width: 100%;
  max-width: 480px;
  max-height: 90vh;
  overflow-y: auto;
  background-color: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-2);
}

.dialog__header {
  padding: var(--space-4) var(--space-5);
  border-bottom: 1px solid var(--color-border);
}

.dialog__title {
  font-size: var(--text-lg);
}

.dialog__body {
  padding: var(--space-5);
  color: var(--color-text);
}

.dialog__confirm {
  margin-top: var(--space-4);
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}

.dialog__confirm-label {
  font-size: var(--text-sm);
  color: var(--color-muted);
}

.dialog__confirm-input {
  min-height: var(--control-height);
  padding: 0 var(--space-3);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  background-color: var(--color-surface);
  color: var(--color-text);
  font-family: var(--font-mono);
}

.dialog__footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-2);
  padding: var(--space-4) var(--space-5);
  border-top: 1px solid var(--color-border);
}

.dialog__btn {
  min-height: var(--control-height);
  padding: 0 var(--space-4);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  background-color: var(--color-surface);
  color: var(--color-text);
  cursor: pointer;
  font-weight: var(--weight-medium);
}

.dialog__btn:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}

.dialog__btn--confirm {
  background-color: var(--color-primary);
  color: var(--color-on-primary);
  border-color: transparent;
}

.dialog__btn--danger {
  background-color: var(--color-danger);
  color: var(--color-on-danger);
}
</style>
