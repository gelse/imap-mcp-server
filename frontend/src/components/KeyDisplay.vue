<script setup lang="ts">
/**
 * KeyDisplay — one-time secret reveal.
 *
 * Props:
 *   - value (required): the secret to display exactly once.
 *   - label: caption above the value (e.g. "Account encryption key").
 *   - confirmText: label for the "I've saved it" action (default "Done").
 *
 * Emits: done, copied.
 *
 * Guarantees:
 *   - The value is rendered as selectable monospace text (user-select: all) so
 *     the user can grab the whole token in one action.
 *   - An explicit "shown once — it will never be shown again" warning is always
 *     rendered.
 *   - A copy button uses lib/clipboard.ts (async API with legacy fallback).
 *   - The component NEVER persists or logs the value, and zeroes its internal
 *     ref on unmount and after "done".
 */
import { onBeforeUnmount, ref, watch } from 'vue'
import { copyText } from '@/lib/clipboard'

const props = withDefaults(
  defineProps<{ value: string; label?: string; confirmText?: string }>(),
  { label: 'Secret key', confirmText: 'Done' },
)

const emit = defineEmits<{ done: []; copied: [] }>()

const revealed = ref<string>(props.value)
const copyState = ref<'idle' | 'copied' | 'failed'>('idle')

watch(
  () => props.value,
  (v) => {
    revealed.value = v
  },
)

async function onCopy(): Promise<void> {
  const ok = await copyText(revealed.value)
  copyState.value = ok ? 'copied' : 'failed'
  if (ok) emit('copied')
}

function clearSecret(): void {
  revealed.value = ''
}

function onDone(): void {
  clearSecret()
  emit('done')
}

onBeforeUnmount(() => {
  clearSecret()
})

defineExpose({ revealed, clearSecret })
</script>

<template>
  <div class="key-display">
    <p class="key-display__warning" role="alert">
      <slot name="warning">Shown once — it will never be shown again. Copy and store it now.</slot>
    </p>

    <p v-if="props.label" class="key-display__label">{{ props.label }}</p>

    <div class="key-display__row">
      <code class="key-display__value" data-testid="key-value">{{ revealed }}</code>
      <button type="button" class="key-display__copy" @click="onCopy">
        Copy
      </button>
    </div>

    <p class="key-display__copy-status" aria-live="polite">
      <span v-if="copyState === 'copied'">Copied to clipboard.</span>
      <span v-else-if="copyState === 'failed'">Copy failed — select and copy manually.</span>
    </p>

    <div class="key-display__actions">
      <button type="button" class="key-display__done" @click="onDone">
        {{ props.confirmText }}
      </button>
    </div>
  </div>
</template>

<style scoped>
.key-display {
  display: flex;
  flex-direction: column;
  gap: var(--space-3);
}

.key-display__warning {
  padding: var(--space-3) var(--space-4);
  border: 1px solid var(--color-warning);
  border-radius: var(--radius-md);
  background-color: var(--color-warning-bg);
  color: var(--color-warning);
  font-weight: var(--weight-medium);
}

.key-display__label {
  font-size: var(--text-sm);
  color: var(--color-muted);
}

.key-display__row {
  display: flex;
  align-items: stretch;
  gap: var(--space-2);
}

.key-display__value {
  flex: 1;
  display: block;
  padding: var(--space-3);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  background-color: var(--color-surface-alt);
  color: var(--color-text);
  font-family: var(--font-mono);
  font-size: var(--text-sm);
  overflow-wrap: anywhere;
  user-select: all;
  -webkit-user-select: all;
}

.key-display__copy,
.key-display__done {
  min-height: var(--control-height);
  padding: 0 var(--space-4);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  background-color: var(--color-surface);
  color: var(--color-text);
  cursor: pointer;
  font-weight: var(--weight-medium);
}

.key-display__done {
  background-color: var(--color-primary);
  color: var(--color-on-primary);
  border-color: transparent;
}

.key-display__copy-status {
  min-height: 1.2em;
  font-size: var(--text-sm);
  color: var(--color-muted);
}

.key-display__actions {
  display: flex;
  justify-content: flex-end;
}
</style>
