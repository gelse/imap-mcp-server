<script setup lang="ts">
/**
 * Button — the single button primitive.
 *
 * Props:
 *   - variant: 'primary' | 'secondary' | 'danger' (default 'secondary').
 *   - type: native button type (default 'button').
 *   - disabled: disables the control.
 *   - loading: shows a busy state and disables the control; sets aria-busy.
 *
 * A loading button is announced as busy and inert so it cannot be double-fired.
 */
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    variant?: 'primary' | 'secondary' | 'danger'
    type?: 'button' | 'submit' | 'reset'
    disabled?: boolean
    loading?: boolean
  }>(),
  { variant: 'secondary', type: 'button', disabled: false, loading: false },
)

const isDisabled = computed(() => props.disabled || props.loading)
const classes = computed(() => ['btn', `btn--${props.variant}`, { 'btn--loading': props.loading }])
</script>

<template>
  <button
    :type="props.type"
    :class="classes"
    :disabled="isDisabled"
    :aria-busy="props.loading ? 'true' : undefined"
  >
    <span v-if="props.loading" class="btn__spinner" aria-hidden="true" />
    <slot />
  </button>
</template>

<style scoped>
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
  min-height: var(--control-height);
  padding: 0 var(--space-4);
  border: 1px solid transparent;
  border-radius: var(--radius-md);
  font-weight: var(--weight-medium);
  cursor: pointer;
  transition: background-color 0.15s ease, border-color 0.15s ease;
}

.btn:disabled {
  cursor: not-allowed;
  opacity: 0.6;
}

.btn--primary {
  background-color: var(--color-primary);
  color: var(--color-on-primary);
}

.btn--primary:hover:not(:disabled) {
  background-color: var(--color-primary-hover);
}

.btn--secondary {
  background-color: var(--color-surface);
  color: var(--color-text);
  border-color: var(--color-border);
}

.btn--secondary:hover:not(:disabled) {
  background-color: var(--color-surface-alt);
}

.btn--danger {
  background-color: var(--color-danger);
  color: var(--color-on-danger);
}

.btn--danger:hover:not(:disabled) {
  filter: brightness(1.08);
}

.btn__spinner {
  width: 1em;
  height: 1em;
  border: 2px solid currentColor;
  border-right-color: transparent;
  border-radius: 50%;
  animation: btn-spin 0.6s linear infinite;
}

@keyframes btn-spin {
  to {
    transform: rotate(360deg);
  }
}
</style>
