<script setup lang="ts">
/**
 * AlertToast — a polite, auto-dismissing notification.
 *
 * Props:
 *   - message (required), variant: 'info' | 'success' | 'warning' | 'danger'.
 *   - dismissible: show a dismiss button (default true).
 *   - duration: ms before auto-dismiss; 0 disables auto-dismiss (default 5000).
 *
 * Emits: dismiss.
 *
 * aria-live="polite" so it is announced without interrupting the user.
 */
import { onBeforeUnmount, onMounted, watch } from 'vue'

const props = withDefaults(
  defineProps<{
    message: string
    variant?: 'info' | 'success' | 'warning' | 'danger'
    dismissible?: boolean
    duration?: number
  }>(),
  { variant: 'info', dismissible: true, duration: 5000 },
)

const emit = defineEmits<{ dismiss: [] }>()

let timer: ReturnType<typeof setTimeout> | undefined

function clearTimer(): void {
  if (timer !== undefined) {
    clearTimeout(timer)
    timer = undefined
  }
}

function schedule(): void {
  clearTimer()
  if (props.duration > 0) {
    timer = setTimeout(() => emit('dismiss'), props.duration)
  }
}

onMounted(schedule)
onBeforeUnmount(clearTimer)
watch(() => [props.duration, props.message], schedule)
</script>

<template>
  <div
    class="toast"
    :class="`toast--${props.variant}`"
    role="status"
    aria-live="polite"
    data-testid="alert-toast"
  >
    <span class="toast__message">{{ props.message }}</span>
    <button
      v-if="props.dismissible"
      type="button"
      class="toast__close"
      aria-label="Dismiss notification"
      @click="emit('dismiss')"
    >
      <svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true" focusable="false">
        <path
          d="M6 6l12 12M18 6L6 18"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
          stroke-linecap="round"
        />
      </svg>
    </button>
  </div>
</template>

<style scoped>
.toast {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-3);
  padding: var(--space-3) var(--space-4);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  background-color: var(--color-surface);
  box-shadow: var(--shadow-2);
  color: var(--color-text);
}

.toast--success {
  background-color: var(--color-success-bg);
}

.toast--warning {
  background-color: var(--color-warning-bg);
}

.toast--danger {
  background-color: var(--color-danger-bg);
}

.toast--info {
  background-color: var(--color-info-bg);
}

.toast__close {
  border: none;
  background: transparent;
  color: var(--color-muted);
  font-size: var(--text-lg);
  line-height: 1;
  cursor: pointer;
  padding: 0 var(--space-1);
}
</style>
