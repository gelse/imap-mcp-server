<script setup lang="ts">
/**
 * Badge — a small status pill.
 *
 * Props: variant: 'success' | 'muted' | 'warning' | 'danger' | 'primary'
 * (default 'muted'). Common use: active → success, disabled → muted.
 */
withDefaults(
  defineProps<{ variant?: 'success' | 'muted' | 'warning' | 'danger' | 'primary' }>(),
  { variant: 'muted' },
)
</script>

<template>
  <span class="badge" :class="`badge--${variant}`">
    <slot />
  </span>
</template>

<style scoped>
.badge {
  display: inline-flex;
  align-items: center;
  gap: var(--space-1);
  padding: 2px var(--space-2);
  border-radius: 999px;
  font-size: var(--text-xs);
  font-weight: var(--weight-medium);
  line-height: 1.6;
  white-space: nowrap;
}

.badge--muted {
  background-color: var(--color-surface-alt);
  color: var(--color-muted);
  border: 1px solid var(--color-border);
}

.badge--success {
  background-color: var(--color-success-bg);
  color: var(--color-success);
  border: 1px solid var(--color-success);
}

.badge--warning {
  background-color: var(--color-warning-bg);
  color: var(--color-warning);
  border: 1px solid var(--color-warning);
}

.badge--danger {
  background-color: var(--color-danger-bg);
  color: var(--color-danger);
  border: 1px solid var(--color-danger);
}

.badge--primary {
  background-color: var(--color-info-bg);
  color: var(--color-primary);
  border: 1px solid var(--color-primary);
}
</style>
