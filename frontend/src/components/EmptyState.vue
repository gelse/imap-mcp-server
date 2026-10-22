<script setup lang="ts">
/**
 * EmptyState — the "nothing here yet" placeholder.
 *
 * Props: title (required), message. Slots: default (message), actions.
 */
withDefaults(defineProps<{ title: string; message?: string }>(), { message: '' })
</script>

<template>
  <div class="empty" role="status">
    <div class="empty__icon" aria-hidden="true">
      <svg viewBox="0 0 48 48" width="48" height="48" focusable="false">
        <rect x="6" y="12" width="36" height="24" rx="3" fill="none" stroke="currentColor" stroke-width="2" />
        <path d="M14 34v-10m10 10v-16m10 16v-8" stroke="currentColor" stroke-width="2" />
      </svg>
    </div>
    <h2 class="empty__title">{{ title }}</h2>
    <p v-if="message || $slots.default" class="empty__message">
      <slot>{{ message }}</slot>
    </p>
    <div v-if="$slots.actions" class="empty__actions">
      <slot name="actions" />
    </div>
  </div>
</template>

<style scoped>
.empty {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  gap: var(--space-3);
  padding: var(--space-7) var(--space-4);
  color: var(--color-muted);
}

.empty__icon {
  color: var(--color-border);
}

.empty__title {
  font-size: var(--text-lg);
  color: var(--color-text);
}

.empty__message {
  max-width: var(--measure);
}

.empty__actions {
  margin-top: var(--space-2);
}
</style>
