<script setup lang="ts">
/**
 * ErrorBanner — an assertive error surface.
 *
 * role="alert" + aria-live="assertive" so failures are announced immediately.
 * Props: message (required), title. Slot: actions.
 */
withDefaults(defineProps<{ message: string; title?: string }>(), { title: 'Something went wrong' })
</script>

<template>
  <div class="error-banner" role="alert" aria-live="assertive">
    <div class="error-banner__icon" aria-hidden="true">
      <svg viewBox="0 0 24 24" width="14" height="14" focusable="false">
        <path
          d="M12 5v9m0 4v.01"
          fill="none"
          stroke="currentColor"
          stroke-width="2.5"
          stroke-linecap="round"
        />
      </svg>
    </div>
    <div class="error-banner__content">
      <p class="error-banner__title">{{ title }}</p>
      <p class="error-banner__message">{{ message }}</p>
      <div v-if="$slots.actions" class="error-banner__actions">
        <slot name="actions" />
      </div>
    </div>
  </div>
</template>

<style scoped>
.error-banner {
  display: flex;
  gap: var(--space-3);
  padding: var(--space-3) var(--space-4);
  border: 1px solid var(--color-danger);
  border-radius: var(--radius-md);
  background-color: var(--color-danger-bg);
  color: var(--color-text);
}

.error-banner__icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  flex: 0 0 auto;
  border-radius: 50%;
  background-color: var(--color-danger);
  color: var(--color-on-danger);
  font-weight: var(--weight-semibold);
}

.error-banner__title {
  font-weight: var(--weight-semibold);
}

.error-banner__message {
  margin-top: var(--space-1);
  color: var(--color-text);
}

.error-banner__actions {
  margin-top: var(--space-2);
}
</style>
