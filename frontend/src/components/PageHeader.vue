<script setup lang="ts">
/**
 * PageHeader — a page-level title with optional description and actions.
 *
 * Slots: default (description), actions.
 */
withDefaults(defineProps<{ title: string; description?: string }>(), { description: '' })
</script>

<template>
  <div class="page-header">
    <div class="page-header__text">
      <h1 class="page-header__title">{{ title }}</h1>
      <p v-if="description || $slots.default" class="page-header__desc">
        <slot>{{ description }}</slot>
      </p>
    </div>
    <div v-if="$slots.actions" class="page-header__actions">
      <slot name="actions" />
    </div>
  </div>
</template>

<style scoped>
.page-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-4);
  margin-bottom: var(--space-5);
  flex-wrap: wrap;
}

.page-header__title {
  font-size: var(--text-xl);
}

.page-header__desc {
  margin-top: var(--space-1);
  color: var(--color-muted);
  max-width: var(--measure);
}

.page-header__actions {
  display: flex;
  gap: var(--space-2);
  flex-wrap: wrap;
}
</style>
