<script setup lang="ts">
/**
 * NotFoundView — the shared "no such page" state.
 *
 * Used for unknown in-section routes and for the admin surface's missing
 * resources. The back link points at the owning section.
 */
import { RouterLink } from 'vue-router'
import EmptyState from '@/components/EmptyState.vue'

const props = withDefaults(defineProps<{ homeTo?: string; title?: string; message?: string }>(), {
  homeTo: '/admin',
  title: 'Page not found',
  message: 'The page you asked for does not exist, or it is no longer available.',
})
</script>

<template>
  <EmptyState :title="props.title" :message="props.message">
    <template #actions>
      <RouterLink class="not-found__link" :to="props.homeTo">Back to the start</RouterLink>
    </template>
  </EmptyState>
</template>

<style scoped>
.not-found__link {
  display: inline-flex;
  align-items: center;
  min-height: var(--control-height);
  padding: 0 var(--space-4);
  border-radius: var(--radius-md);
  background-color: var(--color-primary);
  color: var(--color-on-primary);
  text-decoration: none;
  font-weight: var(--weight-medium);
}

.not-found__link:hover {
  background-color: var(--color-primary-hover);
  color: var(--color-on-primary);
}
</style>
