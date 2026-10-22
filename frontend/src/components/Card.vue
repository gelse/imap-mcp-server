<script setup lang="ts">
/**
 * Card — a surface container with an optional title and footer slot.
 *
 * Slots: default (body), title, footer.
 */
withDefaults(defineProps<{ title?: string }>(), { title: '' })
</script>

<template>
  <section class="card">
    <header v-if="title || $slots.title" class="card__header">
      <h2 v-if="title" class="card__title">{{ title }}</h2>
      <slot name="title" />
    </header>
    <div class="card__body">
      <slot />
    </div>
    <footer v-if="$slots.footer" class="card__footer">
      <slot name="footer" />
    </footer>
  </section>
</template>

<style scoped>
.card {
  display: flex;
  flex-direction: column;
  background-color: var(--color-surface);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-1);
  overflow: hidden;
}

.card__header {
  padding: var(--space-4) var(--space-5);
  border-bottom: 1px solid var(--color-border);
}

.card__title {
  font-size: var(--text-lg);
}

.card__body {
  padding: var(--space-5);
}

.card__footer {
  padding: var(--space-4) var(--space-5);
  border-top: 1px solid var(--color-border);
  background-color: var(--color-surface-alt);
}
</style>
