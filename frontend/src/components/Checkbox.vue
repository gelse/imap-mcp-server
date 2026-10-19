<script setup lang="ts">
/**
 * Checkbox — a labelled checkbox.
 *
 * Props: id (required), label (required), modelValue, disabled, hint.
 * Emits: update:modelValue.
 */
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    id: string
    label: string
    modelValue: boolean
    disabled?: boolean
    hint?: string | undefined
  }>(),
  { disabled: false, hint: undefined },
)

const emit = defineEmits<{ 'update:modelValue': [value: boolean] }>()

const hintId = computed(() => `${props.id}-hint`)

function onChange(event: Event): void {
  emit('update:modelValue', (event.target as HTMLInputElement).checked)
}
</script>

<template>
  <div class="checkbox">
    <input
      :id="props.id"
      class="checkbox__input"
      type="checkbox"
      :checked="props.modelValue"
      :disabled="props.disabled"
      :aria-describedby="props.hint ? hintId : undefined"
      @change="onChange"
    />
    <label class="checkbox__label" :for="props.id">{{ props.label }}</label>
    <p v-if="props.hint" :id="hintId" class="checkbox__hint">{{ props.hint }}</p>
  </div>
</template>

<style scoped>
.checkbox {
  display: grid;
  grid-template-columns: auto 1fr;
  align-items: center;
  gap: var(--space-1) var(--space-2);
}

.checkbox__input {
  width: 18px;
  height: 18px;
  accent-color: var(--color-primary);
}

.checkbox__label {
  font-size: var(--text-base);
  color: var(--color-text);
}

.checkbox__hint {
  grid-column: 2;
  font-size: var(--text-sm);
  color: var(--color-muted);
}
</style>
