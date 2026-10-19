<script setup lang="ts">
/**
 * Select — a labelled dropdown.
 *
 * Props:
 *   - id (required), label (required), modelValue, options ({value,label}[]),
 *     required, disabled, error.
 *
 * Emits: update:modelValue.
 */
import { computed } from 'vue'

export interface SelectOption {
  value: string
  label: string
}

const props = withDefaults(
  defineProps<{
    id: string
    label: string
    modelValue: string
    options: SelectOption[]
    required?: boolean
    disabled?: boolean
    error?: string | undefined
  }>(),
  { required: false, disabled: false, error: undefined },
)

const emit = defineEmits<{ 'update:modelValue': [value: string] }>()

const errorId = computed(() => `${props.id}-error`)
const describedBy = computed(() => (props.error ? errorId.value : undefined))

function onChange(event: Event): void {
  emit('update:modelValue', (event.target as HTMLSelectElement).value)
}
</script>

<template>
  <div class="field">
    <label class="field__label" :for="props.id">
      {{ props.label }}
      <span v-if="props.required" class="field__required" aria-hidden="true">*</span>
    </label>
    <select
      :id="props.id"
      class="field__select"
      :class="{ 'field__select--invalid': !!props.error }"
      :value="props.modelValue"
      :required="props.required"
      :disabled="props.disabled"
      :aria-invalid="props.error ? 'true' : undefined"
      :aria-describedby="describedBy"
      @change="onChange"
    >
      <option v-for="opt in props.options" :key="opt.value" :value="opt.value">
        {{ opt.label }}
      </option>
    </select>
    <p v-if="props.error" :id="errorId" class="field__error">{{ props.error }}</p>
  </div>
</template>

<style scoped>
.field {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
}

.field__label {
  font-size: var(--text-sm);
  font-weight: var(--weight-medium);
  color: var(--color-text);
}

.field__required {
  color: var(--color-danger);
}

.field__select {
  min-height: var(--control-height);
  padding: 0 var(--space-3);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  background-color: var(--color-surface);
  color: var(--color-text);
}

.field__select--invalid {
  border-color: var(--color-danger);
}

.field__error {
  font-size: var(--text-sm);
  color: var(--color-danger);
}
</style>
