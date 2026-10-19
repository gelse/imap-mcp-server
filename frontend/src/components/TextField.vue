<script setup lang="ts">
/**
 * TextField — a labelled single-line input.
 *
 * Props:
 *   - id (required): the control id; the <label for> association is derived
 *     from it, so every field labels itself.
 *   - label (required)
 *   - modelValue, type, name, placeholder, autocomplete, required, disabled,
 *     error (message text).
 *
 * Emits: update:modelValue.
 *
 * When `error` is set the input gets aria-invalid and the message is linked via
 * aria-describedby. Error *announcement* is owned by the parent view's
 * aria-live region — the field only renders the association.
 */
import { computed } from 'vue'

const props = withDefaults(
  defineProps<{
    id: string
    label: string
    modelValue: string
    type?: string
    name?: string | undefined
    placeholder?: string | undefined
    autocomplete?: string | undefined
    required?: boolean
    disabled?: boolean
    error?: string | undefined
  }>(),
  {
    type: 'text',
    name: undefined,
    placeholder: undefined,
    autocomplete: undefined,
    required: false,
    disabled: false,
    error: undefined,
  },
)

const emit = defineEmits<{ 'update:modelValue': [value: string] }>()

const errorId = computed(() => `${props.id}-error`)
const describedBy = computed(() => (props.error ? errorId.value : undefined))

function onInput(event: Event): void {
  emit('update:modelValue', (event.target as HTMLInputElement).value)
}
</script>

<template>
  <div class="field">
    <label class="field__label" :for="props.id">
      {{ props.label }}
      <span v-if="props.required" class="field__required" aria-hidden="true">*</span>
    </label>
    <input
      :id="props.id"
      class="field__input"
      :class="{ 'field__input--invalid': !!props.error }"
      :type="props.type"
      :name="props.name"
      :value="props.modelValue"
      :placeholder="props.placeholder"
      :autocomplete="props.autocomplete"
      :required="props.required"
      :disabled="props.disabled"
      :aria-invalid="props.error ? 'true' : undefined"
      :aria-describedby="describedBy"
      @input="onInput"
    />
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

.field__input {
  min-height: var(--control-height);
  padding: 0 var(--space-3);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  background-color: var(--color-surface);
  color: var(--color-text);
}

.field__input--invalid {
  border-color: var(--color-danger);
}

.field__error {
  font-size: var(--text-sm);
  color: var(--color-danger);
}
</style>
