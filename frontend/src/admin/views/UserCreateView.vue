<script setup lang="ts">
/**
 * UserCreateView — create a registry user (`/admin/users/new`).
 *
 * The create response is the ONLY place a login key ever exists. It is
 * rendered exactly once through the KeyDisplay component and then dropped:
 * the plaintext lives in one local ref for the lifetime of this view and is
 * cleared when the view unmounts. It is never put into the session store,
 * the router state, or any browser storage — navigating away loses it
 * forever, which is the intended contract.
 */
import { onBeforeUnmount, ref } from 'vue'
import { useRouter } from 'vue-router'
import Button from '@/components/Button.vue'
import Card from '@/components/Card.vue'
import ErrorBanner from '@/components/ErrorBanner.vue'
import KeyDisplay from '@/components/KeyDisplay.vue'
import PageHeader from '@/components/PageHeader.vue'
import TextField from '@/components/TextField.vue'
import { ApiError, createAdminUser, type AdminUserCreated } from '@/lib/api'

const router = useRouter()

const name = ref('')
const creating = ref(false)
const errorMessage = ref('')
const created = ref<AdminUserCreated | null>(null)

onBeforeUnmount(() => {
  // The one-time key dies with the view.
  created.value = null
})

async function onSubmit(): Promise<void> {
  if (creating.value) return
  errorMessage.value = ''
  creating.value = true
  try {
    created.value = await createAdminUser(name.value.trim())
    name.value = ''
  } catch (error) {
    errorMessage.value =
      error instanceof ApiError
        ? 'The user could not be created. Check the name and try again.'
        : 'The user could not be created.'
  } finally {
    creating.value = false
  }
}

async function onKeyDone(): Promise<void> {
  const id = created.value?.id
  created.value = null
  if (id) await router.push({ name: 'admin-user-detail', params: { id } })
}
</script>

<template>
  <div>
    <PageHeader
      title="Create user"
      description="A new user receives a one-time login key. It is shown once and never again."
    />

    <Card class="create__card">
      <template v-if="created" #title>
        One-time login key
      </template>

      <div v-if="created" class="create__created">
        <p class="create__summary">
          User <strong>{{ created.name }}</strong> was created
          (key generation {{ created.key_generation }}).
        </p>

        <KeyDisplay
          :value="created.login_key"
          label="Login key"
          confirm-text="I have saved it"
          @done="onKeyDone"
        >
          <template #warning>
            Shown once — it will never be shown again. Copy and store it now.
          </template>
        </KeyDisplay>
      </div>

      <form v-else class="create__form" novalidate @submit.prevent="onSubmit">
        <TextField
          id="new-user-name"
          label="Display name"
          v-model="name"
          name="name"
          autocomplete="off"
          required
          :disabled="creating"
        />

        <ErrorBanner
          v-if="errorMessage"
          title="User not created"
          :message="errorMessage"
        />

        <Button type="submit" variant="primary" :loading="creating">Create user</Button>
      </form>
    </Card>
  </div>
</template>

<style scoped>
.create__card {
  max-width: 640px;
}

.create__form {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  align-items: stretch;
}

.create__created {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
}

.create__summary {
  color: var(--color-muted);
}
</style>
