<script setup lang="ts">
/**
 * LoginView — the admin sign-in page (`/admin/login`).
 *
 * The endpoint contract is unchanged: the admin key is posted form-encoded to
 * `POST /api/admin/login`. A failed attempt renders ONE uniform message (the
 * backend does not distinguish wrong key from unknown key, and neither does
 * the view). A rate-limited answer (429) surfaces the server's `Retry-After`
 * as a visible countdown.
 *
 * Login-page redirect parity: an admin who still holds a valid session and
 * opens this URL is forwarded to the dashboard instead of being asked to
 * sign in again.
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import Button from '@/components/Button.vue'
import Card from '@/components/Card.vue'
import ErrorBanner from '@/components/ErrorBanner.vue'
import TextField from '@/components/TextField.vue'
import { adminLogin, ApiError } from '@/lib/api'
import { bootstrap } from '@/lib/session'

const route = useRoute()
const router = useRouter()

const key = ref('')
const submitting = ref(false)
const errorMessage = ref('')
const rateLimited = ref(false)
const retryAfter = ref(0)
let countdown: ReturnType<typeof setInterval> | undefined

const notice = computed(() =>
  route.query.reason === 'expired'
    ? 'Your session has expired. Please sign in again.'
    : '',
)

onMounted(async () => {
  // Redirect parity: a still-valid session never sees this form.
  const ok = await bootstrap('admin')
  if (ok) void router.replace({ name: 'admin-home' })
})

onBeforeUnmount(stopCountdown)

function stopCountdown(): void {
  if (countdown !== undefined) {
    clearInterval(countdown)
    countdown = undefined
  }
}

function startCountdown(seconds: number): void {
  stopCountdown()
  rateLimited.value = true
  retryAfter.value = Math.max(seconds, 1)
  countdown = setInterval(() => {
    retryAfter.value -= 1
    if (retryAfter.value <= 0) {
      stopCountdown()
      rateLimited.value = false
    }
  }, 1000)
}

async function onSubmit(): Promise<void> {
  if (submitting.value) return
  errorMessage.value = ''
  submitting.value = true
  try {
    await adminLogin(key.value)
    // The key has served its purpose: it is not retained anywhere.
    key.value = ''
    const ok = await bootstrap('admin')
    if (!ok) {
      errorMessage.value = 'Sign-in failed. Please try again.'
      return
    }
    await router.replace({ name: 'admin-home' })
  } catch (error) {
    if (error instanceof ApiError && error.status === 429) {
      startCountdown(error.retryAfter ?? 60)
      errorMessage.value = 'Too many sign-in attempts. Please wait before trying again.'
    } else {
      // Uniform failure: never distinguish "wrong key" from anything else.
      errorMessage.value = 'Sign-in failed. Check the key and try again.'
    }
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="login">
    <Card class="login__card">
      <template #title>Sign in</template>

      <p v-if="notice" class="login__notice" role="status">{{ notice }}</p>

      <form class="login__form" novalidate @submit.prevent="onSubmit">
        <TextField
          id="admin-key"
          label="Admin key"
          v-model="key"
          type="password"
          name="key"
          autocomplete="off"
          required
          :disabled="submitting"
        />

        <ErrorBanner
          v-if="errorMessage"
          title="Sign-in failed"
          :message="errorMessage"
        />

        <p v-if="rateLimited" class="login__countdown" role="status" aria-live="polite">
          Try again in {{ retryAfter }}s.
        </p>

        <Button type="submit" variant="primary" :loading="submitting">Sign in</Button>
      </form>
    </Card>
  </div>
</template>

<style scoped>
.login {
  display: flex;
  justify-content: center;
  padding-top: var(--space-7);
}

.login__card {
  width: 100%;
  max-width: 420px;
}

.login__notice {
  margin-bottom: var(--space-4);
  padding: var(--space-3) var(--space-4);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  background-color: var(--color-info-bg);
  color: var(--color-text);
}

.login__form {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  align-items: stretch;
}

.login__countdown {
  color: var(--color-warning);
  font-weight: var(--weight-medium);
}
</style>
