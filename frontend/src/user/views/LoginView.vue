<script setup lang="ts">
/**
 * LoginView — the user sign-in page (`/user/login`).
 *
 * The endpoint contract is the JSON twin of the retired HTML form:
 * `POST /api/me/login` with the body `{"key": ...}`. The backend keeps the
 * same per-IP login budget, the same same-origin guard and the same HttpOnly
 * cookie — the SPA only surfaces the answers:
 *
 *  - 200 → the response carries the session's CSRF token; it goes straight
 *    into the in-memory session store (never into browser storage) and the
 *    user continues to the account list;
 *  - 401 → ONE uniform message. The backend does not distinguish "wrong key"
 *    from "unknown key" (or from a cross-site rejection) and neither does the
 *    view: no cause ever reaches the screen.
 *  - 429 → the server's `Retry-After` is shown as a countdown.
 *
 * Redirect parity: a visitor who still holds a valid session and opens this
 * URL is forwarded to the account list instead of being asked to sign in
 * again (the client-side equivalent of the old 303).
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import Button from '@/components/Button.vue'
import Card from '@/components/Card.vue'
import ErrorBanner from '@/components/ErrorBanner.vue'
import TextField from '@/components/TextField.vue'
import { ApiError, userLogin } from '@/lib/api'
import { bootstrap, establish } from '@/lib/session'

const route = useRoute()
const router = useRouter()

const key = ref('')
const submitting = ref(false)
const errorMessage = ref('')
const rateLimited = ref(false)
const retryAfter = ref(0)
let countdown: ReturnType<typeof setInterval> | undefined

const notice = computed(() => {
  switch (route.query.reason) {
    case 'expired':
      return 'Your session has expired. Please sign in again.'
    case 'required':
      return 'Please sign in to manage your accounts.'
    case 'signed-out':
      return 'You have been signed out.'
    case 'signed-out-local':
      return 'Signed out — the server could not be reached, but the local session was cleared.'
    default:
      return ''
  }
})

onMounted(async () => {
  // After an explicit sign-out this view never auto-forwards: the user asked
  // to leave, so the login form is what they get.
  if (route.query.reason === 'signed-out' || route.query.reason === 'signed-out-local') return
  // Redirect parity: a still-valid session never sees this form.
  const ok = await bootstrap('user')
  if (ok) void router.replace({ name: 'user-accounts' })
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
    const body = await userLogin(key.value)
    // The key has served its purpose: it is not retained anywhere.
    key.value = ''
    if (typeof body.csrf_token !== 'string' || body.csrf_token.length === 0) {
      errorMessage.value = 'Sign-in failed. Please try again.'
      return
    }
    establish('user', body.csrf_token)
    await router.replace({ name: 'user-accounts' })
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
          id="user-key"
          label="Login key"
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
