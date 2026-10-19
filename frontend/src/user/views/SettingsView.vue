<script setup lang="ts">
/**
 * SettingsView — the user's settings (`/user/settings`).
 *
 * The profile block comes from `GET /api/me` (the same single bootstrap call
 * the account list uses) and shows the account-encryption state from the
 * `aek_active` flag.
 *
 * The one-time disclosures:
 *  - "Activate account encryption" — only offered while the key is NOT
 *    active. The response carries the plaintext hex exactly once; a second
 *    activation is answered 409 (the key existing ciphertext depends on must
 *    never be replaced) and is surfaced as an explicit error.
 *  - "Regenerate login key" — the new key is disclosed exactly once and the
 *    previous key stops working immediately.
 *
 * Sign-out deletes the session cookie; the local session state is dropped
 * either way.
 */
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import AlertToast from '@/components/AlertToast.vue'
import Badge from '@/components/Badge.vue'
import Button from '@/components/Button.vue'
import Card from '@/components/Card.vue'
import ErrorBanner from '@/components/ErrorBanner.vue'
import KeyDisplay from '@/components/KeyDisplay.vue'
import LoadingState from '@/components/LoadingState.vue'
import PageHeader from '@/components/PageHeader.vue'
import {
  activateAccountEncryption,
  ApiError,
  getUserProfile,
  rotateUserLoginKey,
  type UserProfile,
} from '@/lib/api'
import { signOutUser } from '@/user/sign-out'

const router = useRouter()

const profile = ref<UserProfile | null>(null)
const loading = ref(true)
const errorMessage = ref('')
const notice = ref('')
const noticeVariant = ref<'success' | 'info' | 'danger'>('success')

const activating = ref(false)
const rotating = ref(false)
const signingOut = ref(false)
const revealedAek = ref<string | null>(null)
const revealedLoginKey = ref<string | null>(null)

onBeforeUnmount(() => {
  // The one-time secrets die with the view; they are never re-fetchable.
  revealedAek.value = null
  revealedLoginKey.value = null
})

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    profile.value = await getUserProfile()
  } catch (error) {
    errorMessage.value =
      error instanceof ApiError
        ? 'Your settings could not be loaded. The session may have expired.'
        : 'Your settings could not be loaded.'
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  void load()
})

async function onActivate(): Promise<void> {
  if (activating.value) return
  activating.value = true
  errorMessage.value = ''
  try {
    const body = await activateAccountEncryption()
    revealedAek.value = body.account_encryption_key
    if (profile.value !== null) profile.value.aek_active = true
    noticeVariant.value = 'success'
    notice.value = 'Account encryption is now active.'
  } catch (error) {
    if (error instanceof ApiError && error.status === 409) {
      errorMessage.value =
        'Account encryption is already active. Its key was displayed once and cannot be shown again.'
    } else {
      errorMessage.value = 'Account encryption could not be activated.'
    }
  } finally {
    activating.value = false
  }
}

async function onRotateKey(): Promise<void> {
  if (rotating.value) return
  rotating.value = true
  errorMessage.value = ''
  try {
    const rotated = await rotateUserLoginKey()
    revealedLoginKey.value = rotated.login_key
    if (profile.value !== null) profile.value.key_generation = rotated.key_generation
    noticeVariant.value = 'success'
    notice.value = 'A new login key was minted. The previous key no longer works.'
  } catch (error) {
    errorMessage.value = 'The login key could not be regenerated.'
  } finally {
    rotating.value = false
  }
}

async function onSignOut(): Promise<void> {
  if (signingOut.value) return
  signingOut.value = true
  try {
    // The sign-out helper clears the local session and routes to the login
    // view, which tells the user what happened (the reason is in the route).
    await signOutUser(router)
  } finally {
    signingOut.value = false
  }
}
</script>

<template>
  <div>
    <PageHeader title="Settings" description="Your profile, your keys and your session." />

    <LoadingState v-if="loading" label="Loading settings…" />

    <ErrorBanner
      v-else-if="errorMessage"
      title="Action failed"
      :message="errorMessage"
    />

    <template v-else-if="profile">
      <AlertToast
        v-if="notice"
        :message="notice"
        :variant="noticeVariant"
        @dismiss="notice = ''"
      />

      <Card title="Profile" class="settings__card">
        <dl class="settings__grid">
          <div class="settings__pair">
            <dt>Name</dt>
            <dd>{{ profile.name }}</dd>
          </div>
          <div class="settings__pair">
            <dt>Created</dt>
            <dd>{{ profile.created_at }}</dd>
          </div>
          <div class="settings__pair">
            <dt>Key generation</dt>
            <dd>{{ profile.key_generation }}</dd>
          </div>
          <div class="settings__pair">
            <dt>Account encryption</dt>
            <dd>
              <Badge :variant="profile.aek_active ? 'success' : 'muted'">
                {{ profile.aek_active ? 'Active' : 'Not active' }}
              </Badge>
            </dd>
          </div>
        </dl>
      </Card>

      <Card v-if="revealedAek" title="Account encryption key" class="settings__card">
        <p class="settings__hint">
          This key is needed to recover or verify your account-encryption backup.
        </p>
        <KeyDisplay
          :value="revealedAek"
          label="Account encryption key"
          confirm-text="I have saved it"
          @done="revealedAek = null"
        >
          <template #warning>
            Shown once — it will never be shown again. You need it to recover or
            verify your account-encryption backup. Copy and store it now.
          </template>
        </KeyDisplay>
      </Card>

      <Card v-if="revealedLoginKey" title="New login key" class="settings__card">
        <KeyDisplay
          :value="revealedLoginKey"
          label="Login key"
          confirm-text="I have saved it"
          @done="revealedLoginKey = null"
        >
          <template #warning>
            Shown once — it will never be shown again. The previous key stops
            working immediately. Copy and store it now.
          </template>
        </KeyDisplay>
      </Card>

      <Card title="Actions" class="settings__card">
        <div class="settings__actions">
          <Button
            v-if="!profile.aek_active"
            :loading="activating"
            @click="onActivate"
          >
            Activate account encryption
          </Button>

          <Button :loading="rotating" @click="onRotateKey">Regenerate login key</Button>

          <Button variant="danger" :loading="signingOut" @click="onSignOut">Sign out</Button>
        </div>
        <p class="settings__hint">
          Regenerating the login key invalidates the previous one immediately.
          Activating account encryption shows its key exactly once — store it
          somewhere safe.
        </p>
      </Card>
    </template>
  </div>
</template>

<style scoped>
.settings__card {
  margin-bottom: var(--space-5);
}

.settings__grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--space-4);
  margin: 0;
}

.settings__pair dt {
  font-size: var(--text-sm);
  color: var(--color-muted);
}

.settings__pair dd {
  margin: var(--space-1) 0 0;
  color: var(--color-text);
}

.settings__actions {
  display: flex;
  gap: var(--space-2);
  flex-wrap: wrap;
}

.settings__hint {
  margin-top: var(--space-3);
  font-size: var(--text-sm);
  color: var(--color-muted);
}
</style>
