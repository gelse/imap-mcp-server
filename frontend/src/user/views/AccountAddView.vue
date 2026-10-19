<script setup lang="ts">
/**
 * AccountAddView — add a mail account (`/user/accounts/new`).
 *
 * The form covers the API's `CreateAccountBody` exactly; the SPA sends the
 * snake_case field names (the API accepts the upstream camelCase aliases as
 * well).
 *
 * The one-time disclosure: the FIRST add of a user activates the account
 * encryption key, and the response then carries `account_encryption_key` —
 * the plaintext hex, shown exactly once through the KeyDisplay component. It
 * lives in one local ref for the lifetime of this view and is dropped when
 * the view unmounts: it is never put into the session store, the router
 * state, or any browser storage.
 *
 * The backend also has ONE failure-safe disclosure: when the account store
 * write fails after the activation, it answers 500 with the key in the body
 * (the key is already persisted at that point — swallowing it would leave
 * every stored credential encrypted under a key nobody ever saw). The view
 * renders that key too — in the SAME branch as the honest error notice, so
 * both facts reach the user at once: the account was NOT saved, and the key
 * WAS created and is shown only once. The summary text follows the actual
 * outcome; it never claims the account exists when it does not.
 */
import { computed, onBeforeUnmount, ref } from 'vue'
import { useRouter } from 'vue-router'
import Button from '@/components/Button.vue'
import Card from '@/components/Card.vue'
import Checkbox from '@/components/Checkbox.vue'
import ErrorBanner from '@/components/ErrorBanner.vue'
import KeyDisplay from '@/components/KeyDisplay.vue'
import PageHeader from '@/components/PageHeader.vue'
import TextField from '@/components/TextField.vue'
import { ApiError, createUserAccount, type CreateAccountPayload } from '@/lib/api'
import { parseListValue, parseMultiValue, parsePort } from '@/user/account-fields'
import { setUserNotice } from '@/user/notice'

const router = useRouter()

const name = ref('')
const host = ref('')
const port = ref('993')
const user = ref('')
const password = ref('')
const tls = ref(true)
const allowStartTls = ref(false)
const email = ref('')
const saveToSent = ref(false)
const sentFolder = ref('')
const defaultBcc = ref('')
const allowedFrom = ref('')

const smtpHost = ref('')
const smtpPort = ref('587')
const smtpSecure = ref(false)
const smtpUser = ref('')
const smtpPassword = ref('')

const submitting = ref(false)
const errorMessage = ref('')
const fieldError = ref('')
const revealedKey = ref<string | null>(null)
/**
 * How the disclosed key came to be — the disclosure text must never claim
 * more than what actually happened.
 *   - `created-with-account`: the account was stored together with the key.
 *   - `created-after-failed-save`: the store write failed; the key exists,
 *     the account does NOT.
 */
const keyDisclosure = ref<'created-with-account' | 'created-after-failed-save' | null>(null)

const hasSmtp = computed(() => smtpHost.value.trim().length > 0)

const keyAfterFailedSave = computed(() => keyDisclosure.value === 'created-after-failed-save')

const keySummary = computed(() =>
  keyAfterFailedSave.value
    ? 'The account was not saved, but your account-encryption key was created. It is needed to recover or verify your account-encryption backup.'
    : 'Your account-encryption key was created together with this account. It is needed to recover or verify your account-encryption backup.',
)

const keyWarning = computed(() =>
  keyAfterFailedSave.value
    ? 'Shown once — it will never be shown again. The account was not saved, so this is the only chance to copy the key. Copy and store it now.'
    : 'Shown once — it will never be shown again. You need it to recover or verify your account-encryption backup. Copy and store it now.',
)

onBeforeUnmount(() => {
  // The one-time key dies with the view.
  revealedKey.value = null
  keyDisclosure.value = null
})

/** Read the one-time key out of a failure-safe disclosure body. */
function keyFromBody(body: unknown): string | null {
  if (body === null || typeof body !== 'object') return null
  const value = (body as { account_encryption_key?: unknown }).account_encryption_key
  return typeof value === 'string' && value.length > 0 ? value : null
}

function buildPayload(): CreateAccountPayload | null {
  const parsedPort = parsePort(port.value)
  if (name.value.trim().length === 0) {
    fieldError.value = 'A name is required.'
    return null
  }
  if (host.value.trim().length === 0) {
    fieldError.value = 'A host is required.'
    return null
  }
  if (user.value.trim().length === 0) {
    fieldError.value = 'A user name is required.'
    return null
  }
  if (Number.isNaN(parsedPort)) {
    fieldError.value = 'A port between 1 and 65535 is required.'
    return null
  }
  fieldError.value = ''

  const payload: CreateAccountPayload = {
    name: name.value.trim(),
    host: host.value.trim(),
    port: parsedPort,
    user: user.value.trim(),
    password: password.value,
    tls: tls.value,
    allow_start_tls: allowStartTls.value,
    save_to_sent: saveToSent.value,
  }

  const trimmedEmail = email.value.trim()
  if (trimmedEmail.length > 0) payload.email = trimmedEmail

  const trimmedSentFolder = sentFolder.value.trim()
  if (trimmedSentFolder.length > 0) payload.sent_folder = trimmedSentFolder

  const bcc = parseMultiValue(defaultBcc.value)
  if (bcc !== null) payload.default_bcc = bcc

  const from = parseListValue(allowedFrom.value)
  if (from.length > 0) payload.allowed_from = from

  if (hasSmtp.value) {
    const parsedSmtpPort = parsePort(smtpPort.value)
    if (Number.isNaN(parsedSmtpPort)) {
      fieldError.value = 'A valid SMTP port between 1 and 65535 is required.'
      return null
    }
    payload.smtp = {
      host: smtpHost.value.trim(),
      port: parsedSmtpPort,
      secure: smtpSecure.value,
    }
    const trimmedSmtpUser = smtpUser.value.trim()
    if (trimmedSmtpUser.length > 0) payload.smtp.user = trimmedSmtpUser
    if (smtpPassword.value.length > 0) payload.smtp.password = smtpPassword.value
  }

  return payload
}

async function onSubmit(): Promise<void> {
  if (submitting.value) return
  const payload = buildPayload()
  if (payload === null) return
  submitting.value = true
  errorMessage.value = ''
  try {
    const created = await createUserAccount(payload)
    // The credentials served their purpose: they are not retained.
    password.value = ''
    smtpPassword.value = ''
    if (typeof created.account_encryption_key === 'string' && created.account_encryption_key.length > 0) {
      revealedKey.value = created.account_encryption_key
      keyDisclosure.value = 'created-with-account'
    } else {
      // The notice is handed to the account list, which shows it.
      setUserNotice(`The account "${created.account.name}" was added.`)
      await router.push({ name: 'user-accounts' })
    }
  } catch (error) {
    if (error instanceof ApiError && error.status === 409) {
      errorMessage.value =
        'Account encryption is already active — it was activated by another request in the meantime. Retry to add the account.'
    } else if (error instanceof ApiError) {
      const disclosed = keyFromBody(error.body)
      if (disclosed !== null) {
        // The sanctioned failure-safe disclosure: the key is shown anyway.
        // The account was NOT stored — the copy must say so.
        revealedKey.value = disclosed
        keyDisclosure.value = 'created-after-failed-save'
        errorMessage.value =
          'The account was not saved, but your account-encryption key was created. Store it now — it is shown only once.'
      } else {
        errorMessage.value = 'The account could not be added. Check the fields and try again.'
      }
    } else {
      errorMessage.value = 'The account could not be added.'
    }
  } finally {
    submitting.value = false
  }
}

async function onKeyDone(): Promise<void> {
  const failedSave = keyAfterFailedSave.value
  revealedKey.value = null
  keyDisclosure.value = null
  // The key is gone: the stale error notice must not follow it.
  errorMessage.value = ''
  if (failedSave) {
    // The account list shows the notice: the account is NOT there.
    setUserNotice('The account was not saved. The account-encryption key was created — store it, then add the account again.')
  }
  await router.push({ name: 'user-accounts' })
}
</script>

<template>
  <div>
    <PageHeader
      title="Add account"
      description="The credentials are encrypted before they are stored and are never shown again."
    />

    <Card v-if="revealedKey" class="add__card">
      <template #title>Account encryption key</template>

      <ErrorBanner
        v-if="errorMessage"
        class="add__key-error"
        title="Account not added"
        :message="errorMessage"
      />

      <p class="add__summary">
        {{ keySummary }}
      </p>

      <KeyDisplay
        :value="revealedKey"
        label="Account encryption key"
        confirm-text="I have saved it"
        @done="onKeyDone"
      >
        <template #warning>
          {{ keyWarning }}
        </template>
      </KeyDisplay>
    </Card>

    <Card v-else class="add__card">
      <form class="add__form" novalidate @submit.prevent="onSubmit">
        <h2 class="add__legend">IMAP</h2>

        <TextField
          id="account-name"
          label="Account name"
          v-model="name"
          name="name"
          autocomplete="off"
          required
          :disabled="submitting"
        />

        <div class="add__row">
          <TextField
            id="account-host"
            label="Host"
            v-model="host"
            name="host"
            autocomplete="off"
            required
            :disabled="submitting"
          />
          <TextField
            id="account-port"
            label="Port"
            v-model="port"
            name="port"
            type="number"
            required
            :disabled="submitting"
          />
        </div>

        <TextField
          id="account-user"
          label="User name"
          v-model="user"
          name="user"
          autocomplete="off"
          required
          :disabled="submitting"
        />

        <TextField
          id="account-password"
          label="Password"
          v-model="password"
          name="password"
          type="password"
          autocomplete="new-password"
          :disabled="submitting"
        />

        <div class="add__checks">
          <Checkbox
            id="account-tls"
            label="TLS"
            v-model="tls"
            :disabled="submitting"
          />
          <Checkbox
            id="account-allow-start-tls"
            label="Allow STARTTLS"
            v-model="allowStartTls"
            :disabled="submitting"
          />
        </div>

        <h2 class="add__legend">Sending</h2>

        <TextField
          id="account-email"
          label="E-mail address"
          v-model="email"
          name="email"
          type="email"
          autocomplete="off"
          :disabled="submitting"
        />

        <Checkbox
          id="account-save-to-sent"
          label="Save sent messages to the Sent folder"
          v-model="saveToSent"
          :disabled="submitting"
        />

        <TextField
          id="account-sent-folder"
          label="Sent folder"
          v-model="sentFolder"
          name="sent_folder"
          autocomplete="off"
          :disabled="submitting"
        />

        <TextField
          id="account-default-bcc"
          label="Default BCC"
          v-model="defaultBcc"
          name="default_bcc"
          autocomplete="off"
          hint="One address, or several separated by commas."
          :disabled="submitting"
        />

        <TextField
          id="account-allowed-from"
          label="Allowed senders"
          v-model="allowedFrom"
          name="allowed_from"
          autocomplete="off"
          hint="One address, or several separated by commas."
          :disabled="submitting"
        />

        <h2 class="add__legend">SMTP (optional)</h2>

        <div class="add__row">
          <TextField
            id="account-smtp-host"
            label="SMTP host"
            v-model="smtpHost"
            name="smtp_host"
            autocomplete="off"
            :disabled="submitting"
          />
          <TextField
            id="account-smtp-port"
            label="SMTP port"
            v-model="smtpPort"
            name="smtp_port"
            type="number"
            :disabled="submitting"
          />
        </div>

        <Checkbox
          id="account-smtp-secure"
          label="SMTP over TLS"
          v-model="smtpSecure"
          :disabled="submitting"
        />

        <TextField
          id="account-smtp-user"
          label="SMTP user name"
          v-model="smtpUser"
          name="smtp_user"
          autocomplete="off"
          :disabled="submitting"
        />

        <TextField
          id="account-smtp-password"
          label="SMTP password"
          v-model="smtpPassword"
          name="smtp_password"
          type="password"
          autocomplete="new-password"
          :disabled="submitting"
        />

        <ErrorBanner
          v-if="errorMessage"
          title="Account not added"
          :message="errorMessage"
        />

        <p v-if="fieldError" class="add__field-error" role="alert">{{ fieldError }}</p>

        <div class="add__actions">
          <Button type="submit" variant="primary" :loading="submitting">Add account</Button>
        </div>
      </form>
    </Card>
  </div>
</template>

<style scoped>
.add__card {
  max-width: 720px;
}

.add__form {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  align-items: stretch;
}

.add__legend {
  margin-top: var(--space-2);
  font-size: var(--text-sm);
  font-weight: var(--weight-semibold);
  color: var(--color-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.add__row {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: var(--space-4);
}

.add__checks {
  display: flex;
  gap: var(--space-5);
  flex-wrap: wrap;
}

.add__summary {
  margin-bottom: var(--space-4);
  color: var(--color-muted);
}

.add__key-error {
  margin-bottom: var(--space-4);
}

.add__field-error {
  color: var(--color-danger);
  font-size: var(--text-sm);
}

.add__actions {
  display: flex;
  gap: var(--space-2);
}

@media (max-width: 640px) {
  .add__row {
    grid-template-columns: 1fr;
  }
}
</style>
