<script setup lang="ts">
/**
 * AccountEditView — edit a mail account (`/user/accounts/:id`).
 *
 * The account is loaded from the listing (`GET /api/me` — there is no
 * single-account GET by decision) and only the NON-CREDENTIAL fields are
 * prefilled. The credential inputs (`password`, `smtp.password` and the
 * credential-adjacent `smtp.user`) are always blank and are never prefilled:
 * the API never returns them, so a prefilled value could only ever be a
 * secret in the DOM.
 *
 * The submit maps the blank-means-unchanged semantics onto the partial
 * update:
 *  - a blank `password` / `smtp.password` is OMITTED from the body — the
 *    sticky merge keeps the stored value;
 *  - a typed value is sent; the explicit "clear the stored credential"
 *    switches send an empty string, which is the store's documented "no
 *    credential" value (the IMAP password is then sealed like any other
 *    credential — exactly like upstream's `addAccount` writes it);
 *  - the non-credential optional fields (email, sent folder, default BCC,
 *    allowed senders and the `save_to_sent` switch) are prefilled from the
 *    account view and ALWAYS submitted — a blank there is a deliberate
 *    erasure, exactly like the retired HTML form;
 *  - the `smtp` block is only sent when an SMTP host is present (the block
 *    itself cannot be removed through this form).
 */
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import AlertToast from '@/components/AlertToast.vue'
import Button from '@/components/Button.vue'
import Card from '@/components/Card.vue'
import Checkbox from '@/components/Checkbox.vue'
import ErrorBanner from '@/components/ErrorBanner.vue'
import LoadingState from '@/components/LoadingState.vue'
import NotFoundView from '@/admin/views/NotFoundView.vue'
import PageHeader from '@/components/PageHeader.vue'
import TextField from '@/components/TextField.vue'
import { ApiError, getUserProfile, updateUserAccount, type UpdateAccountPayload, type UserAccountView } from '@/lib/api'
import { displayMulti, parseListValue, parseMultiValue, parsePort } from '@/user/account-fields'

const route = useRoute()

const accountId = computed(() => String(route.params.id ?? ''))

const account = ref<UserAccountView | null>(null)
const loading = ref(true)
const notFound = ref(false)
const errorMessage = ref('')
const fieldError = ref('')
const notice = ref('')

const name = ref('')
const host = ref('')
const port = ref('')
const user = ref('')
const password = ref('')
const clearImapCredential = ref(false)
const tls = ref(false)
const allowStartTls = ref(false)
const email = ref('')
const saveToSent = ref(false)
const sentFolder = ref('')
const defaultBcc = ref('')
const allowedFrom = ref('')

const smtpHost = ref('')
const smtpPort = ref('')
const smtpSecure = ref(false)
const smtpUser = ref('')
const smtpPassword = ref('')
const clearSmtpCredential = ref(false)

const submitting = ref(false)

const hasSmtp = computed(() => smtpHost.value.trim().length > 0)

/** Prefill the form from an account view — never with a credential. */
function prefill(view: UserAccountView): void {
  name.value = view.name
  host.value = view.host
  port.value = String(view.port)
  user.value = view.user
  password.value = ''
  clearImapCredential.value = false
  tls.value = view.tls
  allowStartTls.value = view.allow_start_tls === true
  email.value = view.email ?? ''
  saveToSent.value = view.save_to_sent === true
  sentFolder.value = view.sent_folder ?? ''
  defaultBcc.value = displayMulti(view.default_bcc)
  allowedFrom.value = displayMulti(view.allowed_from)
  smtpHost.value = view.smtp?.host ?? ''
  smtpPort.value = view.smtp === undefined ? '' : String(view.smtp.port)
  smtpSecure.value = view.smtp?.secure === true
  // Credential-adjacent fields are never prefilled.
  smtpUser.value = ''
  smtpPassword.value = ''
  clearSmtpCredential.value = false
}

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  notFound.value = false
  try {
    const profile = await getUserProfile()
    const found = profile.accounts.find((entry) => entry.id === accountId.value)
    if (found === undefined) {
      notFound.value = true
      account.value = null
    } else {
      account.value = found
      prefill(found)
    }
  } catch (error) {
    errorMessage.value =
      error instanceof ApiError
        ? 'This account could not be loaded. The session may have expired.'
        : 'This account could not be loaded.'
  } finally {
    loading.value = false
  }
}

onMounted(load)
watch(accountId, () => void load())

function buildPayload(): UpdateAccountPayload | null {
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

  const payload: UpdateAccountPayload = {
    name: name.value.trim(),
    host: host.value.trim(),
    port: parsedPort,
    user: user.value.trim(),
    tls: tls.value,
    allow_start_tls: allowStartTls.value,
    // The non-credential optional fields are always submitted: a blank one is
    // a deliberate erasure, not "keep what is stored".
    email: email.value.trim(),
    save_to_sent: saveToSent.value,
    sent_folder: sentFolder.value.trim(),
    default_bcc: parseMultiValue(defaultBcc.value) ?? '',
    allowed_from: parseListValue(allowedFrom.value),
  }

  // A blank credential means "keep the stored value" — omit it entirely.
  if (clearImapCredential.value) {
    // Explicitly empty: the store's documented "no credential" value.
    payload.password = ''
  } else if (password.value.length > 0) {
    payload.password = password.value
  }

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
    if (clearSmtpCredential.value) {
      // Explicitly empty: the store's documented "no credential" value.
      payload.smtp.password = ''
    } else if (smtpPassword.value.length > 0) {
      payload.smtp.password = smtpPassword.value
    }
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
    const updated = await updateUserAccount(accountId.value, payload)
    // The typed credentials are not kept in the form either.
    password.value = ''
    clearImapCredential.value = false
    smtpPassword.value = ''
    smtpUser.value = ''
    clearSmtpCredential.value = false
    account.value = updated.account
    prefill(updated.account)
    notice.value = 'The account was updated.'
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      notFound.value = true
      errorMessage.value = 'This account no longer exists.'
    } else {
      errorMessage.value = 'The account could not be updated. Check the fields and try again.'
    }
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div>
    <NotFoundView
      v-if="notFound"
      title="Account not found"
      message="This account does not exist, or it was deleted."
    />

    <template v-else>
      <PageHeader
        title="Edit account"
        description="Credentials are write-only: leave them blank to keep the stored values."
      />

      <LoadingState v-if="loading" label="Loading account…" />

      <ErrorBanner
        v-else-if="errorMessage"
        title="Account not updated"
        :message="errorMessage"
      />

      <Card v-else class="edit__card">
        <AlertToast
          v-if="notice"
          :message="notice"
          variant="success"
          @dismiss="notice = ''"
        />

        <form class="edit__form" novalidate @submit.prevent="onSubmit">
          <h2 class="edit__legend">IMAP</h2>

          <TextField
            id="edit-account-name"
            label="Account name"
            v-model="name"
            name="name"
            autocomplete="off"
            required
            :disabled="submitting"
          />

          <div class="edit__row">
            <TextField
              id="edit-account-host"
              label="Host"
              v-model="host"
              name="host"
              autocomplete="off"
              required
              :disabled="submitting"
            />
            <TextField
              id="edit-account-port"
              label="Port"
              v-model="port"
              name="port"
              type="number"
              required
              :disabled="submitting"
            />
          </div>

          <TextField
            id="edit-account-user"
            label="User name"
            v-model="user"
            name="user"
            autocomplete="off"
            required
            :disabled="submitting"
          />

          <TextField
            id="edit-account-password"
            label="Password"
            v-model="password"
            name="password"
            type="password"
            autocomplete="new-password"
            hint="Leave blank to keep the stored password."
            :disabled="submitting"
          />

          <Checkbox
            id="edit-account-clear-imap-credential"
            label="Clear the stored IMAP credential"
            v-model="clearImapCredential"
            :disabled="submitting"
          />

          <div class="edit__checks">
            <Checkbox
              id="edit-account-tls"
              label="TLS"
              v-model="tls"
              :disabled="submitting"
            />
            <Checkbox
              id="edit-account-allow-start-tls"
              label="Allow STARTTLS"
              v-model="allowStartTls"
              :disabled="submitting"
            />
          </div>

          <h2 class="edit__legend">Sending</h2>

          <TextField
            id="edit-account-email"
            label="E-mail address"
            v-model="email"
            name="email"
            type="email"
            autocomplete="off"
            :disabled="submitting"
          />

          <Checkbox
            id="edit-account-save-to-sent"
            label="Save sent messages to the Sent folder"
            v-model="saveToSent"
            :disabled="submitting"
          />

          <TextField
            id="edit-account-sent-folder"
            label="Sent folder"
            v-model="sentFolder"
            name="sent_folder"
            autocomplete="off"
            :disabled="submitting"
          />

          <TextField
            id="edit-account-default-bcc"
            label="Default BCC"
            v-model="defaultBcc"
            name="default_bcc"
            autocomplete="off"
            hint="One address, or several separated by commas."
            :disabled="submitting"
          />

          <TextField
            id="edit-account-allowed-from"
            label="Allowed senders"
            v-model="allowedFrom"
            name="allowed_from"
            autocomplete="off"
            hint="One address, or several separated by commas."
            :disabled="submitting"
          />

          <h2 class="edit__legend">SMTP</h2>

          <div class="edit__row">
            <TextField
              id="edit-account-smtp-host"
              label="SMTP host"
              v-model="smtpHost"
              name="smtp_host"
              autocomplete="off"
              :disabled="submitting"
            />
            <TextField
              id="edit-account-smtp-port"
              label="SMTP port"
              v-model="smtpPort"
              name="smtp_port"
              type="number"
              :disabled="submitting"
            />
          </div>

          <Checkbox
            id="edit-account-smtp-secure"
            label="SMTP over TLS"
            v-model="smtpSecure"
            :disabled="submitting"
          />

          <TextField
            id="edit-account-smtp-user"
            label="SMTP user name"
            v-model="smtpUser"
            name="smtp_user"
            autocomplete="off"
            hint="Leave blank to keep the stored SMTP user name."
            :disabled="submitting"
          />

          <TextField
            id="edit-account-smtp-password"
            label="SMTP password"
            v-model="smtpPassword"
            name="smtp_password"
            type="password"
            autocomplete="new-password"
            hint="Leave blank to keep the stored SMTP password."
            :disabled="submitting"
          />

          <Checkbox
            id="edit-account-clear-smtp-credential"
            label="Clear the stored SMTP credential"
            v-model="clearSmtpCredential"
            :disabled="submitting || !hasSmtp"
          />

          <p v-if="fieldError" class="edit__field-error" role="alert">{{ fieldError }}</p>

          <div class="edit__actions">
            <Button type="submit" variant="primary" :loading="submitting">Save changes</Button>
          </div>
        </form>
      </Card>
    </template>
  </div>
</template>

<style scoped>
.edit__card {
  max-width: 720px;
}

.edit__form {
  display: flex;
  flex-direction: column;
  gap: var(--space-4);
  align-items: stretch;
}

.edit__legend {
  margin-top: var(--space-2);
  font-size: var(--text-sm);
  font-weight: var(--weight-semibold);
  color: var(--color-muted);
  text-transform: uppercase;
  letter-spacing: 0.04em;
}

.edit__row {
  display: grid;
  grid-template-columns: 2fr 1fr;
  gap: var(--space-4);
}

.edit__checks {
  display: flex;
  gap: var(--space-5);
  flex-wrap: wrap;
}

.edit__field-error {
  color: var(--color-danger);
  font-size: var(--text-sm);
}

.edit__actions {
  display: flex;
  gap: var(--space-2);
}

@media (max-width: 640px) {
  .edit__row {
    grid-template-columns: 1fr;
  }
}
</style>
