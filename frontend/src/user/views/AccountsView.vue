<script setup lang="ts">
/**
 * AccountsView — the user's account list (`/user`).
 *
 * ONE bootstrap call (`GET /api/me`) renders both the profile header and the
 * account table — the API returns the profile and the listing together, and
 * the listing is metadata only: it carries no credential material by
 * construction.
 *
 * Row actions:
 *  - edit → the account form (`/user/accounts/:id`);
 *  - delete → a type-to-confirm dialog that mirrors the retired HTML form's
 *    `confirm_name` UX. The confirmation is a UI-level affordance only: the
 *    DELETE endpoint stays CSRF-protected and never asks for a name.
 */
import { onBeforeUnmount, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import AlertToast from '@/components/AlertToast.vue'
import Badge from '@/components/Badge.vue'
import Button from '@/components/Button.vue'
import Card from '@/components/Card.vue'
import DataTable from '@/components/DataTable.vue'
import Dialog from '@/components/Dialog.vue'
import EmptyState from '@/components/EmptyState.vue'
import ErrorBanner from '@/components/ErrorBanner.vue'
import LoadingState from '@/components/LoadingState.vue'
import PageHeader from '@/components/PageHeader.vue'
import { ApiError, deleteUserAccount, getUserProfile, type UserAccountView, type UserProfile } from '@/lib/api'
import { clearUserNotice, setUserNotice, userNotice } from '@/user/notice'

const profile = ref<UserProfile | null>(null)
const loading = ref(true)
const refreshing = ref(false)
const errorMessage = ref('')

const deleteOpen = ref(false)
const deleteTarget = ref<UserAccountView | null>(null)
const deleting = ref(false)

const columns = [
  { key: 'name', label: 'Name' },
  { key: 'host', label: 'Host' },
  { key: 'user', label: 'User' },
  { key: 'tls', label: 'TLS' },
  { key: 'smtp', label: 'SMTP' },
]

function hostPort(row: Record<string, unknown>): string {
  const host = String(row.host ?? '')
  const port = String(row.port ?? '')
  if (host.length === 0) return '—'
  return port.length > 0 ? `${host}:${port}` : host
}

function smtpLabel(row: Record<string, unknown>): string {
  const smtp = row.smtp as { host?: string } | undefined
  if (smtp === undefined || typeof smtp.host !== 'string' || smtp.host.length === 0) {
    return '—'
  }
  return smtp.host
}

async function load(silent = false): Promise<void> {
  if (silent) refreshing.value = true
  else loading.value = true
  errorMessage.value = ''
  try {
    profile.value = await getUserProfile()
    if (silent) setUserNotice('The account list was refreshed.')
  } catch (error) {
    errorMessage.value =
      error instanceof ApiError
        ? 'Your accounts could not be loaded. The session may have expired.'
        : 'Your accounts could not be loaded.'
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

onMounted(() => {
  void load()
})

onBeforeUnmount(() => {
  // A pending notice does not outlive the view that would show it.
  clearUserNotice()
})

function openDelete(account: UserAccountView): void {
  deleteTarget.value = account
  deleteOpen.value = true
}

/** The table hands out its rows untyped; they are account views. */
function asAccount(row: Record<string, unknown>): UserAccountView {
  return row as unknown as UserAccountView
}

async function onDelete(): Promise<void> {
  const target = deleteTarget.value
  if (target === null || deleting.value) return
  deleting.value = true
  errorMessage.value = ''
  try {
    await deleteUserAccount(target.id)
    deleteOpen.value = false
    deleteTarget.value = null
    await load(true)
    setUserNotice(`The account "${target.name}" was deleted.`)
  } catch (error) {
    deleteOpen.value = false
    if (error instanceof ApiError && error.status === 404) {
      deleteTarget.value = null
      await load(true)
      errorMessage.value = 'This account no longer exists. The list was refreshed.'
    } else {
      errorMessage.value = 'The account could not be deleted.'
    }
  } finally {
    deleting.value = false
  }
}
</script>

<template>
  <div>
    <PageHeader
      :title="profile?.name ?? 'My accounts'"
      description="The mail accounts this login key can use."
    >
      <template #actions>
        <Button :loading="refreshing" @click="load(true)">Refresh</Button>
        <RouterLink class="accounts__cta" to="/user/accounts/new">Add account</RouterLink>
      </template>
    </PageHeader>

    <AlertToast
      v-if="userNotice"
      :message="userNotice.message"
      :variant="userNotice.variant"
      @dismiss="clearUserNotice()"
    />

    <LoadingState v-if="loading" label="Loading accounts…" />

    <ErrorBanner
      v-else-if="errorMessage"
      title="Accounts unavailable"
      :message="errorMessage"
    />

    <template v-else-if="profile">
      <Card title="Profile" class="accounts__card">
        <dl class="accounts__profile">
          <div class="accounts__pair">
            <dt>Name</dt>
            <dd>{{ profile.name }}</dd>
          </div>
          <div class="accounts__pair">
            <dt>Key generation</dt>
            <dd>{{ profile.key_generation }}</dd>
          </div>
          <div class="accounts__pair">
            <dt>Account encryption</dt>
            <dd>
              <Badge :variant="profile.aek_active ? 'success' : 'muted'">
                {{ profile.aek_active ? 'Active' : 'Not active' }}
              </Badge>
            </dd>
          </div>
        </dl>
      </Card>

      <Card v-if="profile.accounts.length === 0" class="accounts__card">
        <EmptyState title="No accounts yet">
          Add your first mail account. The credentials are stored encrypted and
          are never shown again.
          <template #actions>
            <RouterLink class="accounts__cta" to="/user/accounts/new">Add account</RouterLink>
          </template>
        </EmptyState>
      </Card>

      <Card v-else class="accounts__card">
        <DataTable :columns="columns" :rows="profile.accounts" caption="Your accounts" stack-on-mobile>
          <template #cell:host="{ row }">
            {{ hostPort(row) }}
          </template>

          <template #cell:tls="{ value }">
            <Badge :variant="value === true ? 'success' : 'muted'">
              {{ value === true ? 'TLS' : 'Plain' }}
            </Badge>
          </template>

          <template #cell:smtp="{ row }">
            {{ smtpLabel(row) }}
          </template>

          <template #actions="{ row }">
            <RouterLink class="accounts__link" :to="`/user/accounts/${String(row.id)}`">
              Edit
            </RouterLink>
            <Button
              variant="danger"
              class="accounts__delete"
              @click="openDelete(asAccount(row))"
            >
              Delete
            </Button>
          </template>
        </DataTable>
      </Card>
    </template>

    <Dialog
      v-model="deleteOpen"
      title="Delete account"
      :confirm-label="deleteTarget?.name ?? ''"
      confirm-text="Delete"
      destructive
      :busy="deleting"
      @confirm="onDelete"
    >
      <p>
        This removes the account and its stored credentials. It cannot be
        undone. Type the account's exact name to confirm.
      </p>
    </Dialog>
  </div>
</template>

<style scoped>
.accounts__card {
  margin-bottom: var(--space-5);
}

.accounts__profile {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--space-4);
  margin: 0;
}

.accounts__pair dt {
  font-size: var(--text-sm);
  color: var(--color-muted);
}

.accounts__pair dd {
  margin: var(--space-1) 0 0;
  color: var(--color-text);
}

.accounts__cta {
  display: inline-flex;
  align-items: center;
  min-height: var(--control-height);
  padding: 0 var(--space-4);
  border-radius: var(--radius-md);
  background-color: var(--color-primary);
  color: var(--color-on-primary);
  text-decoration: none;
  font-weight: var(--weight-medium);
}

.accounts__cta:hover {
  background-color: var(--color-primary-hover);
  color: var(--color-on-primary);
}

.accounts__link {
  font-weight: var(--weight-medium);
}

.accounts__delete {
  min-height: var(--control-height);
}
</style>
