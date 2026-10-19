<script setup lang="ts">
/**
 * UsersView — the user list (`/admin/users`).
 *
 * Renders the admin metadata view of every registry user. The list never
 * carries key material — the API's metadata view is credential-free by
 * construction.
 */
import { onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import AlertToast from '@/components/AlertToast.vue'
import Badge from '@/components/Badge.vue'
import Button from '@/components/Button.vue'
import Card from '@/components/Card.vue'
import DataTable from '@/components/DataTable.vue'
import EmptyState from '@/components/EmptyState.vue'
import ErrorBanner from '@/components/ErrorBanner.vue'
import LoadingState from '@/components/LoadingState.vue'
import PageHeader from '@/components/PageHeader.vue'
import { ApiError, listAdminUsers, type AdminUser } from '@/lib/api'

const users = ref<AdminUser[]>([])
const loading = ref(true)
const refreshing = ref(false)
const errorMessage = ref('')
const notice = ref('')

const columns = [
  { key: 'name', label: 'Name' },
  { key: 'status', label: 'Status' },
  { key: 'key_generation', label: 'Key generation', align: 'right' as const },
  { key: 'account_count', label: 'Accounts', align: 'right' as const },
  { key: 'created_at', label: 'Created' },
]

function formatDate(value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) return '—'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleString()
}

function statusVariant(status: string): 'success' | 'muted' {
  return status === 'active' ? 'success' : 'muted'
}

async function load(silent = false): Promise<void> {
  if (silent) refreshing.value = true
  else loading.value = true
  errorMessage.value = ''
  try {
    users.value = await listAdminUsers()
    if (silent) notice.value = 'The user list was refreshed.'
  } catch (error) {
    errorMessage.value =
      error instanceof ApiError
        ? 'The user list could not be loaded. The session may have expired.'
        : 'The user list could not be loaded.'
  } finally {
    loading.value = false
    refreshing.value = false
  }
}

onMounted(() => {
  void load()
})
</script>

<template>
  <div>
    <PageHeader title="Users" description="Every account in the local user registry.">
      <template #actions>
        <Button :loading="refreshing" @click="load(true)">Refresh</Button>
        <RouterLink class="users__cta" to="/admin/users/new">Create user</RouterLink>
      </template>
    </PageHeader>

    <LoadingState v-if="loading" label="Loading users…" />

    <ErrorBanner
      v-if="errorMessage"
      title="Users unavailable"
      :message="errorMessage"
    />

    <AlertToast
      v-if="notice"
      :message="notice"
      variant="success"
      @dismiss="notice = ''"
    />

    <Card v-if="!loading && !errorMessage && users.length === 0">
      <EmptyState title="No users yet">
        The registry is empty. Create the first user to receive a one-time login key.
        <template #actions>
          <RouterLink class="users__cta" to="/admin/users/new">Create user</RouterLink>
        </template>
      </EmptyState>
    </Card>

    <Card v-if="!loading && !errorMessage && users.length > 0">
      <DataTable :columns="columns" :rows="users" caption="Registered users" stack-on-mobile>
        <template #cell:status="{ row }">
          <Badge :variant="statusVariant(String(row.status))">{{ String(row.status) }}</Badge>
        </template>

        <template #cell:created_at="{ value }">
          {{ formatDate(value) }}
        </template>

        <template #actions="{ row }">
          <RouterLink class="users__link" :to="`/admin/users/${String(row.id)}`">Manage</RouterLink>
        </template>
      </DataTable>
    </Card>
  </div>
</template>

<style scoped>
.users__cta {
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

.users__cta:hover {
  background-color: var(--color-primary-hover);
  color: var(--color-on-primary);
}

.users__link {
  font-weight: var(--weight-medium);
}
</style>
