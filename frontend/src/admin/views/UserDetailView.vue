<script setup lang="ts">
/**
 * UserDetailView — one registry user (`/admin/users/:id`).
 *
 * Actions:
 *  - rotate the login key (the new key is disclosed exactly once);
 *  - enable/disable the user;
 *  - delete the user behind a type-to-confirm dialog that mirrors the old
 *    HTML `confirm_name` UX — the API-level protections (authentication +
 *    CSRF) are unchanged and are never replaced by the confirmation gate.
 */
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import AlertToast from '@/components/AlertToast.vue'
import Badge from '@/components/Badge.vue'
import Button from '@/components/Button.vue'
import Card from '@/components/Card.vue'
import Dialog from '@/components/Dialog.vue'
import ErrorBanner from '@/components/ErrorBanner.vue'
import KeyDisplay from '@/components/KeyDisplay.vue'
import LoadingState from '@/components/LoadingState.vue'
import NotFoundView from '@/admin/views/NotFoundView.vue'
import PageHeader from '@/components/PageHeader.vue'
import {
  ApiError,
  deleteAdminUser,
  getAdminUser,
  rotateAdminUserKey,
  setAdminUserStatus,
  type AdminUser,
} from '@/lib/api'

const route = useRoute()
const router = useRouter()

const user = ref<AdminUser | null>(null)
const loading = ref(true)
const errorMessage = ref('')
const notFound = ref(false)

const rotating = ref(false)
const statusBusy = ref(false)
const deleting = ref(false)
const deleteOpen = ref(false)
const newKey = ref<string | null>(null)

const notice = ref('')
const noticeVariant = ref<'success' | 'danger'>('success')

const userId = computed(() => String(route.params.id ?? ''))
const isActive = computed(() => user.value?.status === 'active')

onBeforeUnmount(() => {
  // The rotated key dies with the view; it is never re-fetchable.
  newKey.value = null
})

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  notFound.value = false
  try {
    user.value = await getAdminUser(userId.value)
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) {
      notFound.value = true
      user.value = null
    } else {
      errorMessage.value = 'The user could not be loaded. The session may have expired.'
    }
  } finally {
    loading.value = false
  }
}

watch(userId, () => void load(), { immediate: true })

async function onRotate(): Promise<void> {
  if (rotating.value) return
  rotating.value = true
  errorMessage.value = ''
  try {
    const rotated = await rotateAdminUserKey(userId.value)
    newKey.value = rotated.login_key
    if (user.value !== null) user.value.key_generation = rotated.key_generation
    noticeVariant.value = 'success'
    notice.value = 'A new login key was minted. The previous key no longer works.'
  } catch (error) {
    errorMessage.value =
      error instanceof ApiError && error.status === 404
        ? 'This user no longer exists.'
        : 'The login key could not be rotated.'
  } finally {
    rotating.value = false
  }
}

function onKeyDone(): void {
  newKey.value = null
}

async function onToggleStatus(): Promise<void> {
  if (user.value === null || statusBusy.value) return
  const next = user.value.status === 'active' ? 'disabled' : 'active'
  statusBusy.value = true
  errorMessage.value = ''
  try {
    user.value = await setAdminUserStatus(userId.value, next)
    noticeVariant.value = 'success'
    notice.value = next === 'active' ? 'The user is enabled again.' : 'The user is disabled.'
  } catch (error) {
    errorMessage.value =
      error instanceof ApiError && error.status === 404
        ? 'This user no longer exists.'
        : 'The status could not be changed.'
  } finally {
    statusBusy.value = false
  }
}

async function onDelete(): Promise<void> {
  if (deleting.value) return
  deleting.value = true
  errorMessage.value = ''
  try {
    await deleteAdminUser(userId.value)
    deleteOpen.value = false
    noticeVariant.value = 'success'
    notice.value = 'The user was deleted.'
    await router.push({ name: 'admin-users' })
  } catch (error) {
    errorMessage.value =
      error instanceof ApiError && error.status === 404
        ? 'This user no longer exists.'
        : 'The user could not be deleted.'
    deleteOpen.value = false
  } finally {
    deleting.value = false
  }
}
</script>

<template>
  <div>
    <NotFoundView
      v-if="notFound"
      title="User not found"
      message="This user does not exist, or it was deleted."
    />

    <template v-else>
      <PageHeader
        :title="user?.name ?? 'User'"
        :description="`Registry id ${userId}`"
      />

      <LoadingState v-if="loading" label="Loading user…" />

      <ErrorBanner
        v-else-if="errorMessage"
        title="Action failed"
        :message="errorMessage"
      />

      <template v-else-if="user">
        <AlertToast
          v-if="notice"
          :message="notice"
          :variant="noticeVariant"
          @dismiss="notice = ''"
        />

        <Card title="Details" class="detail__card">
          <dl class="detail__grid">
            <div class="detail__pair">
              <dt>Name</dt>
              <dd>{{ user.name }}</dd>
            </div>
            <div class="detail__pair">
              <dt>Status</dt>
              <dd>
                <Badge :variant="isActive ? 'success' : 'muted'">{{ user.status }}</Badge>
              </dd>
            </div>
            <div class="detail__pair">
              <dt>Key generation</dt>
              <dd>{{ user.key_generation }}</dd>
            </div>
            <div class="detail__pair">
              <dt>Accounts</dt>
              <dd>{{ user.account_count }}</dd>
            </div>
            <div class="detail__pair">
              <dt>Created</dt>
              <dd>{{ user.created_at }}</dd>
            </div>
          </dl>
        </Card>

        <Card v-if="newKey" title="New login key" class="detail__card">
          <KeyDisplay
            :value="newKey"
            label="Login key"
            confirm-text="I have saved it"
            @done="onKeyDone"
          />
        </Card>

        <Card title="Actions" class="detail__card">
          <div class="detail__actions">
            <Button :loading="rotating" @click="onRotate">Rotate login key</Button>
            <Button :loading="statusBusy" @click="onToggleStatus">
              {{ isActive ? 'Disable user' : 'Enable user' }}
            </Button>
            <Button variant="danger" @click="deleteOpen = true">Delete user</Button>
          </div>
          <p class="detail__hint">
            Rotating a key invalidates the previous one immediately. Disabling a
            user keeps the key but blocks sign-in.
          </p>
        </Card>

        <Dialog
          v-model="deleteOpen"
          title="Delete user"
          :confirm-label="user.name"
          confirm-text="Delete"
          destructive
          :busy="deleting"
          @confirm="onDelete"
        >
          <p>
            This removes the user and their whole directory. It cannot be
            undone. Type the user's exact name to confirm.
          </p>
        </Dialog>
      </template>
    </template>
  </div>
</template>

<style scoped>
.detail__card {
  margin-bottom: var(--space-5);
}

.detail__grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: var(--space-4);
  margin: 0;
}

.detail__pair dt {
  font-size: var(--text-sm);
  color: var(--color-muted);
}

.detail__pair dd {
  margin: var(--space-1) 0 0;
  color: var(--color-text);
}

.detail__actions {
  display: flex;
  gap: var(--space-2);
  flex-wrap: wrap;
}

.detail__hint {
  margin-top: var(--space-3);
  font-size: var(--text-sm);
  color: var(--color-muted);
}
</style>
