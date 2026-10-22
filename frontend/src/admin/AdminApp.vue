<script setup lang="ts">
/**
 * AdminApp — the frame of the admin surface.
 *
 * Owns the navigation, the sign-out action and the surface-level notices.
 * The routed view renders inside the shell's main landmark.
 */
import { computed, ref } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import AlertToast from '@/components/AlertToast.vue'
import AppShell from '@/components/AppShell.vue'
import Button from '@/components/Button.vue'
import { adminLogout, ApiError } from '@/lib/api'
import { forget } from '@/lib/session'

const route = useRoute()
const router = useRouter()

const signingOut = ref(false)
const notice = ref('')
const noticeVariant = ref<'success' | 'danger' | 'info'>('success')

const isLoginView = computed(() => route.name === 'admin-login')

async function onSignOut(): Promise<void> {
  if (signingOut.value) return
  signingOut.value = true
  try {
    await adminLogout()
    noticeVariant.value = 'success'
    notice.value = 'Signed out.'
  } catch (error) {
    // A dead session is not a failure: the local state is dropped either way.
    noticeVariant.value = error instanceof ApiError && error.status === 401 ? 'info' : 'danger'
    notice.value = 'Sign-out could not be confirmed — the local session was cleared anyway.'
  } finally {
    forget()
    signingOut.value = false
    void router.push({ name: 'admin-login' })
  }
}
</script>

<template>
  <AppShell title="Admin">
    <template v-if="!isLoginView" #nav>
      <RouterLink class="nav-link" to="/admin">Dashboard</RouterLink>
      <RouterLink class="nav-link" to="/admin/users">Users</RouterLink>
      <RouterLink class="nav-link" to="/admin/users/new">New user</RouterLink>
    </template>

    <template v-if="!isLoginView" #actions>
      <Button variant="secondary" :loading="signingOut" @click="onSignOut">Sign out</Button>
    </template>

    <AlertToast
      v-if="notice"
      :message="notice"
      :variant="noticeVariant"
      @dismiss="notice = ''"
    />

    <RouterView />
  </AppShell>
</template>

<style scoped>
.nav-link {
  display: block;
  padding: var(--space-2) var(--space-3);
  border-radius: var(--radius-md);
  text-decoration: none;
  color: var(--color-text);
  font-weight: var(--weight-medium);
}

.nav-link:hover {
  background-color: var(--color-surface-alt);
}

.nav-link.router-link-active {
  background-color: var(--color-surface-alt);
  color: var(--color-primary);
}
</style>
