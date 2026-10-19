<script setup lang="ts">
/**
 * UserApp — the frame of the user surface (`/user`).
 *
 * Owns the navigation, the sign-out action and the surface-level notices; the
 * routed view renders inside the shell's main landmark. The sign-out lives
 * here (as on the admin surface) so it is reachable from every view — the
 * settings view offers the same action.
 */
import { computed, ref } from 'vue'
import { RouterLink, RouterView, useRoute, useRouter } from 'vue-router'
import AlertToast from '@/components/AlertToast.vue'
import AppShell from '@/components/AppShell.vue'
import Button from '@/components/Button.vue'
import { signOutUser } from '@/user/sign-out'

const route = useRoute()
const router = useRouter()

const signingOut = ref(false)
const notice = ref('')
const noticeVariant = ref<'success' | 'info' | 'danger'>('success')

const isLoginView = computed(() => route.name === 'user-login')

async function onSignOut(): Promise<void> {
  if (signingOut.value) return
  signingOut.value = true
  try {
    const result = await signOutUser(router)
    noticeVariant.value = result === 'signed-out' ? 'success' : 'info'
    notice.value =
      result === 'signed-out'
        ? 'Signed out.'
        : 'Sign-out could not be confirmed — the local session was cleared anyway.'
  } finally {
    signingOut.value = false
  }
}
</script>

<template>
  <AppShell title="My account">
    <template v-if="!isLoginView" #nav>
      <RouterLink class="nav-link" to="/user">Accounts</RouterLink>
      <RouterLink class="nav-link" to="/user/accounts/new">Add account</RouterLink>
      <RouterLink class="nav-link" to="/user/settings">Settings</RouterLink>
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
