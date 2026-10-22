<script setup lang="ts">
/**
 * HomeView — the admin dashboard (`/admin`).
 *
 * A summary of the registry: how many users exist, how many are active, and
 * whether the API answers. Every number comes from the JSON API — the view
 * never invents state.
 */
import { computed, onMounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import Badge from '@/components/Badge.vue'
import Card from '@/components/Card.vue'
import ErrorBanner from '@/components/ErrorBanner.vue'
import LoadingState from '@/components/LoadingState.vue'
import PageHeader from '@/components/PageHeader.vue'
import { adminHealth, ApiError, listAdminUsers, type AdminUser } from '@/lib/api'

const users = ref<AdminUser[]>([])
const loading = ref(true)
const errorMessage = ref('')
const health = ref<'ok' | 'unavailable' | 'unknown'>('unknown')

const total = computed(() => users.value.length)
const active = computed(() => users.value.filter((u) => u.status === 'active').length)
const disabled = computed(() => users.value.filter((u) => u.status === 'disabled').length)

async function load(): Promise<void> {
  loading.value = true
  errorMessage.value = ''
  try {
    const [list, ping] = await Promise.all([listAdminUsers(), adminHealth()])
    users.value = list
    health.value = ping.status === 'ok' ? 'ok' : 'unavailable'
  } catch (error) {
    health.value = 'unavailable'
    errorMessage.value =
      error instanceof ApiError
        ? 'The dashboard data could not be loaded. The session may have expired.'
        : 'The dashboard data could not be loaded.'
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <PageHeader
      title="Dashboard"
      description="Overview of the user registry and the health of the admin API."
    >
      <template #actions>
        <RouterLink class="dashboard__cta" to="/admin/users/new">Create user</RouterLink>
      </template>
    </PageHeader>

    <LoadingState v-if="loading" label="Loading dashboard…" />

    <ErrorBanner
      v-else-if="errorMessage"
      title="Dashboard unavailable"
      :message="errorMessage"
    />

    <template v-else>
      <div class="dashboard__grid">
        <Card title="Users">
          <p class="dashboard__metric">{{ total }}</p>
          <p class="dashboard__caption">registered in total</p>
        </Card>

        <Card title="Active">
          <p class="dashboard__metric">{{ active }}</p>
          <p class="dashboard__caption">
            <Badge variant="success">Active</Badge>
          </p>
        </Card>

        <Card title="Disabled">
          <p class="dashboard__metric">{{ disabled }}</p>
          <p class="dashboard__caption">
            <Badge variant="muted">Disabled</Badge>
          </p>
        </Card>

        <Card title="API health">
          <p class="dashboard__metric">
            <Badge :variant="health === 'ok' ? 'success' : 'danger'">
              {{ health === 'ok' ? 'OK' : 'Unavailable' }}
            </Badge>
          </p>
          <p class="dashboard__caption">GET /api/admin/health</p>
        </Card>
      </div>

      <Card v-if="total === 0" title="No users yet" class="dashboard__empty">
        <p class="dashboard__caption">
          The registry is empty. Create the first user to get a one-time login key.
        </p>
        <template #footer>
          <RouterLink class="dashboard__cta" to="/admin/users/new">Create user</RouterLink>
        </template>
      </Card>
    </template>
  </div>
</template>

<style scoped>
.dashboard__grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
  gap: var(--space-4);
}

.dashboard__metric {
  font-size: var(--text-xl);
  font-weight: var(--weight-semibold);
  color: var(--color-text);
}

.dashboard__caption {
  margin-top: var(--space-1);
  font-size: var(--text-sm);
  color: var(--color-muted);
}

.dashboard__empty {
  margin-top: var(--space-5);
}

.dashboard__cta {
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

.dashboard__cta:hover {
  background-color: var(--color-primary-hover);
  color: var(--color-on-primary);
}
</style>
