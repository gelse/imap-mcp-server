/**
 * Router — the SPA's history-mode route table.
 *
 * Two role surfaces live under one application, selected by URL prefix:
 * `/admin/*` renders the admin section, `/user/*` the user section.
 *
 * Deep links work because the server serves the SPA shell for every
 * `/admin|/user` GET (M07-T05). In-SPA navigation never triggers a full page
 * load, so the in-memory CSRF token survives navigation.
 *
 * Route guards:
 *  - every route except the two login views requires a session; the guard
 *    bootstraps the CSRF token (the cookie session survives a reload, the
 *    in-memory token does not) and redirects to the OWNING surface's login
 *    view when there is no session;
 *  - a 401 raised by any API call drops the session and routes to the owning
 *    surface's login view with a "session expired" notice.
 */

import {
  createRouter,
  createWebHistory,
  type RouteRecordRaw,
  type Router,
  type RouterHistory,
} from 'vue-router'
import AdminApp from '@/admin/AdminApp.vue'
import HomeView from '@/admin/views/HomeView.vue'
import LoginView from '@/admin/views/LoginView.vue'
import NotFoundView from '@/admin/views/NotFoundView.vue'
import UserCreateView from '@/admin/views/UserCreateView.vue'
import UserDetailView from '@/admin/views/UserDetailView.vue'
import UsersView from '@/admin/views/UsersView.vue'
import UserApp from '@/user/UserApp.vue'
import AccountAddView from '@/user/views/AccountAddView.vue'
import AccountEditView from '@/user/views/AccountEditView.vue'
import AccountsView from '@/user/views/AccountsView.vue'
import UserLoginView from '@/user/views/LoginView.vue'
import SettingsView from '@/user/views/SettingsView.vue'
import { ensureSession, setSessionExpiredHandler, type Surface } from '@/lib/session'

export const routes: RouteRecordRaw[] = [
  {
    path: '/',
    redirect: { name: 'admin-home' },
  },
  {
    path: '/admin',
    component: AdminApp,
    children: [
      { path: '', name: 'admin-home', component: HomeView },
      {
        path: 'login',
        name: 'admin-login',
        component: LoginView,
        meta: { public: true },
      },
      { path: 'users', name: 'admin-users', component: UsersView },
      { path: 'users/new', name: 'admin-user-create', component: UserCreateView },
      { path: 'users/:id', name: 'admin-user-detail', component: UserDetailView },
      { path: ':pathMatch(.*)*', name: 'admin-not-found', component: NotFoundView },
    ],
  },
  {
    path: '/user',
    component: UserApp,
    children: [
      { path: '', name: 'user-accounts', component: AccountsView },
      {
        path: 'login',
        name: 'user-login',
        component: UserLoginView,
        meta: { public: true },
      },
      { path: 'accounts/new', name: 'user-account-add', component: AccountAddView },
      { path: 'accounts/:id', name: 'user-account-edit', component: AccountEditView },
      { path: 'settings', name: 'user-settings', component: SettingsView },
      {
        path: ':pathMatch(.*)*',
        name: 'user-not-found',
        component: NotFoundView,
        props: { homeTo: '/user' },
      },
    ],
  },
]

function surfaceOf(path: string): Surface {
  return path.startsWith('/user') ? 'user' : 'admin'
}

/**
 * Build the application router. The history implementation is injectable so
 * tests can run against a memory history without touching window.location.
 */
export function createAppRouter(history?: RouterHistory): Router {
  const router = createRouter({
    history: history ?? createWebHistory(),
    routes,
  })

  router.beforeEach(async (to) => {
    if (to.meta.public === true) return true
    const surface = surfaceOf(to.path)
    const ok = await ensureSession(surface)
    if (ok) return true
    if (surface === 'user') return { name: 'user-login', query: { reason: 'required' } }
    return { name: 'admin-login', query: { reason: 'required' } }
  })

  setSessionExpiredHandler(() => {
    const current = router.currentRoute.value
    if (current.meta.public === true) return
    // Each surface lands on ITS OWN login view (the sessions are separate).
    if (surfaceOf(current.path) === 'user') {
      void router.push({ name: 'user-login', query: { reason: 'expired' } })
      return
    }
    void router.push({ name: 'admin-login', query: { reason: 'expired' } })
  })

  return router
}

/** The application router instance used by main.ts. */
export const router = createAppRouter()
