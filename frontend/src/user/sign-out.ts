import type { Router } from 'vue-router'
import { userLogout } from '@/lib/api'
import { forget } from '@/lib/session'

/**
 * Sign-out — the shared user-surface action.
 *
 * `POST /api/me/logout` is CSRF-protected; the session cookie is deleted by
 * the server. The local session state is dropped either way: a dead session is
 * not a failed sign-out, it is simply over. The user lands on the login view,
 * which tells them what happened (the reason travels in the route query — a
 * notice, never a secret).
 */
export type SignOutResult = 'signed-out' | 'local-only'

export async function signOutUser(router: Router): Promise<SignOutResult> {
  let result: SignOutResult = 'signed-out'
  try {
    await userLogout()
  } catch {
    result = 'local-only'
  } finally {
    forget()
  }
  await router.push({
    name: 'user-login',
    query: { reason: result === 'signed-out' ? 'signed-out' : 'signed-out-local' },
  })
  return result
}
