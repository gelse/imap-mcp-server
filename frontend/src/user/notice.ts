import { ref } from 'vue'

/**
 * Cross-view notice — the one-line message that survives a navigation.
 *
 * A toast that lives in the view that produced it disappears the moment the
 * router swaps the view. The account-add flow is exactly that case: it
 * reports its success and moves on to the account list, so the message has to
 * outlive the view that created it. This tiny module is the hand-over point.
 *
 * Only non-secret, human-readable text travels through it — never a key, a
 * credential or anything else that must not be re-read.
 */

export interface UserNotice {
  message: string
  variant: 'success' | 'info' | 'danger'
}

/** The pending notice (null when there is none). */
export const userNotice = ref<UserNotice | null>(null)

/** Publish a notice for the next view. */
export function setUserNotice(message: string, variant: UserNotice['variant'] = 'success'): void {
  userNotice.value = { message, variant }
}

/** Drop the pending notice (the toast was dismissed). */
export function clearUserNotice(): void {
  userNotice.value = null
}
