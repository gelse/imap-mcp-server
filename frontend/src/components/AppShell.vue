<script setup lang="ts">
/**
 * AppShell — the application frame.
 *
 * Props:
 *   - title: surface title shown in the top bar (e.g. "Admin", "My account").
 *
 * Slots:
 *   - nav: nav items (rendered inside the <nav> landmark). Each item is an
 *     anchor/router-link supplied by the consuming view.
 *   - actions: top-bar action area (e.g. sign-out button) placed before the
 *     theme toggle.
 *
 * The top bar carries the surface title and a theme toggle. Navigation
 * collapses to a compact horizontal strip under the mobile breakpoint purely
 * via CSS media queries — no JS toggling library.
 */
import { computed, ref } from 'vue'
import {
  applyTheme,
  persistPreference,
  prefersDarkScheme,
  readStoredPreference,
  resolveTheme,
  type Theme,
  type ThemePreference,
} from '@/lib/theme'

const props = withDefaults(defineProps<{ title?: string }>(), { title: '' })

const preference = ref<ThemePreference>(readStoredPreference())
const theme = ref<Theme>(resolveTheme(preference.value, prefersDarkScheme()))

const toggleLabel = computed(() =>
  theme.value === 'dark' ? 'Switch to light theme' : 'Switch to dark theme',
)

function toggleTheme(): void {
  const next: Theme = theme.value === 'dark' ? 'light' : 'dark'
  theme.value = next
  preference.value = next
  applyTheme(next)
  persistPreference(next)
}
defineExpose({ theme, preference, toggleTheme })
</script>

<template>
  <div class="shell">
    <header class="shell__topbar">
      <div class="shell__brand">
        <span class="shell__logo" aria-hidden="true">
          <svg viewBox="0 0 32 32" width="24" height="24" role="img" focusable="false">
            <rect width="32" height="32" rx="6" fill="currentColor" />
            <path d="M7 11h18v10H7z" fill="none" stroke="var(--color-on-primary)" stroke-width="2" />
            <path d="M7 11l9 7 9-7" fill="none" stroke="var(--color-on-primary)" stroke-width="2" />
          </svg>
        </span>
        <span class="shell__title">{{ props.title }}</span>
      </div>

      <div class="shell__actions">
        <slot name="actions" />
        <button
          type="button"
          class="shell__theme-toggle"
          :aria-label="toggleLabel"
          :title="toggleLabel"
          @click="toggleTheme"
        >
          <!-- Inline SVG icons only — no emoji, icon fonts, or remote assets. -->
          <svg
            v-if="theme === 'dark'"
            viewBox="0 0 24 24"
            width="18"
            height="18"
            aria-hidden="true"
            focusable="false"
          >
            <circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="2" />
            <path
              d="M12 2v3m0 14v3M2 12h3m14 0h3M4.9 4.9l2.1 2.1m10 10l2.1 2.1M19.1 4.9L17 7M7 17l-2.1 2.1"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
            />
          </svg>
          <svg
            v-else
            viewBox="0 0 24 24"
            width="18"
            height="18"
            aria-hidden="true"
            focusable="false"
          >
            <path
              d="M20 14.5A8 8 0 0 1 9.5 4 8 8 0 1 0 20 14.5z"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linejoin="round"
            />
          </svg>
        </button>
      </div>
    </header>

    <div class="shell__body">
      <nav class="shell__nav" aria-label="Primary">
        <slot name="nav" />
      </nav>

      <main class="shell__main">
        <slot />
      </main>
    </div>
  </div>
</template>

<style scoped>
.shell {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  background-color: var(--color-bg);
}

.shell__topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-4);
  padding: var(--space-3) var(--space-5);
  background-color: var(--color-surface);
  border-bottom: 1px solid var(--color-border);
  position: sticky;
  top: 0;
  z-index: 10;
}

.shell__brand {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  min-width: 0;
}

.shell__logo {
  display: inline-flex;
  color: var(--color-primary);
}

.shell__title {
  font-size: var(--text-lg);
  font-weight: var(--weight-semibold);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.shell__actions {
  display: flex;
  align-items: center;
  gap: var(--space-3);
}

.shell__theme-toggle {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: var(--control-height);
  height: var(--control-height);
  border: 1px solid var(--color-border);
  border-radius: var(--radius-md);
  background-color: var(--color-surface-alt);
  color: var(--color-text);
  cursor: pointer;
  font-size: var(--text-lg);
}

.shell__body {
  display: grid;
  grid-template-columns: minmax(180px, 240px) 1fr;
  flex: 1;
  align-items: start;
}

.shell__nav {
  display: flex;
  flex-direction: column;
  gap: var(--space-1);
  padding: var(--space-4) var(--space-3);
  border-right: 1px solid var(--color-border);
  min-height: 100%;
}

.shell__main {
  padding: var(--space-5);
  min-width: 0;
}

/* Mobile: stack nav as a compact horizontal strip above the content. */
@media (max-width: 640px) {
  .shell__body {
    grid-template-columns: 1fr;
  }

  .shell__nav {
    flex-direction: row;
    flex-wrap: wrap;
    gap: var(--space-2);
    border-right: none;
    border-bottom: 1px solid var(--color-border);
    padding: var(--space-2) var(--space-3);
    min-height: 0;
  }

  .shell__main {
    padding: var(--space-4);
  }
}
</style>
