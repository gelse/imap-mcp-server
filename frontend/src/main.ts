/**
 * Application entry point.
 *
 * Theme is resolved here (not by an inline <script>) because the CSP forbids
 * inline scripts. See lib/theme.ts for the documented trade-off.
 *
 * The router is installed as a plugin; the admin/user surfaces are selected
 * by URL prefix (see router.ts).
 */
import { createApp } from 'vue'
import App from './App.vue'
import { initTheme } from './lib/theme'
import { router } from './router'

import './styles/tokens.css'
import './styles/themes.css'
import './styles/base.css'

initTheme()

createApp(App).use(router).mount('#app')
