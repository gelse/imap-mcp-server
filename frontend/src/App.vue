<script setup lang="ts">
/**
 * App — the SPA root.
 *
 * The router owns the surface (admin or user) and renders it here. The shell,
 * the design tokens and the base component library live under src/components.
 */
import { RouterView } from 'vue-router'
</script>

<template>
  <RouterView />
</template>
