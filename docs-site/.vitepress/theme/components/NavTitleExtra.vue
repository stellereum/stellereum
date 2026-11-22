<script setup lang="ts">
import { withBase } from 'vitepress'
</script>

<template>
  <span class="st-nav-wordmark">Docs</span>
  <a
    class="st-nav-version"
    :href="withBase('/get-started/networks#network-parameters')"
    title="Consensus ruleset v7"
    aria-label="Consensus ruleset v7"
  >v7</a>
</template>

<style scoped>
.st-nav-wordmark {
  margin-left: 7px;
  color: var(--st-text-3);
  font-weight: 450;
  letter-spacing: -0.01em;
}

.st-nav-version {
  margin-left: 9px;
  padding: 2px 7px;
  border: 1px solid var(--st-line);
  border-radius: 999px;
  background: rgba(94, 184, 255, 0.06);
  color: var(--st-blue);
  font-family: var(--st-font-mono);
  font-size: 10.5px;
  font-weight: 500;
  line-height: 1.5;
  text-decoration: none;
  transition: border-color 0.16s ease, background 0.16s ease;
}

.st-nav-version:hover {
  border-color: var(--st-line-strong);
  background: rgba(94, 184, 255, 0.1);
}

@media (max-width: 640px) {
  .st-nav-wordmark {
    display: none;
  }
}
</style>
