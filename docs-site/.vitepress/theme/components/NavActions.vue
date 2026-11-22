<script setup lang="ts">
defineProps<{
  mobile?: boolean
}>()
</script>

<template>
  <div class="st-nav-actions" :class="{ 'is-mobile': mobile }">
    <a
      class="st-nav-star"
      href="https://github.com/stellereum/stellereum"
      target="_blank"
      rel="noreferrer"
      aria-label="Star Stellereum on GitHub"
    >
      <svg viewBox="0 0 16 16" aria-hidden="true">
        <path
          d="M8 .9a7.1 7.1 0 0 0-2.25 13.84c.36.07.49-.15.49-.34v-1.2c-1.98.43-2.4-.95-2.4-.95-.32-.82-.79-1.04-.79-1.04-.65-.44.05-.43.05-.43.72.05 1.1.74 1.1.74.64 1.09 1.67.78 2.08.6.06-.46.25-.78.45-.96-1.58-.18-3.24-.79-3.24-3.52 0-.78.28-1.41.74-1.91-.08-.18-.32-.91.07-1.89 0 0 .6-.19 1.96.73a6.8 6.8 0 0 1 3.56 0c1.36-.92 1.96-.73 1.96-.73.39.98.15 1.71.07 1.89.46.5.74 1.13.74 1.91 0 2.74-1.66 3.34-3.25 3.52.26.22.49.66.49 1.33v1.97c0 .19.13.41.5.34A7.1 7.1 0 0 0 8 .9Z"
          fill="currentColor"
        />
      </svg>
      <span>Star</span>
    </a>
    <span class="st-nav-divider" aria-hidden="true"></span>
    <a
      class="st-nav-testnet"
      href="https://testnet.stellereum.org"
      target="_blank"
      rel="noreferrer"
    >
      Testnet
      <svg viewBox="0 0 16 16" aria-hidden="true">
        <path
          d="M5 11L11 5M6 5h5v5"
          fill="none"
          stroke="currentColor"
          stroke-width="1.4"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
      </svg>
    </a>
  </div>
</template>

<style scoped>
.st-nav-actions {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-left: 6px;
  padding-left: 14px;
  border-left: 1px solid var(--st-line-soft);
}

.st-nav-star,
.st-nav-testnet {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12.5px;
  font-weight: 500;
  text-decoration: none;
  white-space: nowrap;
  transition: color 0.16s ease, border-color 0.16s ease, background 0.16s ease;
}

.st-nav-star {
  color: var(--st-text-3);
}

.st-nav-star svg {
  width: 14px;
  height: 14px;
}

.st-nav-star:hover {
  color: var(--st-text-1);
}

.st-nav-divider {
  width: 1px;
  height: 14px;
  background: var(--st-line-soft);
}

.st-nav-testnet {
  padding: 5px 11px;
  border: 1px solid var(--st-line-strong);
  border-radius: 5px;
  background: rgba(124, 141, 255, 0.08);
  color: var(--st-text-1);
}

.st-nav-testnet svg {
  width: 12px;
  height: 12px;
  color: var(--st-blue);
}

.st-nav-testnet:hover {
  border-color: var(--st-blue);
  background: rgba(94, 184, 255, 0.1);
}

.st-nav-actions.is-mobile {
  flex-direction: column;
  align-items: stretch;
  gap: 12px;
  margin: 28px 0 0;
  padding: 20px 0 0;
  border-top: 1px solid var(--st-line);
  border-left: 0;
}

.st-nav-actions.is-mobile .st-nav-star,
.st-nav-actions.is-mobile .st-nav-testnet {
  justify-content: center;
  min-height: 42px;
  padding: 0 16px;
  border: 1px solid var(--st-line);
  border-radius: 6px;
  background: var(--st-surface);
  font-size: 13.5px;
}

.st-nav-actions.is-mobile .st-nav-testnet {
  border-color: transparent;
  background: var(--st-indigo);
  color: #060811;
}

.st-nav-actions.is-mobile .st-nav-divider {
  display: none;
}

@media (max-width: 767px) {
  .st-nav-actions:not(.is-mobile) {
    display: none;
  }
}
</style>
