<script setup lang="ts">
import DefaultTheme from 'vitepress/theme'
import NavActions from './components/NavActions.vue'
import NavTitleExtra from './components/NavTitleExtra.vue'

const { Layout } = DefaultTheme
</script>

<template>
  <Layout>
    <template #nav-bar-title-after><NavTitleExtra /></template>
    <template #nav-bar-content-after><NavActions /></template>
    <template #nav-screen-content-after><NavActions mobile /></template>
  </Layout>
</template>
