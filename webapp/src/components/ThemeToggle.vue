<template>
  <button class="theme-toggle" type="button" :title="t('theme.toggle')" :aria-pressed="isDark" @click="toggle">
    <i class="ri-moon-line light-icon" aria-hidden="true"></i>
    <i class="ri-sun-line dark-icon" aria-hidden="true"></i>
  </button>
</template>

<script setup lang="ts">
import { computed, inject } from 'vue';
import { useI18n } from 'vue-i18n';

type ThemeContext = {
  isDark: { value: boolean };
  toggle: () => void;
}

const theme = inject<ThemeContext>('theme', null);
const isDark = computed(() => theme?.isDark.value ?? false);
const { t } = useI18n({ useScope: 'global' });

function toggle() {
  theme?.toggle();
}
</script>
