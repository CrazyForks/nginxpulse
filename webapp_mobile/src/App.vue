<template>
  <div class="mobile-shell" :class="{ 'nav-top-mode': !tabbarAtBottom }">
    <van-nav-bar
      fixed
      placeholder
      safe-area-inset-top
      class="mobile-nav"
    >
      <template #title>
        <button
          v-if="!tabbarAtBottom"
          type="button"
          class="nav-title-trigger"
          @click="toggleTopMenu"
        >
          <span>{{ pageTitle }}</span>
          <van-icon name="arrow-down" class="nav-title-icon" :class="{ open: topMenuVisible }" />
        </button>
        <span v-else class="nav-title-text">{{ pageTitle }}</span>
      </template>
      <template #left>
        <div class="mobile-brand">
          <img src="/brand-mark.svg" alt="NginxPulse" class="brand-logo" />
        </div>
      </template>
      <template #right>
        <div class="nav-actions">
          <van-button
            size="small"
            type="default"
            plain
            class="nav-icon-btn"
            :aria-label="t('app.sidebar.language')"
            @click="languageSheetVisible = true"
          >
            <i class="nav-icon ri-translate-2" aria-hidden="true"></i>
          </van-button>
          <van-button
            size="small"
            type="default"
            plain
            class="nav-icon-btn"
            :aria-label="t('theme.toggle')"
            @click="toggleTheme"
          >
            <span class="theme-emoji" aria-hidden="true">{{ isDark ? '☀️' : '🌙' }}</span>
          </van-button>
        </div>
      </template>
    </van-nav-bar>

    <van-notice-bar
      v-if="demoMode && !setupRequired"
      class="demo-banner"
      color="#c2410c"
      background="#fff4e5"
      left-icon="info-o"
      wrapable
    >
      {{ t('demo.text') }}
      <a href="https://github.com/likaia/nginxpulse/" target="_blank" rel="noopener">
        https://github.com/likaia/nginxpulse/
      </a>
    </van-notice-bar>

    <main class="mobile-main" :class="[mainClass, { 'parsing-lock': parsingActive }]">
      <van-empty
        v-if="setupRequired"
        image="network"
        :description="t('mobile.setupRequiredDesc')"
      >
        <div class="setup-empty-title">{{ t('mobile.setupRequiredTitle') }}</div>
        <div class="setup-empty-hint">{{ t('mobile.setupRequiredHint') }}</div>
      </van-empty>

      <RouterView v-else :key="`${route.fullPath}-${currentLocale}-${accessKeyReloadToken}`" />
    </main>

    <van-tabbar
      v-if="!setupRequired && tabbarAtBottom"
      ref="tabbarRef"
      route
      fixed
      safe-area-inset-bottom
      class="mobile-tabbar"
    >
      <van-tabbar-item to="/" class="tabbar-item">
        <template #icon="{ active }">
          <svg class="tab-icon" :class="{ active }" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="3.5" y="4" width="17" height="16" rx="3" />
            <path d="M7 15l3-3 3 2 4-5" />
          </svg>
        </template>
        {{ t('app.menu.overview') }}
      </van-tabbar-item>
      <van-tabbar-item to="/daily" class="tabbar-item">
        <template #icon="{ active }">
          <svg class="tab-icon" :class="{ active }" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="4" y="5" width="16" height="15" rx="3" />
            <path d="M8 3v4M16 3v4M7 11h10M7 15h6" />
          </svg>
        </template>
        {{ t('app.menu.daily') }}
      </van-tabbar-item>
      <van-tabbar-item to="/realtime" class="tabbar-item">
        <template #icon="{ active }">
          <svg class="tab-icon" :class="{ active }" viewBox="0 0 24 24" aria-hidden="true">
            <path d="M3 12h4l2-4 4 8 2-4h4" />
            <circle cx="12" cy="12" r="9" />
          </svg>
        </template>
        {{ t('app.menu.realtime') }}
      </van-tabbar-item>
      <van-tabbar-item to="/logs" class="tabbar-item">
        <template #icon="{ active }">
          <svg class="tab-icon" :class="{ active }" viewBox="0 0 24 24" aria-hidden="true">
            <rect x="4" y="4" width="16" height="16" rx="3" />
            <path d="M8 9h8M8 13h8M8 17h5" />
          </svg>
        </template>
        {{ t('app.menu.logs') }}
      </van-tabbar-item>
    </van-tabbar>

    <Teleport to="body">
      <van-overlay
        :show="topMenuVisible"
        class="top-menu-overlay"
        @click="closeTopMenu"
      />
      <transition name="top-menu-slide">
        <div v-show="topMenuVisible" class="top-menu-panel">
          <button type="button" class="top-menu-close" @click="closeTopMenu">
            <van-icon name="cross" />
          </button>
          <nav class="top-menu-list">
            <RouterLink
              v-for="item in navMenuItems"
              :key="item.name"
              :to="item.to"
              class="top-menu-item"
              :class="{ active: item.name === route.name }"
              @click="closeTopMenu"
            >
              {{ item.label }}
            </RouterLink>
          </nav>
        </div>
      </transition>
    </Teleport>

    <van-popup
      v-model:show="accessKeyRequired"
      position="bottom"
      round
      :close-on-click-overlay="false"
      class="access-popup"
    >
      <div class="access-sheet">
        <div class="access-title">{{ t('access.title') }}</div>
        <div class="access-sub">{{ t('access.subtitle') }}</div>
        <van-field
          v-model="accessKeyInput"
          type="password"
          :placeholder="t('access.placeholder')"
          autocomplete="current-password"
          clearable
        />
        <van-button
          block
          type="primary"
          :loading="accessKeySubmitting"
          class="access-submit"
          @click="submitAccessKey"
        >
          {{ accessKeySubmitting ? t('access.submitting') : t('access.submit') }}
        </van-button>
        <div v-if="accessKeyErrorMessage" class="access-error">{{ accessKeyErrorMessage }}</div>
      </div>
    </van-popup>

    <van-action-sheet
      v-model:show="languageSheetVisible"
      teleport="body"
      :duration="ACTION_SHEET_DURATION"
      :actions="languageActions"
      :cancel-text="t('common.cancel')"
      close-on-click-action
      @select="onSelectLanguage"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, provide, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { useI18n } from 'vue-i18n';
import { fetchAppStatus } from '@/api';
import { getLocaleFromQuery, getStoredLocale, normalizeLocale, setLocale } from '@/i18n';
import {
  ACTION_SHEET_DURATION,
  HERO_ACCENT_ALPHA,
  HERO_ACCENT_ALPHA_DARK,
  HERO_BORDER_ALPHA,
  HERO_BORDER_ALPHA_DARK,
  HERO_PRIMARY_ALPHA,
  HERO_PRIMARY_ALPHA_DARK,
  CARD_SHADOW_ALPHA,
  CARD_SHADOW_ALPHA_DARK,
  CARD_SHADOW_SOFT_ALPHA,
  CARD_SHADOW_SOFT_ALPHA_DARK,
  MOBILE_CARD_PADDING,
  MOBILE_CARD_RADIUS,
  MOBILE_GAP,
  NAV_BLUR,
  NAV_BG_ALPHA,
  NAV_BG_ALPHA_DARK,
  NAV_ICON_BG_ALPHA,
  NAV_ICON_BG_ALPHA_DARK,
  NAV_ICON_BLUR,
  NAV_ICON_SHADOW_ALPHA,
  NAV_SHADOW_ALPHA,
  NAV_SHADOW_ALPHA_DARK,
  METRIC_TINT_ALPHA,
  METRIC_TINT_ALPHA_DARK,
  PANEL_GLOW_ALPHA,
  PANEL_TINT_ALPHA,
  PANEL_TINT_ALPHA_DARK,
  TABBAR_BLUR,
  TABBAR_BG_ALPHA,
  TABBAR_BG_ALPHA_DARK,
  TABBAR_GUTTER,
  TABBAR_INDICATOR_DURATION,
  TABBAR_INDICATOR_EASING,
  TABBAR_INDICATOR_INSET,
  TABBAR_INDICATOR_RADIUS,
  TABBAR_MARGIN_BOTTOM,
  TABBAR_MAX_WIDTH,
  TABBAR_PADDING_X,
  TABBAR_PADDING_Y,
  TABBAR_RADIUS,
  TABBAR_SHADOW_ALPHA,
  TABBAR_SHADOW_ALPHA_DARK,
  MOBILE_TABBAR_BOTTOM,
} from '@mobile/constants/ui';

const route = useRoute();
const { t, locale } = useI18n({ useScope: 'global' });

const ACCESS_KEY_STORAGE = 'nginxpulse_access_key';
const ACCESS_KEY_EVENT = 'nginxpulse:access-key-required';

const mainClass = computed(() => (route.meta.mainClass as string) || '');

const isDark = ref(localStorage.getItem('darkMode') === 'true');
const parsingActive = ref(false);
const demoMode = ref(false);
const migrationRequired = ref(false);
const setupRequired = ref(false);
const accessKeyRequired = ref(false);
const accessKeySubmitting = ref(false);
const accessKeyInput = ref(localStorage.getItem(ACCESS_KEY_STORAGE) || '');
const accessKeyErrorKey = ref<string | null>(null);
const accessKeyErrorText = ref('');
const accessKeyReloadToken = ref(0);
const languageSheetVisible = ref(false);
const tabbarRef = ref<any>(null);
const topMenuVisible = ref(false);
const tabbarAtBottom = MOBILE_TABBAR_BOTTOM;

const languageOptions = computed(() => {
  const _locale = locale.value;
  return [
    { value: 'zh-CN', label: t('language.zh'), shortLabel: t('language.zhShort') },
    { value: 'en-US', label: t('language.en'), shortLabel: t('language.enShort') },
  ];
});

const languageActions = computed(() =>
  languageOptions.value.map((option) => ({
    name: option.label,
    value: option.value,
  }))
);

const currentLocale = computed({
  get: () => normalizeLocale(locale.value),
  set: (value: string) => setLocale(normalizeLocale(value)),
});

const accessKeyErrorMessage = computed(() => {
  if (accessKeyErrorKey.value) {
    return t(accessKeyErrorKey.value);
  }
  return accessKeyErrorText.value;
});

const pageTitle = computed(() => {
  if (setupRequired.value) {
    return t('mobile.setupRequiredTitle');
  }
  switch (route.name) {
    case 'overview':
      return t('app.menu.overview');
    case 'daily':
      return t('app.menu.daily');
    case 'realtime':
      return t('app.menu.realtime');
    case 'logs':
      return t('app.menu.logs');
    default:
      return 'NginxPulse';
  }
});

const navMenuItems = computed(() => [
  { name: 'overview', label: t('app.menu.overview'), to: '/' },
  { name: 'daily', label: t('app.menu.daily'), to: '/daily' },
  { name: 'realtime', label: t('app.menu.realtime'), to: '/realtime' },
  { name: 'logs', label: t('app.menu.logs'), to: '/logs' },
]);

const activeTabIndex = computed(() => {
  switch (route.name) {
    case 'daily':
      return 1;
    case 'realtime':
      return 2;
    case 'logs':
      return 3;
    case 'overview':
    default:
      return 0;
  }
});

const updateTabIndicator = () => {
  if (!tabbarAtBottom) {
    return;
  }
  const el = tabbarRef.value?.$el ?? tabbarRef.value;
  if (!el || setupRequired.value) {
    return;
  }
  const items = el.querySelectorAll('.van-tabbar-item');
  const target = items[activeTabIndex.value] as HTMLElement | undefined;
  if (!target) {
    return;
  }
  const rect = target.getBoundingClientRect();
  const parentRect = el.getBoundingClientRect();
  const x = rect.left - parentRect.left;
  el.style.setProperty('--tab-indicator-x', `${x}px`);
  el.style.setProperty('--tab-indicator-w', `${rect.width}px`);
};

const applyTheme = (value: boolean) => {
  if (value) {
    document.body.classList.add('dark-mode');
    document.documentElement.classList.add('dark-mode');
    localStorage.setItem('darkMode', 'true');
  } else {
    document.body.classList.remove('dark-mode');
    document.documentElement.classList.remove('dark-mode');
    localStorage.setItem('darkMode', 'false');
  }
};

const toggleTheme = () => {
  isDark.value = !isDark.value;
};

const applyUiTokens = () => {
  const root = document.documentElement;
  root.style.setProperty('--nav-bg-alpha', String(NAV_BG_ALPHA));
  root.style.setProperty('--nav-bg-alpha-dark', String(NAV_BG_ALPHA_DARK));
  root.style.setProperty('--nav-icon-bg-alpha', String(NAV_ICON_BG_ALPHA));
  root.style.setProperty('--nav-icon-bg-alpha-dark', String(NAV_ICON_BG_ALPHA_DARK));
  root.style.setProperty('--nav-blur', `${NAV_BLUR}px`);
  root.style.setProperty('--nav-shadow-alpha', String(NAV_SHADOW_ALPHA));
  root.style.setProperty('--nav-shadow-alpha-dark', String(NAV_SHADOW_ALPHA_DARK));
  root.style.setProperty('--nav-icon-shadow-alpha', String(NAV_ICON_SHADOW_ALPHA));
  root.style.setProperty('--nav-icon-blur', `${NAV_ICON_BLUR}px`);
  root.style.setProperty('--tabbar-bg-alpha', String(TABBAR_BG_ALPHA));
  root.style.setProperty('--tabbar-bg-alpha-dark', String(TABBAR_BG_ALPHA_DARK));
  root.style.setProperty('--tabbar-indicator-duration', `${TABBAR_INDICATOR_DURATION}s`);
  root.style.setProperty('--tabbar-indicator-ease', TABBAR_INDICATOR_EASING);
  root.style.setProperty('--tabbar-blur', `${TABBAR_BLUR}px`);
  root.style.setProperty('--tabbar-radius', `${TABBAR_RADIUS}px`);
  root.style.setProperty('--tabbar-margin-bottom', `${TABBAR_MARGIN_BOTTOM}px`);
  root.style.setProperty('--tabbar-gutter', `${TABBAR_GUTTER}px`);
  root.style.setProperty('--tabbar-max-width', `${TABBAR_MAX_WIDTH}px`);
  root.style.setProperty('--tabbar-padding-x', `${TABBAR_PADDING_X}px`);
  root.style.setProperty('--tabbar-padding-y', `${TABBAR_PADDING_Y}px`);
  root.style.setProperty('--tabbar-shadow-alpha', String(TABBAR_SHADOW_ALPHA));
  root.style.setProperty('--tabbar-shadow-alpha-dark', String(TABBAR_SHADOW_ALPHA_DARK));
  root.style.setProperty('--tabbar-indicator-inset', `${TABBAR_INDICATOR_INSET}px`);
  root.style.setProperty('--tabbar-indicator-radius', `${TABBAR_INDICATOR_RADIUS}px`);
  root.style.setProperty('--mobile-gap', `${MOBILE_GAP}px`);
  root.style.setProperty('--mobile-radius', `${MOBILE_CARD_RADIUS}px`);
  root.style.setProperty('--mobile-card-padding', `${MOBILE_CARD_PADDING}px`);
  root.style.setProperty('--hero-primary-alpha', String(HERO_PRIMARY_ALPHA));
  root.style.setProperty('--hero-accent-alpha', String(HERO_ACCENT_ALPHA));
  root.style.setProperty('--hero-border-alpha', String(HERO_BORDER_ALPHA));
  root.style.setProperty('--hero-primary-alpha-dark', String(HERO_PRIMARY_ALPHA_DARK));
  root.style.setProperty('--hero-accent-alpha-dark', String(HERO_ACCENT_ALPHA_DARK));
  root.style.setProperty('--hero-border-alpha-dark', String(HERO_BORDER_ALPHA_DARK));
  root.style.setProperty('--card-shadow-alpha', String(CARD_SHADOW_ALPHA));
  root.style.setProperty('--card-shadow-alpha-dark', String(CARD_SHADOW_ALPHA_DARK));
  root.style.setProperty('--card-shadow-soft-alpha', String(CARD_SHADOW_SOFT_ALPHA));
  root.style.setProperty('--card-shadow-soft-alpha-dark', String(CARD_SHADOW_SOFT_ALPHA_DARK));
  root.style.setProperty('--panel-tint-alpha', String(PANEL_TINT_ALPHA));
  root.style.setProperty('--panel-tint-alpha-dark', String(PANEL_TINT_ALPHA_DARK));
  root.style.setProperty('--panel-glow-alpha', String(PANEL_GLOW_ALPHA));
  root.style.setProperty('--metric-tint-alpha', String(METRIC_TINT_ALPHA));
  root.style.setProperty('--metric-tint-alpha-dark', String(METRIC_TINT_ALPHA_DARK));
};

onMounted(() => {
  applyUiTokens();
  applyTheme(isDark.value);
  refreshAppStatus();
  window.addEventListener(ACCESS_KEY_EVENT, handleAccessKeyEvent);
  window.addEventListener('resize', updateTabIndicator);
  nextTick(updateTabIndicator);
});

onBeforeUnmount(() => {
  window.removeEventListener(ACCESS_KEY_EVENT, handleAccessKeyEvent);
  window.removeEventListener('resize', updateTabIndicator);
});

watch(isDark, (value) => {
  applyTheme(value);
});

watch([activeTabIndex, setupRequired], () => {
  nextTick(updateTabIndicator);
});

const closeTopMenu = () => {
  topMenuVisible.value = false;
};

const toggleTopMenu = () => {
  if (setupRequired.value) {
    return;
  }
  topMenuVisible.value = !topMenuVisible.value;
};

watch(locale, () => {
  nextTick(updateTabIndicator);
});

watch(route, () => {
  topMenuVisible.value = false;
});

provide('setParsingActive', (value: boolean) => {
  parsingActive.value = value;
});

provide('demoMode', demoMode);
provide('migrationRequired', migrationRequired);

async function refreshAppStatus() {
  try {
    const status = await fetchAppStatus();
    demoMode.value = Boolean(status.demo_mode);
    migrationRequired.value = Boolean(status.migration_required);
    setupRequired.value = Boolean(status.setup_required);
    accessKeyRequired.value = false;
    accessKeyErrorKey.value = null;
    accessKeyErrorText.value = '';
    const hasStoredLocale = getStoredLocale() !== null;
    const hasQueryLocale = getLocaleFromQuery() !== null;
    if (!hasStoredLocale && !hasQueryLocale && status.language) {
      setLocale(normalizeLocale(status.language), false);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : t('common.requestFailed');
    if (message.toLowerCase().includes('key') || message.includes('密钥')) {
      accessKeyRequired.value = true;
      setAccessKeyErrorMessage(message);
    } else {
      console.error('获取系统状态失败:', error);
    }
  }
}

function handleAccessKeyEvent(event: Event) {
  const detail = (event as CustomEvent<{ message?: string }>).detail;
  accessKeyRequired.value = true;
  setAccessKeyErrorMessage(detail?.message || '');
}

async function submitAccessKey() {
  const value = accessKeyInput.value.trim();
  if (!value) {
    accessKeyErrorKey.value = 'access.required';
    accessKeyErrorText.value = '';
    return;
  }
  accessKeySubmitting.value = true;
  localStorage.setItem(ACCESS_KEY_STORAGE, value);
  try {
    await refreshAppStatus();
    if (!accessKeyRequired.value) {
      accessKeyReloadToken.value += 1;
    }
  } finally {
    accessKeySubmitting.value = false;
  }
}

function setAccessKeyErrorMessage(message: string) {
  const normalized = message.trim().toLowerCase();
  if (!message || normalized.includes('需要访问密钥') || normalized.includes('access key required')) {
    accessKeyErrorKey.value = 'access.title';
    accessKeyErrorText.value = '';
    return;
  }
  if (normalized.includes('访问密钥无效') || normalized.includes('invalid')) {
    accessKeyErrorKey.value = 'access.invalid';
    accessKeyErrorText.value = '';
    return;
  }
  accessKeyErrorKey.value = null;
  accessKeyErrorText.value = message;
}

function onSelectLanguage(action: { value?: string }) {
  if (action?.value) {
    currentLocale.value = action.value;
  }
}
</script>

<style lang="scss" scoped>
.mobile-nav {
  --van-nav-bar-background: rgba(255, 255, 255, var(--nav-bg-alpha, 0.55));
  --van-nav-bar-title-text-color: #0f172a;
  --van-nav-bar-icon-color: #0f172a;
  backdrop-filter: blur(var(--nav-blur, 18px));
  box-shadow: 0 8px 20px rgba(15, 23, 42, var(--nav-shadow-alpha, 0.08));
  border-bottom: 1px solid rgba(226, 232, 240, 0.5);
}

:global(body.dark-mode) .mobile-nav {
  --van-nav-bar-background: rgba(15, 23, 42, var(--nav-bg-alpha-dark, 0.4));
  --van-nav-bar-title-text-color: #f8fafc;
  --van-nav-bar-icon-color: #f8fafc;
  box-shadow: 0 8px 20px rgba(0, 0, 0, var(--nav-shadow-alpha-dark, 0.35));
  border-bottom: 1px solid rgba(148, 163, 184, 0.18);
}

.mobile-brand {
  display: inline-flex;
  align-items: center;
  gap: 0;
  font-weight: 700;
  color: inherit;
}

.brand-logo {
  width: 26px;
  height: 26px;
  border-radius: 8px;
  display: block;
  box-shadow: 0 6px 12px rgba(15, 23, 42, 0.1);
}

.nav-actions {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.nav-icon-btn {
  padding: 0 8px;
  min-width: 36px;
  height: 32px;
  border-radius: 12px;
  background: rgba(255, 255, 255, var(--nav-icon-bg-alpha, 0.55));
  border: 1px solid rgba(226, 232, 240, 0.6);
  box-shadow: 0 6px 14px rgba(15, 23, 42, var(--nav-icon-shadow-alpha, 0.12));
  backdrop-filter: blur(var(--nav-icon-blur, 12px));
}

.nav-icon {
  font-size: 18px;
}

.theme-emoji {
  font-size: 16px;
  line-height: 1;
}

.demo-banner a {
  color: inherit;
  text-decoration: underline;
  text-underline-offset: 2px;
}

.access-popup {
  padding-bottom: env(safe-area-inset-bottom);
}

.access-sheet {
  padding: 20px 18px 24px;
  display: grid;
  gap: 12px;
}

.access-title {
  font-size: 18px;
  font-weight: 700;
}

.access-sub {
  font-size: 12px;
  color: var(--muted);
}

.access-submit {
  margin-top: 4px;
}

.access-error {
  font-size: 12px;
  color: var(--error-color);
}

.setup-empty-title {
  font-weight: 700;
  margin-bottom: 4px;
}

.setup-empty-hint {
  font-size: 12px;
  color: var(--muted);
}
</style>
