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
      v-if="demoMode && !setupRequired && demoBannerVisible"
      class="demo-banner"
      color="#c2410c"
      background="#fff4e5"
      left-icon="info-o"
      mode="closeable"
      wrapable
      @close="demoBannerVisible = false"
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

    <transition name="pwa-banner-fade">
      <div v-if="pwaPromptVisible" class="pwa-banner" :class="{ 'with-tabbar': tabbarAtBottom }">
        <div class="pwa-banner__icon">
          <img src="/brand-mark.svg" alt="NginxPulse" />
        </div>
        <div class="pwa-banner__content">
          <div class="pwa-banner__title">{{ pwaTitle }}</div>
          <div class="pwa-banner__desc">{{ pwaDesc }}</div>
        </div>
        <div class="pwa-banner__actions">
          <van-button size="small" type="primary" class="pwa-banner__primary" @click="handlePwaPrimary">
            {{ pwaPrimaryLabel }}
          </van-button>
          <van-button size="small" plain class="pwa-banner__secondary" @click="dismissPwaPrompt">
            {{ t('pwa.dismiss') }}
          </van-button>
        </div>
      </div>
    </transition>

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

    <van-popup
      v-model:show="pwaGuideVisible"
      position="bottom"
      round
      class="pwa-guide"
      :close-on-click-overlay="true"
    >
      <div class="pwa-guide__header">
        <div class="pwa-guide__title">{{ t('pwa.iosGuideTitle') }}</div>
        <button type="button" class="pwa-guide__close" @click="pwaGuideVisible = false">
          <van-icon name="cross" />
        </button>
      </div>
      <div class="pwa-guide__hint">{{ t('pwa.iosGuideHint') }}</div>
      <div class="pwa-guide__steps">
        <div class="pwa-guide__step">
          <div class="pwa-guide__step-icon">
            <i class="ri-share-line" aria-hidden="true"></i>
          </div>
          <div class="pwa-guide__step-body">
            <div class="pwa-guide__step-title">{{ t('pwa.iosStepShareTitle') }}</div>
            <div class="pwa-guide__step-desc">{{ t('pwa.iosStepShareDesc') }}</div>
          </div>
        </div>
        <div class="pwa-guide__step">
          <div class="pwa-guide__step-icon">
            <i class="ri-add-box-line" aria-hidden="true"></i>
          </div>
          <div class="pwa-guide__step-body">
            <div class="pwa-guide__step-title">{{ t('pwa.iosStepAddTitle') }}</div>
            <div class="pwa-guide__step-desc">{{ t('pwa.iosStepAddDesc') }}</div>
          </div>
        </div>
        <div class="pwa-guide__step">
          <div class="pwa-guide__step-icon">
            <i class="ri-checkbox-circle-line" aria-hidden="true"></i>
          </div>
          <div class="pwa-guide__step-body">
            <div class="pwa-guide__step-title">{{ t('pwa.iosStepConfirmTitle') }}</div>
            <div class="pwa-guide__step-desc">{{ t('pwa.iosStepConfirmDesc') }}</div>
          </div>
        </div>
      </div>
      <van-button block type="primary" class="pwa-guide__done" @click="dismissPwaPrompt">
        {{ t('pwa.iosGuideDone') }}
      </van-button>
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
const PWA_PROMPT_DISMISS_KEY = 'nginxpulse_pwa_prompt_dismissed_at';
const PWA_PROMPT_THROTTLE_DAYS = 14;

type BeforeInstallPromptEvent = Event & {
  prompt: () => Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed'; platform: string }>;
};

const mainClass = computed(() => (route.meta.mainClass as string) || '');

const isDark = ref(localStorage.getItem('darkMode') === 'true');
const parsingActive = ref(false);
const demoMode = ref(false);
const demoBannerVisible = ref(true);
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
const isPwaMode = ref(false);
const pwaFeatureEnabled = ref(false);
const tabbarAtBottom = computed(() => (isPwaMode.value ? true : MOBILE_TABBAR_BOTTOM));
const pwaPromptVisible = ref(false);
const pwaGuideVisible = ref(false);
const pwaPromptMode = ref<'ios' | 'install' | 'none'>('none');

let deferredPrompt: BeforeInstallPromptEvent | null = null;
let pwaPromptTimer: number | undefined;
let displayModeQuery: MediaQueryList | null = null;
const handleDisplayModeChange = () => refreshPwaMode();

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

const pwaTitle = computed(() =>
  pwaPromptMode.value === 'ios' ? t('pwa.iosTitle') : t('pwa.installTitle')
);
const pwaDesc = computed(() => (pwaPromptMode.value === 'ios' ? t('pwa.iosDesc') : t('pwa.installDesc')));
const pwaPrimaryLabel = computed(() =>
  pwaPromptMode.value === 'ios' ? t('pwa.iosAction') : t('pwa.installAction')
);

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
  if (!tabbarAtBottom.value) {
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

const getStandaloneMode = () =>
  window.matchMedia('(display-mode: standalone)').matches ||
  (window.navigator as unknown as { standalone?: boolean }).standalone === true;

const getPwaFeatureEnabled = () => {
  const value = (window as unknown as Record<string, unknown>).__NGINXPULSE_MOBILE_PWA_ENABLED__;
  if (typeof value === 'boolean') {
    return value;
  }
  if (typeof value === 'string') {
    return value.toLowerCase() === 'true';
  }
  return false;
};

const refreshPwaMode = () => {
  pwaFeatureEnabled.value = getPwaFeatureEnabled();
  isPwaMode.value = pwaFeatureEnabled.value && getStandaloneMode();
  return isPwaMode.value;
};

refreshPwaMode();

const isIOSDevice = () => {
  const ua = navigator.userAgent.toLowerCase();
  return /iphone|ipad|ipod/.test(ua) || (ua.includes('macintosh') && navigator.maxTouchPoints > 1);
};

const isSafariBrowser = () => {
  const ua = navigator.userAgent.toLowerCase();
  return ua.includes('safari') && !ua.includes('crios') && !ua.includes('fxios') && !ua.includes('edgios');
};

const shouldShowPwaPrompt = () => {
  if (!pwaFeatureEnabled.value) {
    return false;
  }
  if (refreshPwaMode()) {
    return false;
  }
  const raw = localStorage.getItem(PWA_PROMPT_DISMISS_KEY);
  if (!raw) {
    return true;
  }
  const ts = Number(raw);
  if (!ts) {
    return true;
  }
  const diffDays = (Date.now() - ts) / (1000 * 60 * 60 * 24);
  return diffDays > PWA_PROMPT_THROTTLE_DAYS;
};

const markPwaPromptDismissed = () => {
  localStorage.setItem(PWA_PROMPT_DISMISS_KEY, String(Date.now()));
};

const canShowPwaPrompt = () => !setupRequired.value && !accessKeyRequired.value && pwaFeatureEnabled.value;

const evaluatePwaPrompt = () => {
  if (!canShowPwaPrompt() || !shouldShowPwaPrompt()) {
    return;
  }
  if (isIOSDevice() && isSafariBrowser()) {
    pwaPromptMode.value = 'ios';
    pwaPromptVisible.value = true;
    return;
  }
  if (deferredPrompt) {
    pwaPromptMode.value = 'install';
    pwaPromptVisible.value = true;
  }
};

const dismissPwaPrompt = () => {
  pwaPromptVisible.value = false;
  pwaGuideVisible.value = false;
  markPwaPromptDismissed();
};

const handlePwaPrimary = async () => {
  if (pwaPromptMode.value === 'ios') {
    pwaGuideVisible.value = true;
    return;
  }
  if (!deferredPrompt) {
    dismissPwaPrompt();
    return;
  }
  try {
    await deferredPrompt.prompt();
    const choice = await deferredPrompt.userChoice;
    if (choice.outcome === 'accepted') {
      dismissPwaPrompt();
    }
  } finally {
    deferredPrompt = null;
  }
};

const handleBeforeInstallPrompt = (event: Event) => {
  event.preventDefault();
  deferredPrompt = event as BeforeInstallPromptEvent;
  evaluatePwaPrompt();
};

const handleAppInstalled = () => {
  deferredPrompt = null;
  pwaPromptVisible.value = false;
  pwaPromptMode.value = 'none';
  markPwaPromptDismissed();
  refreshPwaMode();
};

onMounted(() => {
  applyUiTokens();
  applyTheme(isDark.value);
  refreshPwaMode();
  refreshAppStatus();
  window.addEventListener(ACCESS_KEY_EVENT, handleAccessKeyEvent);
  window.addEventListener('resize', updateTabIndicator);
  window.addEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
  window.addEventListener('appinstalled', handleAppInstalled);
  window.addEventListener('visibilitychange', refreshPwaMode);
  if (window.matchMedia) {
    displayModeQuery = window.matchMedia('(display-mode: standalone)');
    if (displayModeQuery.addEventListener) {
      displayModeQuery.addEventListener('change', handleDisplayModeChange);
    } else if (displayModeQuery.addListener) {
      displayModeQuery.addListener(handleDisplayModeChange);
    }
  }
  nextTick(updateTabIndicator);
  pwaPromptTimer = window.setTimeout(() => {
    evaluatePwaPrompt();
  }, 1200);
});

onBeforeUnmount(() => {
  window.removeEventListener(ACCESS_KEY_EVENT, handleAccessKeyEvent);
  window.removeEventListener('resize', updateTabIndicator);
  window.removeEventListener('beforeinstallprompt', handleBeforeInstallPrompt);
  window.removeEventListener('appinstalled', handleAppInstalled);
  window.removeEventListener('visibilitychange', refreshPwaMode);
  if (displayModeQuery) {
    if (displayModeQuery.removeEventListener) {
      displayModeQuery.removeEventListener('change', handleDisplayModeChange);
    } else if (displayModeQuery.removeListener) {
      displayModeQuery.removeListener(handleDisplayModeChange);
    }
  }
  if (pwaPromptTimer) {
    window.clearTimeout(pwaPromptTimer);
  }
});

watch(isDark, (value) => {
  applyTheme(value);
});

watch([activeTabIndex, setupRequired], () => {
  nextTick(updateTabIndicator);
});

watch(tabbarAtBottom, () => {
  nextTick(updateTabIndicator);
});

watch([setupRequired, accessKeyRequired], () => {
  if (!canShowPwaPrompt()) {
    pwaPromptVisible.value = false;
    return;
  }
  if (!pwaPromptVisible.value) {
    evaluatePwaPrompt();
  }
});

watch(pwaFeatureEnabled, (enabled) => {
  if (!enabled) {
    pwaPromptVisible.value = false;
    pwaGuideVisible.value = false;
  }
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

.demo-banner .van-notice-bar__close {
  font-size: 14px;
  margin-left: 8px;
  cursor: pointer;
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

.pwa-banner {
  position: fixed;
  left: 16px;
  right: 16px;
  bottom: calc(env(safe-area-inset-bottom) + 16px);
  display: grid;
  grid-template-columns: auto minmax(0, 1fr) auto;
  gap: 12px;
  align-items: center;
  padding: 12px 12px;
  border-radius: 18px;
  background: rgba(255, 255, 255, 0.86);
  border: 1px solid rgba(226, 232, 240, 0.7);
  box-shadow: var(--mobile-shadow-soft);
  backdrop-filter: blur(16px);
  z-index: 20;
}

.pwa-banner.with-tabbar {
  bottom: calc(env(safe-area-inset-bottom) + 88px);
}

.pwa-banner__icon img {
  width: 40px;
  height: 40px;
  border-radius: 12px;
  box-shadow: 0 10px 20px rgba(15, 23, 42, 0.15);
}

.pwa-banner__title {
  font-size: 13px;
  font-weight: 700;
  color: var(--text);
}

.pwa-banner__desc {
  font-size: 11px;
  color: var(--muted);
}

.pwa-banner__actions {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.pwa-banner__primary,
.pwa-banner__secondary {
  padding: 0 10px;
  height: 28px;
  border-radius: 10px;
  font-size: 12px;
}

.pwa-banner__secondary {
  color: var(--muted);
  border-color: rgba(226, 232, 240, 0.8);
  background: rgba(255, 255, 255, 0.6);
}

.pwa-banner-fade-enter-active,
.pwa-banner-fade-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.pwa-banner-fade-enter-from,
.pwa-banner-fade-leave-to {
  opacity: 0;
  transform: translateY(10px);
}

.pwa-guide {
  padding: 20px 18px 24px;
  background: var(--panel);
  padding-bottom: calc(env(safe-area-inset-bottom) + 20px);
}

.pwa-guide__header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.pwa-guide__title {
  font-size: 16px;
  font-weight: 700;
}

.pwa-guide__close {
  border: 0;
  background: transparent;
  color: inherit;
  font-size: 18px;
  cursor: pointer;
}

.pwa-guide__hint {
  font-size: 12px;
  color: var(--muted);
  margin: 6px 0 14px;
}

.pwa-guide__steps {
  display: grid;
  gap: 12px;
  margin-bottom: 16px;
}

.pwa-guide__step {
  display: grid;
  grid-template-columns: 36px 1fr;
  gap: 12px;
  align-items: start;
}

.pwa-guide__step-icon {
  width: 36px;
  height: 36px;
  border-radius: 12px;
  display: grid;
  place-items: center;
  background: rgba(29, 107, 255, 0.12);
  color: var(--mobile-primary);
  border: 1px solid rgba(29, 107, 255, 0.2);
  font-size: 18px;
}

.pwa-guide__step-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
}

.pwa-guide__step-desc {
  font-size: 12px;
  color: var(--muted);
  margin-top: 2px;
}

.pwa-guide__done {
  border-radius: 12px;
}

:global(body.dark-mode) .pwa-banner {
  background: rgba(15, 23, 42, 0.86);
  border: 1px solid rgba(148, 163, 184, 0.18);
  box-shadow: var(--mobile-shadow);
}

:global(body.dark-mode) .pwa-banner__secondary {
  background: rgba(15, 23, 42, 0.6);
  border-color: rgba(148, 163, 184, 0.2);
}

:global(body.dark-mode) .pwa-guide__step-icon {
  background: rgba(90, 162, 255, 0.18);
  border-color: rgba(90, 162, 255, 0.25);
  color: #5aa2ff;
}
</style>
