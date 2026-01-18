<template>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <div class="brand-mark" aria-hidden="true">
          <span class="brand-initials">NP</span>
          <svg class="brand-pulse" viewBox="0 0 32 16" role="presentation" aria-hidden="true">
            <path
              d="M1 8H7L10 3L14 13L18 8H31"
              fill="none"
              stroke="currentColor"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            ></path>
          </svg>
        </div>
        <div class="brand-text">
          <div class="brand-title">NginxPulse</div>
          <div class="brand-sub">Nginx 访问分析</div>
        </div>
      </div>
      <nav class="menu">
        <RouterLink to="/" class="menu-item" :class="{ active: isActive('/') }">概况</RouterLink>
        <RouterLink to="/daily" class="menu-item" :class="{ active: isActive('/daily') }">数据日报</RouterLink>
        <RouterLink to="/realtime" class="menu-item" :class="{ active: isActive('/realtime') }">实时</RouterLink>
        <RouterLink to="/logs" class="menu-item" :class="{ active: isActive('/logs') }">访问明细</RouterLink>
      </nav>
      <div class="sidebar-footer">
        <template v-if="isActive('/')">
          <div class="sidebar-label">近期活跃</div>
          <div class="sidebar-metric">
            <div class="sidebar-metric-value">{{ liveVisitorText }}</div>
            <div class="sidebar-metric-label">15 分钟活跃访客</div>
          </div>
        </template>
        <template v-else>
          <div class="sidebar-label">{{ sidebarLabel }}</div>
          <div class="sidebar-hint">{{ sidebarHint }}</div>
        </template>
        <div v-if="versionText" class="app-version">
          <span class="app-version-dot" aria-hidden="true"></span>
          <span>{{ versionText }}</span>
        </div>
      </div>
    </aside>

    <main class="main-content" :class="[mainClass, { 'parsing-lock': parsingActive }]">
      <div v-if="demoMode" class="demo-mode-banner">
        <span class="demo-mode-badge">演示模式</span>
        <span class="demo-mode-text">
          当前处于演示模式，数据均为模拟数据。项目源码请移步：
          <a href="https://github.com/likaia/nginxpulse/" target="_blank" rel="noopener">https://github.com/likaia/nginxpulse/</a>
        </span>
      </div>
      <RouterView />
    </main>

    <div v-if="accessKeyRequired" class="access-gate">
      <div class="access-card">
        <div class="access-title">需要访问密钥</div>
        <div class="access-sub">请输入配置的访问密钥后继续使用 NginxPulse。</div>
        <form class="access-form" @submit.prevent="submitAccessKey">
          <input
            v-model="accessKeyInput"
            class="access-input"
            type="password"
            autocomplete="current-password"
            placeholder="输入访问密钥"
          />
          <button class="access-submit" type="submit" :disabled="accessKeySubmitting">
            {{ accessKeySubmitting ? '验证中...' : '进入系统' }}
          </button>
        </form>
        <div v-if="accessKeyError" class="access-error">{{ accessKeyError }}</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, provide, ref, watch } from 'vue';
import { RouterLink, RouterView, useRoute } from 'vue-router';
import { fetchAppStatus } from '@/api';

const route = useRoute();

const ACCESS_KEY_STORAGE = 'nginxpulse_access_key';
const ACCESS_KEY_EVENT = 'nginxpulse:access-key-required';

const sidebarLabel = computed(() => (route.meta.sidebarLabel as string) || '');
const sidebarHint = computed(() => (route.meta.sidebarHint as string) || '');
const mainClass = computed(() => (route.meta.mainClass as string) || '');

const isActive = (path: string) => route.path === path;

const isDark = ref(localStorage.getItem('darkMode') === 'true');
const parsingActive = ref(false);
const liveVisitorCount = ref<number | null>(null);
const demoMode = ref(false);
const appVersion = ref('');
const accessKeyRequired = ref(false);
const accessKeySubmitting = ref(false);
const accessKeyInput = ref(localStorage.getItem(ACCESS_KEY_STORAGE) || '');
const accessKeyError = ref('');

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

onMounted(() => {
  applyTheme(isDark.value);
  refreshAppStatus();
  window.addEventListener(ACCESS_KEY_EVENT, handleAccessKeyEvent);
});

onBeforeUnmount(() => {
  window.removeEventListener(ACCESS_KEY_EVENT, handleAccessKeyEvent);
});

watch(isDark, (value) => {
  applyTheme(value);
});

provide('theme', {
  isDark,
  toggle: toggleTheme,
});

provide('setParsingActive', (value: boolean) => {
  parsingActive.value = value;
});

provide('setLiveVisitorCount', (value: number | null) => {
  liveVisitorCount.value = value;
});

provide('demoMode', demoMode);

async function refreshAppStatus() {
  try {
    const status = await fetchAppStatus();
    demoMode.value = Boolean(status.demo_mode);
    appVersion.value = status.version ?? '';
    accessKeyRequired.value = false;
    accessKeyError.value = '';
  } catch (error) {
    const message = error instanceof Error ? error.message : '请求失败';
    if (message.includes('密钥')) {
      accessKeyRequired.value = true;
      accessKeyError.value = message;
    } else {
      console.error('获取系统状态失败:', error);
    }
  }
}

function handleAccessKeyEvent(event: Event) {
  const detail = (event as CustomEvent<{ message?: string }>).detail;
  accessKeyRequired.value = true;
  accessKeyError.value = detail?.message || '需要访问密钥';
}

async function submitAccessKey() {
  const value = accessKeyInput.value.trim();
  if (!value) {
    accessKeyError.value = '请输入访问密钥';
    return;
  }
  accessKeySubmitting.value = true;
  localStorage.setItem(ACCESS_KEY_STORAGE, value);
  try {
    await refreshAppStatus();
  } finally {
    accessKeySubmitting.value = false;
  }
}

const liveVisitorText = computed(() =>
  Number.isFinite(liveVisitorCount.value ?? NaN)
    ? (liveVisitorCount.value as number).toLocaleString('zh-CN')
    : '--'
);

const versionText = computed(() => appVersion.value || '');
</script>

<style lang="scss" scoped>
.demo-mode-banner {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
  margin-bottom: 16px;
  border-radius: 14px;
  border: 1px solid rgba(239, 68, 68, 0.2);
  background: rgba(239, 68, 68, 0.08);
  color: #991b1b;
  font-size: 13px;
  font-weight: 500;
  box-shadow: var(--shadow-soft);
}

.demo-mode-badge {
  display: inline-flex;
  align-items: center;
  padding: 4px 10px;
  border-radius: 999px;
  background: rgba(239, 68, 68, 0.14);
  color: #b91c1c;
  font-weight: 700;
  font-size: 12px;
  letter-spacing: 0.4px;
}

.demo-mode-text {
  color: inherit;
  line-height: 1.5;
}

.demo-mode-text a {
  color: inherit;
  text-decoration: underline;
  text-underline-offset: 3px;
}

.access-gate {
  position: fixed;
  inset: 0;
  display: grid;
  place-items: center;
  padding: 24px;
  background: rgba(15, 23, 42, 0.35);
  backdrop-filter: blur(10px);
  z-index: 50;
}

.access-card {
  width: min(420px, 100%);
  background: var(--panel);
  border-radius: 22px;
  border: 1px solid var(--border);
  box-shadow: var(--shadow);
  padding: 28px;
  text-align: center;
}

.access-title {
  font-size: 20px;
  font-weight: 700;
  margin-bottom: 6px;
}

.access-sub {
  font-size: 13px;
  color: var(--muted);
  margin-bottom: 18px;
}

.access-form {
  display: grid;
  gap: 12px;
}

.access-input {
  width: 100%;
  padding: 12px 14px;
  border-radius: 14px;
  border: 1px solid var(--border);
  background: var(--input-bg);
  color: var(--text);
  font-size: 14px;
  outline: none;
}

.access-input:focus {
  border-color: rgba(var(--primary-color-rgb), 0.6);
  box-shadow: 0 0 0 3px rgba(var(--primary-color-rgb), 0.15);
}

.access-submit {
  border: none;
  border-radius: 14px;
  padding: 12px 14px;
  font-size: 14px;
  font-weight: 600;
  color: #fff;
  background: linear-gradient(135deg, var(--primary) 0%, var(--primary-strong) 100%);
  cursor: pointer;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
  box-shadow: var(--shadow-soft);
}

.access-submit:hover {
  transform: translateY(-1px);
}

.access-submit:disabled {
  cursor: default;
  opacity: 0.75;
  transform: none;
}

.access-error {
  margin-top: 12px;
  font-size: 12px;
  color: var(--error-color);
}

.app-version {
  margin-top: 14px;
  font-size: 11px;
  color: var(--muted);
  letter-spacing: 0.02em;
  display: flex;
  gap: 6px;
  align-items: center;
}

.app-version-dot {
  width: 6px;
  height: 6px;
  border-radius: 999px;
  background: var(--primary);
  box-shadow: 0 0 0 3px var(--primary-soft);
}
</style>
