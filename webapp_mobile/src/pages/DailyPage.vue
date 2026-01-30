<template>
  <div class="mobile-page">
    <section class="mobile-panel has-dropdown">
      <div class="mobile-panel-header">
        <div>
          <div class="section-title">{{ t('daily.title') }}</div>
          <div class="section-sub">{{ t('daily.subtitle') }}</div>
        </div>
        <van-button size="small" type="primary" plain icon="replay" @click="refreshDaily">
          {{ t('common.refresh') }}
        </van-button>
      </div>
      <div class="filter-row">
        <button type="button" class="filter-trigger" @click="websiteSheetVisible = true">
          <span class="filter-value">{{ currentWebsiteLabel }}</span>
          <van-icon name="arrow-down" />
        </button>
        <button type="button" class="filter-trigger filter-trigger--date" @click="calendarVisible = true">
          <span class="filter-value">{{ currentDateLabel }}</span>
          <van-icon name="arrow-down" />
        </button>
      </div>
    </section>

    <van-empty v-if="!currentWebsiteId && !websitesLoading" :description="t('common.emptyWebsite')" />

    <div v-else class="mobile-page">
      <div v-if="loading" class="mobile-panel">
        <van-loading size="24" />
      </div>

      <div v-else class="mobile-stack">
        <div class="hero-card">
          <div class="hero-title">{{ t('daily.title') }} · {{ currentDate }}</div>
          <div class="hero-value">{{ summaryPv }}</div>
          <div class="hero-meta">
            <span>PV {{ summaryPv }}</span>
            <span>UV {{ summaryUv }}</span>
          </div>
        </div>

        <div class="metric-grid">
          <div v-for="item in metricCards" :key="item.key" class="metric-card">
            <div class="metric-card-header">
              <div class="metric-icon" :class="item.key">
                <svg v-if="item.key === 'pv'" viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M4 15l4-4 4 3 6-7" />
                  <path d="M4 19h16" />
                </svg>
                <svg v-else-if="item.key === 'uv'" viewBox="0 0 24 24" aria-hidden="true">
                  <circle cx="8" cy="8" r="3" />
                  <circle cx="16" cy="10" r="3" />
                  <path d="M4 19c0-3 2.5-5 5-5" />
                  <path d="M12 19c0-2.5 2-4 4-4" />
                </svg>
                <svg v-else-if="item.key === 'session'" viewBox="0 0 24 24" aria-hidden="true">
                  <rect x="4" y="5" width="16" height="13" rx="3" />
                  <path d="M8 10h8M8 14h5" />
                </svg>
                <svg v-else viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M4 18h16" />
                  <path d="M7 16V8" />
                  <path d="M12 16V6" />
                  <path d="M17 16v-5" />
                </svg>
              </div>
              <div class="metric-label">{{ item.label }}</div>
            </div>
            <div class="metric-value">{{ item.value }}</div>
          </div>
        </div>

        <section class="mobile-panel list-card">
          <div class="mobile-panel-header">
            <div class="mobile-panel-title">{{ t('daily.trendTitle') }}</div>
          </div>
          <van-cell-group inset>
            <van-cell
              v-for="item in hourlyRows"
              :key="item.label"
              :title="item.label"
            >
              <template #label>
                <van-progress :percentage="item.percent" stroke-width="6" :show-pivot="false" />
              </template>
              <template #value>
                <div class="inline-tags">
                  <van-tag type="primary">PV {{ item.pv }}</van-tag>
                  <van-tag type="success">UV {{ item.uv }}</van-tag>
                </div>
              </template>
            </van-cell>
          </van-cell-group>
          <div v-if="hourlyRows.length === 0" class="list-empty">{{ t('daily.trendEmpty') }}</div>
        </section>
      </div>
    </div>

    <van-calendar
      v-model:show="calendarVisible"
      teleport="body"
      :lazy-render="false"
      :min-date="minDate"
      :max-date="maxDate"
      @confirm="onConfirmDate"
    />

    <van-action-sheet
      v-model:show="websiteSheetVisible"
      :duration="ACTION_SHEET_DURATION"
      teleport="body"
      :actions="websiteActions"
      :cancel-text="t('common.cancel')"
      close-on-click-action
      @select="onSelectWebsite"
    />
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import { fetchOverallStats, fetchTimeSeriesStats, fetchWebsites } from '@/api';
import type { TimeSeriesStats, WebsiteInfo } from '@/api/types';
import { formatDate, formatTraffic, getUserPreference, saveUserPreference } from '@/utils';
import { ACTION_SHEET_DURATION } from '@mobile/constants/ui';

const { t, n } = useI18n({ useScope: 'global' });

const websites = ref<WebsiteInfo[]>([]);
const websitesLoading = ref(false);
const websiteSheetVisible = ref(false);
const currentWebsiteId = ref('');
const currentDate = ref(getUserPreference('dailyReportDate', '') || formatDate(new Date()));
const calendarVisible = ref(false);
const loading = ref(false);
const overall = ref<Record<string, any> | null>(null);
const timeSeries = ref<TimeSeriesStats | null>(null);

const minDate = new Date(2020, 0, 1);
const maxDate = new Date();

const websiteOptions = computed(() =>
  websites.value.map((site) => ({ text: site.name, value: site.id }))
);

const websiteActions = computed(() =>
  websites.value.map((site) => ({ name: site.name, value: site.id }))
);

const todayLabel = computed(() => formatDate(new Date()));
const yesterdayLabel = computed(() => {
  const date = new Date();
  date.setDate(date.getDate() - 1);
  return formatDate(date);
});

const currentWebsiteLabel = computed(() => {
  if (!currentWebsiteId.value) {
    return t('common.selectWebsite');
  }
  return websites.value.find((site) => site.id === currentWebsiteId.value)?.name || t('common.selectWebsite');
});

const currentDateLabel = computed(() => {
  if (currentDate.value === todayLabel.value) {
    return t('common.today');
  }
  if (currentDate.value === yesterdayLabel.value) {
    return t('common.yesterday');
  }
  return currentDate.value;
});

const metricCards = computed(() => {
  const data = overall.value || {};
  return [
    {
      key: 'pv',
      label: t('daily.pv'),
      value: formatCount(data.pv),
    },
    {
      key: 'uv',
      label: t('daily.uv'),
      value: formatCount(data.uv),
    },
    {
      key: 'session',
      label: t('daily.session'),
      value: formatCount(data.sessionCount),
    },
    {
      key: 'traffic',
      label: t('common.traffic'),
      value: formatTraffic(Number(data.traffic || 0)),
    },
  ];
});

const summaryPv = computed(() => formatCount(overall.value?.pv));
const summaryUv = computed(() => formatCount(overall.value?.uv));

const hourlyMax = computed(() => {
  const values = timeSeries.value?.pageviews || [];
  return values.reduce((max, value) => (value > max ? value : max), 0);
});

const hourlyRows = computed(() => {
  if (!timeSeries.value) {
    return [] as Array<{ label: string; pv: string; uv: string }>;
  }
  return timeSeries.value.labels.map((label, index) => {
    const pv = timeSeries.value?.pageviews?.[index] ?? 0;
    const uv = timeSeries.value?.visitors?.[index] ?? 0;
    const max = hourlyMax.value || 0;
    const percent = max > 0 ? Math.min(100, Math.round((pv / max) * 100)) : 0;
    return {
      label,
      pv: formatCount(pv),
      uv: formatCount(uv),
      percent,
    };
  });
});

function formatCount(value: number | string | undefined | null) {
  const num = Number(value || 0);
  if (!Number.isFinite(num)) {
    return t('common.none');
  }
  return n(num);
}

function onConfirmDate(date: Date | Date[]) {
  const picked = Array.isArray(date) ? date[0] : date;
  currentDate.value = formatDate(picked);
  calendarVisible.value = false;
}

function onSelectWebsite(action: { value?: string }) {
  if (action?.value) {
    currentWebsiteId.value = action.value;
  }
}

async function loadWebsites() {
  websitesLoading.value = true;
  try {
    const data = await fetchWebsites();
    websites.value = data || [];
    const saved = getUserPreference('selectedWebsite', '');
    if (saved && websites.value.find((site) => site.id === saved)) {
      currentWebsiteId.value = saved;
    } else if (websites.value.length > 0) {
      currentWebsiteId.value = websites.value[0].id;
    } else {
      currentWebsiteId.value = '';
    }
  } catch (error) {
    console.error('初始化网站失败:', error);
    websites.value = [];
    currentWebsiteId.value = '';
  } finally {
    websitesLoading.value = false;
  }
}

async function refreshDaily() {
  if (!currentWebsiteId.value) {
    return;
  }
  loading.value = true;
  try {
    const [overallData, timeSeriesData] = await Promise.all([
      fetchOverallStats(currentWebsiteId.value, currentDate.value),
      fetchTimeSeriesStats(currentWebsiteId.value, currentDate.value, 'hourly'),
    ]);
    overall.value = overallData;
    timeSeries.value = timeSeriesData;
  } catch (error) {
    console.error('加载日报失败:', error);
  } finally {
    loading.value = false;
  }
}

watch(currentWebsiteId, (value) => {
  if (value) {
    saveUserPreference('selectedWebsite', value);
  }
  refreshDaily();
});

watch(currentDate, (value) => {
  if (value) {
    saveUserPreference('dailyReportDate', value);
  }
  refreshDaily();
});

watch(calendarVisible, (value) => {
  if (value) {
    nextTick(() => {
      requestAnimationFrame(() => {
        window.dispatchEvent(new Event('resize'));
      });
    });
  }
});

onMounted(() => {
  loadWebsites();
});
</script>
