<template>
  <header class="page-header">
    <div class="page-title">
      <span class="title-chip">{{ t('daily.title') }}</span>
      <p class="title-sub">{{ t('daily.subtitle') }}</p>
    </div>
    <div class="header-actions header-actions-tech">
      <HeaderToolbar class="header-toolbar-tech">
        <template #primary>
          <div class="site-select-pill">
            <span class="site-label">{{ t('common.website') }}</span>
            <WebsiteSelect
              v-model="currentWebsiteId"
              class="website-select-compact"
              :websites="websites"
              :loading="websitesLoading"
              id="daily-website-selector"
              label=""
            />
          </div>
          <div class="site-select-pill">
            <span class="site-label">{{ t('common.date') }}</span>
            <DatePicker
              v-model="currentDate"
              class="daily-date-picker toolbar-date-picker"
              dateFormat="yy-mm-dd"
              updateModelType="string"
              :showClear="false"
              showButtonBar
              :showIcon="true"
            />
          </div>
        </template>
        <template #utility>
          <SystemNotifications />
          <ThemeToggle />
        </template>
      </HeaderToolbar>
    </div>
  </header>

  <section class="daily-kpi-grid">
    <div class="card daily-kpi-card">
      <div class="daily-kpi-header">
        <div>
          <div class="daily-kpi-title">{{ t('daily.pv') }}</div>
          <div class="daily-kpi-date">{{ currentDate }}</div>
        </div>
        <span class="daily-kpi-icon orange"><i class="ri-pages-line"></i></span>
      </div>
      <div class="daily-kpi-value">{{ kpiMetrics.pv.valueText }}</div>
      <div class="daily-kpi-compare">
        <span>{{ t('common.comparePrev') }}</span>
        <span class="daily-kpi-delta" :class="kpiMetrics.pv.deltaClass">{{ kpiMetrics.pv.deltaText }}</span>
        <span class="daily-kpi-rate" :class="kpiMetrics.pv.rateClass">{{ kpiMetrics.pv.rateText }}</span>
      </div>
    </div>
    <div class="card daily-kpi-card">
      <div class="daily-kpi-header">
        <div>
          <div class="daily-kpi-title">{{ t('daily.uv') }}</div>
          <div class="daily-kpi-date">{{ currentDate }}</div>
        </div>
        <span class="daily-kpi-icon green"><i class="ri-user-3-line"></i></span>
      </div>
      <div class="daily-kpi-value">{{ kpiMetrics.uv.valueText }}</div>
      <div class="daily-kpi-compare">
        <span>{{ t('common.comparePrev') }}</span>
        <span class="daily-kpi-delta" :class="kpiMetrics.uv.deltaClass">{{ kpiMetrics.uv.deltaText }}</span>
        <span class="daily-kpi-rate" :class="kpiMetrics.uv.rateClass">{{ kpiMetrics.uv.rateText }}</span>
      </div>
    </div>
    <div class="card daily-kpi-card">
      <div class="daily-kpi-header">
        <div>
          <div class="daily-kpi-title">{{ t('daily.session') }}</div>
          <div class="daily-kpi-date">{{ currentDate }}</div>
        </div>
        <span class="daily-kpi-icon blue"><i class="ri-chat-3-line"></i></span>
      </div>
      <div class="daily-kpi-value">{{ kpiMetrics.session.valueText }}</div>
      <div class="daily-kpi-compare">
        <span>{{ t('common.comparePrev') }}</span>
        <span class="daily-kpi-delta" :class="kpiMetrics.session.deltaClass">{{ kpiMetrics.session.deltaText }}</span>
        <span class="daily-kpi-rate" :class="kpiMetrics.session.rateClass">{{ kpiMetrics.session.rateText }}</span>
      </div>
    </div>
    <div class="card daily-kpi-card">
      <div class="daily-kpi-header">
        <div>
          <div class="daily-kpi-title">{{ t('daily.bounce') }}</div>
          <div class="daily-kpi-date">{{ currentDate }}</div>
        </div>
        <span class="daily-kpi-icon purple"><i class="ri-run-line"></i></span>
      </div>
      <div class="daily-kpi-value">{{ kpiMetrics.bounce.valueText }}</div>
      <div class="daily-kpi-compare">
        <span>{{ t('common.comparePrev') }}</span>
        <span class="daily-kpi-delta" :class="kpiMetrics.bounce.deltaClass">{{ kpiMetrics.bounce.deltaText }}</span>
        <span class="daily-kpi-rate" :class="kpiMetrics.bounce.rateClass">{{ kpiMetrics.bounce.rateText }}</span>
      </div>
    </div>
    <div class="card daily-kpi-card">
      <div class="daily-kpi-header">
        <div>
          <div class="daily-kpi-title">{{ t('daily.duration') }}</div>
          <div class="daily-kpi-date">{{ currentDate }}</div>
        </div>
        <span class="daily-kpi-icon teal"><i class="ri-time-line"></i></span>
      </div>
      <div class="daily-kpi-value">{{ kpiMetrics.duration.valueText }}</div>
      <div class="daily-kpi-compare">
        <span>{{ t('common.comparePrev') }}</span>
        <span class="daily-kpi-delta" :class="kpiMetrics.duration.deltaClass">{{ kpiMetrics.duration.deltaText }}</span>
        <span class="daily-kpi-rate" :class="kpiMetrics.duration.rateClass">{{ kpiMetrics.duration.rateText }}</span>
      </div>
    </div>
  </section>

  <section class="daily-mini-grid">
    <div class="card daily-mini-card">
      <div class="daily-mini-title">{{ t('daily.ipAvg') }}</div>
      <div class="daily-mini-body">
        <div class="daily-mini-metric">
          <div class="daily-mini-label">{{ t('daily.changeRate') }}</div>
          <div class="daily-mini-value" :class="ipAvg.rateClass">{{ ipAvg.rateText }}</div>
        </div>
        <div class="daily-mini-meta">
          <div>{{ t('daily.yesterday') }} <span>{{ ipAvg.currentText }}</span></div>
          <div>{{ t('daily.prevDay') }} <span>{{ ipAvg.prevText }}</span></div>
        </div>
      </div>
    </div>
    <div class="card daily-mini-card">
      <div class="daily-mini-title">{{ t('daily.uvAvg') }}</div>
      <div class="daily-mini-body">
        <div class="daily-mini-metric">
          <div class="daily-mini-label">{{ t('daily.changeRate') }}</div>
          <div class="daily-mini-value" :class="ipAvg.rateClass">{{ ipAvg.rateText }}</div>
        </div>
        <div class="daily-mini-meta">
          <div>{{ t('daily.yesterday') }} <span>{{ ipAvg.currentText }}</span></div>
          <div>{{ t('daily.prevDay') }} <span>{{ ipAvg.prevText }}</span></div>
        </div>
      </div>
    </div>
    <div class="card daily-trend-card">
      <div class="daily-trend-header">
        <div class="daily-trend-title">{{ t('daily.trendTitle') }}</div>
        <div class="daily-trend-sub">{{ trendSummary }}</div>
      </div>
      <div class="daily-trend-chart">
        <canvas ref="ipChartRef"></canvas>
      </div>
    </div>
  </section>

  <section class="card daily-section">
    <div class="daily-section-header">
      <div class="daily-section-title">
        <span class="section-icon blue"><i class="ri-compass-3-line"></i></span>
        {{ t('daily.sourceAnalysis') }}
      </div>
    </div>
    <div class="daily-section-body daily-source-grid">
      <div class="daily-donut-card">
        <div class="daily-donut">
          <canvas ref="sourceChartRef"></canvas>
        </div>
        <div class="daily-summary-cards">
          <div class="daily-summary-card search">
            <div class="daily-summary-label">{{ t('daily.searchEngine') }}</div>
            <div class="daily-summary-value">{{ sourceCards.search.countText }}</div>
            <div class="daily-summary-rate" :class="sourceCards.search.rateClass">{{ sourceCards.search.rateText }}</div>
          </div>
          <div class="daily-summary-card direct">
            <div class="daily-summary-label">{{ t('daily.direct') }}</div>
            <div class="daily-summary-value">{{ sourceCards.direct.countText }}</div>
            <div class="daily-summary-rate" :class="sourceCards.direct.rateClass">{{ sourceCards.direct.rateText }}</div>
          </div>
          <div class="daily-summary-card external">
            <div class="daily-summary-label">{{ t('daily.external') }}</div>
            <div class="daily-summary-value">{{ sourceCards.external.countText }}</div>
            <div class="daily-summary-rate" :class="sourceCards.external.rateClass">{{ sourceCards.external.rateText }}</div>
          </div>
        </div>
      </div>
      <div class="daily-table-card">
        <div class="daily-tab-bar">
          <button class="daily-tab" :class="{ active: sourceTab === 'referer' }" @click="sourceTab = 'referer'">{{ t('daily.refererTop') }}</button>
          <button class="daily-tab" :class="{ active: sourceTab === 'search' }" @click="sourceTab = 'search'">{{ t('daily.searchEngine') }}</button>
          <button class="daily-tab" :class="{ active: sourceTab === 'ip' }" @click="sourceTab = 'ip'">{{ t('daily.visitorIpTop') }}</button>
        </div>
        <div v-if="sourceTab === 'ip'" class="daily-source-inline">
          <span class="daily-source-filter-label">{{ t('daily.ipSourceFilter') }}</span>
          <button class="daily-source-link" :class="{ active: sourceIPTab === 'all' }" @click="sourceIPTab = 'all'">
            {{ t('daily.ipSourceAll') }}
          </button>
          <span class="daily-source-divider">/</span>
          <button class="daily-source-link" :class="{ active: sourceIPTab === 'search' }" @click="sourceIPTab = 'search'">
            {{ t('daily.ipSourceSearch') }}
          </button>
          <span class="daily-source-divider">/</span>
          <button class="daily-source-link" :class="{ active: sourceIPTab === 'direct' }" @click="sourceIPTab = 'direct'">
            {{ t('daily.ipSourceDirect') }}
          </button>
          <span class="daily-source-divider">/</span>
          <button class="daily-source-link" :class="{ active: sourceIPTab === 'external' }" @click="sourceIPTab = 'external'">
            {{ t('daily.ipSourceExternal') }}
          </button>
        </div>
        <div class="table-wrapper">
          <table class="ranking-table" v-show="sourceTab === 'referer'">
            <thead>
              <tr>
                <th>{{ t('daily.refererTop') }}</th>
                <th>{{ t('daily.ipCount') }}</th>
                <th>{{ t('daily.ipDelta') }}</th>
                <th>{{ t('daily.changeRate') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="!refererRows.length">
                <td colspan="4">{{ t('common.noData') }}</td>
              </tr>
              <tr v-else v-for="row in refererRows" :key="row.label">
                <td>{{ row.label }}</td>
                <td>{{ row.valueText }}</td>
                <td :class="row.deltaClass">{{ row.deltaText }}</td>
                <td :class="row.rateClass">{{ row.rateText }}</td>
              </tr>
            </tbody>
          </table>
          <table class="ranking-table" v-show="sourceTab === 'search'">
            <thead>
              <tr>
                <th>{{ t('daily.searchEngine') }}</th>
                <th>{{ t('daily.ipCount') }}</th>
                <th>{{ t('daily.ipDelta') }}</th>
                <th>{{ t('daily.changeRate') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="!searchRows.length">
                <td colspan="4">{{ t('common.noData') }}</td>
              </tr>
              <tr v-else v-for="row in searchRows" :key="row.label">
                <td>{{ row.label }}</td>
                <td>{{ row.valueText }}</td>
                <td :class="row.deltaClass">{{ row.deltaText }}</td>
                <td :class="row.rateClass">{{ row.rateText }}</td>
              </tr>
            </tbody>
          </table>
          <table class="ranking-table" v-show="sourceTab === 'ip'">
            <thead>
              <tr>
                <th>{{ sourceIPTableTitle }}</th>
                <th>{{ t('daily.ipCount') }}</th>
                <th>{{ t('daily.ipDelta') }}</th>
                <th>{{ t('daily.changeRate') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="!sourceIPRows.length">
                <td colspan="4">{{ t('common.noData') }}</td>
              </tr>
              <tr v-else v-for="row in sourceIPRows" :key="row.label" class="daily-ip-row" @click="goToLogsByIP(row.label)">
                <td class="daily-ip-cell">
                  <span class="daily-ip-main">
                    <span class="daily-ip-label" :title="row.label">{{ row.label }}</span>
                    <i class="ri-information-line daily-ip-info" aria-hidden="true"></i>
                  </span>
                  <div class="daily-ip-popover" role="tooltip">
                    <div class="daily-ip-popover-line">
                      <span>{{ t('daily.ipSourceShare') }}</span>
                      <strong>{{ row.sourceShareText }}</strong>
                    </div>
                    <div class="daily-ip-popover-line">
                      <span>{{ t('daily.ipRegion') }}</span>
                      <strong>{{ row.regionText }}</strong>
                    </div>
                  </div>
                </td>
                <td>{{ row.valueText }}</td>
                <td :class="row.deltaClass">{{ row.deltaText }}</td>
                <td :class="row.rateClass">{{ row.rateText }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div class="daily-summary-strip">{{ sourceSummaryText }}</div>
      </div>
    </div>
  </section>

  <section class="daily-dual-grid">
    <div class="card daily-section">
    <div class="daily-section-header">
      <div class="daily-section-title">
        <span class="section-icon orange"><i class="ri-pages-line"></i></span>
        {{ t('daily.contentAnalysis') }}
      </div>
    </div>
    <div class="table-wrapper">
      <table class="ranking-table">
        <thead>
          <tr>
            <th>{{ t('daily.topPages') }}</th>
            <th>{{ t('daily.ipContribution') }}</th>
            <th>{{ t('daily.change') }}</th>
            <th>{{ t('daily.pvContribution') }}</th>
            <th>{{ t('daily.change') }}</th>
          </tr>
        </thead>
        <tbody>
          <tr v-if="!contentRows.length">
            <td colspan="5">{{ t('common.noData') }}</td>
          </tr>
            <tr v-else v-for="row in contentRows" :key="row.label">
              <td>{{ row.label }}</td>
              <td>{{ row.uvText }}</td>
              <td :class="row.uvRateClass">{{ row.uvRateText }}</td>
              <td>{{ row.pvText }}</td>
              <td :class="row.pvRateClass">{{ row.pvRateText }}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
    <div class="card daily-section">
    <div class="daily-section-header">
      <div class="daily-section-title">
        <span class="section-icon green"><i class="ri-user-heart-line"></i></span>
        {{ t('daily.visitorAnalysis') }}
      </div>
    </div>
      <div class="daily-visitor-grid">
        <div class="daily-donut">
          <canvas ref="visitorChartRef"></canvas>
        </div>
        <div class="daily-visitor-table">
          <table class="ranking-table">
            <thead>
              <tr>
                <th>{{ t('daily.visitor') }}</th>
                <th>{{ t('common.percentage') }}</th>
                <th>{{ t('common.change') }}</th>
                <th>{{ t('daily.avgDuration') }}</th>
                <th>{{ t('daily.avgPageview') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="!visitorRows.length">
                <td colspan="5">{{ t('common.noData') }}</td>
              </tr>
              <tr v-else v-for="row in visitorRows" :key="row.label">
                <td>{{ row.label }}</td>
                <td>{{ row.shareText }}</td>
                <td :class="row.rateClass">{{ row.rateText }}</td>
                <td>{{ row.durationText }}</td>
                <td>{{ row.avgPvText }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </section>

  <section class="card daily-section">
    <div class="daily-section-header">
      <div class="daily-section-title">
        <span class="section-icon blue"><i class="ri-device-line"></i></span>
        {{ t('daily.deviceAnalysis') }}
      </div>
    </div>
    <div class="daily-device-grid">
      <div class="daily-device-left">
        <div class="daily-donut">
          <canvas ref="deviceChartRef"></canvas>
        </div>
        <div class="daily-device-cards">
          <div class="daily-device-card">
            <div class="daily-device-icon"><i class="ri-computer-line"></i></div>
            <div class="daily-device-label">{{ t('daily.devicePc') }}</div>
            <div class="daily-device-value">{{ deviceCards.pc }}</div>
          </div>
          <div class="daily-device-card">
            <div class="daily-device-icon"><i class="ri-apple-line"></i></div>
            <div class="daily-device-label">{{ t('daily.deviceIos') }}</div>
            <div class="daily-device-value">{{ deviceCards.ios }}</div>
          </div>
          <div class="daily-device-card">
            <div class="daily-device-icon"><i class="ri-android-line"></i></div>
            <div class="daily-device-label">{{ t('daily.deviceAndroid') }}</div>
            <div class="daily-device-value">{{ deviceCards.android }}</div>
          </div>
        </div>
      </div>
      <div class="daily-device-list">
        <div class="daily-list-title">{{ t('daily.cityTop') }}</div>
        <div class="table-wrapper">
          <table class="ranking-table">
            <thead>
              <tr>
                <th>{{ t('daily.city') }}</th>
                <th>{{ t('common.percentage') }}</th>
                <th>{{ t('common.change') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="!cityRows.length">
                <td colspan="3">{{ t('common.noData') }}</td>
              </tr>
              <tr v-else v-for="row in cityRows" :key="row.label">
                <td>{{ row.label }}</td>
                <td>{{ row.shareText }}</td>
                <td :class="row.rateClass">{{ row.rateText }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
      <div class="daily-device-list">
        <div class="daily-list-title">{{ t('daily.browserTop') }}</div>
        <div class="table-wrapper">
          <table class="ranking-table">
            <thead>
              <tr>
                <th>{{ t('common.browser') }}</th>
                <th>{{ t('common.percentage') }}</th>
                <th>{{ t('common.change') }}</th>
              </tr>
            </thead>
            <tbody>
              <tr v-if="!browserRows.length">
                <td colspan="3">{{ t('common.noData') }}</td>
              </tr>
              <tr v-else v-for="row in browserRows" :key="row.label">
                <td>{{ row.label }}</td>
                <td>{{ row.shareText }}</td>
                <td :class="row.rateClass">{{ row.rateText }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </section>

  <ParsingOverlay @finished="loadDailyReport" />
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import { useRouter } from 'vue-router';
import {
  fetchBrowserStats,
  fetchDeviceStats,
  fetchLocationStats,
  fetchOSStats,
  fetchOverallStats,
  fetchRefererIPBatchStats,
  fetchRefererStats,
  fetchSessionSummary,
  fetchTimeSeriesStats,
  fetchUrlStats,
  fetchWebsites,
} from '@/api';
import type { RefererIPBatchStats, RefererIPGroupStats, SimpleSeriesStats, TimeSeriesStats, WebsiteInfo } from '@/api/types';
import {
  formatBrowserLabel,
  formatDeviceLabel,
  formatLocationLabel,
  formatRefererLabel,
  isDirectReferer,
  normalizeDeviceCategory,
} from '@/i18n/mappings';
import { normalizeLocale } from '@/i18n';
import { formatDate, getUserPreference, saveUserPreference } from '@/utils';
import { Chart } from '@/utils/chartjs';
import ParsingOverlay from '@/components/ParsingOverlay.vue';
import HeaderToolbar from '@/components/HeaderToolbar.vue';
import SystemNotifications from '@/components/SystemNotifications.vue';
import ThemeToggle from '@/components/ThemeToggle.vue';
import WebsiteSelect from '@/components/WebsiteSelect.vue';

const websites = ref<WebsiteInfo[]>([]);
const websitesLoading = ref(true);
const currentWebsiteId = ref('');
const currentDate = ref(formatDate(new Date()));
const router = useRouter();
const { t, n, locale } = useI18n({ useScope: 'global' });
const currentLocale = computed(() => normalizeLocale(locale.value));

const overall = ref<Record<string, any> | null>(null);
const sessionSummary = ref<Record<string, any> | null>(null);
const sessionSummaryPrev = ref<Record<string, any> | null>(null);
const timeSeries = ref<TimeSeriesStats | null>(null);
const refererStats = ref<SimpleSeriesStats | null>(null);
const refererPrev = ref<SimpleSeriesStats | null>(null);
const urlStats = ref<SimpleSeriesStats | null>(null);
const urlPrev = ref<SimpleSeriesStats | null>(null);
const deviceStats = ref<SimpleSeriesStats | null>(null);
const devicePrev = ref<SimpleSeriesStats | null>(null);
const osStats = ref<SimpleSeriesStats | null>(null);
const osPrev = ref<SimpleSeriesStats | null>(null);
const browserStats = ref<SimpleSeriesStats | null>(null);
const browserPrev = ref<SimpleSeriesStats | null>(null);
const cityStats = ref<SimpleSeriesStats | null>(null);
const cityPrev = ref<SimpleSeriesStats | null>(null);

type SourceIPKind = 'all' | 'search' | 'direct' | 'external';

const refererIPBatch = ref<RefererIPBatchStats | null>(null);
const refererIPBatchPrev = ref<RefererIPBatchStats | null>(null);

const sourceTab = ref<'referer' | 'search' | 'ip'>('referer');
const sourceIPTab = ref<SourceIPKind>('all');

const ipChartRef = ref<HTMLCanvasElement | null>(null);
const sourceChartRef = ref<HTMLCanvasElement | null>(null);
const visitorChartRef = ref<HTMLCanvasElement | null>(null);
const deviceChartRef = ref<HTMLCanvasElement | null>(null);

let ipChart: Chart | null = null;
let sourceChart: Chart | null = null;
let visitorChart: Chart | null = null;
let deviceChart: Chart | null = null;

let dailyRequestId = 0;

const trendSummary = computed(() => {
  if (!timeSeries.value || !timeSeries.value.labels) {
    return t('daily.trendPending');
  }
  const data = timeSeries.value.visitors || [];
  if (!data.length) {
    return t('daily.trendEmpty');
  }
  const maxIndex = data.indexOf(Math.max(...data));
  const minIndex = data.indexOf(Math.min(...data));
  return t('daily.trendSummary', { max: maxIndex, min: minIndex });
});

const kpiMetrics = computed(() => {
  const current = overall.value || {};
  const prev = current.compare?.previous || {};
  const currentSession = sessionSummary.value || {};
  const prevSession = sessionSummaryPrev.value || {};

  return {
    pv: buildMetric(current.pv || 0, prev.pv || 0),
    uv: buildMetric(current.uv || 0, prev.uv || 0),
    session: buildMetric(current.sessionCount || 0, prev.sessionCount || 0),
    bounce: buildPercentMetric(currentSession.bounceRate || 0, prevSession.bounceRate || 0),
    duration: buildDurationMetric(currentSession.avgDurationSeconds || 0, prevSession.avgDurationSeconds || 0),
  }
});

const ipAvg = computed(() => {
  const current = overall.value || {};
  const prev = current.compare?.previous || {};
  const avg = current.uv > 0 ? current.pv / current.uv : 0;
  const prevAvg = prev.uv > 0 ? prev.pv / prev.uv : 0;
  const rate = calcRate(avg, prevAvg);
  return {
    currentText: formatNumber(avg),
    prevText: formatNumber(prevAvg),
    rateText: formatRate(rate),
    rateClass: rateClass(rate),
  }
});

const sourceGroups = computed(() => groupReferers(refererStats.value));
const sourcePrevGroups = computed(() => groupReferers(refererPrev.value));

const sourceCards = computed(() => {
  const current = sourceGroups.value;
  const prev = sourcePrevGroups.value;
  return {
    search: buildSourceCard(current.search, prev.search),
    direct: buildSourceCard(current.direct, prev.direct),
    external: buildSourceCard(current.external, prev.external),
  }
});

const refererRows = computed(() => buildRefererRows(refererStats.value, refererPrev.value, false));
const searchRows = computed(() => buildRefererRows(refererStats.value, refererPrev.value, true));
const sourceIPRows = computed(() =>
  buildIPRows(
    getSourceIPGroup(refererIPBatch.value, sourceIPTab.value),
    getSourceIPGroup(refererIPBatchPrev.value, sourceIPTab.value)
  )
);
const sourceIPScopeLabel = computed(() => {
  if (sourceIPTab.value === 'search') {
    return t('daily.ipSourceSearch');
  }
  if (sourceIPTab.value === 'direct') {
    return t('daily.ipSourceDirect');
  }
  if (sourceIPTab.value === 'external') {
    return t('daily.ipSourceExternal');
  }
  return t('daily.ipSourceAll');
});
const sourceIPTableTitle = computed(() => `${sourceIPScopeLabel.value} · ${t('daily.visitorIp')}`);
const sourceSummary = computed(() => buildSourceSummary(refererStats.value, refererPrev.value));
const sourceIPSummary = computed(() => buildSourceIPSummary(sourceIPRows.value, sourceIPScopeLabel.value));
const sourceSummaryText = computed(() => (sourceTab.value === 'ip' ? sourceIPSummary.value : sourceSummary.value));
const contentRows = computed(() => buildContentRows(urlStats.value, urlPrev.value));
const visitorRows = computed(() => buildVisitorRows(overall.value, sessionSummary.value));
const deviceCards = computed(() => buildDeviceCards(deviceStats.value, osStats.value));
const browserRows = computed(() =>
  buildSimpleRows(browserStats.value, browserPrev.value, (label) => formatBrowserLabel(label, t))
);
const cityRows = computed(() =>
  buildSimpleRows(cityStats.value, cityPrev.value, (label) => formatLocationLabel(label, currentLocale.value, t))
);

onMounted(() => {
  initDateFromQuery();
  loadWebsites();
});

onBeforeUnmount(() => {
  destroyCharts();
});

watch(currentWebsiteId, (value) => {
  if (value) {
    saveUserPreference('selectedWebsite', value);
  }
  loadDailyReport();
});

watch(currentDate, (value) => {
  if (value) {
    saveUserPreference('dailyReportDate', value);
  }
  loadDailyReport();
});

watch(timeSeries, (stats) => {
  if (stats) {
    renderTrend(stats);
  }
});

watch(sourceGroups, (groups) => {
  renderSourceDonut(groups);
});

watch(visitorRows, () => {
  renderVisitorDonut();
});

watch(deviceCards, () => {
  renderDeviceDonut();
});

function initDateFromQuery() {
  const queryDate = getDateFromQuery();
  const savedDate = getUserPreference('dailyReportDate', '');
  const defaultDate = queryDate || savedDate || formatDate(new Date());
  currentDate.value = defaultDate;
  if (queryDate) {
    saveUserPreference('dailyReportDate', defaultDate);
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

async function loadDailyReport() {
  if (!currentWebsiteId.value || !currentDate.value) {
    return;
  }

  const requestId = ++dailyRequestId;
  const dateStr = currentDate.value;
  const prevDate = shiftDate(dateStr, -1);

  try {
    const [
      overallData,
      sessionData,
      sessionPrevData,
      timeSeriesData,
      refererData,
      refererPrevData,
      refererIPBatchData,
      refererIPBatchPrevData,
      urlData,
      urlPrevData,
      deviceData,
      devicePrevData,
      osData,
      osPrevData,
      browserData,
      browserPrevData,
      cityData,
      cityPrevData,
    ] = await Promise.all([
      fetchOverallStats(currentWebsiteId.value, dateStr),
      fetchSessionSummary(currentWebsiteId.value, dateStr),
      fetchSessionSummary(currentWebsiteId.value, prevDate),
      fetchTimeSeriesStats(currentWebsiteId.value, prevDate, 'hourly'),
      fetchRefererStats(currentWebsiteId.value, dateStr, 10),
      fetchRefererStats(currentWebsiteId.value, prevDate, 10),
      fetchRefererIPBatchStats(currentWebsiteId.value, dateStr, 10),
      fetchRefererIPBatchStats(currentWebsiteId.value, prevDate, 10),
      fetchUrlStats(currentWebsiteId.value, dateStr, 10),
      fetchUrlStats(currentWebsiteId.value, prevDate, 10),
      fetchDeviceStats(currentWebsiteId.value, dateStr, 10),
      fetchDeviceStats(currentWebsiteId.value, prevDate, 10),
      fetchOSStats(currentWebsiteId.value, dateStr, 10),
      fetchOSStats(currentWebsiteId.value, prevDate, 10),
      fetchBrowserStats(currentWebsiteId.value, dateStr, 10),
      fetchBrowserStats(currentWebsiteId.value, prevDate, 10),
      fetchLocationStats(currentWebsiteId.value, dateStr, 'city', 10),
      fetchLocationStats(currentWebsiteId.value, prevDate, 'city', 10),
    ]);

    if (requestId !== dailyRequestId) {
      return;
    }

    overall.value = overallData;
    sessionSummary.value = sessionData;
    sessionSummaryPrev.value = sessionPrevData;
    timeSeries.value = timeSeriesData;
    refererStats.value = refererData;
    refererPrev.value = refererPrevData;
    refererIPBatch.value = refererIPBatchData;
    refererIPBatchPrev.value = refererIPBatchPrevData;
    urlStats.value = urlData;
    urlPrev.value = urlPrevData;
    deviceStats.value = deviceData;
    devicePrev.value = devicePrevData;
    osStats.value = osData;
    osPrev.value = osPrevData;
    browserStats.value = browserData;
    browserPrev.value = browserPrevData;
    cityStats.value = cityData;
    cityPrev.value = cityPrevData;
  } catch (error) {
    console.error('加载日报失败:', error);
  }
}

function renderTrend(stats: TimeSeriesStats) {
  if (!ipChartRef.value) {
    return;
  }
  if (ipChart) {
    ipChart.destroy();
  }
  const ctx = ipChartRef.value.getContext('2d');
  if (!ctx) {
    return;
  }
  const gradient = ctx.createLinearGradient(0, 0, 0, ipChartRef.value.height || 160);
  gradient.addColorStop(0, 'rgba(30, 123, 255, 0.35)');
  gradient.addColorStop(1, 'rgba(30, 123, 255, 0.05)');
  ipChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: stats.labels,
      datasets: [
        {
          label: t('daily.ipTraffic'),
          data: stats.visitors,
          borderColor: '#1e7bff',
          backgroundColor: gradient,
          borderWidth: 2,
          tension: 0.4,
          pointRadius: 0,
          fill: true,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { ticks: { color: '#94a3b8', maxTicksLimit: 12 }, grid: { display: false } },
        y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(148, 163, 184, 0.2)' } },
      },
      plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
    },
  });
}

function renderSourceDonut(groups: Record<string, number>) {
  if (!sourceChartRef.value) {
    return;
  }
  if (sourceChart) {
    sourceChart.destroy();
  }
  const ctx = sourceChartRef.value.getContext('2d');
  if (!ctx) {
    return;
  }
  sourceChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: [t('daily.searchEngine'), t('daily.direct'), t('daily.external')],
      datasets: [
        {
          data: [groups.search, groups.direct, groups.external],
          backgroundColor: ['#1e7bff', '#ff8a3d', '#22c55e'],
          borderWidth: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '60%',
      plugins: { legend: { display: false } },
    },
  });
}

function renderVisitorDonut() {
  if (!visitorChartRef.value) {
    return;
  }
  if (visitorChart) {
    visitorChart.destroy();
  }
  const ctx = visitorChartRef.value.getContext('2d');
  if (!ctx) {
    return;
  }
  const current = overall.value || {};
  visitorChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: [t('daily.newVisitor'), t('daily.oldVisitor')],
      datasets: [
        {
          data: [current.newVisitorCount || 0, current.returningVisitorCount || 0],
          backgroundColor: ['#1e7bff', '#22c55e'],
          borderWidth: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: { legend: { position: 'bottom' } },
    },
  });
}

function renderDeviceDonut() {
  if (!deviceChartRef.value) {
    return;
  }
  if (deviceChart) {
    deviceChart.destroy();
  }
  const ctx = deviceChartRef.value.getContext('2d');
  if (!ctx) {
    return;
  }
  const pcCount = getDeviceCount(deviceStats.value, 'desktop');
  const iosCount = getOsCount(osStats.value, ['ios', 'iphone', 'ipad']);
  const androidCount = getOsCount(osStats.value, ['android']);
  deviceChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: [t('daily.devicePc'), t('daily.deviceIos'), t('daily.deviceAndroid')],
      datasets: [
        {
          data: [pcCount, iosCount, androidCount],
          backgroundColor: ['#1e7bff', '#22c55e', '#ff8a3d', '#6366f1'],
          borderWidth: 0,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '60%',
      plugins: { legend: { position: 'bottom' } },
    },
  });
}

function destroyCharts() {
  if (ipChart) {
    ipChart.destroy();
    ipChart = null;
  }
  if (sourceChart) {
    sourceChart.destroy();
    sourceChart = null;
  }
  if (visitorChart) {
    visitorChart.destroy();
    visitorChart = null;
  }
  if (deviceChart) {
    deviceChart.destroy();
    deviceChart = null;
  }
}

function getSourceIPGroup(stats: RefererIPBatchStats | null, kind: SourceIPKind): RefererIPGroupStats | null {
  if (!stats) {
    return null;
  }
  return stats[kind];
}

function buildMetric(current: number, prev: number) {
  const delta = current - prev;
  const rate = calcRate(current, prev);
  return {
    valueText: formatNumber(current),
    deltaText: formatSigned(delta),
    rateText: formatRate(rate),
    deltaClass: deltaClass(delta),
    rateClass: rateClass(rate),
  }
}

function buildPercentMetric(current: number, prev: number) {
  const delta = current - prev;
  const rate = calcRate(current, prev);
  return {
    valueText: formatPercent(current),
    deltaText: formatSignedPercent(delta),
    rateText: formatRate(rate),
    deltaClass: deltaClass(delta),
    rateClass: rateClass(rate),
  }
}

function buildDurationMetric(current: number, prev: number) {
  const delta = current - prev;
  const rate = calcRate(current, prev);
  return {
    valueText: formatDuration(current),
    deltaText: formatSignedDuration(delta),
    rateText: formatRate(rate),
    deltaClass: deltaClass(delta),
    rateClass: rateClass(rate),
  }
}

function buildSourceCard(current: number, prev: number) {
  const rate = calcRate(current, prev);
  return {
    countText: formatNumber(current),
    rateText: formatRate(rate),
    rateClass: rateClass(rate),
  }
}

function buildRefererRows(stats: SimpleSeriesStats | null, prevStats: SimpleSeriesStats | null, searchOnly: boolean) {
  const prevMap = buildStatMap(prevStats);
  const keys = stats?.key || [];
  const uvs = stats?.uv || [];
  const rows = keys
    .map((key, idx) => ({ rawLabel: key, label: formatRefererLabel(key, currentLocale.value, t), value: uvs[idx] || 0 }))
    .filter((item) => (searchOnly ? isSearchEngine(item.rawLabel) : true));

  return rows.map((item) => {
    const prev = prevMap[item.rawLabel] || 0;
    const delta = item.value - prev;
    const rate = calcRate(item.value, prev);
    return {
      label: item.label,
      valueText: formatNumber(item.value),
      deltaText: formatSigned(delta),
      deltaClass: deltaClass(delta),
      rateText: formatRate(rate),
      rateClass: rateClass(rate),
    }
  });
}

function buildIPRows(stats: RefererIPGroupStats | null, prevStats: RefererIPGroupStats | null) {
  const prevMap = buildSeriesMap(prevStats?.key || [], prevStats?.uv || []);
  const keys = stats?.key || [];
  const uvs = stats?.uv || [];
  const shares = stats?.share || [];
  const domestics = stats?.domestic || [];
  const globals = stats?.global || [];
  const total = stats?.total_uv || 0;

  return keys.map((key, idx) => {
    const value = uvs[idx] || 0;
    const prev = prevMap[key] || 0;
    const delta = value - prev;
    const rate = calcRate(value, prev);
    const share = shares[idx] ?? (total > 0 ? value / total : 0);
    return {
      label: key,
      valueText: formatNumber(value),
      deltaText: formatSigned(delta),
      deltaClass: deltaClass(delta),
      rateText: formatRate(rate),
      rateClass: rateClass(rate),
      sourceShareText: formatPercent(share),
      regionText: formatRegion(domestics[idx], globals[idx]),
    };
  });
}

function buildContentRows(stats: SimpleSeriesStats | null, prevStats: SimpleSeriesStats | null) {
  const prevPV = buildStatMap(prevStats, 'pv');
  const prevUV = buildStatMap(prevStats, 'uv');

  const keys = stats?.key || [];
  const pvs = stats?.pv || [];
  const uvs = stats?.uv || [];

  return keys.map((key, idx) => {
    const pv = pvs[idx] || 0;
    const uv = uvs[idx] || 0;
    const pvRate = calcRate(pv, prevPV[key] || 0);
    const uvRate = calcRate(uv, prevUV[key] || 0);
    return {
      label: key,
      pvText: formatNumber(pv),
      uvText: formatNumber(uv),
      pvRateText: formatRate(pvRate),
      uvRateText: formatRate(uvRate),
      pvRateClass: rateClass(pvRate),
      uvRateClass: rateClass(uvRate),
    }
  });
}

function buildVisitorRows(overallData: Record<string, any> | null, sessionData: Record<string, any> | null) {
  if (!overallData) {
    return [];
  }
  const newCount = overallData.newVisitorCount || 0;
  const returningCount = overallData.returningVisitorCount || 0;
  const total = newCount + returningCount;

  const prevNew = overallData.prevNewVisitorCount || 0;
  const prevReturning = overallData.prevReturningVisitorCount || 0;
  const avgDuration = sessionData?.avgDurationSeconds || 0;
  const avgPV = overallData.uv ? overallData.pv / overallData.uv : 0;

  const rows = [
    { label: t('daily.newVisitor'), count: newCount, prev: prevNew },
    { label: t('daily.oldVisitor'), count: returningCount, prev: prevReturning },
  ];

  return rows.map((item) => {
    const share = total > 0 ? item.count / total : 0;
    const rate = calcRate(item.count, item.prev);
    return {
      label: item.label,
      shareText: formatPercent(share),
      rateText: formatRate(rate),
      rateClass: rateClass(rate),
      durationText: formatDuration(avgDuration),
      avgPvText: formatNumber(avgPV),
    }
  });
}

function buildDeviceCards(deviceData: SimpleSeriesStats | null, osData: SimpleSeriesStats | null) {
  const pcCount = getDeviceCount(deviceData, 'desktop');
  const iosCount = getOsCount(osData, ['ios', 'iphone', 'ipad']);
  const androidCount = getOsCount(osData, ['android']);
  return {
    pc: formatNumber(pcCount),
    ios: formatNumber(iosCount),
    android: formatNumber(androidCount),
  }
}

function buildSimpleRows(
  stats: SimpleSeriesStats | null,
  prevStats: SimpleSeriesStats | null,
  formatLabel?: (label: string) => string
) {
  const prevMap = buildStatMap(prevStats);
  const keys = stats?.key || [];
  const uvs = stats?.uv || [];
  if (!keys.length) {
    return [];
  }

  const total = uvs.reduce((sum, val) => sum + val, 0);
  return keys.map((key, idx) => {
    const value = uvs[idx] || 0;
    const share = total > 0 ? value / total : 0;
    const prev = prevMap[key] || 0;
    const rate = calcRate(value, prev);
    return {
      label: formatLabel ? formatLabel(key) : key,
      shareText: formatPercent(share),
      rateText: formatRate(rate),
      rateClass: rateClass(rate),
    }
  });
}

function buildSourceSummary(stats: SimpleSeriesStats | null, prevStats: SimpleSeriesStats | null) {
  if (!stats || !stats.key) {
    return t('daily.sourceEmpty');
  }
  const prevMap = buildStatMap(prevStats);
  const keys = stats.key || [];
  const uvs = stats.uv || [];
  if (!keys.length) {
    return t('daily.sourceEmpty');
  }
  const diffs = keys.map((key, idx) => ({
    key,
    rate: calcRate(uvs[idx] || 0, prevMap[key] || 0),
  }));
  const rising = diffs.reduce((acc, item) => (item.rate !== null && item.rate > (acc.rate ?? -Infinity) ? item : acc), {
    rate: -Infinity,
  });
  const falling = diffs.reduce((acc, item) => (item.rate !== null && item.rate < (acc.rate ?? Infinity) ? item : acc), {
    rate: Infinity,
  });
  const risingLabel = rising.key ? formatRefererLabel(rising.key, currentLocale.value, t) : t('common.none');
  const fallingLabel = falling.key ? formatRefererLabel(falling.key, currentLocale.value, t) : t('common.none');
  return t('daily.sourceSummary', {
    rising: risingLabel,
    risingRate: formatRate(rising.rate),
    falling: fallingLabel,
    fallingRate: formatRate(falling.rate),
  });
}

function buildSourceIPSummary(
  rows: Array<{
    label: string;
    valueText: string;
    deltaText: string;
    rateText: string;
    sourceShareText: string;
    regionText: string;
  }>,
  scope: string
) {
  if (!rows.length) {
    return t('daily.sourceEmpty');
  }
  const topRow = rows[0];
  return t('daily.ipTopSummary', {
    scope,
    ip: topRow.label,
    count: topRow.valueText,
    share: topRow.sourceShareText,
    region: topRow.regionText,
    delta: topRow.deltaText,
    rate: topRow.rateText,
  });
}

function formatRegion(domestic?: string, global?: string) {
  const domesticText = normalizeRegionValue(domestic);
  const globalText = normalizeRegionValue(global);
  if (globalText && domesticText && globalText !== domesticText) {
    return `${globalText} · ${domesticText}`;
  }
  return domesticText || globalText || t('common.none');
}

function normalizeRegionValue(value?: string) {
  const normalized = String(value || '').trim();
  if (!normalized || normalized === '-') {
    return '';
  }
  return normalized;
}

function calcRate(current: number, prev: number) {
  if (prev === 0) {
    if (current === 0) {
      return 0;
    }
    return null;
  }
  return (current - prev) / prev;
}

function formatNumber(value: number) {
  if (value === null || value === undefined) {
    return t('common.none');
  }
  return n(Number(value));
}

function formatPercent(value: number) {
  if (value === null || value === undefined) {
    return t('common.none');
  }
  return n(value, 'percent');
}

function formatRate(rate: number | null) {
  if (rate === null) {
    return t('common.none');
  }
  return `${rate >= 0 ? '+' : ''}${(rate * 100).toFixed(2)}%`;
}

function formatSigned(value: number) {
  if (value === null || value === undefined) {
    return t('common.none');
  }
  return `${value >= 0 ? '+' : ''}${value}`;
}

function formatSignedPercent(value: number) {
  if (value === null || value === undefined) {
    return t('common.none');
  }
  return `${value >= 0 ? '+' : ''}${(value * 100).toFixed(2)}%`;
}

function formatSignedDuration(value: number) {
  if (value === null || value === undefined) {
    return t('common.none');
  }
  const prefix = value >= 0 ? '+' : '-';
  return `${prefix}${formatDuration(Math.abs(value))}`;
}

function formatDuration(seconds: number) {
  const total = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

function deltaClass(delta: number) {
  if (delta > 0) return 'trend-up';
  if (delta < 0) return 'trend-down';
  return 'trend-flat';
}

function rateClass(rate: number | null) {
  if (rate === null) return 'trend-flat';
  if (rate > 0) return 'trend-up';
  if (rate < 0) return 'trend-down';
  return 'trend-flat';
}

function buildStatMap(stats: SimpleSeriesStats | null, field: 'uv' | 'pv' = 'uv') {
  const map: Record<string, number> = {};
  if (!stats || !stats.key) {
    return map;
  }
  const values = stats[field] || [];
  stats.key.forEach((key, idx) => {
    map[key] = values[idx] || 0;
  });
  return map;
}

function buildSeriesMap(keys: string[], values: number[]) {
  const map: Record<string, number> = {};
  keys.forEach((key, idx) => {
    map[key] = values[idx] || 0;
  });
  return map;
}

function getDeviceCount(stats: SimpleSeriesStats | null, category: 'desktop' | 'mobile' | 'other') {
  if (!stats || !stats.key) {
    return 0;
  }
  let total = 0;
  const values = stats.uv || [];
  stats.key.forEach((key, idx) => {
    if (normalizeDeviceCategory(key) === category) {
      total += values[idx] || 0;
    }
  });
  return total;
}

function getOsCount(stats: SimpleSeriesStats | null, keywords: string[]) {
  if (!stats || !stats.key) {
    return 0;
  }
  let total = 0;
  const values = stats.uv || [];
  stats.key.forEach((key, idx) => {
    const lower = String(key || '').toLowerCase();
    if (keywords.some((word) => lower.includes(word))) {
      total += values[idx] || 0;
    }
  });
  return total;
}

function groupReferers(stats: SimpleSeriesStats | null) {
  const keys = stats?.key || [];
  const uvs = stats?.uv || [];
  const groups = { search: 0, direct: 0, external: 0 };
  keys.forEach((key, idx) => {
    const value = uvs[idx] || 0;
    if (isDirectReferer(key)) {
      groups.direct += value;
    } else if (isSearchEngine(key)) {
      groups.search += value;
    } else {
      groups.external += value;
    }
  });
  return groups;
}

const searchEngines = ['baidu.', 'google.', 'bing.', 'sogou.', '360.', 'so.com', 'yahoo.', 'duckduckgo.', 'yandex.'];

function isSearchEngine(value: string) {
  const lower = value.toLowerCase();
  return searchEngines.some((engine) => lower.includes(engine));
}

function shiftDate(dateStr: string, offsetDays: number) {
  const date = new Date(dateStr);
  if (Number.isNaN(date.getTime())) {
    return formatDate(new Date());
  }
  date.setDate(date.getDate() + offsetDays);
  return formatDate(date);
}

function getDateFromQuery() {
  const params = new URLSearchParams(window.location.search || '');
  const raw = params.get('date');
  if (!raw) {
    return '';
  }
  if (raw === 'today') {
    return formatDate(new Date());
  }
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw)) {
    return raw;
  }
  return '';
}

function goToLogsByIP(ip: string) {
  const normalizedIP = String(ip || '').trim();
  if (!normalizedIP || !currentWebsiteId.value) {
    return;
  }
  const { start, end } = buildDayTimeRange(currentDate.value);
  router.push({
    name: 'logs',
    query: {
      id: currentWebsiteId.value,
      ipFilter: normalizedIP,
      timeStart: start,
      timeEnd: end,
    },
  });
}

function buildDayTimeRange(dateStr: string) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr || '')) {
    const fallback = formatDate(new Date());
    return {
      start: `${fallback} 00:00`,
      end: `${fallback} 23:59`,
    };
  }
  return {
    start: `${dateStr} 00:00`,
    end: `${dateStr} 23:59`,
  };
}
</script>

<style scoped lang="scss">
:global(.daily-page) {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.daily-date-picker {
  min-width: 190px;
}

.daily-kpi-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 16px;
}

.daily-kpi-card {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-height: 150px;
}

.daily-kpi-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.daily-kpi-title {
  font-weight: 600;
  font-size: 14px;
}

.daily-kpi-date {
  color: var(--muted);
  font-size: 12px;
  margin-top: 2px;
}

.daily-kpi-icon {
  width: 36px;
  height: 36px;
  border-radius: var(--radius-sm);
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 18px;
  background: var(--panel-muted);
  color: var(--primary);
}

.daily-kpi-icon.orange {
  color: var(--accent);
  background: rgba(245, 158, 11, 0.12);
}

.daily-kpi-icon.green {
  color: var(--green);
  background: rgba(34, 197, 94, 0.12);
}

.daily-kpi-icon.blue {
  color: var(--primary);
  background: rgba(var(--primary-color-rgb), 0.12);
}

.daily-kpi-icon.purple {
  color: #0ea5e9;
  background: rgba(14, 165, 233, 0.12);
}

.daily-kpi-icon.teal {
  color: #14b8a6;
  background: rgba(20, 184, 166, 0.12);
}

.daily-kpi-value {
  font-size: 28px;
  font-weight: 700;
}

:deep(.p-datepicker-dropdown) {
  border-start-end-radius: var(--radius-pill);
  border-end-end-radius: var(--radius-pill);
}

.daily-kpi-compare {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  color: var(--muted);
}

.daily-kpi-delta,
.daily-kpi-rate {
  font-weight: 600;
}

.trend-up {
  color: #ef4444;
}

.trend-down {
  color: #16a34a;
}

.trend-flat {
  color: var(--muted);
}

.daily-mini-grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 16px;
}

.daily-mini-card {
  grid-column: span 3;
  background: linear-gradient(135deg, rgba(var(--primary-color-rgb), 0.12), rgba(var(--primary-color-rgb), 0.03));
  min-height: 140px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}

.daily-mini-card:nth-of-type(2) {
  background: linear-gradient(135deg, rgba(14, 165, 233, 0.12), rgba(14, 165, 233, 0.03));
}

.daily-mini-title {
  font-weight: 600;
  font-size: 14px;
}

.daily-mini-body {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
}

.daily-mini-metric {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.daily-mini-label {
  font-size: 12px;
  color: var(--muted);
}

.daily-mini-value {
  font-size: 24px;
  font-weight: 700;
}

.daily-mini-meta {
  font-size: 12px;
  color: var(--muted);
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.daily-trend-card {
  grid-column: span 6;
  min-height: 240px;
}

.daily-trend-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 8px;
}

.daily-trend-title {
  font-weight: 600;
}

.daily-trend-sub {
  font-size: 12px;
  color: var(--muted);
}

.daily-trend-chart {
  height: 180px;
}

.daily-source-grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 16px;
  position: relative;
  z-index: 6;
}

.daily-donut-card {
  grid-column: span 4;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.daily-donut {
  height: 220px;
}

.daily-summary-cards {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.daily-summary-card {
  border-radius: var(--radius-md);
  padding: 14px;
  border: 1px solid var(--border);
  background: var(--panel-muted);
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.daily-summary-card.search {
  border-color: rgba(30, 123, 255, 0.25);
}

.daily-summary-card.direct {
  border-color: rgba(245, 158, 11, 0.2);
}

.daily-summary-card.external {
  border-color: rgba(34, 197, 94, 0.2);
}

.daily-summary-label {
  font-size: 12px;
  color: var(--muted);
}

.daily-summary-value {
  font-size: 18px;
  font-weight: 700;
}

.daily-summary-rate {
  font-size: 12px;
  font-weight: 600;
}

.daily-table-card {
  grid-column: span 8;
  position: relative;
  z-index: 8;
}

.daily-tab-bar {
  display: inline-flex;
  gap: 8px;
  padding: 4px;
  background: var(--panel-muted);
  border: 1px solid var(--border);
  border-radius: var(--radius-pill);
  margin-bottom: 12px;
}

.daily-tab {
  border: none;
  background: transparent;
  padding: 6px 14px;
  border-radius: var(--radius-pill);
  font-size: 12px;
  font-weight: 600;
  color: var(--muted);
  cursor: pointer;
}

.daily-tab.active {
  background: linear-gradient(135deg, var(--primary), var(--primary-strong));
  color: white;
}

.daily-source-inline {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
  margin-left: 10px;
}

.daily-source-filter-label {
  font-size: 12px;
  color: var(--muted);
  font-weight: 600;
}

.daily-source-link {
  border: none;
  background: transparent;
  padding: 0;
  font-size: 12px;
  font-weight: 600;
  color: var(--muted);
  cursor: pointer;
  text-decoration: none;
  text-underline-offset: 4px;
}

.daily-source-link:hover {
  color: var(--text);
}

.daily-source-link.active {
  color: var(--primary);
  text-decoration: underline;
}

.daily-source-divider {
  font-size: 12px;
  color: var(--muted);
}

.daily-ip-cell {
  position: relative;
  overflow: visible !important;
}

.daily-ip-row {
  cursor: pointer;
}

.daily-ip-main {
  display: flex;
  align-items: center;
  gap: 6px;
  min-width: 0;
  width: 100%;
}

.daily-ip-label {
  display: block;
  flex: 1 1 auto;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono', 'Courier New', monospace;
  letter-spacing: 0.01em;
}

.daily-ip-info {
  flex: 0 0 auto;
  margin-left: 6px;
  font-size: 12px;
  color: var(--muted);
}

.daily-ip-popover {
  position: absolute;
  left: 0;
  top: calc(100% + 8px);
  min-width: 240px;
  padding: 10px 12px;
  border-radius: var(--radius-sm);
  border: 1px solid rgba(var(--primary-color-rgb), 0.22);
  background: linear-gradient(160deg, rgba(255, 255, 255, 0.98), rgba(244, 248, 255, 0.94));
  box-shadow: 0 14px 30px rgba(15, 23, 42, 0.12);
  opacity: 0;
  transform: translateY(6px);
  pointer-events: none;
  transition: opacity 0.18s ease, transform 0.18s ease;
  z-index: 80;
}

.daily-ip-popover-line {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  font-size: 12px;
  color: var(--muted);
}

.daily-ip-popover-line + .daily-ip-popover-line {
  margin-top: 6px;
}

.daily-ip-popover-line strong {
  color: var(--text);
  font-weight: 600;
}

.daily-ip-cell:hover .daily-ip-popover,
.daily-ip-cell:focus-within .daily-ip-popover {
  opacity: 1;
  transform: translateY(0);
}

:global(body.dark-mode) .daily-ip-popover {
  border-color: rgba(148, 163, 184, 0.35);
  background: linear-gradient(160deg, rgba(17, 24, 39, 0.96), rgba(15, 23, 42, 0.94));
  box-shadow: 0 14px 30px rgba(2, 6, 23, 0.5);
}

.daily-summary-strip {
  margin-top: 10px;
  font-size: 12px;
  color: var(--muted);
}

.daily-dual-grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 16px;
}

.daily-section {
  grid-column: span 6;
}

.daily-section-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
}

.daily-section-title {
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 8px;
}

.daily-visitor-grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 16px;
}

.daily-visitor-grid .daily-donut {
  grid-column: span 4;
}

.daily-visitor-table {
  grid-column: span 8;
}

.daily-device-grid {
  display: grid;
  grid-template-columns: repeat(12, 1fr);
  gap: 16px;
}

.daily-device-left {
  grid-column: span 4;
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.daily-device-cards {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px;
}

.daily-device-card {
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 6px;
  background: var(--panel-muted);
}

.daily-device-icon {
  font-size: 18px;
  color: var(--primary);
}

.daily-device-label {
  font-size: 12px;
  color: var(--muted);
}

.daily-device-value {
  font-size: 18px;
  font-weight: 700;
}

.daily-device-list {
  grid-column: span 4;
}

.daily-list-title {
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 8px;
}

@media (max-width: 1200px) {
  .daily-mini-card {
    grid-column: span 6;
  }

  .daily-trend-card {
    grid-column: span 12;
  }

  .daily-donut-card {
    grid-column: span 12;
  }

  .daily-table-card {
    grid-column: span 12;
  }

  .daily-section {
    grid-column: span 12;
  }

  .daily-visitor-grid .daily-donut,
  .daily-visitor-table,
  .daily-device-left,
  .daily-device-list {
    grid-column: span 12;
  }

  .daily-device-cards {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 768px) {
  .daily-date-picker {
    min-width: 0;
    width: 100%;
  }

  .daily-mini-card {
    grid-column: span 12;
  }

  .daily-device-cards {
    grid-template-columns: 1fr;
  }

  .daily-summary-cards {
    grid-template-columns: 1fr;
  }
}
</style>
