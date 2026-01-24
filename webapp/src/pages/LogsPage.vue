<template>
  <div class="logs-layout">
    <header class="page-header">
    <div class="page-title">
        <span class="title-chip">{{ t('logs.title') }}</span>
        <p class="title-sub">{{ t('logs.subtitle') }}</p>
      </div>
      <div class="header-actions">
        <WebsiteSelect
          v-model="currentWebsiteId"
          :websites="websites"
          :loading="websitesLoading"
          id="logs-website-selector"
          :label="t('common.website')"
        />
        <ThemeToggle />
      </div>
    </header>

    <div class="card logs-control-box">
      <div class="logs-control-content">
        <div class="control-row">
          <div class="search-box">
            <InputText
              v-model="searchInput"
              class="search-input"
              :placeholder="t('logs.searchPlaceholder')"
              @keyup.enter="applySearch"
            />
            <Button class="search-btn" severity="primary" @click="applySearch">{{ t('common.search') }}</Button>
            <span class="action-divider" aria-hidden="true"></span>
            <Button
              class="reparse-btn"
              outlined
              severity="danger"
              :label="reparseButtonLabel"
              :disabled="!currentWebsiteId || isParsingBusy"
              @click="openReparseDialog"
            />
            <span class="action-divider" aria-hidden="true"></span>
            <Button
              class="export-btn"
              outlined
              severity="secondary"
              :label="exportButtonLabel"
              :loading="exportLoading"
              :disabled="!currentWebsiteId || exportLoading"
              @click="handleExport"
            />
          </div>
          <div class="filter-row filter-row-fields">
            <div class="status-code-container">
              <label for="status-code">{{ t('logs.statusCode') }}</label>
              <InputNumber
                v-model="statusCodeFilter"
                inputId="status-code"
                class="status-code-input"
                :placeholder="t('logs.statusCodePlaceholder')"
                :useGrouping="false"
                :min="100"
                :max="599"
                :minFractionDigits="0"
                :maxFractionDigits="0"
              />
            </div>
            <div class="sort-field-container">
              <label for="sort-field">{{ t('logs.sortField') }}</label>
              <Dropdown
                inputId="sort-field"
                v-model="sortField"
                class="sort-select"
                :options="sortFieldOptions"
                optionLabel="label"
                optionValue="value"
              />
            </div>
            <div class="sort-order-container">
              <label for="sort-order">{{ t('logs.sortOrder') }}</label>
              <Dropdown
                inputId="sort-order"
                v-model="sortOrder"
                class="sort-select"
                :options="sortOrderOptions"
                optionLabel="label"
                optionValue="value"
              />
            </div>
            <div class="page-size-container">
              <label for="page-size">{{ t('logs.pageSize') }}</label>
              <Dropdown
                inputId="page-size"
                v-model="pageSize"
                class="sort-select"
                :options="pageSizeOptions"
                optionLabel="label"
                optionValue="value"
              />
            </div>
            <button
              class="advanced-toggle"
              type="button"
              :aria-expanded="advancedFiltersOpen"
              @click="advancedFiltersOpen = !advancedFiltersOpen"
            >
              <i class="ri-filter-3-line" aria-hidden="true"></i>
              <span>{{ advancedFiltersOpen ? t('logs.collapseFilters') : t('logs.advancedFilters') }}</span>
            </button>
          </div>
        </div>
        <transition name="filter-collapse">
          <div v-if="advancedFiltersOpen" class="filter-row filter-row-toggles">
            <div class="filter-toggle-container">
              <Checkbox v-model="excludeInternal" inputId="exclude-internal" binary />
              <label for="exclude-internal">{{ t('logs.excludeInternal') }}</label>
            </div>
            <div class="filter-toggle-container">
              <Checkbox v-model="pageviewOnly" inputId="pageview-only" binary />
              <label for="pageview-only">{{ t('logs.excludeNoPv') }}</label>
            </div>
            <div class="filter-toggle-container">
              <Checkbox v-model="excludeSpider" inputId="exclude-spider" binary />
              <label for="exclude-spider">{{ t('logs.excludeSpider') }}</label>
            </div>
            <div class="filter-toggle-container">
              <Checkbox v-model="excludeForeign" inputId="exclude-foreign" binary />
              <label for="exclude-foreign">{{ t('logs.excludeForeign') }}</label>
            </div>
          </div>
        </transition>
      </div>
    </div>
    <div v-if="ipParsing || parsingPending || ipGeoParsing || ipGeoPending" class="logs-ip-notice">
      <div v-if="ipParsing">{{ t('logs.ipParsing', { progress: ipParsingProgressLabel }) }}</div>
      <div v-else-if="parsingPending">{{ t('logs.backfillParsing', { progress: parsingPendingProgressLabel }) }}</div>
      <div v-if="ipGeoParsing || ipGeoPending">{{ ipGeoParsingMessage }}</div>
    </div>

    <div class="card logs-table-box">
      <div class="logs-table-wrapper">
        <DataTable
          class="logs-table"
          :value="logs"
          :loading="loading"
          :resizableColumns="true"
          columnResizeMode="fit"
          :rowHover="true"
          :stripedRows="true"
          :emptyMessage="t('logs.empty')"
          :tableStyle="{ minWidth: '1200px' }"
          @row-click="openLogDetail"
        >
          <template #loading>
            <div class="logs-table-loading">{{ t('common.loading') }}</div>
          </template>
          <Column field="time" :header="t('logs.time')" :style="{ width: '180px' }">
            <template #body="{ data }">
              <span :title="data.time">{{ data.time }}</span>
            </template>
          </Column>
          <Column field="ip" :header="t('common.ip')" :style="{ width: '140px' }">
            <template #body="{ data }">
              <span :title="data.ip">{{ data.ip }}</span>
            </template>
          </Column>
          <Column field="location" :header="t('common.location')" :style="{ width: '160px' }">
            <template #body="{ data }">
              <span :title="data.location">{{ data.location }}</span>
            </template>
          </Column>
          <Column field="request" :header="t('logs.request')" :style="{ width: '240px' }">
            <template #body="{ data }">
              <span :title="data.request">{{ data.request }}</span>
            </template>
          </Column>
          <Column field="statusCode" :header="t('common.status')" :style="{ width: '110px' }">
            <template #body="{ data }">
              <span :style="{ color: statusColor(data.statusCode) }">{{ data.statusCode }}</span>
            </template>
          </Column>
          <Column field="trafficText" :header="t('common.traffic')" :style="{ width: '130px' }">
            <template #body="{ data }">
              <span :title="data.trafficTitle">{{ data.trafficText }}</span>
            </template>
          </Column>
          <Column field="referer" :header="t('logs.source')" :style="{ width: '220px' }">
            <template #body="{ data }">
              <span :title="data.referer">{{ data.referer }}</span>
            </template>
          </Column>
          <Column field="browser" :header="t('common.browser')" :style="{ width: '160px' }">
            <template #body="{ data }">
              <span :title="data.browser">{{ data.browser }}</span>
            </template>
          </Column>
          <Column field="os" :header="t('common.os')" :style="{ width: '150px' }">
            <template #body="{ data }">
              <span :title="data.os">{{ data.os }}</span>
            </template>
          </Column>
          <Column field="device" :header="t('common.device')" :style="{ width: '140px' }">
            <template #body="{ data }">
              <span :title="data.device">{{ data.device }}</span>
            </template>
          </Column>
          <Column field="pageview" :header="t('common.pageview')" :style="{ width: '90px' }" bodyClass="logs-pv-cell">
            <template #body="{ data }">
              <span :style="{ color: data.pageview ? 'var(--success-color)' : 'inherit' }">
                {{ data.pageview ? '✓' : '-' }}
              </span>
            </template>
          </Column>
        </DataTable>
      </div>
    </div>

    <Dialog
      v-model:visible="logDetailVisible"
      modal
      class="log-detail-dialog"
      :header="t('logs.detailTitle')"
    >
      <div class="log-detail-grid">
        <div class="log-detail-item">
          <span class="log-detail-label">{{ t('logs.time') }}</span>
          <span class="log-detail-value">{{ selectedLog?.time || t('common.none') }}</span>
        </div>
        <div class="log-detail-item">
          <span class="log-detail-label">{{ t('common.ip') }}</span>
          <span class="log-detail-value">{{ selectedLog?.ip || t('common.none') }}</span>
        </div>
        <div class="log-detail-item">
          <span class="log-detail-label">{{ t('common.location') }}</span>
          <span class="log-detail-value">{{ selectedLog?.location || t('common.none') }}</span>
        </div>
        <div class="log-detail-item">
          <span class="log-detail-label">{{ t('logs.request') }}</span>
          <span class="log-detail-value">{{ selectedLog?.request || t('common.none') }}</span>
        </div>
        <div class="log-detail-item">
          <span class="log-detail-label">{{ t('common.status') }}</span>
          <span class="log-detail-value" :style="{ color: statusColor(selectedLog?.statusCode ?? '') }">
            {{ selectedLog?.statusCode ?? t('common.none') }}
          </span>
        </div>
        <div class="log-detail-item">
          <span class="log-detail-label">{{ t('common.traffic') }}</span>
          <span class="log-detail-value" :title="selectedLog?.trafficTitle">
            {{ selectedLog?.trafficText || t('common.none') }}
          </span>
        </div>
        <div class="log-detail-item">
          <span class="log-detail-label">{{ t('logs.source') }}</span>
          <span class="log-detail-value">{{ selectedLog?.referer || t('common.none') }}</span>
        </div>
        <div class="log-detail-item">
          <span class="log-detail-label">{{ t('common.browser') }}</span>
          <span class="log-detail-value">{{ selectedLog?.browser || t('common.none') }}</span>
        </div>
        <div class="log-detail-item">
          <span class="log-detail-label">{{ t('common.os') }}</span>
          <span class="log-detail-value">{{ selectedLog?.os || t('common.none') }}</span>
        </div>
        <div class="log-detail-item">
          <span class="log-detail-label">{{ t('common.device') }}</span>
          <span class="log-detail-value">{{ selectedLog?.device || t('common.none') }}</span>
        </div>
        <div class="log-detail-item">
          <span class="log-detail-label">{{ t('common.pageview') }}</span>
          <span class="log-detail-value">
            {{ selectedLog?.pageview ? '✓' : '-' }}
          </span>
        </div>
      </div>
    </Dialog>

    <div class="card pagination-box">
      <div class="pagination-controls">
        <Button class="page-btn" outlined :disabled="loading || currentPage <= 1" @click="prevPage">
          &lt; {{ t('logs.prevPage') }}
        </Button>
        <div class="pagination-center">
          <div class="page-info">
            <span>{{ t('logs.pageInfo', { current: currentPage, total: totalPages }) }}</span>
          </div>
          <div class="page-jump">
            <InputNumber
              v-model="pageJump"
              class="page-jump-input"
              :min="1"
              :max="totalPages || 1"
              :step="1"
              :useGrouping="false"
              :minFractionDigits="0"
              :maxFractionDigits="0"
              :placeholder="`1-${totalPages || 1}`"
              @keyup.enter="jumpToPage"
            />
            <Button class="page-btn" outlined :disabled="loading" @click="jumpToPage">{{ t('logs.jump') }}</Button>
          </div>
        </div>
        <Button class="page-btn" outlined :disabled="loading || currentPage >= totalPages" @click="nextPage">
          {{ t('logs.nextPage') }} &gt;
        </Button>
      </div>
    </div>

    <Dialog
      v-model:visible="migrationDialogVisible"
      modal
      :closable="!migrationLoading"
      :dismissableMask="!migrationLoading"
      class="reparse-dialog migration-dialog"
      :header="t('logs.migrationTitle')"
    >
      <div class="reparse-dialog-body">
        <p>{{ t('logs.migrationBody') }}</p>
        <p class="reparse-dialog-note">{{ t('logs.migrationNote') }}</p>
        <p v-if="migrationError" class="reparse-dialog-error">{{ migrationError }}</p>
      </div>
      <template #footer>
        <Button
          text
          severity="secondary"
          :label="t('logs.migrationCancel')"
          :disabled="migrationLoading"
          @click="migrationDialogVisible = false"
        />
        <Button
          severity="danger"
          :label="migrationButtonLabel"
          :loading="migrationLoading"
          @click="confirmMigration"
        />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="reparseDialogVisible"
      modal
      :closable="!reparseLoading"
      :dismissableMask="!reparseLoading"
      class="reparse-dialog"
      :header="reparseDialogTitle"
    >
      <div class="reparse-dialog-body">
        <template v-if="reparseDialogMode === 'blocked'">
          <p>{{ t('logs.reparseBlocked') }}</p>
        </template>
        <template v-else>
          <p>
            {{ t('logs.reparseConfirm', { name: currentWebsiteLabel }) }}
          </p>
          <p class="reparse-dialog-note">{{ t('logs.reparseNote') }}</p>
        </template>
        <p v-if="reparseError" class="reparse-dialog-error">{{ reparseError }}</p>
      </div>
      <template #footer>
        <template v-if="reparseDialogMode === 'blocked'">
          <Button :label="t('logs.reparseAcknowledge')" @click="reparseDialogVisible = false" />
        </template>
        <template v-else>
          <Button
            text
            severity="secondary"
            :label="t('logs.reparseCancel')"
            :disabled="reparseLoading"
            @click="reparseDialogVisible = false"
          />
          <Button
            severity="danger"
            :label="t('logs.reparseSubmit')"
            :loading="reparseLoading"
            @click="confirmReparse"
          />
        </template>
      </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import Dialog from 'primevue/dialog';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import { exportLogs, fetchLogs, fetchWebsites, reparseAllLogs, reparseLogs } from '@/api';
import type { WebsiteInfo } from '@/api/types';
import { formatTraffic, getUserPreference, saveUserPreference } from '@/utils';
import { formatBrowserLabel, formatDeviceLabel, formatLocationLabel, formatOSLabel, formatRefererLabel } from '@/i18n/mappings';
import { normalizeLocale } from '@/i18n';
import ThemeToggle from '@/components/ThemeToggle.vue';
import WebsiteSelect from '@/components/WebsiteSelect.vue';

type LogRow = {
  time: string;
  ip: string;
  location: string;
  request: string;
  statusCode: number | string;
  trafficText: string;
  trafficTitle: string;
  referer: string;
  browser: string;
  os: string;
  device: string;
  pageview: boolean;
};

type LogRowClickEvent = {
  data: LogRow;
  originalEvent?: MouseEvent;
};

const websites = ref<WebsiteInfo[]>([]);
const websitesLoading = ref(true);
const currentWebsiteId = ref('');

const searchInput = ref('');
const searchFilter = ref('');
const excludeInternal = ref(false);
const pageviewOnly = ref(false);
const excludeSpider = ref(false);
const excludeForeign = ref(false);
const statusCodeFilter = ref<number | null>(null);
const sortField = ref(getUserPreference('logsSortField', 'timestamp'));
const sortOrder = ref(getUserPreference('logsSortOrder', 'desc'));
const pageSize = ref(Number(getUserPreference('logsPageSize', '100')));
const advancedFiltersOpen = ref(false);
const currentPage = ref(1);
const totalPages = ref(0);
const pageJump = ref<number | null>(null);
const reparseDialogVisible = ref(false);
const reparseLoading = ref(false);
const reparseError = ref('');
const reparseDialogMode = ref<'confirm' | 'blocked'>('confirm');
const migrationDialogVisible = ref(false);
const migrationLoading = ref(false);
const migrationError = ref('');
const exportLoading = ref(false);
const demoMode = inject<{ value: boolean } | null>('demoMode', null);
const migrationRequired = inject<{ value: boolean } | null>('migrationRequired', null);
const migrationAckKey = 'pgMigrationAck';

const { t, n, locale } = useI18n({ useScope: 'global' });
const currentLocale = computed(() => normalizeLocale(locale.value));

const sortFieldOptions = computed(() => [
  { value: 'timestamp', label: t('logs.time') },
  { value: 'ip', label: t('common.ip') },
  { value: 'url', label: t('common.url') },
  { value: 'status_code', label: t('common.status') },
  { value: 'bytes_sent', label: t('common.traffic') },
]);
const sortOrderOptions = computed(() => [
  { value: 'desc', label: t('logs.sortDesc') },
  { value: 'asc', label: t('logs.sortAsc') },
]);
const pageSizeOptions = [50, 100, 200, 500].map((value) => ({ value, label: `${value}` }));

const rawLogs = ref<Array<Record<string, any>>>([]);
const loading = ref(false);
const ipParsing = ref(false);
const ipParsingProgress = ref<number | null>(null);
const ipParsingEstimatedRemainingSeconds = ref<number | null>(null);
const ipGeoParsing = ref(false);
const ipGeoPending = ref(false);
const ipGeoProgress = ref<number | null>(null);
const ipGeoEstimatedRemainingSeconds = ref<number | null>(null);
const parsingPending = ref(false);
const parsingPendingProgress = ref<number | null>(null);
const logDetailVisible = ref(false);
const selectedLog = ref<LogRow | null>(null);
const progressPollIntervalMs = 3000;
let progressPollTimer: ReturnType<typeof setInterval> | null = null;
let progressPollInFlight = false;

const ipParsingProgressText = computed(() => {
  if (ipParsingProgress.value === null) {
    return '';
  }
  if (ipParsingEstimatedRemainingSeconds.value) {
    const duration = formatDurationSeconds(ipParsingEstimatedRemainingSeconds.value);
    return t('parsing.progressWithRemaining', { value: ipParsingProgress.value, duration });
  }
  return t('parsing.progress', { value: ipParsingProgress.value });
});
const ipParsingProgressLabel = computed(() => {
  if (!ipParsingProgressText.value) {
    return '';
  }
  return currentLocale.value === 'zh-CN'
    ? `（${ipParsingProgressText.value}）`
    : ` (${ipParsingProgressText.value})`;
});

const ipGeoProgressText = computed(() => {
  if (ipGeoProgress.value === null) {
    return '';
  }
  return t('parsing.progress', { value: ipGeoProgress.value });
});
const ipGeoProgressLabel = computed(() => {
  if (!ipGeoProgressText.value) {
    return '';
  }
  return currentLocale.value === 'zh-CN'
    ? `（${ipGeoProgressText.value}）`
    : ` (${ipGeoProgressText.value})`;
});
const ipGeoRemainingLabel = computed(() => {
  if (ipGeoEstimatedRemainingSeconds.value === null) {
    return '';
  }
  return formatDurationSeconds(ipGeoEstimatedRemainingSeconds.value);
});
const ipGeoParsingMessage = computed(() => {
  if (ipGeoProgressLabel.value && ipGeoRemainingLabel.value) {
    return t('logs.ipGeoParsingProgress', {
      progress: ipGeoProgressLabel.value,
      remaining: ipGeoRemainingLabel.value,
    });
  }
  if (ipGeoProgressLabel.value) {
    return t('logs.ipGeoParsingProgressOnly', { progress: ipGeoProgressLabel.value });
  }
  return t('logs.ipGeoParsing');
});

const parsingPendingProgressText = computed(() => {
  if (parsingPendingProgress.value === null) {
    return '';
  }
  return t('parsing.progress', { value: parsingPendingProgress.value });
});
const parsingPendingProgressLabel = computed(() => {
  if (!parsingPendingProgressText.value) {
    return '';
  }
  return currentLocale.value === 'zh-CN'
    ? `（${parsingPendingProgressText.value}）`
    : ` (${parsingPendingProgressText.value})`;
});

const currentWebsiteLabel = computed(() => {
  const match = websites.value.find((site) => site.id === currentWebsiteId.value);
  return match?.name || t('common.currentWebsite');
});

const isParsingBusy = computed(() => reparseLoading.value || migrationLoading.value || ipParsing.value);
const reparseButtonLabel = computed(() =>
  isParsingBusy.value ? t('logs.reparseLoading') : t('logs.reparse')
);
const migrationButtonLabel = computed(() =>
  migrationLoading.value ? t('logs.migrationLoading') : t('logs.migrationSubmit')
);
const exportButtonLabel = computed(() =>
  exportLoading.value ? t('logs.exportLoading') : t('logs.export')
);
const isDemoMode = computed(() => demoMode?.value ?? false);
const reparseDialogTitle = computed(() =>
  reparseDialogMode.value === 'blocked' ? t('demo.badge') : t('logs.reparseTitle')
);

function normalizeProgress(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }
  return Math.min(100, Math.max(0, Math.round(value)));
}

function normalizeSeconds(value: unknown): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    return null;
  }
  const normalized = Math.round(value);
  if (normalized <= 0) {
    return null;
  }
  return normalized;
}

function formatDurationSeconds(seconds: number) {
  const total = Math.max(0, Math.floor(seconds));
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (hours > 0) {
    return t('overview.durationHoursMinutes', { hours, minutes });
  }
  if (minutes > 0) {
    return t('overview.durationMinutesSeconds', { minutes, seconds: secs });
  }
  return t('overview.durationSeconds', { seconds: secs });
}

function resolveStatusCodeParam() {
  if (statusCodeFilter.value === null || statusCodeFilter.value === undefined) {
    return undefined;
  }
  const value = Math.trunc(statusCodeFilter.value);
  if (!Number.isFinite(value) || value < 100 || value > 599) {
    return undefined;
  }
  return String(value);
}

function buildExportParams() {
  const statusCode = resolveStatusCodeParam();
  const params: Record<string, unknown> = {
    id: currentWebsiteId.value,
    page: currentPage.value,
    pageSize: pageSize.value,
    sortField: sortField.value,
    sortOrder: sortOrder.value,
    lang: currentLocale.value,
  };
  if (searchFilter.value) {
    params.filter = searchFilter.value;
  }
  if (statusCode) {
    params.statusCode = statusCode;
  }
  if (excludeInternal.value) {
    params.excludeInternal = true;
  }
  if (pageviewOnly.value) {
    params.pageviewOnly = true;
  }
  if (excludeSpider.value) {
    params.excludeSpider = true;
  }
  if (excludeForeign.value) {
    params.excludeForeign = true;
  }
  return params;
}

function extractExportFileName(disposition?: string) {
  if (!disposition) {
    return '';
  }
  const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1]);
    } catch {
      return utf8Match[1];
    }
  }
  const quotedMatch = disposition.match(/filename=\"([^\"]+)\"/i);
  if (quotedMatch?.[1]) {
    return quotedMatch[1];
  }
  const fallbackMatch = disposition.match(/filename=([^;]+)/i);
  return fallbackMatch?.[1]?.trim() || '';
}

function formatExportTimestamp() {
  const now = new Date();
  const pad = (value: number) => `${value}`.padStart(2, '0');
  return `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}_${pad(
    now.getHours()
  )}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
}

async function handleExport() {
  if (!currentWebsiteId.value || exportLoading.value) {
    return;
  }
  exportLoading.value = true;
  try {
    const response = await exportLogs(buildExportParams());
    const headerName = extractExportFileName(response.headers?.['content-disposition']);
    const fallbackName = `nginxpulse_logs_${formatExportTimestamp()}.csv`;
    const fileName = headerName || fallbackName;
    const url = window.URL.createObjectURL(response.data);
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  } catch (error) {
    console.error('导出日志失败:', error);
  } finally {
    exportLoading.value = false;
  }
}

function applyParsingStatus(result: Record<string, any>) {
  ipParsing.value = Boolean(result.ip_parsing);
  ipParsingProgress.value = ipParsing.value ? normalizeProgress(result.ip_parsing_progress) : null;
  ipParsingEstimatedRemainingSeconds.value = ipParsing.value
    ? normalizeSeconds(result.ip_parsing_estimated_remaining_seconds)
    : null;
  ipGeoParsing.value = Boolean(result.ip_geo_parsing);
  ipGeoPending.value = Boolean(result.ip_geo_pending);
  ipGeoProgress.value = ipGeoParsing.value || ipGeoPending.value
    ? normalizeProgress(result.ip_geo_progress)
    : null;
  ipGeoEstimatedRemainingSeconds.value = ipGeoParsing.value || ipGeoPending.value
    ? normalizeSeconds(result.ip_geo_estimated_remaining_seconds)
    : null;
  parsingPending.value = Boolean(result.parsing_pending);
  parsingPendingProgress.value = parsingPending.value
    ? normalizeProgress(result.parsing_pending_progress)
    : null;
}

function statusColor(statusCode: number | string) {
  if (typeof statusCode !== 'number') {
    return 'inherit';
  }
  if (statusCode >= 400) {
    return 'var(--error-color)';
  }
  if (statusCode >= 300) {
    return 'var(--warning-color)';
  }
  return 'var(--success-color)';
}

function openLogDetail(event: LogRowClickEvent) {
  const target = event?.originalEvent?.target;
  if (target instanceof HTMLElement && target.closest('.p-column-resizer')) {
    return;
  }
  selectedLog.value = event.data;
  logDetailVisible.value = true;
}

const logs = computed(() => {
  const emptyLabel = t('common.none');
  return rawLogs.value.map((log) => {
    const time = log.time || emptyLabel;
    const ip = log.ip || emptyLabel;
    const locationRaw = log.domestic_location || log.global_location || '';
    const location = formatLocationLabel(locationRaw, currentLocale.value, t) || emptyLabel;
    const method = log.method || '';
    const url = log.url || '';
    const requestText = `${method} ${url}`.trim() || emptyLabel;
    const statusCode = log.status_code ?? emptyLabel;
    const bytesSent = Number(log.bytes_sent) || 0;
    const refererRaw = log.referer ?? '';
    const referer = formatRefererLabel(refererRaw, currentLocale.value, t) || emptyLabel;
    const browserRaw = log.user_browser ?? '';
    const browser = formatBrowserLabel(browserRaw, t) || emptyLabel;
    const osRaw = log.user_os ?? '';
    const os = formatOSLabel(osRaw, t) || emptyLabel;
    const deviceRaw = log.user_device ?? '';
    const device = formatDeviceLabel(deviceRaw, t) || emptyLabel;
    const pageview = Boolean(log.pageview_flag);
    return {
      time,
      ip,
      location,
      request: requestText,
      statusCode,
      trafficText: formatTraffic(bytesSent),
      trafficTitle: t('common.bytes', { value: n(bytesSent) }),
      referer,
      browser,
      os,
      device,
      pageview,
    }
  });
});

onMounted(() => {
  initPreferences();
  loadWebsites();
});

onUnmounted(() => {
  stopProgressPolling();
});

watch(currentWebsiteId, (value) => {
  if (value) {
    saveUserPreference('selectedWebsite', value);
  }
  currentPage.value = 1;
  loadLogs();
});

watch([ipParsing, parsingPending, ipGeoParsing, ipGeoPending, currentWebsiteId], ([ipActive, pendingActive, geoActive, geoPendingActive, websiteId], prev) => {
  if (!websiteId) {
    stopProgressPolling();
    return;
  }
  const wasActive = Array.isArray(prev) && Boolean(prev[0] || prev[1] || prev[2] || prev[3]);
  const isActive = Boolean(ipActive || pendingActive || geoActive || geoPendingActive);
  if (ipActive || pendingActive || geoActive || geoPendingActive) {
    startProgressPolling();
    refreshParsingStatus();
  } else {
    stopProgressPolling(wasActive);
  }
});

watch([sortField, sortOrder, pageSize, excludeInternal, pageviewOnly, excludeSpider, excludeForeign, statusCodeFilter], () => {
  saveUserPreference('logsSortField', sortField.value);
  saveUserPreference('logsSortOrder', sortOrder.value);
  saveUserPreference('logsPageSize', String(pageSize.value));
  saveUserPreference('logsExcludeInternal', excludeInternal.value ? 'true' : 'false');
  saveUserPreference('logsPageviewOnly', pageviewOnly.value ? 'true' : 'false');
  saveUserPreference('logsExcludeSpider', excludeSpider.value ? 'true' : 'false');
  saveUserPreference('logsExcludeForeign', excludeForeign.value ? 'true' : 'false');
  saveUserPreference('logsStatusCode', statusCodeFilter.value ? String(statusCodeFilter.value) : '');
  currentPage.value = 1;
  loadLogs();
});

function initPreferences() {
  excludeInternal.value = getUserPreference('logsExcludeInternal', 'false') === 'true';
  pageviewOnly.value = getUserPreference('logsPageviewOnly', 'false') === 'true';
  excludeSpider.value = getUserPreference('logsExcludeSpider', 'false') === 'true';
  excludeForeign.value = getUserPreference('logsExcludeForeign', 'false') === 'true';
  const savedStatusCode = Number(getUserPreference('logsStatusCode', ''));
  statusCodeFilter.value = Number.isFinite(savedStatusCode) && savedStatusCode > 0 ? savedStatusCode : null;
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
    maybeShowMigrationDialog();
  } catch (error) {
    console.error('初始化网站失败:', error);
    websites.value = [];
    currentWebsiteId.value = '';
  } finally {
    websitesLoading.value = false;
  }
}

async function loadLogs() {
  if (!currentWebsiteId.value) {
    return;
  }
  loading.value = true;
  try {
    const statusCodeParam = resolveStatusCodeParam();
    const result = await fetchLogs(
      currentWebsiteId.value,
      currentPage.value,
      pageSize.value,
      sortField.value,
      sortOrder.value,
      searchFilter.value,
      undefined,
      undefined,
      statusCodeParam,
      excludeInternal.value,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      pageviewOnly.value,
      undefined,
      undefined,
      excludeSpider.value,
      excludeForeign.value
    );
    rawLogs.value = result.logs || [];
    totalPages.value = result.pagination?.pages || 0;
    applyParsingStatus(result);
  } catch (error) {
    console.error('加载日志失败:', error);
    rawLogs.value = [];
    totalPages.value = 0;
    ipParsing.value = false;
    ipParsingProgress.value = null;
    parsingPending.value = false;
    parsingPendingProgress.value = null;
  } finally {
    loading.value = false;
  }
}

async function refreshParsingStatus() {
  if (!currentWebsiteId.value || progressPollInFlight || loading.value) {
    return;
  }
  progressPollInFlight = true;
  try {
    const statusCodeParam = resolveStatusCodeParam();
    const result = await fetchLogs(
      currentWebsiteId.value,
      currentPage.value,
      pageSize.value,
      sortField.value,
      sortOrder.value,
      searchFilter.value,
      undefined,
      undefined,
      statusCodeParam,
      excludeInternal.value,
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      pageviewOnly.value,
      undefined,
      undefined,
      excludeSpider.value,
      excludeForeign.value
    );
    applyParsingStatus(result);
  } catch (error) {
    console.debug('刷新解析进度失败:', error);
  } finally {
    progressPollInFlight = false;
  }
}

function startProgressPolling() {
  if (progressPollTimer) {
    return;
  }
  progressPollTimer = setInterval(() => {
    if (ipParsing.value || parsingPending.value || ipGeoParsing.value || ipGeoPending.value) {
      refreshParsingStatus();
    }
  }, progressPollIntervalMs);
}

function stopProgressPolling(refresh = false) {
  if (progressPollTimer) {
    clearInterval(progressPollTimer);
    progressPollTimer = null;
  }
  if (refresh) {
    loadLogs();
  }
}

function applySearch() {
  searchFilter.value = searchInput.value.trim();
  currentPage.value = 1;
  loadLogs();
}

function openReparseDialog() {
  reparseError.value = '';
  if (isDemoMode.value) {
    reparseDialogMode.value = 'blocked';
    reparseDialogVisible.value = true;
    return;
  }
  reparseDialogMode.value = 'confirm';
  reparseDialogVisible.value = true;
}

function maybeShowMigrationDialog() {
  const acknowledged = getUserPreference(migrationAckKey, 'false') === 'true';
  if (
    acknowledged ||
    isDemoMode.value ||
    websites.value.length === 0 ||
    !migrationRequired?.value
  ) {
    return;
  }
  migrationError.value = '';
  migrationDialogVisible.value = true;
}

async function confirmMigration() {
  if (migrationLoading.value) {
    return;
  }
  if (websites.value.length === 0) {
    migrationError.value = t('logs.migrationError');
    return;
  }
  migrationLoading.value = true;
  migrationError.value = '';
  try {
    await reparseAllLogs();
    saveUserPreference(migrationAckKey, 'true');
    if (migrationRequired) {
      migrationRequired.value = false;
    }
    migrationDialogVisible.value = false;
    currentPage.value = 1;
    await loadLogs();
  } catch (error) {
    if (error instanceof Error) {
      migrationError.value = error.message;
    } else {
      migrationError.value = t('logs.migrationError');
    }
  } finally {
    migrationLoading.value = false;
  }
}

async function confirmReparse() {
  if (reparseDialogMode.value !== 'confirm') {
    reparseDialogVisible.value = false;
    return;
  }
  if (!currentWebsiteId.value) {
    return;
  }
  reparseLoading.value = true;
  reparseError.value = '';
  try {
    await reparseLogs(currentWebsiteId.value);
    reparseDialogVisible.value = false;
    currentPage.value = 1;
    await loadLogs();
  } catch (error) {
    if (error instanceof Error) {
      reparseError.value = error.message;
    } else {
      reparseError.value = t('logs.reparseError');
    }
  } finally {
    reparseLoading.value = false;
  }
}

function jumpToPage() {
  const pageNum = pageJump.value ?? 1;
  if (!Number.isFinite(pageNum) || pageNum < 1 || pageNum > totalPages.value) {
    return;
  }
  currentPage.value = Math.trunc(pageNum);
  loadLogs();
}

function prevPage() {
  if (currentPage.value > 1) {
    currentPage.value -= 1;
    loadLogs();
  }
}

function nextPage() {
  if (currentPage.value < totalPages.value) {
    currentPage.value += 1;
    loadLogs();
  }
}

</script>

<style scoped lang="scss">
.logs-layout {
  height: calc(100vh - 32px - 24px);
  display: flex;
  flex-direction: column;
  min-height: 0;
}

.logs-control-box {
  padding: 18px 20px;
  margin-bottom: 18px;
  position: relative;
  z-index: 30;
  --control-height: 40px;
}

.logs-layout .card:hover {
  transform: none;
  box-shadow: var(--shadow);
  border-color: var(--border);
}

.logs-ip-notice {
  padding: 10px 14px;
  margin-bottom: 18px;
  border-radius: 12px;
  background: rgba(var(--primary-color-rgb), 0.12);
  color: var(--accent-color);
  font-size: 13px;
  font-weight: 500;
}

.logs-control-content {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.control-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px 18px;
}

.logs-control-box :deep(.p-button),
.logs-control-box :deep(.p-inputtext),
.logs-control-box :deep(.p-inputnumber-input),
.logs-control-box :deep(.p-dropdown) {
  height: var(--control-height);
}

.logs-control-box :deep(.p-dropdown-label) {
  display: flex;
  align-items: center;
}

.search-box {
  display: flex;
  align-items: center;
  gap: 10px;
  flex: 1 1 420px;
  min-width: 320px;
  flex-wrap: wrap;
}

.search-input {
  flex: 1 1 240px;
  min-width: 200px;
  max-width: none;
}

.search-btn {
  font-weight: 600;
  border-radius: 12px;
  min-width: 88px;
  padding: 0 16px;
}

.filter-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
}

.filter-collapse-enter-active,
.filter-collapse-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}

.filter-collapse-enter-from,
.filter-collapse-leave-to {
  opacity: 0;
  transform: translateY(-6px);
}

.filter-row-fields {
  gap: 16px;
  margin-left: auto;
  justify-content: flex-end;
  flex: 1 1 520px;
  min-width: 320px;
}

.filter-row-toggles {
  padding: 10px 12px;
  border-radius: 12px;
  background: var(--panel-muted);
  border: 1px solid var(--border);
  gap: 10px;
}

.filter-toggle-container {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 10px;
  border-radius: 10px;
  background: var(--panel-muted);
  border: 1px solid var(--border);
  font-size: 12px;
  font-weight: 600;
  color: var(--text);
  flex: 0 0 auto;
  white-space: nowrap;
  min-height: var(--control-height);
}

.status-code-container {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 0 0 auto;
  white-space: nowrap;
}

.status-code-container label,
.sort-field-container label,
.sort-order-container label,
.page-size-container label {
  font-size: 12px;
  color: var(--muted);
  font-weight: 600;
}

.status-code-input {
  width: 110px;
}

.status-code-input :deep(.p-inputtext) {
  font-size: 12px;
}

.sort-field-container,
.sort-order-container,
.page-size-container {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 0 0 auto;
  white-space: nowrap;
}

.sort-select {
  min-width: 120px;
}

.sort-select :deep(.p-dropdown) {
  font-size: 12px;
}

.sort-select :deep(.p-dropdown-label) {
  font-size: 12px;
}

.logs-table-box {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 0;
  position: relative;
  z-index: 1;
}

:global(.logs-page) .page-header {
  z-index: 60;
}

.logs-table-wrapper {
  overflow: auto;
  width: 100%;
  flex: 1;
  min-height: 0;
  border-radius: 14px;
  border: 1px solid var(--border);
  background: var(--panel);
}

.logs-table {
  background: transparent;
  border: none;
}

.logs-table :deep(.p-datatable-table) {
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  table-layout: fixed;
}

.logs-table :deep(.p-datatable-thead > tr > th),
.logs-table :deep(.p-datatable-tbody > tr > td) {
  padding: 8px 10px;
  text-align: left;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.logs-table :deep(.p-datatable-thead > tr > th) {
  position: sticky;
  top: 0;
  background-color: var(--panel);
  z-index: 2;
  font-weight: 600;
}

.logs-table :deep(.p-datatable-tbody > tr.p-row-odd) {
  background-color: var(--row-alt-bg);
}

.logs-table :deep(.p-datatable-tbody > tr) {
  cursor: pointer;
}

.logs-table :deep(.p-datatable-tbody > tr:hover) {
  background-color: rgba(var(--primary-color-rgb), 0.08);
}

.logs-table :deep(.p-column-resizer) {
  cursor: col-resize;
  width: 6px;
}

.logs-table :deep(.p-column-resizer:hover) {
  background-color: rgba(var(--primary-color-rgb), 0.2);
}

.logs-table-loading {
  padding: 14px 16px;
  color: var(--muted);
  font-size: 13px;
}

.logs-pv-cell {
  text-align: center;
}

.log-detail-dialog :deep(.p-dialog-content) {
  padding-top: 8px;
}

.log-detail-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px 18px;
}

.log-detail-item {
  padding: 10px 12px;
  border-radius: 12px;
  background: var(--panel-muted);
  border: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.log-detail-label {
  font-size: 12px;
  color: var(--muted);
  font-weight: 600;
}

.log-detail-value {
  font-size: 13px;
  color: var(--text);
  word-break: break-all;
}

.pagination-box {
  padding: 15px 20px;
  margin-top: 15px;
}

.pagination-controls {
  display: flex;
  align-items: center;
  justify-content: space-between;
  width: 100%;
}

.pagination-center {
  display: flex;
  align-items: center;
  gap: 12px;
}

.page-info {
  font-size: 12px;
  color: var(--muted);
}

.page-jump {
  display: flex;
  align-items: center;
  gap: 8px;
}

.page-jump-input {
  width: 120px;
}

.page-btn {
  border-radius: 10px;
}

.action-divider {
  width: 1px;
  height: 22px;
  background: var(--border);
  opacity: 0.7;
}

.advanced-toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: var(--control-height);
  padding: 0 12px;
  border-radius: 12px;
  border: 1px dashed rgba(var(--primary-color-rgb), 0.3);
  background: rgba(var(--primary-color-rgb), 0.06);
  color: var(--accent-color);
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  transition: border-color 0.2s ease, background 0.2s ease, color 0.2s ease;
}

.advanced-toggle:hover {
  border-color: rgba(var(--primary-color-rgb), 0.5);
  background: rgba(var(--primary-color-rgb), 0.12);
}

.reparse-btn {
  border-radius: 12px;
  font-weight: 600;
  min-width: 118px;
  padding: 0 12px;
}

.export-btn {
  border-radius: 12px;
  font-weight: 600;
  min-width: 112px;
  padding: 0 16px;
  border-color: rgba(34, 197, 94, 0.4);
  background: rgba(34, 197, 94, 0.12);
  color: #166534;
}

.export-btn:not(:disabled):hover {
  background: rgba(34, 197, 94, 0.18);
  border-color: rgba(34, 197, 94, 0.6);
}

.reparse-dialog :deep(.p-dialog-content) {
  padding-top: 8px;
}

.reparse-dialog-body {
  display: flex;
  flex-direction: column;
  gap: 10px;
  font-size: 14px;
  color: var(--text);
}

.reparse-dialog-note {
  font-size: 13px;
  color: var(--muted);
}

.reparse-dialog-error {
  font-size: 13px;
  color: var(--error-color);
  font-weight: 600;
}

@media (max-width: 900px) {
  .logs-control-content {
    align-items: stretch;
  }

  .control-row {
    align-items: flex-start;
  }

  .search-box {
    width: 100%;
  }

  .filter-row-fields {
    margin-left: 0;
    justify-content: flex-start;
  }

  .filter-row {
    gap: 10px;
  }

  .action-divider {
    display: none;
  }

  .pagination-controls {
    flex-direction: column;
    gap: 12px;
  }

  .log-detail-grid {
    grid-template-columns: 1fr;
  }
}
</style>
