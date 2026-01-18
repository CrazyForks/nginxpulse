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
        <div class="search-box">
          <InputText
            v-model="searchInput"
            class="search-input"
            :placeholder="t('logs.searchPlaceholder')"
            @keyup.enter="applySearch"
          />
          <Button class="search-btn" severity="primary" @click="applySearch">{{ t('common.search') }}</Button>
          <Button
            class="reparse-btn"
            outlined
            severity="danger"
            :label="reparseButtonLabel"
            :disabled="!currentWebsiteId || reparseLoading || ipParsing"
            @click="openReparseDialog"
          />
        </div>
        <div class="sort-controls">
          <div class="filter-toggle-container">
            <Checkbox v-model="excludeInternal" inputId="exclude-internal" binary />
            <label for="exclude-internal">{{ t('logs.excludeInternal') }}</label>
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
        </div>
      </div>
    </div>
    <div v-if="ipParsing" class="logs-ip-notice">
      {{ t('logs.ipParsing', { progress: ipParsingProgressLabel }) }}
    </div>
    <div v-if="parsingPending" class="logs-ip-notice">
      {{ t('logs.parsingPending') }}
    </div>

    <div class="card logs-table-box">
      <div class="logs-table-wrapper">
        <table class="logs-table">
          <thead>
            <tr>
              <th>{{ t('logs.time') }}</th>
              <th>{{ t('common.ip') }}</th>
              <th>{{ t('common.location') }}</th>
              <th>{{ t('logs.request') }}</th>
              <th>{{ t('common.status') }}</th>
              <th>{{ t('common.traffic') }}</th>
              <th>{{ t('logs.source') }}</th>
              <th>{{ t('common.browser') }}</th>
              <th>{{ t('common.os') }}</th>
              <th>{{ t('common.device') }}</th>
              <th>{{ t('common.pageview') }}</th>
            </tr>
          </thead>
          <tbody>
            <tr v-if="loading">
              <td colspan="11">{{ t('common.loading') }}</td>
            </tr>
            <tr v-else-if="logs.length === 0">
              <td colspan="11">{{ t('logs.empty') }}</td>
            </tr>
            <tr v-else v-for="(log, index) in logs" :key="index">
              <td :title="log.time">{{ log.time }}</td>
              <td :title="log.ip">{{ log.ip }}</td>
              <td :title="log.location">{{ log.location }}</td>
              <td :title="log.request">{{ log.request }}</td>
              <td :style="{ color: statusColor(log.statusCode) }">{{ log.statusCode }}</td>
              <td :title="log.trafficTitle">{{ log.trafficText }}</td>
              <td :title="log.referer">{{ log.referer }}</td>
              <td :title="log.browser">{{ log.browser }}</td>
              <td :title="log.os">{{ log.os }}</td>
              <td :title="log.device">{{ log.device }}</td>
              <td class="logs-pv-cell" :style="{ color: log.pageview ? 'var(--success-color)' : 'inherit' }">
                {{ log.pageview ? '✓' : '-' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

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
import { computed, inject, onMounted, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import Dialog from 'primevue/dialog';
import { fetchLogs, fetchWebsites, reparseLogs } from '@/api';
import type { WebsiteInfo } from '@/api/types';
import { formatTraffic, getUserPreference, saveUserPreference } from '@/utils';
import { formatBrowserLabel, formatDeviceLabel, formatLocationLabel, formatOSLabel, formatRefererLabel } from '@/i18n/mappings';
import { normalizeLocale } from '@/i18n';
import ThemeToggle from '@/components/ThemeToggle.vue';
import WebsiteSelect from '@/components/WebsiteSelect.vue';

const websites = ref<WebsiteInfo[]>([]);
const websitesLoading = ref(true);
const currentWebsiteId = ref('');

const searchInput = ref('');
const searchFilter = ref('');
const excludeInternal = ref(false);
const sortField = ref(getUserPreference('logsSortField', 'timestamp'));
const sortOrder = ref(getUserPreference('logsSortOrder', 'desc'));
const pageSize = ref(Number(getUserPreference('logsPageSize', '100')));
const currentPage = ref(1);
const totalPages = ref(0);
const pageJump = ref<number | null>(null);
const reparseDialogVisible = ref(false);
const reparseLoading = ref(false);
const reparseError = ref('');
const reparseDialogMode = ref<'confirm' | 'blocked'>('confirm');
const demoMode = inject<{ value: boolean } | null>('demoMode', null);

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
const parsingPending = ref(false);

const ipParsingProgressText = computed(() => {
  if (ipParsingProgress.value === null) {
    return '';
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

const currentWebsiteLabel = computed(() => {
  const match = websites.value.find((site) => site.id === currentWebsiteId.value);
  return match?.name || t('common.currentWebsite');
});

const reparseButtonLabel = computed(() =>
  (reparseLoading.value || ipParsing.value) ? t('logs.reparseLoading') : t('logs.reparse')
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

watch(currentWebsiteId, (value) => {
  if (value) {
    saveUserPreference('selectedWebsite', value);
  }
  currentPage.value = 1;
  loadLogs();
});

watch([sortField, sortOrder, pageSize, excludeInternal], () => {
  saveUserPreference('logsSortField', sortField.value);
  saveUserPreference('logsSortOrder', sortOrder.value);
  saveUserPreference('logsPageSize', String(pageSize.value));
  saveUserPreference('logsExcludeInternal', excludeInternal.value ? 'true' : 'false');
  currentPage.value = 1;
  loadLogs();
});

function initPreferences() {
  excludeInternal.value = getUserPreference('logsExcludeInternal', 'false') === 'true';
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

async function loadLogs() {
  if (!currentWebsiteId.value) {
    return;
  }
  loading.value = true;
  try {
    const result = await fetchLogs(
      currentWebsiteId.value,
      currentPage.value,
      pageSize.value,
      sortField.value,
      sortOrder.value,
      searchFilter.value,
      undefined,
      undefined,
      undefined,
      excludeInternal.value
    );
    rawLogs.value = result.logs || [];
    totalPages.value = result.pagination?.pages || 0;
    ipParsing.value = Boolean(result.ip_parsing);
    ipParsingProgress.value = ipParsing.value ? normalizeProgress(result.ip_parsing_progress) : null;
    parsingPending.value = Boolean(result.parsing_pending);
  } catch (error) {
    console.error('加载日志失败:', error);
    rawLogs.value = [];
    totalPages.value = 0;
    ipParsing.value = false;
    ipParsingProgress.value = null;
    parsingPending.value = false;
  } finally {
    loading.value = false;
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
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 10px;
}

.search-box {
  display: flex;
  gap: 10px;
  flex: 0 1 360px;
  min-width: 240px;
}

.search-input {
  flex: 1 1 auto;
  max-width: 320px;
}

.search-btn {
  font-weight: 600;
  border-radius: 12px;
  min-width: 90px;
  padding: 0 16px;
}

.sort-controls {
  display: flex;
  gap: 20px;
  align-items: center;
  flex-wrap: wrap;
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
}

.sort-field-container,
.sort-order-container,
.page-size-container {
  display: flex;
  align-items: center;
  gap: 8px;
}

.sort-select {
  min-width: 110px;
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
  width: 100%;
  border-collapse: collapse;
  font-size: 13px;
  table-layout: fixed;
}

.logs-table th,
.logs-table td {
  padding: 8px 10px;
  text-align: left;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.logs-table th {
  position: sticky;
  top: 0;
  background-color: var(--panel);
  z-index: 1;
  font-weight: 600;
}

.logs-table tbody tr:nth-child(even) {
  background-color: var(--row-alt-bg);
}

.logs-table tbody tr:hover {
  background-color: rgba(var(--primary-color-rgb), 0.08);
}

.logs-table th:nth-child(1) {
  width: 12%;
}

.logs-table th:nth-child(2) {
  width: 8%;
}

.logs-table th:nth-child(3) {
  width: 5%;
}

.logs-table th:nth-child(4) {
  width: 12%;
}

.logs-table th:nth-child(5) {
  width: 5%;
}

.logs-table th:nth-child(6) {
  width: 7%;
}

.logs-table th:nth-child(7) {
  width: 12%;
}

.logs-table th:nth-child(8) {
  width: 8%;
}

.logs-table th:nth-child(9) {
  width: 7%;
}

.logs-table th:nth-child(10) {
  width: 5%;
}

.logs-table th:nth-child(11) {
  width: 4%;
}

.logs-pv-cell {
  text-align: center;
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

.reparse-btn {
  border-radius: 12px;
  font-weight: 600;
  min-width: 150px;
  padding: 0 18px;
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
    flex-direction: column;
    align-items: stretch;
  }

  .search-box {
    width: 100%;
  }

  .sort-controls {
    gap: 12px;
  }

  .pagination-controls {
    flex-direction: column;
    gap: 12px;
  }
}
</style>
