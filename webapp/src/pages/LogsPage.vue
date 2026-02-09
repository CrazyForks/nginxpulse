<template>
  <div class="logs-layout">
    <header class="page-header">
    <div class="page-title">
        <span class="title-chip">{{ t('logs.title') }}</span>
        <p class="title-sub">{{ t('logs.subtitle') }}</p>
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
                id="logs-website-selector"
                label=""
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
            <div class="search-actions">
              <Button
                class="search-btn"
                severity="primary"
                icon="pi pi-search"
                :label="t('common.search')"
                @click="applySearch"
              />
              <Button
                class="reparse-btn action-btn"
                outlined
                severity="danger"
                icon="pi pi-refresh"
                :label="reparseButtonLabel"
                :disabled="!currentWebsiteId || isParsingBusy"
                @click="openReparseDialog"
              />
              <Button
                class="export-btn action-btn"
                severity="success"
                icon="pi pi-file-export"
                :label="exportButtonLabel"
                :loading="exportLoading"
                :disabled="!currentWebsiteId || exportLoading"
                :title="isDemoMode ? t('logs.exportBlocked') : undefined"
                @click="handleExport"
              />
            </div>
          </div>
        <div class="filter-row filter-row-fields">
          <div class="filter-row-left">
            <div class="status-code-container">
              <label for="status-code">{{ t('logs.statusCode') }}</label>
              <InputText
                v-model="statusCodeFilter"
                inputId="status-code"
                class="status-code-input"
                :placeholder="t('logs.statusCodePlaceholder')"
              />
              <div class="status-code-quick">
                <button
                  type="button"
                  class="status-quick-btn"
                  :class="{ active: statusClassPreset === '' && !statusCodeFilter.trim() }"
                  @click="setStatusCodePreset('')"
                >
                  {{ t('common.all') }}
                </button>
                <button
                  type="button"
                  class="status-quick-btn"
                  :class="{ active: statusClassPreset === '2xx' }"
                  @click="setStatusCodePreset('2xx')"
                >
                  2xx
                </button>
                <button
                  type="button"
                  class="status-quick-btn"
                  :class="{ active: statusClassPreset === '3xx' }"
                  @click="setStatusCodePreset('3xx')"
                >
                  3xx
                </button>
                <button
                  type="button"
                  class="status-quick-btn"
                  :class="{ active: statusClassPreset === '4xx' }"
                  @click="setStatusCodePreset('4xx')"
                >
                  4xx
                </button>
                <button
                  type="button"
                  class="status-quick-btn"
                  :class="{ active: statusClassPreset === '5xx' }"
                  @click="setStatusCodePreset('5xx')"
                >
                  5xx
                </button>
              </div>
            </div>
            <div class="date-range-container">
              <label>{{ t('logs.dateRange') }}</label>
              <div class="date-range-inputs">
                <Dropdown
                  v-model="dateRangePreset"
                  class="date-range-select"
                  :options="dateRangePresetOptions"
                  optionLabel="label"
                  optionValue="value"
                />
              <DatePicker
                v-model="dateRange"
                class="date-range-picker"
                dateFormat="yy-mm-dd"
                selectionMode="range"
                :hideOnRangeSelection="true"
                showButtonBar
                :showClear="true"
                :placeholder="`${t('logs.dateStart')} - ${t('logs.dateEnd')}`"
              />
            </div>
          </div>
          </div>
          <div class="filter-row-right">
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
        <div v-if="loading" class="logs-table-overlay" role="status" aria-live="polite">
          <div class="logs-table-overlay-card">
            <span class="logs-table-overlay-spinner" aria-hidden="true"></span>
            <span>{{ t('common.loading') }}</span>
          </div>
        </div>
        <DataTable
          class="logs-table"
          :value="logs"
          scrollable
          scrollHeight="flex"
          :resizableColumns="true"
          columnResizeMode="fit"
          :rowHover="true"
          :stripedRows="true"
          :emptyMessage="t('logs.empty')"
          :tableStyle="{ minWidth: '1200px' }"
          @row-click="openLogDetail"
        >
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
          <p>{{ t(reparseDialogBlockedMessageKey) }}</p>
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

    <Dialog
      v-model:visible="ipGeoIssueVisible"
      modal
      :closable="!ipGeoIssueFixLoading"
      :dismissableMask="!ipGeoIssueFixLoading"
      class="reparse-dialog ip-geo-dialog"
      :header="t('logs.ipGeoIssueTitle')"
    >
      <div class="reparse-dialog-body">
        <p>{{ t('logs.ipGeoIssueBody', { name: currentWebsiteLabel, count: ipGeoIssueCount }) }}</p>
        <div v-if="ipGeoIssueRows.length" class="ip-geo-issue-list">
          <DataTable
            :value="ipGeoIssueRows"
            v-model:selection="ipGeoIssueSelection"
            dataKey="id"
            scrollable
            scrollHeight="320px"
            class="ip-geo-issue-table"
            ref="ipGeoIssueTableRef"
          >
            <Column selectionMode="multiple" headerStyle="width: 3rem" />
            <Column field="time" :header="t('logs.time')" />
            <Column field="ipDisplay" :header="t('common.ip')" />
            <Column field="location" :header="t('common.location')" />
            <Column field="request" :header="t('logs.request')" />
          </DataTable>
        </div>
        <ul v-else-if="ipGeoIssueSamples.length" class="ip-geo-samples">
          <li v-for="sample in ipGeoIssueSamples" :key="sample">{{ sample }}</li>
        </ul>
        <p v-else class="reparse-dialog-note">{{ t('logs.ipGeoIssueEmptyList') }}</p>
        <p v-if="ipGeoIssueHasMore" class="reparse-dialog-note">{{ t('logs.ipGeoIssueScrollHint') }}</p>
        <p v-if="ipGeoIssueLoadingMore" class="reparse-dialog-note">{{ t('logs.ipGeoIssueLoadingMore') }}</p>
        <p class="reparse-dialog-note">{{ t('logs.ipGeoIssueNote') }}</p>
        <p v-if="ipGeoIssueError" class="reparse-dialog-error">{{ ipGeoIssueError }}</p>
      </div>
      <template #footer>
        <Button
          text
          severity="secondary"
          :label="t('logs.ipGeoIssueCancel')"
          :disabled="ipGeoIssueFixLoading"
          @click="ipGeoIssueVisible = false"
        />
        <Button
          severity="danger"
          :label="t('logs.ipGeoIssueConfirm')"
          :loading="ipGeoIssueFixLoading"
          @click="confirmIPGeoRepair"
        />
      </template>
    </Dialog>

    <Dialog
      v-model:visible="exportDialogVisible"
      modal
      class="reparse-dialog export-dialog"
      :header="t('logs.exportDialogTitle')"
    >
      <div class="reparse-dialog-body">
        <template v-if="exportJob">
          <p>
            {{ t('logs.exportCurrent') }}
            <span class="export-status">{{ exportStatusLabel }}</span>
          </p>
          <div v-if="exportProgressPercent !== null" class="export-progress">
            <div class="export-progress-bar" :style="{ width: `${exportProgressPercent}%` }"></div>
          </div>
          <p v-if="exportProgressText" class="reparse-dialog-note">{{ exportProgressText }}</p>
        </template>
        <p v-if="exportJobError" class="reparse-dialog-error">{{ exportJobError }}</p>
        <p class="reparse-dialog-note">{{ t('logs.exportHistory') }}</p>
        <DataTable
          :value="exportJobs"
          :loading="exportJobsLoading"
          scrollable
          scrollHeight="240px"
          class="export-table"
          ref="exportHistoryTableRef"
        >
          <Column :header="t('logs.time')">
            <template #body="{ data }">
              {{ formatExportJobTime(data.created_at) }}
            </template>
          </Column>
          <Column :header="t('logs.exportStatus')">
            <template #body="{ data }">
              {{ formatExportStatus(data.status) }}
            </template>
          </Column>
          <Column :header="t('logs.exportProgressLabel')">
            <template #body="{ data }">
              {{ formatExportJobProgress(data) }}
            </template>
          </Column>
          <Column :header="t('logs.exportFile')">
            <template #body="{ data }">
              {{ data.fileName || '-' }}
            </template>
          </Column>
          <Column :header="t('common.action')">
            <template #body="{ data }">
              <Button
                text
                severity="secondary"
                :disabled="data.status !== 'success'"
                :label="t('logs.exportDownload')"
                @click="handleDownloadHistory(data)"
              />
              <Button
                text
                severity="secondary"
                :disabled="!canRetryExport(data)"
                :title="isDemoMode ? t('logs.exportBlocked') : undefined"
                :label="t('logs.exportRetry')"
                @click="handleRetryHistory(data)"
              />
            </template>
          </Column>
        </DataTable>
        <p v-if="exportHistoryHasMore" class="reparse-dialog-note">{{ t('logs.exportHistoryScrollHint') }}</p>
        <p v-if="exportHistoryLoadingMore" class="reparse-dialog-note">{{ t('logs.exportHistoryLoadingMore') }}</p>
      </div>
      <template #footer>
        <Button
          v-if="exportJob && (exportJob.status === 'running' || exportJob.status === 'pending')"
          text
          severity="secondary"
          :label="t('logs.exportCancel')"
          :loading="exportCancelLoading"
          @click="cancelExportJob"
        />
        <Button :label="t('common.close')" @click="exportDialogVisible = false" />
      </template>
    </Dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import { useRoute } from 'vue-router';
import Dialog from 'primevue/dialog';
import DataTable from 'primevue/datatable';
import Column from 'primevue/column';
import {
  fetchIPGeoAnomaly,
  fetchLogs,
  fetchWebsites,
  cancelLogsExport,
  downloadLogsExport,
  reparseAllLogs,
  reparseLogs,
  repairIPGeoAnomaly,
  listLogsExportJobs,
  startLogsExport,
  fetchLogsExportStatus,
  retryLogsExport,
} from '@/api';
import type { IPGeoAnomalyLog, LogsExportJob, WebsiteInfo } from '@/api/types';
import { formatTraffic, getUserPreference, saveUserPreference } from '@/utils';
import { formatBrowserLabel, formatDeviceLabel, formatLocationLabel, formatOSLabel, formatRefererLabel } from '@/i18n/mappings';
import { normalizeLocale } from '@/i18n';
import HeaderToolbar from '@/components/HeaderToolbar.vue';
import SystemNotifications from '@/components/SystemNotifications.vue';
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

type IPGeoIssueRow = {
  id: number;
  time: string;
  ip: string;
  ipDisplay: string;
  location: string;
  request: string;
};

type LogRowClickEvent = {
  data: LogRow;
  originalEvent?: MouseEvent;
};

const websites = ref<WebsiteInfo[]>([]);
const websitesLoading = ref(true);
const currentWebsiteId = ref('');
const route = useRoute();
const routeWebsiteIdOverride = ref('');

const searchInput = ref('');
const searchFilter = ref('');
const excludeInternal = ref(false);
const pageviewOnly = ref(false);
const excludeSpider = ref(false);
const excludeForeign = ref(false);
const statusCodeFilter = ref('');
const timeStart = ref<string>('');
const timeEnd = ref<string>('');
const dateRange = ref<Date[] | null>(null);
const dateRangePreset = ref('custom');
let updatingDatePreset = false;
let updatingDateRange = false;
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
const reparseDialogBlockedMessageKey = ref<'logs.reparseBlocked' | 'logs.exportBlocked'>(
  'logs.reparseBlocked'
);
const migrationDialogVisible = ref(false);
const migrationLoading = ref(false);
const migrationError = ref('');
const exportLoading = ref(false);
const exportDialogVisible = ref(false);
const exportJob = ref<LogsExportJob | null>(null);
const exportJobError = ref('');
const exportJobs = ref<LogsExportJob[]>([]);
const exportJobsLoading = ref(false);
const exportCancelLoading = ref(false);
let exportPollTimer: ReturnType<typeof setInterval> | null = null;
const exportHistoryPageSize = 20;
const exportHistoryPage = ref(1);
const exportHistoryHasMore = ref(false);
const exportHistoryLoadingMore = ref(false);
const exportHistoryTableRef = ref<InstanceType<typeof DataTable> | null>(null);
let exportHistoryScrollHandler: ((event: Event) => void) | null = null;
let exportHistoryTimer: ReturnType<typeof setInterval> | null = null;
const ipGeoIssueVisible = ref(false);
const ipGeoIssueLoading = ref(false);
const ipGeoIssueFixLoading = ref(false);
const ipGeoIssueError = ref('');
const ipGeoIssueCount = ref(0);
const ipGeoIssueSamples = ref<string[]>([]);
const ipGeoIssueLogs = ref<IPGeoAnomalyLog[]>([]);
const ipGeoIssueSelection = ref<IPGeoIssueRow[]>([]);
const ipGeoIssueChecked = new Set<string>();
const ipGeoIssuePageSize = 50;
const ipGeoIssuePage = ref(1);
const ipGeoIssueHasMore = ref(false);
const ipGeoIssueLoadingMore = ref(false);
const ipGeoIssueTableRef = ref<InstanceType<typeof DataTable> | null>(null);
let ipGeoIssueScrollHandler: ((event: Event) => void) | null = null;
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
const dateRangePresetOptions = computed(() => [
  { value: 'today', label: t('common.today') },
  { value: 'yesterday', label: t('common.yesterday') },
  { value: 'last7Days', label: t('common.last7Days') },
  { value: 'last30Days', label: t('common.last30Days') },
  { value: 'all', label: t('common.all') },
  { value: 'custom', label: t('logs.dateRangeCustom') },
]);

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
const exportProgressPercent = computed(() => {
  const job = exportJob.value;
  if (!job || !job.total || job.total <= 0) {
    return null;
  }
  const processed = job.processed ?? 0;
  return Math.min(100, Math.max(0, Math.round((processed / job.total) * 100)));
});
const exportProgressText = computed(() => {
  const job = exportJob.value;
  if (!job) {
    return '';
  }
  if (job.total && job.total > 0) {
    return t('logs.exportProgress', { processed: job.processed ?? 0, total: job.total });
  }
  if (job.processed) {
    return t('logs.exportProgressOnly', { processed: job.processed ?? 0 });
  }
  return '';
});
const exportStatusLabel = computed(() => {
  const status = exportJob.value?.status;
  if (!status) {
    return '';
  }
  switch (status) {
    case 'pending':
      return t('logs.exportStatusPending');
    case 'running':
      return t('logs.exportStatusRunning');
    case 'success':
      return t('logs.exportStatusSuccess');
    case 'failed':
      return t('logs.exportStatusFailed');
    case 'canceled':
      return t('logs.exportStatusCanceled');
    default:
      return status;
  }
});
const statusClassPreset = computed(() => parseStatusFilter(statusCodeFilter.value).statusClass || '');
const isDemoMode = computed(() => demoMode?.value ?? false);
const reparseDialogTitle = computed(() =>
  reparseDialogMode.value === 'blocked' ? t('demo.badge') : t('logs.reparseTitle')
);

function getRouteQueryValue(key: string) {
  const raw = route.query[key];
  if (Array.isArray(raw)) {
    return String(raw[0] || '').trim();
  }
  return String(raw || '').trim();
}

function isDateTimeValue(value: string) {
  return /^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}$/.test(value || '');
}

function getIPFilterFromSearch(value: string) {
  const normalized = String(value || '').trim();
  if (!normalized) {
    return '';
  }
  const ipv4Pattern =
    /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
  if (ipv4Pattern.test(normalized)) {
    return normalized;
  }
  const ipv6Pattern = /^[0-9a-fA-F:.]+$/;
  if (normalized.includes(':') && ipv6Pattern.test(normalized)) {
    return normalized;
  }
  return '';
}

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

function parseStatusFilter(value: string) {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed) {
    return {};
  }
  if (/^[2-5]\d{2}$/.test(trimmed)) {
    return { statusCode: trimmed };
  }
  const classMatch = trimmed.match(/^([2-5])(?:xx|x{2,3}|\*{2,3})$/);
  if (classMatch?.[1]) {
    return { statusClass: `${classMatch[1]}xx` };
  }
  return {};
}

function resolveStatusParams() {
  return parseStatusFilter(statusCodeFilter.value);
}

function setStatusCodePreset(preset: string) {
  statusCodeFilter.value = preset;
}

function buildExportParams() {
  const { statusCode, statusClass } = resolveStatusParams();
  const ipFilter = getIPFilterFromSearch(searchFilter.value);
  const params: Record<string, unknown> = {
    id: currentWebsiteId.value,
    website_id: currentWebsiteId.value,
    page: currentPage.value,
    pageSize: pageSize.value,
    sortField: sortField.value,
    sortOrder: sortOrder.value,
    lang: currentLocale.value,
  };
  if (searchFilter.value) {
    params.filter = searchFilter.value;
  }
  if (statusClass) {
    params.statusClass = statusClass;
  }
  if (statusCode) {
    params.statusCode = statusCode;
  }
  if (excludeInternal.value) {
    params.excludeInternal = true;
  }
  if (ipFilter) {
    params.ipFilter = ipFilter;
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
  if (timeStart.value) {
    params.timeStart = timeStart.value;
  }
  if (timeEnd.value) {
    params.timeEnd = timeEnd.value;
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

function formatExportJobTime(value?: string) {
  if (!value) {
    return '-';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function formatExportStatus(status?: string) {
  if (!status) {
    return '-';
  }
  switch (status) {
    case 'pending':
      return t('logs.exportStatusPending');
    case 'running':
      return t('logs.exportStatusRunning');
    case 'success':
      return t('logs.exportStatusSuccess');
    case 'failed':
      return t('logs.exportStatusFailed');
    case 'canceled':
      return t('logs.exportStatusCanceled');
    default:
      return status;
  }
}

function formatExportJobProgress(job: LogsExportJob) {
  const processed = job.processed ?? 0;
  const total = job.total ?? 0;
  if (total > 0) {
    return `${processed}/${total}`;
  }
  if (processed > 0) {
    return `${processed}`;
  }
  return '-';
}

function canRetryExport(job: LogsExportJob) {
  return job.status === 'failed' || job.status === 'canceled';
}

function formatDateTimeValue(date: Date) {
  const pad = (value: number) => String(value).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(
    date.getHours()
  )}:${pad(date.getMinutes())}`;
}

function parseDateFromTime(value: string) {
  const match = value.match(/^(\d{4})-(\d{2})-(\d{2})/);
  if (!match) {
    return null;
  }
  const year = Number(match[1]);
  const month = Number(match[2]) - 1;
  const day = Number(match[3]);
  if (!Number.isFinite(year) || !Number.isFinite(month) || !Number.isFinite(day)) {
    return null;
  }
  return new Date(year, month, day);
}

function buildDateRangeFromTime(start: string, end: string) {
  const startDate = start ? parseDateFromTime(start) : null;
  const endDate = end ? parseDateFromTime(end) : null;
  if (!startDate && !endDate) {
    return null;
  }
  if (startDate && endDate) {
    return [startDate, endDate];
  }
  return [startDate || endDate] as Date[];
}

function startOfDay(date: Date) {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate(), 0, 0, 0);
}

function endOfDay(date: Date) {
  return new Date(date.getFullYear(), date.getMonth(), date.getDate(), 23, 59, 59);
}

function applyDatePreset(preset: string) {
  const now = new Date();
  switch (preset) {
    case 'today': {
      timeStart.value = formatDateTimeValue(startOfDay(now));
      timeEnd.value = formatDateTimeValue(now);
      break;
    }
    case 'yesterday': {
      const base = new Date(now);
      base.setDate(base.getDate() - 1);
      timeStart.value = formatDateTimeValue(startOfDay(base));
      timeEnd.value = formatDateTimeValue(endOfDay(base));
      break;
    }
    case 'last7Days': {
      const start = new Date(now);
      start.setDate(start.getDate() - 6);
      timeStart.value = formatDateTimeValue(startOfDay(start));
      timeEnd.value = formatDateTimeValue(now);
      break;
    }
    case 'last30Days': {
      const start = new Date(now);
      start.setDate(start.getDate() - 29);
      timeStart.value = formatDateTimeValue(startOfDay(start));
      timeEnd.value = formatDateTimeValue(now);
      break;
    }
    case 'all': {
      timeStart.value = '';
      timeEnd.value = '';
      break;
    }
    default:
      break;
  }
}

async function handleExport() {
  if (!currentWebsiteId.value || exportLoading.value) {
    return;
  }
  if (isDemoMode.value) {
    openDemoBlockedDialog('logs.exportBlocked');
    return;
  }
  stopExportPolling();
  exportLoading.value = true;
  exportDialogVisible.value = true;
  exportJobError.value = '';
  exportJob.value = null;
  try {
    const start = await startLogsExport(buildExportParams());
    exportJob.value = {
      id: start.job_id,
      status: start.status,
      fileName: start.fileName,
      website_id: currentWebsiteId.value,
    };
    startExportPolling();
    await refreshExportJobs();
  } catch (error) {
    console.error('导出日志失败:', error);
    exportJobError.value = error instanceof Error ? error.message : t('logs.exportError');
    exportLoading.value = false;
  } finally {
  }
}

async function refreshExportJobs() {
  if (!currentWebsiteId.value) {
    exportJobs.value = [];
    return;
  }
  exportJobsLoading.value = true;
  try {
    const response = await listLogsExportJobs(currentWebsiteId.value, 1, exportHistoryPageSize);
    exportJobs.value = response.jobs || [];
    exportHistoryPage.value = 1;
    exportHistoryHasMore.value = Boolean(response.has_more);
    updateExportHistoryPolling();
  } catch (error) {
    console.debug('读取导出任务失败:', error);
  } finally {
    exportJobsLoading.value = false;
  }
}

async function loadMoreExportJobs() {
  if (!currentWebsiteId.value || exportHistoryLoadingMore.value || !exportHistoryHasMore.value) {
    return;
  }
  exportHistoryLoadingMore.value = true;
  try {
    const nextPage = exportHistoryPage.value + 1;
    const response = await listLogsExportJobs(currentWebsiteId.value, nextPage, exportHistoryPageSize);
    const incoming = response.jobs || [];
    if (incoming.length > 0) {
      const existing = new Set(exportJobs.value.map((job) => job.id));
      const merged = exportJobs.value.slice();
      for (const job of incoming) {
        if (!existing.has(job.id)) {
          merged.push(job);
        }
      }
      exportJobs.value = merged;
    }
    exportHistoryPage.value = nextPage;
    exportHistoryHasMore.value = Boolean(response.has_more);
    updateExportHistoryPolling();
  } catch (error) {
    console.debug('加载更多导出任务失败:', error);
  } finally {
    exportHistoryLoadingMore.value = false;
  }
}

async function refreshExportJobsSilently() {
  if (!currentWebsiteId.value || exportHistoryPage.value > 1) {
    return;
  }
  try {
    const response = await listLogsExportJobs(currentWebsiteId.value, 1, exportHistoryPageSize);
    const latest = response.jobs || [];
    if (latest.length === 0) {
      exportJobs.value = [];
      exportHistoryHasMore.value = Boolean(response.has_more);
      return;
    }
    const existingMap = new Map(exportJobs.value.map((job) => [job.id, job]));
    const updated: LogsExportJob[] = [];
    for (const job of latest) {
      if (existingMap.has(job.id)) {
        updated.push({ ...existingMap.get(job.id)!, ...job });
      } else {
        updated.push(job);
      }
    }
    for (const job of exportJobs.value) {
      if (!updated.find((item) => item.id === job.id)) {
        updated.push(job);
      }
    }
    exportJobs.value = updated;
    exportHistoryHasMore.value = Boolean(response.has_more);
    updateExportHistoryPolling();
  } catch (error) {
    console.debug('刷新导出任务失败:', error);
  }
}

function bindExportHistoryScroll() {
  if (exportHistoryScrollHandler || !exportHistoryTableRef.value) {
    return;
  }
  const wrapper = exportHistoryTableRef.value.$el?.querySelector?.('.p-datatable-wrapper') as
    | HTMLElement
    | undefined;
  if (!wrapper) {
    return;
  }
  exportHistoryScrollHandler = () => {
    if (!exportHistoryHasMore.value || exportHistoryLoadingMore.value) {
      return;
    }
    const threshold = 40;
    if (wrapper.scrollTop + wrapper.clientHeight >= wrapper.scrollHeight - threshold) {
      loadMoreExportJobs();
    }
  };
  wrapper.addEventListener('scroll', exportHistoryScrollHandler);
}

function unbindExportHistoryScroll() {
  if (!exportHistoryScrollHandler || !exportHistoryTableRef.value) {
    exportHistoryScrollHandler = null;
    return;
  }
  const wrapper = exportHistoryTableRef.value.$el?.querySelector?.('.p-datatable-wrapper') as
    | HTMLElement
    | undefined;
  if (wrapper) {
    wrapper.removeEventListener('scroll', exportHistoryScrollHandler);
  }
  exportHistoryScrollHandler = null;
}

function startExportHistoryPolling() {
  if (exportHistoryTimer) {
    return;
  }
  exportHistoryTimer = setInterval(() => {
    refreshExportJobsSilently();
  }, 4000);
  refreshExportJobsSilently();
}

function stopExportHistoryPolling() {
  if (exportHistoryTimer) {
    clearInterval(exportHistoryTimer);
    exportHistoryTimer = null;
  }
}

function updateExportHistoryPolling() {
  if (!exportDialogVisible.value) {
    stopExportHistoryPolling();
    return;
  }
  if (exportHistoryPage.value > 1) {
    stopExportHistoryPolling();
    return;
  }
  const hasRunning = exportJobs.value.some((job) => job.status === 'running' || job.status === 'pending');
  const currentActive =
    exportJob.value?.status === 'running' || exportJob.value?.status === 'pending';
  if (hasRunning || currentActive) {
    startExportHistoryPolling();
  } else {
    stopExportHistoryPolling();
  }
}

async function refreshCurrentExportStatus() {
  if (!exportJob.value?.id) {
    return;
  }
  try {
    const status = await fetchLogsExportStatus(exportJob.value.id);
    exportJob.value = status;
    if (status.website_id && currentWebsiteId.value && status.website_id !== currentWebsiteId.value) {
      stopExportPolling();
      exportLoading.value = false;
      await refreshExportJobs();
      return;
    }
    updateExportHistoryPolling();
    if (status.status === 'success') {
      stopExportPolling();
      exportLoading.value = false;
      await downloadExportJob(status.id, status.fileName);
      await refreshExportJobs();
    } else if (status.status === 'failed' || status.status === 'canceled') {
      stopExportPolling();
      exportLoading.value = false;
      exportJobError.value = status.error || (status.status === 'canceled' ? t('logs.exportCanceled') : t('logs.exportError'));
      await refreshExportJobs();
    }
  } catch (error) {
    console.debug('读取导出状态失败:', error);
  }
}

function startExportPolling() {
  if (exportPollTimer) {
    return;
  }
  exportPollTimer = setInterval(() => {
    refreshCurrentExportStatus();
  }, 1500);
  refreshCurrentExportStatus();
}

function stopExportPolling() {
  if (exportPollTimer) {
    clearInterval(exportPollTimer);
    exportPollTimer = null;
  }
}

async function cancelExportJob() {
  if (!exportJob.value?.id || exportCancelLoading.value) {
    return;
  }
  exportCancelLoading.value = true;
  try {
    await cancelLogsExport(exportJob.value.id);
    exportJob.value = { ...exportJob.value, status: 'canceled' };
    exportJobError.value = t('logs.exportCanceled');
    exportLoading.value = false;
    stopExportPolling();
    updateExportHistoryPolling();
    await refreshExportJobs();
  } catch (error) {
    exportJobError.value = error instanceof Error ? error.message : t('logs.exportError');
  } finally {
    exportCancelLoading.value = false;
  }
}

async function downloadExportJob(jobId: string, fallbackName?: string) {
  const response = await downloadLogsExport(jobId, currentWebsiteId.value || undefined);
  const headerName = extractExportFileName(response.headers?.['content-disposition']);
  const fileName = headerName || fallbackName || `nginxpulse_logs_${formatExportTimestamp()}.xlsx`;
  const url = window.URL.createObjectURL(response.data);
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}

function handleDownloadHistory(job: LogsExportJob) {
  if (!job?.id || job.status !== 'success') {
    return;
  }
  if (job.website_id && currentWebsiteId.value && job.website_id !== currentWebsiteId.value) {
    return;
  }
  downloadExportJob(job.id, job.fileName);
}

async function handleRetryHistory(job: LogsExportJob) {
  if (!job?.id || exportLoading.value) {
    return;
  }
  if (isDemoMode.value) {
    openDemoBlockedDialog('logs.exportBlocked');
    return;
  }
  stopExportPolling();
  exportLoading.value = true;
  exportJobError.value = '';
  try {
    const start = await retryLogsExport(job.id);
    exportJob.value = {
      id: start.job_id,
      status: start.status,
      fileName: start.fileName,
      website_id: currentWebsiteId.value,
    };
    exportDialogVisible.value = true;
    startExportPolling();
    await refreshExportJobs();
  } catch (error) {
    exportJobError.value = error instanceof Error ? error.message : t('logs.exportError');
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

const ipGeoIssueRows = computed<IPGeoIssueRow[]>(() => {
  const emptyLabel = t('common.none');
  return ipGeoIssueLogs.value.map((log) => {
    const time = log.time || emptyLabel;
    const rawIP = log.ip || '';
    const ipDisplay = rawIP || emptyLabel;
    const locationRaw = log.domestic_location || log.global_location || '';
    const location = formatLocationLabel(locationRaw, currentLocale.value, t) || emptyLabel;
    const method = log.method || '';
    const url = log.url || '';
    const requestText = `${method} ${url}`.trim() || emptyLabel;
    return {
      id: log.id,
      time,
      ip: rawIP,
      ipDisplay,
      location,
      request: requestText,
    };
  });
});

onMounted(() => {
  initPreferences();
  applyRouteOverrides();
  loadWebsites();
});

onUnmounted(() => {
  stopProgressPolling();
  unbindIPGeoIssueScroll();
  stopExportPolling();
  stopExportHistoryPolling();
  unbindExportHistoryScroll();
});

watch(ipGeoIssueVisible, (visible) => {
  if (visible) {
    setTimeout(() => bindIPGeoIssueScroll(), 0);
  } else {
    unbindIPGeoIssueScroll();
  }
});

watch(exportDialogVisible, (visible) => {
  if (visible) {
    refreshExportJobs();
    setTimeout(() => bindExportHistoryScroll(), 0);
  } else {
    stopExportHistoryPolling();
    unbindExportHistoryScroll();
  }
});

watch(dateRangePreset, (preset) => {
  if (updatingDatePreset) {
    return;
  }
  updatingDatePreset = true;
  applyDatePreset(preset);
  updatingDatePreset = false;
  saveUserPreference('logsDatePreset', dateRangePreset.value || '');
});

watch(dateRange, (range) => {
  if (updatingDateRange) {
    return;
  }
  updatingDateRange = true;
  const [start, end] = Array.isArray(range) ? range : [];
  if (start) {
    timeStart.value = formatDateTimeValue(startOfDay(start));
  } else {
    timeStart.value = '';
  }
  if (end) {
    timeEnd.value = formatDateTimeValue(endOfDay(end));
  } else {
    timeEnd.value = '';
  }
  updatingDateRange = false;
});

watch([timeStart, timeEnd], ([start, end]) => {
  if (!updatingDatePreset) {
    if (!start && !end) {
      dateRangePreset.value = 'all';
    } else if (dateRangePreset.value !== 'custom') {
      dateRangePreset.value = 'custom';
    }
  }
  if (!updatingDateRange) {
    updatingDateRange = true;
    dateRange.value = buildDateRangeFromTime(start || '', end || '');
    updatingDateRange = false;
  }
});

watch(currentWebsiteId, (value) => {
  if (value) {
    saveUserPreference('selectedWebsite', value);
  }
  stopExportPolling();
  exportLoading.value = false;
  exportJob.value = null;
  exportJobError.value = '';
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

watch([sortField, sortOrder, pageSize, excludeInternal, pageviewOnly, excludeSpider, excludeForeign, statusCodeFilter, timeStart, timeEnd], () => {
  saveUserPreference('logsSortField', sortField.value);
  saveUserPreference('logsSortOrder', sortOrder.value);
  saveUserPreference('logsPageSize', String(pageSize.value));
  saveUserPreference('logsExcludeInternal', excludeInternal.value ? 'true' : 'false');
  saveUserPreference('logsPageviewOnly', pageviewOnly.value ? 'true' : 'false');
  saveUserPreference('logsExcludeSpider', excludeSpider.value ? 'true' : 'false');
  saveUserPreference('logsExcludeForeign', excludeForeign.value ? 'true' : 'false');
  saveUserPreference('logsStatusCode', statusCodeFilter.value || '');
  saveUserPreference('logsTimeStart', timeStart.value || '');
  saveUserPreference('logsTimeEnd', timeEnd.value || '');
  currentPage.value = 1;
  loadLogs();
});

function initPreferences() {
  excludeInternal.value = getUserPreference('logsExcludeInternal', 'false') === 'true';
  pageviewOnly.value = getUserPreference('logsPageviewOnly', 'false') === 'true';
  excludeSpider.value = getUserPreference('logsExcludeSpider', 'false') === 'true';
  excludeForeign.value = getUserPreference('logsExcludeForeign', 'false') === 'true';
  statusCodeFilter.value = getUserPreference('logsStatusCode', '');
  timeStart.value = getUserPreference('logsTimeStart', '');
  timeEnd.value = getUserPreference('logsTimeEnd', '');
  const savedPreset = getUserPreference('logsDatePreset', '');
  if (savedPreset) {
    dateRangePreset.value = savedPreset;
  } else if (!timeStart.value && !timeEnd.value) {
    dateRangePreset.value = 'all';
  } else {
    dateRangePreset.value = 'custom';
  }
}

function applyRouteOverrides() {
  const websiteID = getRouteQueryValue('id');
  if (websiteID) {
    routeWebsiteIdOverride.value = websiteID;
  }

  const ipFilter = getRouteQueryValue('ipFilter');
  if (ipFilter) {
    searchInput.value = ipFilter;
    searchFilter.value = ipFilter;
  }

  const start = getRouteQueryValue('timeStart');
  const end = getRouteQueryValue('timeEnd');
  if (isDateTimeValue(start) || isDateTimeValue(end)) {
    timeStart.value = isDateTimeValue(start) ? start : '';
    timeEnd.value = isDateTimeValue(end) ? end : '';
    dateRangePreset.value = 'custom';
  }
}

async function loadWebsites() {
  websitesLoading.value = true;
  try {
    const data = await fetchWebsites();
    websites.value = data || [];
    const saved = getUserPreference('selectedWebsite', '');
    if (routeWebsiteIdOverride.value && websites.value.find((site) => site.id === routeWebsiteIdOverride.value)) {
      currentWebsiteId.value = routeWebsiteIdOverride.value;
    } else if (saved && websites.value.find((site) => site.id === saved)) {
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
    const { statusCode: statusCodeParam, statusClass: statusClassParam } = resolveStatusParams();
    const ipFilterParam = getIPFilterFromSearch(searchFilter.value) || undefined;
    const timeStartParam = timeStart.value || undefined;
    const timeEndParam = timeEnd.value || undefined;
    const result = await fetchLogs(
      currentWebsiteId.value,
      currentPage.value,
      pageSize.value,
      sortField.value,
      sortOrder.value,
      searchFilter.value,
      undefined,
      statusClassParam,
      statusCodeParam,
      excludeInternal.value,
      ipFilterParam,
      timeStartParam,
      timeEndParam,
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
    await checkIPGeoIssue();
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

async function checkIPGeoIssue() {
  if (!currentWebsiteId.value || ipGeoIssueLoading.value || isDemoMode.value) {
    return;
  }
  if (ipGeoIssueChecked.has(currentWebsiteId.value)) {
    return;
  }
  ipGeoIssueLoading.value = true;
  ipGeoIssueError.value = '';
  try {
    const result = await fetchIPGeoAnomaly(currentWebsiteId.value, {
      page: 1,
      pageSize: ipGeoIssuePageSize,
    });
    ipGeoIssueChecked.add(currentWebsiteId.value);
    if (result?.has_issue) {
      ipGeoIssueCount.value = result.count || 0;
      ipGeoIssueSamples.value = result.samples || [];
      ipGeoIssueLogs.value = result.logs || [];
      ipGeoIssueSelection.value = [...ipGeoIssueRows.value];
      ipGeoIssuePage.value = 1;
      ipGeoIssueHasMore.value = (result.logs || []).length === ipGeoIssuePageSize;
      ipGeoIssueVisible.value = true;
    } else {
      ipGeoIssueLogs.value = [];
      ipGeoIssueSelection.value = [];
      ipGeoIssuePage.value = 1;
      ipGeoIssueHasMore.value = false;
    }
  } catch (error) {
    console.debug('检测 IP 归属地异常失败:', error);
  } finally {
    ipGeoIssueLoading.value = false;
  }
}

async function refreshParsingStatus() {
  if (!currentWebsiteId.value || progressPollInFlight || loading.value) {
    return;
  }
  progressPollInFlight = true;
  try {
    const { statusCode: statusCodeParam, statusClass: statusClassParam } = resolveStatusParams();
    const ipFilterParam = getIPFilterFromSearch(searchFilter.value) || undefined;
    const timeStartParam = timeStart.value || undefined;
    const timeEndParam = timeEnd.value || undefined;
    const result = await fetchLogs(
      currentWebsiteId.value,
      currentPage.value,
      pageSize.value,
      sortField.value,
      sortOrder.value,
      searchFilter.value,
      undefined,
      statusClassParam,
      statusCodeParam,
      excludeInternal.value,
      ipFilterParam,
      timeStartParam,
      timeEndParam,
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
    openDemoBlockedDialog('logs.reparseBlocked');
    return;
  }
  reparseDialogMode.value = 'confirm';
  reparseDialogVisible.value = true;
}

function openDemoBlockedDialog(messageKey: 'logs.reparseBlocked' | 'logs.exportBlocked') {
  reparseDialogBlockedMessageKey.value = messageKey;
  reparseDialogMode.value = 'blocked';
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

async function confirmIPGeoRepair() {
  if (!currentWebsiteId.value || ipGeoIssueFixLoading.value) {
    return;
  }
  if (ipGeoIssueSelection.value.length === 0) {
    ipGeoIssueError.value = t('logs.ipGeoIssueEmpty');
    return;
  }
  ipGeoIssueFixLoading.value = true;
  ipGeoIssueError.value = '';
  try {
    const ips = Array.from(
      new Set(ipGeoIssueSelection.value.map((row) => row.ip).filter((ip) => Boolean(ip)))
    );
    await repairIPGeoAnomaly(currentWebsiteId.value, ips);
    ipGeoIssueVisible.value = false;
    ipGeoIssueLogs.value = [];
    ipGeoIssueSelection.value = [];
    currentPage.value = 1;
    await loadLogs();
  } catch (error) {
    if (error instanceof Error) {
      ipGeoIssueError.value = error.message;
    } else {
      ipGeoIssueError.value = t('logs.ipGeoIssueError');
    }
  } finally {
    ipGeoIssueFixLoading.value = false;
  }
}

async function loadMoreIPGeoIssues() {
  if (!currentWebsiteId.value || ipGeoIssueLoadingMore.value || !ipGeoIssueHasMore.value) {
    return;
  }
  ipGeoIssueLoadingMore.value = true;
  try {
    const nextPage = ipGeoIssuePage.value + 1;
    const result = await fetchIPGeoAnomaly(currentWebsiteId.value, {
      page: nextPage,
      pageSize: ipGeoIssuePageSize,
    });
    const newLogs = result.logs || [];
    if (newLogs.length > 0) {
      const previousCount = ipGeoIssueLogs.value.length;
      ipGeoIssueLogs.value = [...ipGeoIssueLogs.value, ...newLogs];
      const newRows = ipGeoIssueRows.value.slice(previousCount);
      ipGeoIssueSelection.value = mergeIssueSelections(ipGeoIssueSelection.value, newRows);
    }
    ipGeoIssuePage.value = nextPage;
    ipGeoIssueHasMore.value = newLogs.length === ipGeoIssuePageSize;
  } catch (error) {
    console.debug('加载更多异常日志失败:', error);
  } finally {
    ipGeoIssueLoadingMore.value = false;
  }
}

function mergeIssueSelections(existing: IPGeoIssueRow[], additions: IPGeoIssueRow[]) {
  if (additions.length === 0) {
    return existing;
  }
  const seen = new Set(existing.map((row) => row.id));
  const merged = existing.slice();
  for (const row of additions) {
    if (seen.has(row.id)) {
      continue;
    }
    seen.add(row.id);
    merged.push(row);
  }
  return merged;
}

function bindIPGeoIssueScroll() {
  if (ipGeoIssueScrollHandler || !ipGeoIssueTableRef.value) {
    return;
  }
  const wrapper = ipGeoIssueTableRef.value.$el?.querySelector?.('.p-datatable-wrapper') as
    | HTMLElement
    | undefined;
  if (!wrapper) {
    return;
  }
  ipGeoIssueScrollHandler = () => {
    if (!ipGeoIssueHasMore.value || ipGeoIssueLoadingMore.value) {
      return;
    }
    const threshold = 40;
    if (wrapper.scrollTop + wrapper.clientHeight >= wrapper.scrollHeight - threshold) {
      loadMoreIPGeoIssues();
    }
  };
  wrapper.addEventListener('scroll', ipGeoIssueScrollHandler);
}

function unbindIPGeoIssueScroll() {
  if (!ipGeoIssueScrollHandler || !ipGeoIssueTableRef.value) {
    ipGeoIssueScrollHandler = null;
    return;
  }
  const wrapper = ipGeoIssueTableRef.value.$el?.querySelector?.('.p-datatable-wrapper') as
    | HTMLElement
    | undefined;
  if (wrapper) {
    wrapper.removeEventListener('scroll', ipGeoIssueScrollHandler);
  }
  ipGeoIssueScrollHandler = null;
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
  border-radius: var(--radius-sm);
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
  flex-direction: column;
  align-items: stretch;
  justify-content: flex-start;
  gap: 12px;
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
  gap: 12px;
  flex: 0 0 auto;
  width: 100%;
  min-width: 320px;
  flex-wrap: wrap;
}

.search-input {
  flex: 1 1 380px;
  min-width: 240px;
  max-width: none;
}

.search-actions {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 4px;
  margin-left: auto;
  border-radius: calc(var(--radius-sm) + 2px);
  border: 1px solid var(--border);
  background: color-mix(in srgb, var(--panel-muted) 90%, var(--panel) 10%);
  flex: 0 0 auto;
}

.search-btn {
  font-weight: 600;
  border-radius: var(--radius-sm);
  min-width: 82px;
  padding: 0 14px;
}

.action-btn {
  border-radius: var(--radius-sm);
  min-width: 0;
  padding: 0 10px;
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
  margin-left: 0;
  justify-content: space-between;
  flex: 0 0 auto;
  width: 100%;
  min-width: 0;
}

.filter-row-left,
.filter-row-right {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.filter-row-left {
  flex: 1 1 520px;
  min-width: 0;
}

.filter-row-right {
  flex: 0 0 auto;
  margin-left: auto;
}

.filter-row-toggles {
  padding: 10px 12px;
  border-radius: var(--radius-sm);
  background: var(--panel-muted);
  border: 1px solid var(--border);
  gap: 10px;
}

.filter-toggle-container {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 10px;
  border-radius: var(--radius-xs);
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
  flex-wrap: wrap;
  row-gap: 6px;
  white-space: normal;
}

.status-code-container label,
.sort-field-container label,
.sort-order-container label,
.page-size-container label,
.date-range-container label {
  font-size: 12px;
  color: var(--muted);
  font-weight: 600;
}

.status-code-input {
  width: 120px;
}

.status-code-input :deep(.p-inputtext) {
  font-size: 12px;
}

.status-code-quick {
  display: none;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  row-gap: 6px;
}

.status-code-container:focus-within .status-code-quick {
  display: flex;
}

.status-quick-btn {
  border: 1px solid var(--border);
  background: var(--panel);
  color: var(--text);
  border-radius: var(--radius-xs);
  padding: 6px 10px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
}

.status-quick-btn:hover {
  border-color: rgba(var(--primary-color-rgb), 0.5);
  color: var(--accent-color);
}

.status-quick-btn.active {
  border-color: rgba(var(--primary-color-rgb), 0.8);
  background: rgba(var(--primary-color-rgb), 0.12);
  color: var(--accent-color);
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

.date-range-container {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 0 0 auto;
  flex-wrap: wrap;
  row-gap: 6px;
  white-space: normal;
}

.date-range-inputs {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
  row-gap: 6px;
}

.date-range-select {
  min-width: 120px;
}

.date-range-select :deep(.p-dropdown-label) {
  font-size: 12px;
}

.date-range-picker {
  width: 220px;
}

.date-range-picker :deep(.p-inputtext) {
  width: 100%;
  font-size: 12px;
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
  overflow: hidden;
  width: 100%;
  flex: 1;
  min-height: 0;
  position: relative;
  display: flex;
  flex-direction: column;
  border-radius: var(--radius-md);
  border: 1px solid var(--border);
  background: var(--panel);
}

.logs-table {
  background: transparent;
  border: none;
  flex: 1;
  min-height: 0;
}

.logs-table :deep(.p-datatable-wrapper) {
  flex: 1;
  min-height: 0;
}

.logs-table :deep(.p-datatable-table-container) {
  flex: 1;
  min-height: 0;
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

.logs-table-overlay {
  position: absolute;
  inset: 0;
  z-index: 5;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: inherit;
  background: color-mix(in srgb, var(--panel) 75%, transparent);
  backdrop-filter: blur(1px);
}

:global(body.dark-mode) .logs-table-overlay {
  background: color-mix(in srgb, var(--panel) 70%, transparent);
}

.logs-table-overlay-card {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 10px 16px;
  border-radius: var(--radius-pill);
  background: var(--panel);
  border: 1px solid var(--border);
  box-shadow: var(--shadow-soft);
  color: var(--muted);
  font-size: 13px;
  font-weight: 600;
}

.logs-table-overlay-spinner {
  width: 14px;
  height: 14px;
  border-radius: 50%;
  border: 2px solid rgba(var(--primary-color-rgb), 0.25);
  border-top-color: var(--primary);
  animation: logs-spin 0.8s linear infinite;
}

@keyframes logs-spin {
  to {
    transform: rotate(360deg);
  }
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
  border-radius: var(--radius-sm);
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
  border-radius: var(--radius-xs);
}

.advanced-toggle {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: var(--control-height);
  padding: 0 12px;
  border-radius: var(--radius-sm);
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
  font-weight: 600;
  white-space: nowrap;
}

.export-btn {
  font-weight: 600;
  white-space: nowrap;
  color: #ffffff;
  border-color: #16a34a;
  background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
  box-shadow: 0 8px 16px rgba(22, 163, 74, 0.28);
  transition: background 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease, transform 0.15s ease;
}

.export-btn:not(:disabled):hover {
  border-color: #15803d;
  background: linear-gradient(135deg, #34d399 0%, #16a34a 100%);
  box-shadow: 0 10px 18px rgba(21, 128, 61, 0.34);
}

.export-btn:not(:disabled):active {
  transform: translateY(1px);
  box-shadow: 0 6px 12px rgba(21, 128, 61, 0.28);
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

.ip-geo-samples {
  margin: 6px 0;
  padding-left: 18px;
  font-size: 13px;
  color: var(--muted);
}

.ip-geo-issue-list {
  border: 1px solid var(--border);
  border-radius: var(--radius-xs);
  overflow: hidden;
}

.ip-geo-issue-table {
  font-size: 13px;
}

.ip-geo-issue-table :deep(.p-datatable-thead > tr > th) {
  font-weight: 600;
}

.export-progress {
  height: 8px;
  border-radius: var(--radius-pill);
  background: rgba(59, 130, 246, 0.15);
  overflow: hidden;
}

.export-progress-bar {
  height: 100%;
  background: rgba(59, 130, 246, 0.9);
  transition: width 0.3s ease;
}

.export-status {
  margin-left: 6px;
  color: var(--muted);
  font-size: 13px;
}

.export-table {
  font-size: 13px;
}

.reparse-dialog-error {
  font-size: 13px;
  color: var(--error-color);
  font-weight: 600;
}

@media (max-width: 1800px) {
  .control-row {
    flex-direction: column;
    align-items: stretch;
    justify-content: flex-start;
  }

  .search-box {
    width: 100%;
    flex-wrap: wrap;
    min-width: 0;
    flex: 0 0 auto;
  }

  .search-input {
    flex-basis: 320px;
    min-width: 200px;
  }

  .search-actions {
    margin-left: 0;
  }

  .filter-row-fields {
    margin-left: 0;
    justify-content: space-between;
    flex: 0 0 auto;
    width: 100%;
  }
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
    flex-wrap: wrap;
  }

  .search-actions {
    width: 100%;
    margin-left: 0;
    justify-content: flex-start;
  }

  .filter-row-fields {
    margin-left: 0;
    flex-direction: column;
    align-items: stretch;
    justify-content: flex-start;
  }

  .filter-row-left,
  .filter-row-right {
    width: 100%;
    justify-content: flex-start;
  }

  .filter-row-right {
    margin-left: 0;
  }

  .filter-row {
    gap: 10px;
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
