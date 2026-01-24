<template>
  <div class="setup-page" :class="{ 'manage-mode': isManageMode }">
    <div v-if="loading" class="setup-loading">
      <div class="setup-loading-card">
        <div class="setup-loading-spinner" aria-hidden="true"></div>
        <div class="setup-loading-text">{{ t('common.loading') }}</div>
      </div>
    </div>

    <div v-else-if="loadError" class="setup-loading">
      <div class="setup-loading-card">
        <div class="setup-loading-text">{{ loadError }}</div>
        <button class="setup-primary-btn" type="button" @click="loadConfig">
          {{ t('common.retry') }}
        </button>
      </div>
    </div>

    <div v-else class="setup-surface">
      <div v-if="!isManageMode" class="setup-lang">
        <div class="sidebar-language-compact" role="group" :aria-label="t('app.sidebar.language')" :key="currentLocale">
          <button
            v-for="option in languageOptions"
            :key="option.value"
            class="sidebar-language-btn"
            :class="{ active: option.value === currentLocale }"
            type="button"
            :aria-pressed="option.value === currentLocale"
            :aria-label="option.label"
            @click="currentLocale = option.value"
          >
            <i :class="['language-icon', option.icon]" aria-hidden="true"></i>
            <span>{{ option.shortLabel }}</span>
          </button>
        </div>
      </div>
      <div class="setup-grid">
        <aside class="setup-rail">
        <div v-if="!isManageMode" class="setup-brand">
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
            <div class="brand-sub">{{ t(subtitleKey) }}</div>
          </div>
        </div>
        <ol class="setup-steps" role="list">
          <li
            v-for="(step, index) in steps"
            :key="step.key"
            class="setup-step"
            :class="{ active: currentStep === index, done: currentStep > index }"
          >
            <span class="setup-step-index">{{ index + 1 }}</span>
            <div class="setup-step-text">
              <div class="setup-step-title">{{ step.title }}</div>
              <div class="setup-step-desc">{{ step.desc }}</div>
            </div>
          </li>
        </ol>
        </aside>

        <section class="setup-content">
          <div v-if="configReadonly" class="setup-alert warning setup-readonly-banner">
            <div class="setup-alert-title">{{ t('setup.readOnlyTitle') }}</div>
            <div class="setup-hint">{{ t('setup.readOnly') }}</div>
            <div class="setup-hint">{{ t('setup.readOnlyEnvHint') }}</div>
            <div class="setup-inline-actions">
              <button class="ghost-button" type="button" @click="copyConfig">
                {{ t('setup.actions.copyConfig') }}
              </button>
              <span v-if="copyStatus" class="setup-hint">{{ copyStatus }}</span>
            </div>
          </div>
          <div class="setup-scroll">
            <transition name="setup-fade" mode="out-in">
              <div :key="currentStep" class="card setup-card" data-anim>
            <header class="setup-card-header">
              <div>
                <div class="setup-card-title">{{ steps[currentStep].title }}</div>
                <div class="setup-card-sub">{{ steps[currentStep].desc }}</div>
              </div>
              <div class="setup-card-chip">{{ t('setup.stepLabel', { value: currentStep + 1, total: steps.length }) }}</div>
            </header>

            <div v-if="currentStepErrors.length" class="setup-alert">
              <div class="setup-alert-title">{{ t('setup.validationTitle') }}</div>
              <ul class="setup-alert-list">
                <li v-for="(item, idx) in currentStepErrors" :key="`${item.field}-${idx}`">
                  {{ item.message }}
                </li>
              </ul>
            </div>

            <div v-if="currentStep === 0" class="setup-section">
              <div
                v-for="(site, index) in websiteDrafts"
                :key="`site-${index}`"
                class="setup-site-card"
              >
                <div class="setup-site-header">
                  <div class="setup-site-title">{{ t('setup.websiteBlock', { value: index + 1 }) }}</div>
                  <button
                    v-if="websiteDrafts.length > 1"
                    class="ghost-button"
                    type="button"
                    @click="removeWebsite(index)"
                  >
                    {{ t('setup.actions.remove') }}
                  </button>
                </div>
                <div class="setup-field-grid">
                  <div class="setup-field">
                    <label class="setup-label">{{ t('setup.fields.websiteName') }}</label>
                    <input v-model.trim="site.name" class="setup-input" type="text" />
                    <div v-if="fieldError(`websites[${index}].name`)" class="setup-error">
                      {{ fieldError(`websites[${index}].name`) }}
                    </div>
                  </div>
                  <div class="setup-field">
                    <label class="setup-label">{{ t('setup.fields.domains') }}</label>
                    <input v-model.trim="site.domainsInput" class="setup-input" type="text" :placeholder="t('setup.placeholders.domains')" />
                  </div>
                </div>
                <div class="setup-field">
                  <label class="setup-label">{{ t('setup.fields.logPath') }}</label>
                  <input v-model.trim="site.logPath" class="setup-input" type="text" :placeholder="t('setup.placeholders.logPath')" />
                  <div class="setup-hint">{{ t('setup.hints.logPath') }}</div>
                  <div v-if="fieldError(`websites[${index}].logPath`)" class="setup-error">
                    {{ fieldError(`websites[${index}].logPath`) }}
                  </div>
                </div>

                <button
                  class="setup-advanced-toggle"
                  type="button"
                  :aria-expanded="advancedOpen.website[index]"
                  @click="toggleWebsiteAdvanced(index)"
                >
                  <span>{{ advancedOpen.website[index] ? t('setup.actions.collapse') : t('setup.actions.advanced') }}</span>
                  <i class="ri-arrow-down-s-line" :class="{ flipped: advancedOpen.website[index] }" aria-hidden="true"></i>
                </button>

                <div v-if="advancedOpen.website[index]" class="setup-advanced">
                  <div class="setup-field-grid">
                    <div class="setup-field">
                      <label class="setup-label">{{ t('setup.fields.logType') }}</label>
                      <input v-model.trim="site.logType" class="setup-input" type="text" />
                    </div>
                    <div class="setup-field">
                      <label class="setup-label">{{ t('setup.fields.timeLayout') }}</label>
                      <input v-model.trim="site.timeLayout" class="setup-input" type="text" />
                    </div>
                  </div>
                  <div class="setup-field">
                    <label class="setup-label">{{ t('setup.fields.logFormat') }}</label>
                    <input v-model.trim="site.logFormat" class="setup-input" type="text" />
                  </div>
                  <div class="setup-field">
                    <label class="setup-label">{{ t('setup.fields.logRegex') }}</label>
                    <input v-model.trim="site.logRegex" class="setup-input" type="text" />
                  </div>
                  <div class="setup-field">
                    <label class="setup-label">{{ t('setup.fields.sourcesJson') }}</label>
                    <textarea v-model.trim="site.sourcesJson" class="setup-textarea" rows="6" :placeholder="t('setup.placeholders.sourcesJson')"></textarea>
                    <div class="setup-hint">{{ t('setup.hints.sourcesJson') }}</div>
                    <div v-if="fieldError(`websites[${index}].sources`)" class="setup-error">
                      {{ fieldError(`websites[${index}].sources`) }}
                    </div>
                  </div>
                </div>
              </div>

              <button class="ghost-button setup-add-btn" type="button" @click="addWebsite">
                <i class="ri-add-line" aria-hidden="true"></i>
                {{ t('setup.actions.addWebsite') }}
              </button>
            </div>

            <div v-else-if="currentStep === 1" class="setup-section">
              <div class="setup-field">
                <label class="setup-label">{{ t('setup.fields.databaseDsn') }}</label>
                <input
                  v-model.trim="databaseDraft.dsn"
                  class="setup-input"
                  type="text"
                  :placeholder="t('setup.placeholders.databaseDsn', { at: '@' })"
                />
                <div v-if="fieldError('database.dsn')" class="setup-error">
                  {{ fieldError('database.dsn') }}
                </div>
              </div>

              <button
                class="setup-advanced-toggle"
                type="button"
                :aria-expanded="advancedOpen.database"
                @click="advancedOpen.database = !advancedOpen.database"
              >
                <span>{{ advancedOpen.database ? t('setup.actions.collapse') : t('setup.actions.advanced') }}</span>
                <i class="ri-arrow-down-s-line" :class="{ flipped: advancedOpen.database }" aria-hidden="true"></i>
              </button>

              <div v-if="advancedOpen.database" class="setup-advanced">
                <div class="setup-field-grid">
                  <div class="setup-field">
                    <label class="setup-label">{{ t('setup.fields.dbMaxOpen') }}</label>
                    <input v-model.trim="databaseDraft.maxOpenConns" class="setup-input" type="number" min="0" />
                  </div>
                  <div class="setup-field">
                    <label class="setup-label">{{ t('setup.fields.dbMaxIdle') }}</label>
                    <input v-model.trim="databaseDraft.maxIdleConns" class="setup-input" type="number" min="0" />
                  </div>
                </div>
                <div class="setup-field">
                  <label class="setup-label">{{ t('setup.fields.dbConnLifetime') }}</label>
                  <input v-model.trim="databaseDraft.connMaxLifetime" class="setup-input" type="text" />
                </div>
              </div>
            </div>

            <div v-else-if="currentStep === 2" class="setup-section">
              <div class="setup-field-grid">
                <div class="setup-field">
                  <label class="setup-label">{{ t('setup.fields.serverPort') }}</label>
                  <input v-model.trim="serverPort" class="setup-input" type="text" :placeholder="t('setup.placeholders.serverPort')" />
                </div>
                <div class="setup-field">
                  <label class="setup-label">{{ t('setup.fields.taskInterval') }}</label>
                  <input v-model.trim="systemDraft.taskInterval" class="setup-input" type="text" />
                </div>
              </div>
              <div class="setup-field-grid">
                <div class="setup-field">
                  <label class="setup-label">{{ t('setup.fields.logRetentionDays') }}</label>
                  <input v-model.trim="systemDraft.logRetentionDays" class="setup-input" type="number" min="1" />
                </div>
                <div class="setup-field">
                  <label class="setup-label">{{ t('setup.fields.parseBatchSize') }}</label>
                  <input v-model.trim="systemDraft.parseBatchSize" class="setup-input" type="number" min="1" />
                </div>
              </div>
              <div class="setup-field-grid">
                <div class="setup-field">
                  <label class="setup-label">{{ t('setup.fields.ipGeoCacheLimit') }}</label>
                  <input v-model.trim="systemDraft.ipGeoCacheLimit" class="setup-input" type="number" min="1" />
                </div>
                <div class="setup-field">
                  <label class="setup-label">{{ t('setup.fields.language') }}</label>
                  <select v-model="systemDraft.language" class="setup-select">
                    <option value="zh-CN">中文</option>
                    <option value="en-US">English</option>
                  </select>
                </div>
              </div>
              <div class="setup-field">
                <label class="setup-label">{{ t('setup.fields.accessKeys') }}</label>
                <input v-model.trim="systemDraft.accessKeysText" class="setup-input" type="text" :placeholder="t('setup.placeholders.accessKeys')" />
                <div class="setup-hint">{{ t('setup.hints.accessKeys') }}</div>
              </div>
              <div class="setup-field setup-toggle">
                <label class="setup-label">{{ t('setup.fields.demoMode') }}</label>
                <button
                  class="setup-switch"
                  type="button"
                  :class="{ active: systemDraft.demoMode }"
                  :aria-pressed="systemDraft.demoMode"
                  @click="systemDraft.demoMode = !systemDraft.demoMode"
                >
                  <span class="setup-switch-dot"></span>
                </button>
              </div>

              <button
                class="setup-advanced-toggle"
                type="button"
                :aria-expanded="advancedOpen.system"
                @click="advancedOpen.system = !advancedOpen.system"
              >
                <span>{{ advancedOpen.system ? t('setup.actions.collapse') : t('setup.actions.advanced') }}</span>
                <i class="ri-arrow-down-s-line" :class="{ flipped: advancedOpen.system }" aria-hidden="true"></i>
              </button>

              <div v-if="advancedOpen.system" class="setup-advanced">
                <div class="setup-field">
                  <label class="setup-label">{{ t('setup.fields.logDestination') }}</label>
                  <input v-model.trim="systemDraft.logDestination" class="setup-input" type="text" />
                </div>
                <div class="setup-field">
                  <label class="setup-label">{{ t('setup.fields.statusCodeInclude') }}</label>
                  <input v-model.trim="pvDraft.statusCodeIncludeText" class="setup-input" type="text" :placeholder="t('setup.placeholders.statusCodeInclude')" />
                  <div v-if="fieldError('pvFilter.statusCodeInclude')" class="setup-error">
                    {{ fieldError('pvFilter.statusCodeInclude') }}
                  </div>
                </div>
                <div class="setup-field">
                  <label class="setup-label">{{ t('setup.fields.excludePatterns') }}</label>
                  <textarea v-model.trim="pvDraft.excludePatternsText" class="setup-textarea" rows="4"></textarea>
                  <div v-if="fieldError('pvFilter.excludePatterns')" class="setup-error">
                    {{ fieldError('pvFilter.excludePatterns') }}
                  </div>
                </div>
                <div class="setup-field">
                  <label class="setup-label">{{ t('setup.fields.excludeIps') }}</label>
                  <textarea v-model.trim="pvDraft.excludeIPsText" class="setup-textarea" rows="3"></textarea>
                </div>
              </div>
            </div>

            <div v-else class="setup-section">
              <div class="setup-review">
                <div class="setup-review-block">
                  <div class="setup-review-title">{{ t('setup.review.summary') }}</div>
                  <div class="setup-review-item" v-for="(site, index) in websiteDrafts" :key="`review-${index}`">
                    <div class="setup-review-label">{{ site.name || t('setup.review.unnamed') }}</div>
                    <div class="setup-review-value">{{ site.logPath || t('setup.review.noPath') }}</div>
                  </div>
                </div>
                <div class="setup-review-block">
                  <div class="setup-review-title">{{ t('setup.review.database') }}</div>
                  <div class="setup-review-value">{{ databaseDraft.dsn || t('setup.review.emptyDsn') }}</div>
                </div>
              </div>

              <div v-if="validationWarnings.length" class="setup-alert warning">
                <div class="setup-alert-title">{{ t('setup.warningTitle') }}</div>
                <ul class="setup-alert-list">
                  <li v-for="(item, idx) in validationWarnings" :key="`${item.field}-warn-${idx}`">
                    {{ item.message }}
                  </li>
                </ul>
              </div>

              <div class="setup-field">
                <label class="setup-label">{{ t('setup.review.jsonPreview') }}</label>
                <textarea class="setup-textarea" rows="10" readonly :value="configPreview"></textarea>
              </div>

              <div v-if="saveSuccess" class="setup-alert success">
                <div class="setup-alert-title">{{ t(savedLabelKey) }}</div>
                <div class="setup-hint">{{ t(restartHintKey) }}</div>
                <div v-if="autoRefreshSeconds > 0" class="setup-hint">
                  {{ t('setup.autoRefreshHint', { seconds: autoRefreshSeconds }) }}
                </div>
              </div>
              <div v-if="saveError" class="setup-alert">
                <div class="setup-alert-title">{{ t('common.requestFailed') }}</div>
                <div class="setup-hint">{{ saveError }}</div>
              </div>
            </div>
              </div>
            </transition>
          </div>

        <div class="setup-footer">
          <button
            class="ghost-button"
            type="button"
            :disabled="currentStep === 0 || saving || nextLoading"
            @click="prevStep"
          >
            {{ t('setup.actions.prev') }}
          </button>
          <button
            v-if="currentStep < steps.length - 1"
            class="setup-primary-btn"
            type="button"
            :disabled="saving || nextLoading"
            @click="nextStep"
          >
            {{ nextLoading ? t('setup.actions.nexting') : t('setup.actions.next') }}
          </button>
          <button
            v-else
            class="setup-primary-btn"
            type="button"
            :disabled="saving || configReadonly"
            @click="saveAll"
          >
            {{ saving ? t('setup.actions.saving') : t(saveLabelKey) }}
          </button>
        </div>
        <div v-if="configReadonly" class="setup-readonly">
          {{ t('setup.readOnly') }}
        </div>
        </section>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue';
import { useI18n } from 'vue-i18n';
import { fetchConfig, restartSystem, saveConfig, validateConfig } from '@/api';
import { normalizeLocale, setLocale } from '@/i18n';
import type { ConfigPayload, FieldError, SourceConfig } from '@/api/types';

interface WebsiteDraft {
  name: string;
  logPath: string;
  domainsInput: string;
  logType: string;
  logFormat: string;
  logRegex: string;
  timeLayout: string;
  sourcesJson: string;
}

const props = withDefaults(defineProps<{ mode?: 'setup' | 'manage' }>(), {
  mode: 'setup',
});

const { t, locale } = useI18n({ useScope: 'global' });

const isManageMode = computed(() => props.mode === 'manage');
const subtitleKey = computed(() => (isManageMode.value ? 'setup.manageSubtitle' : 'setup.subtitle'));
const saveLabelKey = computed(() =>
  isManageMode.value ? 'setup.actions.saveManage' : 'setup.actions.save'
);
const savedLabelKey = computed(() =>
  isManageMode.value ? 'setup.actions.savedManage' : 'setup.actions.saved'
);
const restartHintKey = computed(() =>
  isManageMode.value ? 'setup.restartManageHint' : 'setup.restartDockerHint'
);

const languageOptions = computed(() => {
  const _locale = locale.value;
  return [
    { value: 'zh-CN', label: t('language.zh'), shortLabel: t('language.zhShort'), icon: 'ri-translate-2' },
    { value: 'en-US', label: t('language.en'), shortLabel: t('language.enShort'), icon: 'ri-global-line' },
  ];
});

const currentLocale = computed({
  get: () => normalizeLocale(locale.value),
  set: (value: string) => setLocale(normalizeLocale(value)),
});

const steps = computed(() => [
  {
    key: 'website',
    title: t('setup.steps.website.title'),
    desc: t('setup.steps.website.desc'),
  },
  {
    key: 'database',
    title: t('setup.steps.database.title'),
    desc: t('setup.steps.database.desc'),
  },
  {
    key: 'system',
    title: t('setup.steps.system.title'),
    desc: t('setup.steps.system.desc'),
  },
  {
    key: 'review',
    title: t('setup.steps.review.title'),
    desc: t('setup.steps.review.desc'),
  },
]);

const currentStep = ref(0);
const loading = ref(true);
const loadError = ref('');
const saving = ref(false);
const saveSuccess = ref(false);
const saveError = ref('');
const nextLoading = ref(false);
const autoRefreshSeconds = ref(0);
let autoRefreshTimer: number | null = null;
const AUTO_REFRESH_SECONDS = 5;
const validationErrors = ref<FieldError[]>([]);
const validationWarnings = ref<FieldError[]>([]);
const fieldErrors = ref<Record<string, string>>({});
const configReadonly = ref(false);
const copyStatus = ref('');
let copyStatusTimer: number | null = null;

const serverPort = ref(':8089');
const databaseDraft = reactive({
  driver: 'postgres',
  dsn: '',
  maxOpenConns: '10',
  maxIdleConns: '5',
  connMaxLifetime: '30m',
});
const systemDraft = reactive({
  logDestination: 'file',
  taskInterval: '1m',
  logRetentionDays: '30',
  parseBatchSize: '100',
  ipGeoCacheLimit: '1000000',
  demoMode: false,
  accessKeysText: '',
  language: 'zh-CN',
});
const pvDraft = reactive({
  statusCodeIncludeText: '',
  excludePatternsText: '',
  excludeIPsText: '',
});

const websiteDrafts = ref<WebsiteDraft[]>([createWebsiteDraft()]);
const advancedOpen = reactive<{ website: Record<number, boolean>; database: boolean; system: boolean }>({
  website: {},
  database: false,
  system: false,
});

const currentStepErrors = computed(() => filterErrorsForStep(validationErrors.value, currentStep.value));

const configPreview = computed(() => {
  const { config } = buildConfig(false);
  return JSON.stringify(config, null, 2);
});

function createWebsiteDraft(): WebsiteDraft {
  return {
    name: '',
    logPath: '',
    domainsInput: '',
    logType: '',
    logFormat: '',
    logRegex: '',
    timeLayout: '',
    sourcesJson: '',
  };
}

function normalizePort(value: string) {
  const trimmed = value.trim();
  if (!trimmed) {
    return '';
  }
  if (trimmed.includes(':')) {
    return trimmed;
  }
  return `:${trimmed}`;
}

function addWebsite() {
  websiteDrafts.value.push(createWebsiteDraft());
}

function removeWebsite(index: number) {
  websiteDrafts.value.splice(index, 1);
}

function toggleWebsiteAdvanced(index: number) {
  advancedOpen.website[index] = !advancedOpen.website[index];
}

function fieldError(field: string) {
  return fieldErrors.value[field];
}

function splitList(value: string) {
  return value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseOptionalInt(
  value: string,
  field: string,
  errors: FieldError[],
  allowZero: boolean
): number | undefined {
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  const parsed = Number(trimmed);
  if (!Number.isFinite(parsed)) {
    errors.push({ field, message: t('setup.errors.invalidNumber') });
    return undefined;
  }
  if (!allowZero && parsed <= 0) {
    errors.push({ field, message: t('setup.errors.positiveNumber') });
  }
  if (allowZero && parsed < 0) {
    errors.push({ field, message: t('setup.errors.nonNegativeNumber') });
  }
  return Math.floor(parsed);
}

function parseIntList(value: string, field: string, errors: FieldError[]) {
  const items = splitList(value);
  if (items.length === 0) {
    errors.push({ field, message: t('setup.errors.required') });
    return [] as number[];
  }
  const result: number[] = [];
  for (const item of items) {
    const parsed = Number(item);
    if (!Number.isFinite(parsed)) {
      errors.push({ field, message: t('setup.errors.invalidNumber') });
      continue;
    }
    result.push(Math.floor(parsed));
  }
  return result;
}

function buildConfig(collectErrors = true): { config: ConfigPayload; errors: FieldError[] } {
  const errors: FieldError[] = [];
  const websites = websiteDrafts.value.map((site, index) => {
    const sourcesJson = site.sourcesJson.trim();
    let sources: SourceConfig[] | undefined;
    if (sourcesJson) {
      try {
        const parsed = JSON.parse(sourcesJson);
        if (Array.isArray(parsed)) {
          sources = parsed;
        } else if (collectErrors) {
          errors.push({ field: `websites[${index}].sources`, message: t('setup.errors.sourcesArray') });
        }
      } catch (err) {
        if (collectErrors) {
          const message = err instanceof Error ? err.message : t('setup.errors.invalidJson');
          errors.push({ field: `websites[${index}].sources`, message: t('setup.errors.parseJson', { message }) });
        }
      }
    }

    if (collectErrors) {
      if (!site.name.trim()) {
        errors.push({ field: `websites[${index}].name`, message: t('setup.errors.required') });
      }
      if (!site.logPath.trim() && (!sources || sources.length === 0)) {
        errors.push({ field: `websites[${index}].logPath`, message: t('setup.errors.logPathRequired') });
      }
    }

    return {
      name: site.name.trim(),
      logPath: site.logPath.trim(),
      domains: splitList(site.domainsInput),
      logType: site.logType.trim(),
      logFormat: site.logFormat.trim(),
      logRegex: site.logRegex.trim(),
      timeLayout: site.timeLayout.trim(),
      sources,
    };
  });

  const statusCodes = parseIntList(pvDraft.statusCodeIncludeText, 'pvFilter.statusCodeInclude', errors);
  const excludePatterns = splitList(pvDraft.excludePatternsText);
  if (collectErrors && excludePatterns.length === 0) {
    errors.push({ field: 'pvFilter.excludePatterns', message: t('setup.errors.required') });
  }

  const config: ConfigPayload = {
    websites,
    system: {
      logDestination: systemDraft.logDestination.trim(),
      taskInterval: systemDraft.taskInterval.trim(),
      logRetentionDays: parseOptionalInt(systemDraft.logRetentionDays, 'system.logRetentionDays', errors, false),
      parseBatchSize: parseOptionalInt(systemDraft.parseBatchSize, 'system.parseBatchSize', errors, false),
      ipGeoCacheLimit: parseOptionalInt(systemDraft.ipGeoCacheLimit, 'system.ipGeoCacheLimit', errors, false),
      demoMode: systemDraft.demoMode,
      accessKeys: splitList(systemDraft.accessKeysText),
      language: systemDraft.language,
    },
    server: {
      Port: normalizePort(serverPort.value),
    },
    database: {
      driver: databaseDraft.driver,
      dsn: databaseDraft.dsn.trim(),
      maxOpenConns: parseOptionalInt(databaseDraft.maxOpenConns, 'database.maxOpenConns', errors, true),
      maxIdleConns: parseOptionalInt(databaseDraft.maxIdleConns, 'database.maxIdleConns', errors, true),
      connMaxLifetime: databaseDraft.connMaxLifetime.trim(),
    },
    pvFilter: {
      statusCodeInclude: statusCodes,
      excludePatterns,
      excludeIPs: splitList(pvDraft.excludeIPsText),
    },
  };

  if (collectErrors && !databaseDraft.dsn.trim()) {
    errors.push({ field: 'database.dsn', message: t('setup.errors.required') });
  }

  return { config, errors };
}

function filterErrorsForStep(errors: FieldError[], step: number) {
  if (step >= steps.value.length - 1) {
    return errors;
  }
  const prefixes =
    step === 0
      ? ['websites', 'config']
      : step === 1
        ? ['database']
        : ['system', 'server', 'pvFilter'];
  return errors.filter((item) => {
    if (!item.field) {
      return true;
    }
    return prefixes.some((prefix) => item.field.startsWith(prefix));
  });
}

function applyErrors(errors: FieldError[]) {
  const map: Record<string, string> = {};
  errors.forEach((item) => {
    if (item.field && !map[item.field]) {
      map[item.field] = item.message;
    }
  });
  fieldErrors.value = map;
}

async function validateStep(step: number, remote: boolean) {
  saveError.value = '';
  const { config, errors: localErrors } = buildConfig(true);
  let remoteErrors: FieldError[] = [];
  let warnings: FieldError[] = [];

  if (remote) {
    try {
      const result = await validateConfig(config);
      remoteErrors = result.errors || [];
      warnings = result.warnings || [];
    } catch (err) {
      const message = err instanceof Error ? err.message : t('common.requestFailed');
      remoteErrors = [{ field: '', message }];
    }
  }

  const errors = [...localErrors, ...remoteErrors];
  validationErrors.value = errors;
  validationWarnings.value = warnings;
  applyErrors(errors);
  return filterErrorsForStep(errors, step).length === 0;
}

async function nextStep() {
  if (nextLoading.value) {
    return;
  }
  nextLoading.value = true;
  try {
    const remote = currentStep.value === 0;
    const ok = await validateStep(currentStep.value, remote);
    if (!ok) {
      return;
    }
    currentStep.value += 1;
  } finally {
    nextLoading.value = false;
  }
}

function prevStep() {
  currentStep.value = Math.max(0, currentStep.value - 1);
}

async function saveAll() {
  const ok = await validateStep(steps.value.length - 1, true);
  if (!ok) {
    return;
  }
  const { config } = buildConfig(false);
  saving.value = true;
  saveError.value = '';
  try {
    const result = await saveConfig(config);
    saveSuccess.value = Boolean(result.success);
    if (saveSuccess.value) {
      try {
        await restartSystem();
      } catch (err) {
        console.warn('触发重启失败:', err);
      }
      startAutoRefresh();
    }
  } catch (err) {
    saveError.value = err instanceof Error ? err.message : t('common.requestFailed');
  } finally {
    saving.value = false;
  }
}

async function copyConfig() {
  if (!configPreview.value) {
    return;
  }
  if (copyStatusTimer) {
    window.clearTimeout(copyStatusTimer);
    copyStatusTimer = null;
  }
  try {
    await navigator.clipboard.writeText(configPreview.value);
    copyStatus.value = t('setup.copySuccess');
  } catch (err) {
    const textarea = document.createElement('textarea');
    textarea.value = configPreview.value;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textarea);
    copyStatus.value = ok ? t('setup.copySuccess') : t('setup.copyFailed');
  }
  copyStatusTimer = window.setTimeout(() => {
    copyStatus.value = '';
    copyStatusTimer = null;
  }, 2000);
}

function startAutoRefresh() {
  if (autoRefreshTimer) {
    window.clearInterval(autoRefreshTimer);
  }
  autoRefreshSeconds.value = AUTO_REFRESH_SECONDS;
  autoRefreshTimer = window.setInterval(() => {
    autoRefreshSeconds.value -= 1;
    if (autoRefreshSeconds.value <= 0) {
      window.clearInterval(autoRefreshTimer as number);
      autoRefreshTimer = null;
      window.location.assign('/');
    }
  }, 1000);
}

async function loadConfig() {
  loading.value = true;
  loadError.value = '';
  try {
    const response = await fetchConfig();
    configReadonly.value = Boolean(response.readonly);
    hydrateDraft(response.config);
  } catch (err) {
    loadError.value = err instanceof Error ? err.message : t('common.requestFailed');
  } finally {
    loading.value = false;
  }
}

function hydrateDraft(config: ConfigPayload) {
  serverPort.value = config.server?.Port || ':8089';
  databaseDraft.driver = config.database?.driver || 'postgres';
  databaseDraft.dsn = config.database?.dsn || '';
  databaseDraft.maxOpenConns = String(config.database?.maxOpenConns ?? 10);
  databaseDraft.maxIdleConns = String(config.database?.maxIdleConns ?? 5);
  databaseDraft.connMaxLifetime = config.database?.connMaxLifetime || '30m';

  systemDraft.logDestination = config.system?.logDestination || 'file';
  systemDraft.taskInterval = config.system?.taskInterval || '1m';
  systemDraft.logRetentionDays = String(config.system?.logRetentionDays ?? 30);
  systemDraft.parseBatchSize = String(config.system?.parseBatchSize ?? 100);
  systemDraft.ipGeoCacheLimit = String(config.system?.ipGeoCacheLimit ?? 1000000);
  systemDraft.demoMode = Boolean(config.system?.demoMode);
  systemDraft.accessKeysText = (config.system?.accessKeys || []).join(', ');
  systemDraft.language = config.system?.language || 'zh-CN';

  pvDraft.statusCodeIncludeText = (config.pvFilter?.statusCodeInclude || []).join(', ');
  pvDraft.excludePatternsText = (config.pvFilter?.excludePatterns || []).join('\n');
  pvDraft.excludeIPsText = (config.pvFilter?.excludeIPs || []).join(', ');

  const mapped = (config.websites || []).map((site) => ({
    name: site.name || '',
    logPath: site.logPath || '',
    domainsInput: (site.domains || []).join(', '),
    logType: site.logType || '',
    logFormat: site.logFormat || '',
    logRegex: site.logRegex || '',
    timeLayout: site.timeLayout || '',
    sourcesJson: site.sources && site.sources.length > 0 ? JSON.stringify(site.sources, null, 2) : '',
  }));
  websiteDrafts.value = mapped.length ? mapped : [createWebsiteDraft()];
}

onMounted(() => {
  loadConfig();
});

onBeforeUnmount(() => {
  if (autoRefreshTimer) {
    window.clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }
  if (copyStatusTimer) {
    window.clearTimeout(copyStatusTimer);
    copyStatusTimer = null;
  }
});
</script>
