export interface WebsiteInfo {
  id: string;
  name: string;
}

export interface WebsitesResponse {
  websites: WebsiteInfo[];
}

export interface AppStatusResponse {
  log_parsing: boolean;
  log_parsing_stage?: string;
  log_parsing_progress?: number;
  log_parsing_estimated_total_seconds?: number;
  log_parsing_estimated_remaining_seconds?: number;
  ip_geo_parsing?: boolean;
  ip_geo_pending?: boolean;
  ip_geo_progress?: number;
  ip_geo_estimated_remaining_seconds?: number;
  demo_mode?: boolean;
  mobile_pwa_enabled?: boolean;
  language?: string;
  version?: string;
  git_commit?: string;
  migration_required?: boolean;
  setup_required?: boolean;
  config_readonly?: boolean;
}

export interface SourceConfig {
  [key: string]: any;
}

export interface WhitelistConfig {
  enabled?: boolean;
  ips?: string[];
  cities?: string[];
  nonMainland?: boolean;
}

export interface WebsiteConfig {
  name: string;
  logPath?: string;
  domains?: string[];
  logType?: string;
  logFormat?: string;
  logRegex?: string;
  timeLayout?: string;
  sources?: SourceConfig[];
  whitelist?: WhitelistConfig;
}

export interface SystemConfig {
  logDestination?: string;
  taskInterval?: string;
  logRetentionDays?: number;
  parseBatchSize?: number;
  ipGeoCacheLimit?: number;
  demoMode?: boolean;
  accessKeys?: string[];
  language?: string;
  webBasePath?: string;
  mobilePwaEnabled?: boolean;
}

export interface ServerConfig {
  Port?: string;
}

export interface DatabaseConfig {
  driver?: string;
  dsn?: string;
  maxOpenConns?: number;
  maxIdleConns?: number;
  connMaxLifetime?: string;
}

export interface PVFilterConfig {
  statusCodeInclude?: number[];
  excludePatterns?: string[];
  excludeIPs?: string[];
}

export interface ConfigPayload {
  system: SystemConfig;
  server: ServerConfig;
  database: DatabaseConfig;
  websites: WebsiteConfig[];
  pvFilter: PVFilterConfig;
}

export interface FieldError {
  field: string;
  message: string;
}

export interface ConfigValidationResult {
  errors: FieldError[];
  warnings: FieldError[];
}

export interface ConfigResponse {
  config: ConfigPayload;
  readonly: boolean;
  setup_required: boolean;
  default_log_path?: string;
}

export interface ConfigSaveResponse {
  success: boolean;
  restart_required?: boolean;
}

export interface TimeSeriesStats {
  labels: string[];
  visitors: number[];
  pageviews: number[];
}

export interface SimpleSeriesStats {
  key: string[];
  uv: number[];
  uv_percent?: number[];
  pv?: number[];
  pv_percent?: number[];
}

export interface RefererIPGroupStats {
  key: string[];
  uv: number[];
  share: number[];
  domestic: string[];
  global: string[];
  total_uv: number;
}

export interface RefererIPBatchStats {
  all: RefererIPGroupStats;
  search: RefererIPGroupStats;
  direct: RefererIPGroupStats;
  external: RefererIPGroupStats;
}

export interface RealtimeSeriesItem {
  name: string;
  count: number;
  percent: number;
}

export interface RealtimeStats {
  activeCount: number;
  activeSeries: number[];
  deviceBreakdown: RealtimeSeriesItem[];
  referers: RealtimeSeriesItem[];
  pages: RealtimeSeriesItem[];
  entryPages: RealtimeSeriesItem[];
  browsers: RealtimeSeriesItem[];
  locations: RealtimeSeriesItem[];
}

export interface IPGeoAnomalyResponse {
  has_issue: boolean;
  count: number;
  samples?: string[];
  logs?: IPGeoAnomalyLog[];
}

export interface IPGeoAnomalyLog {
  id: number;
  ip: string;
  timestamp: number;
  time?: string;
  method?: string;
  url?: string;
  domestic_location?: string;
  global_location?: string;
}

export interface LogsExportStartResponse {
  job_id: string;
  status: string;
  fileName?: string;
}

export interface LogsExportJob {
  id: string;
  status: string;
  processed?: number;
  total?: number;
  fileName?: string;
  error?: string;
  created_at?: string;
  updated_at?: string;
  website_id?: string;
}

export interface LogsExportStatusResponse {
  id: string;
  status: string;
  processed?: number;
  total?: number;
  fileName?: string;
  error?: string;
  created_at?: string;
  updated_at?: string;
  website_id?: string;
}

export interface LogsExportListResponse {
  jobs: LogsExportJob[];
  total?: number;
  has_more?: boolean;
}

export interface IPGeoAPIFailure {
  id: number;
  ip: string;
  source: string;
  reason: string;
  error?: string;
  status_code?: number;
  created_at?: string;
}

export interface IPGeoAPIFailureListResponse {
  failures: IPGeoAPIFailure[];
  has_more?: boolean;
}

export interface SystemNotification {
  id: number;
  level: string;
  category: string;
  title: string;
  message: string;
  fingerprint?: string;
  occurrences?: number;
  created_at?: string;
  last_occurred_at?: string;
  read_at?: string | null;
  metadata?: Record<string, any>;
}

export interface SystemNotificationListResponse {
  notifications: SystemNotification[];
  has_more?: boolean;
  unread_count?: number;
}

export type ApiResponse<T> = T;
