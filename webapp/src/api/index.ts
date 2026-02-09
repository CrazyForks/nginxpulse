import type { AxiosResponse } from 'axios';
import client from './client';
import type {
  AppStatusResponse,
  ApiResponse,
  ConfigPayload,
  ConfigResponse,
  ConfigSaveResponse,
  ConfigValidationResult,
  RealtimeStats,
  IPGeoAnomalyResponse,
  LogsExportStartResponse,
  LogsExportStatusResponse,
  LogsExportListResponse,
  IPGeoAPIFailureListResponse,
  RefererIPBatchStats,
  SimpleSeriesStats,
  SystemNotificationListResponse,
  TimeSeriesStats,
  WebsiteInfo,
  WebsitesResponse,
} from './types';

const buildParams = (params: Record<string, unknown> = {}) => {
  const normalized: Record<string, string> = {};
  Object.keys(params)
    .sort()
    .forEach((key) => {
      const value = params[key];
      if (value !== undefined && value !== null) {
        normalized[key] = String(value);
      }
    });
  return normalized;
};

export const fetchWebsites = async (): Promise<WebsiteInfo[]> => {
  const response = await client.get<ApiResponse<WebsitesResponse>>('api/websites');
  return response.data.websites || [];
};

export const fetchAppStatus = async (): Promise<AppStatusResponse> => {
  const response = await client.get<ApiResponse<AppStatusResponse>>('api/status');
  return response.data;
};

export const fetchConfig = async (): Promise<ConfigResponse> => {
  const response = await client.get<ApiResponse<ConfigResponse>>('api/config');
  return response.data;
};

export const validateConfig = async (config: ConfigPayload): Promise<ConfigValidationResult> => {
  const response = await client.post<ApiResponse<ConfigValidationResult>>('api/config/validate', {
    config,
  });
  return response.data;
};

export const saveConfig = async (config: ConfigPayload): Promise<ConfigSaveResponse> => {
  const response = await client.post<ApiResponse<ConfigSaveResponse>>('api/config/save', {
    config,
  });
  return response.data;
};

export const restartSystem = async (): Promise<{ success: boolean }> => {
  const response = await client.post<ApiResponse<{ success: boolean }>>('api/system/restart');
  return response.data;
};

export const reparseLogs = async (websiteId: string): Promise<void> => {
  await client.post<ApiResponse<{ success: boolean }>>('api/logs/reparse', {
    id: websiteId,
  });
};

export const reparseAllLogs = async (): Promise<void> => {
  await client.post<ApiResponse<{ success: boolean }>>('api/logs/reparse', {
    id: '',
    migration: true,
  });
};

export const fetchIPGeoAnomaly = async (
  websiteId: string,
  options: { page?: number; pageSize?: number; limit?: number } = {}
): Promise<IPGeoAnomalyResponse> => {
  const response = await client.get<ApiResponse<IPGeoAnomalyResponse>>('api/ip-geo/anomaly', {
    params: buildParams({ id: websiteId, ...options }),
  });
  return response.data;
};

export const repairIPGeoAnomaly = async (websiteId: string, ips: string[]): Promise<void> => {
  await client.post<ApiResponse<{ success: boolean }>>('api/ip-geo/repair', {
    id: websiteId,
    ips,
  });
};

export const fetchIPGeoFailures = async (
  page = 1,
  pageSize = 50,
  options: { websiteId?: string; reason?: string; keyword?: string } = {}
): Promise<IPGeoAPIFailureListResponse> => {
  const response = await client.get<ApiResponse<IPGeoAPIFailureListResponse>>('api/ip-geo/failures', {
    params: buildParams({
      page,
      pageSize,
      id: options.websiteId,
      reason: options.reason,
      keyword: options.keyword,
    }),
  });
  return response.data;
};

export const exportIPGeoFailures = async (options: {
  websiteId?: string;
  reason?: string;
  keyword?: string;
}): Promise<AxiosResponse<Blob>> => {
  return client.get('api/ip-geo/failures/export', {
    params: buildParams({
      id: options.websiteId,
      reason: options.reason,
      keyword: options.keyword,
    }),
    responseType: 'blob',
  });
};

const fetchStats = async <T>(type: string, params: Record<string, unknown> = {}): Promise<T> => {
  const response = await client.get<ApiResponse<T>>(`/api/stats/${type}`, {
    params: buildParams(params),
  });
  return response.data;
};

export const fetchTimeSeriesStats = (
  websiteId: string,
  timeRange: string,
  viewType: string
): Promise<TimeSeriesStats> => fetchStats('timeseries', { id: websiteId, timeRange, viewType });

export const fetchOverallStats = (
  websiteId: string,
  timeRange: string,
  entryLimit?: number
): Promise<Record<string, any>> => fetchStats('overall', { id: websiteId, timeRange, entryLimit });

export const fetchUrlStats = (
  websiteId: string,
  timeRange: string,
  limit = 10
): Promise<SimpleSeriesStats> => fetchStats('url', { id: websiteId, timeRange, limit });

export const fetchRefererStats = (
  websiteId: string,
  timeRange: string,
  limit = 10
): Promise<SimpleSeriesStats> => fetchStats('referer', { id: websiteId, timeRange, limit });

export const fetchRefererIPStats = (
  websiteId: string,
  timeRange: string,
  sourceKind: 'all' | 'search' | 'direct' | 'external' = 'all',
  limit = 10
): Promise<SimpleSeriesStats> => fetchStats('referer_ip', { id: websiteId, timeRange, sourceKind, limit });

export const fetchRefererIPBatchStats = (
  websiteId: string,
  timeRange: string,
  limit = 10
): Promise<RefererIPBatchStats> => fetchStats('referer_ip_batch', { id: websiteId, timeRange, limit });

export const fetchBrowserStats = (
  websiteId: string,
  timeRange: string,
  limit = 10
): Promise<SimpleSeriesStats> => fetchStats('browser', { id: websiteId, timeRange, limit });

export const fetchOSStats = (
  websiteId: string,
  timeRange: string,
  limit = 10
): Promise<SimpleSeriesStats> => fetchStats('os', { id: websiteId, timeRange, limit });

export const fetchDeviceStats = (
  websiteId: string,
  timeRange: string,
  limit = 10
): Promise<SimpleSeriesStats> => fetchStats('device', { id: websiteId, timeRange, limit });

export const fetchLocationStats = (
  websiteId: string,
  timeRange: string,
  locationType: string,
  limit = 99
): Promise<SimpleSeriesStats> =>
  fetchStats('location', { id: websiteId, locationType, timeRange, limit });

export const fetchSessionSummary = (
  websiteId: string,
  timeRange: string
): Promise<Record<string, any>> => fetchStats('session_summary', { id: websiteId, timeRange });

export const fetchRealtimeStats = (
  websiteId: string,
  window: number
): Promise<RealtimeStats> => fetchStats('realtime', { id: websiteId, window });

export const fetchSystemNotifications = async (
  page = 1,
  pageSize = 20,
  unreadOnly = false
): Promise<SystemNotificationListResponse> => {
  const response = await client.get<ApiResponse<SystemNotificationListResponse>>(
    'api/system/notifications',
    {
      params: buildParams({ page, pageSize, unreadOnly }),
    }
  );
  return response.data;
};

export const markSystemNotificationsRead = async (options: {
  ids?: number[];
  all?: boolean;
}): Promise<void> => {
  await client.post<ApiResponse<{ success: boolean }>>('api/system/notifications/read', {
    ids: options.ids || [],
    all: Boolean(options.all),
  });
};

export const fetchLogs = (
  websiteId: string,
  page: number,
  pageSize: number,
  sortField: string,
  sortOrder: string,
  filter?: string,
  timeRange?: string,
  statusClass?: string,
  statusCode?: string,
  excludeInternal?: boolean,
  ipFilter?: string,
  timeStart?: string,
  timeEnd?: string,
  locationFilter?: string,
  urlFilter?: string,
  pageviewOnly?: boolean,
  newVisitor?: string,
  distinctIp?: boolean,
  excludeSpider?: boolean,
  excludeForeign?: boolean
): Promise<Record<string, any>> => {
  const params: Record<string, unknown> = {
    id: websiteId,
    page,
    pageSize,
    sortField,
    sortOrder,
  };

  if (filter) {
    params.filter = filter;
  }
  if (timeRange) {
    params.timeRange = timeRange;
  }
  if (statusClass) {
    params.statusClass = statusClass;
  }
  if (statusCode !== undefined && statusCode !== null && statusCode !== '') {
    params.statusCode = statusCode;
  }
  if (excludeInternal) {
    params.excludeInternal = true;
  }
  if (ipFilter) {
    params.ipFilter = ipFilter;
  }
  if (timeStart) {
    params.timeStart = timeStart;
  }
  if (timeEnd) {
    params.timeEnd = timeEnd;
  }
  if (locationFilter) {
    params.locationFilter = locationFilter;
  }
  if (urlFilter) {
    params.urlFilter = urlFilter;
  }
  if (pageviewOnly) {
    params.pageviewOnly = true;
  }
  if (newVisitor) {
    params.newVisitor = newVisitor;
  }
  if (distinctIp) {
    params.distinctIp = true;
  }
  if (excludeSpider) {
    params.excludeSpider = true;
  }
  if (excludeForeign) {
    params.excludeForeign = true;
  }

  return fetchStats('logs', params);
};

export const exportLogs = async (
  params: Record<string, unknown> = {}
): Promise<AxiosResponse<Blob>> =>
  client.get('api/logs/export', {
    params: buildParams(params),
    responseType: 'blob',
  });

export const startLogsExport = async (
  params: Record<string, unknown> = {}
): Promise<LogsExportStartResponse> => {
  const response = await client.post<ApiResponse<LogsExportStartResponse>>('api/logs/export', params);
  return response.data;
};

export const fetchLogsExportStatus = async (jobId: string): Promise<LogsExportStatusResponse> => {
  const response = await client.get<ApiResponse<LogsExportStatusResponse>>('api/logs/export/status', {
    params: buildParams({ id: jobId }),
  });
  return response.data;
};

export const listLogsExportJobs = async (
  websiteId: string,
  page = 1,
  pageSize = 20
): Promise<LogsExportListResponse> => {
  const response = await client.get<ApiResponse<LogsExportListResponse>>('api/logs/export/list', {
    params: buildParams({ id: websiteId, website_id: websiteId, page, pageSize }),
  });
  return response.data;
};

export const cancelLogsExport = async (jobId: string): Promise<{ status: string }> => {
  const response = await client.post<ApiResponse<{ status: string }>>('api/logs/export/cancel', {
    id: jobId,
  });
  return response.data;
};

export const retryLogsExport = async (
  jobId: string
): Promise<LogsExportStartResponse> => {
  const response = await client.post<ApiResponse<LogsExportStartResponse>>('api/logs/export/retry', {
    id: jobId,
  });
  return response.data;
};

export const downloadLogsExport = async (
  jobId: string,
  websiteId?: string
): Promise<AxiosResponse<Blob>> =>
  client.get('api/logs/export/download', {
    params: buildParams({ id: jobId, website_id: websiteId }),
    responseType: 'blob',
  });

export const fetchSessions = (
  websiteId: string,
  page: number,
  pageSize: number,
  timeRange?: string,
  timeStart?: string,
  timeEnd?: string,
  ipFilter?: string,
  deviceFilter?: string,
  browserFilter?: string,
  osFilter?: string
): Promise<Record<string, any>> => {
  const params: Record<string, unknown> = {
    id: websiteId,
    page,
    pageSize,
  };

  if (timeRange) {
    params.timeRange = timeRange;
  }
  if (timeStart) {
    params.timeStart = timeStart;
  }
  if (timeEnd) {
    params.timeEnd = timeEnd;
  }
  if (ipFilter) {
    params.ipFilter = ipFilter;
  }
  if (deviceFilter) {
    params.deviceFilter = deviceFilter;
  }
  if (browserFilter) {
    params.browserFilter = browserFilter;
  }
  if (osFilter) {
    params.osFilter = osFilter;
  }

  return fetchStats('session', params);
};
