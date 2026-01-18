export interface WebsiteInfo {
  id: string;
  name: string;
}

export interface WebsitesResponse {
  websites: WebsiteInfo[];
}

export interface AppStatusResponse {
  log_parsing: boolean;
  log_parsing_progress?: number;
  demo_mode?: boolean;
  version?: string;
  git_commit?: string;
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

export type ApiResponse<T> = T;
