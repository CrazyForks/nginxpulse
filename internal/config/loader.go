package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	envConfigJSON        = "CONFIG_JSON"
	envWebsites          = "WEBSITES"
	envLogDestination    = "LOG_DEST"
	envTaskInterval      = "TASK_INTERVAL"
	envLogRetentionDays  = "LOG_RETENTION_DAYS"
	envLogParseBatchSize = "LOG_PARSE_BATCH_SIZE"
	envServerPort        = "SERVER_PORT"
	envPVStatusCodes     = "PV_STATUS_CODES"
	envPVExcludePatterns = "PV_EXCLUDE_PATTERNS"
	envPVExcludeIPs      = "PV_EXCLUDE_IPS"
	envDemoMode          = "DEMO_MODE"
	envAccessKeys        = "ACCESS_KEYS"
	envLanguage          = "APP_LANGUAGE"
	envWebBasePath       = "WEB_BASE_PATH"
	envMobilePWAEnabled  = "MOBILE_PWA_ENABLED"
	envIPGeoCacheLimit   = "IP_GEO_CACHE_LIMIT"
	envIPGeoAPIURL       = "IP_GEO_API_URL"
	envDBDriver          = "DB_DRIVER"
	envDBDSN             = "DB_DSN"
	envDBMaxOpenConns    = "DB_MAX_OPEN_CONNS"
	envDBMaxIdleConns    = "DB_MAX_IDLE_CONNS"
	envDBConnMaxLifetime = "DB_CONN_MAX_LIFETIME"
)

var (
	defaultStatusCodeInclude = []int{200}
	defaultExcludePatterns   = []string{
		"favicon.ico$",
		"robots.txt$",
		"sitemap.xml$",
		`\.(?:js|css|jpg|jpeg|png|gif|svg|webp|woff|woff2|ttf|eot|ico)$`,
		"^/api/",
		"^/ajax/",
		"^/health$",
		"^/_(?:nuxt|next)/",
		"rss.xml$",
		"feed.xml$",
		"atom.xml$",
	}
	defaultSystem = SystemConfig{
		LogDestination:   "file",
		TaskInterval:     "1m",
		LogRetentionDays: 30,
		ParseBatchSize:   100,
		IPGeoCacheLimit:  1000000,
		IPGeoAPIURL:      DefaultIPGeoAPIURL,
		DemoMode:         false,
		AccessKeys:       nil,
		Language:         "zh-CN",
		MobilePWAEnabled: false,
	}
	defaultServer = ServerConfig{
		Port: ":8089",
	}
	defaultDatabase = DatabaseConfig{
		Driver:          "postgres",
		DSN:             "",
		MaxOpenConns:    10,
		MaxIdleConns:    5,
		ConnMaxLifetime: "30m",
	}
)

func DefaultConfig() Config {
	return Config{
		System: defaultSystem,
		Server: defaultServer,
		Database: DatabaseConfig{
			Driver:          defaultDatabase.Driver,
			DSN:             defaultDatabase.DSN,
			MaxOpenConns:    defaultDatabase.MaxOpenConns,
			MaxIdleConns:    defaultDatabase.MaxIdleConns,
			ConnMaxLifetime: defaultDatabase.ConnMaxLifetime,
		},
		PVFilter: PVFilterConfig{
			StatusCodeInclude: copyIntSlice(defaultStatusCodeInclude),
			ExcludePatterns:   copyStringSlice(defaultExcludePatterns),
		},
	}
}

func loadConfig() (*Config, error) {
	cfg := DefaultConfig()
	cfgPtr := &cfg
	loaded := false

	if ForceEmptyConfigEnabled() {
		loaded = false
	} else if raw, key := getEnvValue(envConfigJSON); raw != "" {
		if err := json.Unmarshal([]byte(raw), cfgPtr); err != nil {
			return nil, fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		loaded = true
	} else {
		bytes, err := os.ReadFile(ConfigFile)
		if err == nil {
			if err := json.Unmarshal(bytes, cfgPtr); err != nil {
				return nil, err
			}
			loaded = true
		} else if !os.IsNotExist(err) {
			return nil, err
		} else if !HasEnvConfigSource() {
			// 配置不存在且未注入环境变量，进入初始化模式
			loaded = false
		}
	}

	if err := applyEnvOverrides(cfgPtr); err != nil {
		return nil, err
	}
	applyDefaults(cfgPtr)

	if !loaded && len(cfgPtr.Websites) == 0 && !NeedsSetup() {
		return nil, fmt.Errorf("未提供网站配置")
	}

	return cfgPtr, nil
}

// HasEnvConfigSource reports if config can be loaded from env vars.
func HasEnvConfigSource() bool {
	return hasEnvValue(envConfigJSON) || hasEnvValue(envWebsites)
}

func applyEnvOverrides(cfg *Config) error {
	if raw, key := getEnvValue(envWebsites); raw != "" {
		websites := []WebsiteConfig{}
		if err := json.Unmarshal([]byte(raw), &websites); err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		cfg.Websites = websites
	}

	if raw, _ := getEnvValue(envLogDestination); raw != "" {
		cfg.System.LogDestination = raw
	}

	if raw, _ := getEnvValue(envTaskInterval); raw != "" {
		cfg.System.TaskInterval = raw
	}

	if raw, key := getEnvValue(envLogRetentionDays); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		if parsed <= 0 {
			return fmt.Errorf("%s 必须大于0", key)
		}
		cfg.System.LogRetentionDays = parsed
	}
	if raw, key := getEnvValue(envLogParseBatchSize); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		if parsed <= 0 {
			return fmt.Errorf("%s 必须大于0", key)
		}
		cfg.System.ParseBatchSize = parsed
	}
	if raw, key := getEnvValue(envIPGeoCacheLimit); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		if parsed <= 0 {
			return fmt.Errorf("%s 必须大于0", key)
		}
		cfg.System.IPGeoCacheLimit = parsed
	}
	if raw, _ := getEnvValue(envIPGeoAPIURL); raw != "" {
		cfg.System.IPGeoAPIURL = strings.TrimSpace(raw)
	}

	if raw, key := getEnvValue(envDemoMode); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		cfg.System.DemoMode = parsed
	}

	if raw, key := getEnvValue(envAccessKeys); raw != "" {
		values, err := parseStringSliceFlexible(raw)
		if err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		cfg.System.AccessKeys = values
	}

	if raw, _ := getEnvValue(envLanguage); raw != "" {
		cfg.System.Language = raw
	}
	if raw, _ := getEnvValue(envWebBasePath); raw != "" {
		cfg.System.WebBasePath = strings.TrimSpace(raw)
	}
	if raw, key := getEnvValue(envMobilePWAEnabled); raw != "" {
		parsed, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		cfg.System.MobilePWAEnabled = parsed
	}

	if raw, _ := getEnvValue(envServerPort); raw != "" {
		if !strings.Contains(raw, ":") {
			raw = ":" + raw
		}
		cfg.Server.Port = raw
	}

	if raw, _ := getEnvValue(envDBDriver); raw != "" {
		cfg.Database.Driver = raw
	}
	if raw, _ := getEnvValue(envDBDSN); raw != "" {
		cfg.Database.DSN = raw
	}
	if raw, key := getEnvValue(envDBMaxOpenConns); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		if parsed < 0 {
			return fmt.Errorf("%s 不能小于0", key)
		}
		cfg.Database.MaxOpenConns = parsed
	}
	if raw, key := getEnvValue(envDBMaxIdleConns); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		if parsed < 0 {
			return fmt.Errorf("%s 不能小于0", key)
		}
		cfg.Database.MaxIdleConns = parsed
	}
	if raw, key := getEnvValue(envDBConnMaxLifetime); raw != "" {
		if _, err := time.ParseDuration(raw); err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		cfg.Database.ConnMaxLifetime = raw
	}

	if raw, key := getEnvValue(envPVStatusCodes); raw != "" {
		values, err := parseIntSlice(raw)
		if err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		cfg.PVFilter.StatusCodeInclude = values
	}

	if raw, key := getEnvValue(envPVExcludePatterns); raw != "" {
		values, err := parseStringSliceJSON(raw)
		if err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		cfg.PVFilter.ExcludePatterns = values
	}

	if raw, key := getEnvValue(envPVExcludeIPs); raw != "" {
		values, err := parseStringSliceFlexible(raw)
		if err != nil {
			return fmt.Errorf("解析 %s 失败: %w", key, err)
		}
		cfg.PVFilter.ExcludeIPs = values
	}

	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.System.LogDestination == "" {
		cfg.System.LogDestination = defaultSystem.LogDestination
	}
	if cfg.System.TaskInterval == "" {
		cfg.System.TaskInterval = defaultSystem.TaskInterval
	}
	if cfg.System.LogRetentionDays <= 0 {
		cfg.System.LogRetentionDays = defaultSystem.LogRetentionDays
	}
	if cfg.System.ParseBatchSize <= 0 {
		cfg.System.ParseBatchSize = defaultSystem.ParseBatchSize
	}
	if cfg.System.IPGeoCacheLimit <= 0 {
		cfg.System.IPGeoCacheLimit = defaultSystem.IPGeoCacheLimit
	}
	if cfg.System.IPGeoAPIURL == "" {
		cfg.System.IPGeoAPIURL = defaultSystem.IPGeoAPIURL
	}
	if cfg.System.Language == "" {
		cfg.System.Language = defaultSystem.Language
	}
	cfg.System.Language = NormalizeLanguage(cfg.System.Language)
	cfg.System.WebBasePath = NormalizeWebBasePath(cfg.System.WebBasePath)
	if cfg.Server.Port == "" {
		cfg.Server.Port = defaultServer.Port
	}
	if cfg.Database.Driver == "" {
		cfg.Database.Driver = defaultDatabase.Driver
	}
	if cfg.Database.MaxOpenConns <= 0 {
		cfg.Database.MaxOpenConns = defaultDatabase.MaxOpenConns
	}
	if cfg.Database.MaxIdleConns <= 0 {
		cfg.Database.MaxIdleConns = defaultDatabase.MaxIdleConns
	}
	if cfg.Database.ConnMaxLifetime == "" {
		cfg.Database.ConnMaxLifetime = defaultDatabase.ConnMaxLifetime
	}
	if len(cfg.PVFilter.StatusCodeInclude) == 0 {
		cfg.PVFilter.StatusCodeInclude = copyIntSlice(defaultStatusCodeInclude)
	}
	if len(cfg.PVFilter.ExcludePatterns) == 0 {
		cfg.PVFilter.ExcludePatterns = copyStringSlice(defaultExcludePatterns)
	}
}

func parseStringSliceJSON(value string) ([]string, error) {
	values := []string{}
	if err := json.Unmarshal([]byte(value), &values); err != nil {
		return nil, err
	}
	return values, nil
}

func parseStringSliceFlexible(value string) ([]string, error) {
	if strings.HasPrefix(strings.TrimSpace(value), "[") {
		return parseStringSliceJSON(value)
	}
	values := []string{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		values = append(values, item)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("值为空")
	}
	return values, nil
}

func parseIntSlice(value string) ([]int, error) {
	if strings.HasPrefix(strings.TrimSpace(value), "[") {
		values := []int{}
		if err := json.Unmarshal([]byte(value), &values); err != nil {
			return nil, err
		}
		return values, nil
	}

	values := []int{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		parsed, err := strconv.Atoi(item)
		if err != nil {
			return nil, err
		}
		values = append(values, parsed)
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("值为空")
	}
	return values, nil
}

func copyStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	copied := make([]string, len(values))
	copy(copied, values)
	return copied
}

func copyIntSlice(values []int) []int {
	if len(values) == 0 {
		return nil
	}
	copied := make([]int, len(values))
	copy(copied, values)
	return copied
}

func hasEnvValue(keys ...string) bool {
	_, key := getEnvValue(keys...)
	return key != ""
}

func getEnvValue(keys ...string) (string, string) {
	for _, key := range keys {
		value := strings.TrimSpace(os.Getenv(key))
		if value != "" {
			return value, key
		}
	}
	return "", ""
}
