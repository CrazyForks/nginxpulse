package config

import (
	"crypto/md5"
	"encoding/hex"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

var (
	globalConfig *Config
	websiteIDMap sync.Map
)

const (
	DataDir            = "./var/nginxpulse_data"
	ConfigFile         = "./configs/nginxpulse_config.json"
	DefaultIPGeoAPIURL = "http://ip-api.com/batch"
)

type Config struct {
	System   SystemConfig    `json:"system"`
	Server   ServerConfig    `json:"server"`
	Database DatabaseConfig  `json:"database"`
	Websites []WebsiteConfig `json:"websites"`
	PVFilter PVFilterConfig  `json:"pvFilter"`
}

type WebsiteConfig struct {
	Name       string           `json:"name"`
	LogPath    string           `json:"logPath"`
	Domains    []string         `json:"domains,omitempty"`
	LogType    string           `json:"logType,omitempty"`
	LogFormat  string           `json:"logFormat,omitempty"`
	LogRegex   string           `json:"logRegex,omitempty"`
	TimeLayout string           `json:"timeLayout,omitempty"`
	Sources    []SourceConfig   `json:"sources,omitempty"`
	Whitelist  *WhitelistConfig `json:"whitelist,omitempty"`
}

type SourceConfig struct {
	ID           string            `json:"id"`
	Type         string            `json:"type"`
	Mode         string            `json:"mode,omitempty"`
	PollInterval string            `json:"pollInterval,omitempty"`
	Path         string            `json:"path,omitempty"`
	Pattern      string            `json:"pattern,omitempty"`
	Compression  string            `json:"compression,omitempty"`
	Parse        *ParseConfig      `json:"parse,omitempty"`
	Host         string            `json:"host,omitempty"`
	Port         int               `json:"port,omitempty"`
	User         string            `json:"user,omitempty"`
	Auth         *SourceAuth       `json:"auth,omitempty"`
	URL          string            `json:"url,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	RangePolicy  string            `json:"rangePolicy,omitempty"`
	Index        *HTTPIndexConfig  `json:"index,omitempty"`
	Endpoint     string            `json:"endpoint,omitempty"`
	Region       string            `json:"region,omitempty"`
	Bucket       string            `json:"bucket,omitempty"`
	Prefix       string            `json:"prefix,omitempty"`
	AccessKey    string            `json:"accessKey,omitempty"`
	SecretKey    string            `json:"secretKey,omitempty"`
}

type SourceAuth struct {
	KeyFile  string `json:"keyFile,omitempty"`
	Password string `json:"password,omitempty"`
}

type HTTPIndexConfig struct {
	URL     string            `json:"url"`
	Method  string            `json:"method,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	JSONMap map[string]string `json:"jsonMap,omitempty"`
}

type ParseConfig struct {
	LogType    string `json:"logType,omitempty"`
	LogFormat  string `json:"logFormat,omitempty"`
	LogRegex   string `json:"logRegex,omitempty"`
	TimeLayout string `json:"timeLayout,omitempty"`
}

type WhitelistConfig struct {
	Enabled     bool     `json:"enabled"`
	IPs         []string `json:"ips,omitempty"`
	Cities      []string `json:"cities,omitempty"`
	NonMainland bool     `json:"nonMainland"`
}

type SystemConfig struct {
	LogDestination   string   `json:"logDestination"`
	TaskInterval     string   `json:"taskInterval"` // "5m" "25s"
	LogRetentionDays int      `json:"logRetentionDays"`
	ParseBatchSize   int      `json:"parseBatchSize"`
	IPGeoCacheLimit  int      `json:"ipGeoCacheLimit"`
	IPGeoAPIURL      string   `json:"ipGeoApiUrl"`
	DemoMode         bool     `json:"demoMode"`
	AccessKeys       []string `json:"accessKeys"`
	Language         string   `json:"language"`
	WebBasePath      string   `json:"webBasePath,omitempty"`
	MobilePWAEnabled bool     `json:"mobilePwaEnabled"`
}

type ServerConfig struct {
	Port string `json:"Port"`
}

type DatabaseConfig struct {
	Driver          string `json:"driver"`
	DSN             string `json:"dsn"`
	MaxOpenConns    int    `json:"maxOpenConns"`
	MaxIdleConns    int    `json:"maxIdleConns"`
	ConnMaxLifetime string `json:"connMaxLifetime"`
}

type PVFilterConfig struct {
	StatusCodeInclude []int    `json:"statusCodeInclude"`
	ExcludePatterns   []string `json:"excludePatterns"`
	ExcludeIPs        []string `json:"excludeIPs"`
}

// ReadRawConfig 读取配置（支持环境变量覆盖与默认值）但不初始化全局变量
func ReadRawConfig() (*Config, error) {
	return loadConfig()
}

// ReadConfig 读取配置文件并返回配置，同时初始化 ID 映射
func ReadConfig() *Config {
	if globalConfig != nil {
		return globalConfig
	}

	cfg, err := loadConfig()
	if err != nil {
		panic(err)
	}

	// 初始化 ID 映射
	for _, website := range cfg.Websites {
		id := generateID(website.Name)
		websiteIDMap.Store(id, website)
	}

	globalConfig = cfg
	return globalConfig
}

// GetWebsiteByID 根据 ID 获取对应的 WebsiteConfig
func GetWebsiteByID(id string) (WebsiteConfig, bool) {
	value, ok := websiteIDMap.Load(id)
	if ok {
		return value.(WebsiteConfig), true
	}
	return WebsiteConfig{}, false
}

// GetAllWebsiteIDs 获取所有网站的 ID 列表
func GetAllWebsiteIDs() []string {
	var ids []string
	websiteIDMap.Range(func(key, value interface{}) bool {
		ids = append(ids, key.(string))
		return true
	})
	return ids
}

func GetIPGeoAPIURL() string {
	cfg := ReadConfig()
	value := strings.TrimSpace(cfg.System.IPGeoAPIURL)
	if value == "" {
		return DefaultIPGeoAPIURL
	}
	return value
}

// ParseInterval 解析间隔配置字符串，支持分钟(m)和秒(s)单位
func ParseInterval(intervalStr string, defaultInterval time.Duration) time.Duration {
	if intervalStr == "" {
		return defaultInterval
	}

	// 尝试解析配置的时间间隔
	duration, err := time.ParseDuration(intervalStr)
	if err != nil {
		logrus.WithField("interval", intervalStr).Info(
			"无效的时间间隔配置，使用默认值")
		return defaultInterval
	}

	minInterval := 5 * time.Second
	if duration < minInterval {
		logrus.WithField("interval", intervalStr).Info(
			"配置的时间间隔过短，已调整为最小值5秒")
		return minInterval
	}

	return duration
}

// generateID 根据输入字符串生成唯一 ID
func generateID(input string) string {
	hash := md5.Sum([]byte(input))
	return hex.EncodeToString(hash[:2])
}
