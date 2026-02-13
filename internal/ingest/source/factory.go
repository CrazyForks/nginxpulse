package source

import (
	"fmt"
	"strings"

	"github.com/likaia/nginxpulse/internal/config"
)

func NewFromConfig(websiteID string, cfg config.SourceConfig) (LogSource, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Type)) {
	case string(SourceLocal):
		return NewLocalSource(websiteID, cfg.ID, cfg.Path, cfg.Pattern, cfg.Compression), nil
	case string(SourceSFTP):
		keyFile := ""
		password := ""
		if cfg.Auth != nil {
			keyFile = cfg.Auth.KeyFile
			password = cfg.Auth.Password
		}
		return NewSFTPSource(
			websiteID,
			cfg.ID,
			cfg.Host,
			cfg.Port,
			cfg.User,
			keyFile,
			password,
			cfg.Path,
			cfg.Pattern,
			cfg.Compression,
		), nil
	case string(SourceHTTP):
		var index *HTTPIndex
		if cfg.Index != nil {
			index = &HTTPIndex{
				URL:     cfg.Index.URL,
				Method:  cfg.Index.Method,
				Headers: cfg.Index.Headers,
				JSONMap: cfg.Index.JSONMap,
			}
		}
		return NewHTTPSourceWithTimeout(
			websiteID,
			cfg.ID,
			cfg.URL,
			cfg.Headers,
			normalizeRangePolicy(cfg.RangePolicy),
			index,
			cfg.Compression,
			config.GetHTTPSourceTimeout(),
		), nil
	case string(SourceS3):
		return NewS3Source(
			websiteID,
			cfg.ID,
			cfg.Endpoint,
			cfg.Region,
			cfg.Bucket,
			cfg.Prefix,
			cfg.Pattern,
			cfg.AccessKey,
			cfg.SecretKey,
			cfg.Compression,
		)
	case string(SourceAgent):
		return NewAgentSource(websiteID, cfg.ID), nil
	default:
		return nil, fmt.Errorf("unsupported source type: %s", cfg.Type)
	}
}
