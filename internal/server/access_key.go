package server

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/likaia/nginxpulse/internal/config"
)

const accessKeyHeader = "X-NginxPulse-Key"

func accessKeyMiddleware() gin.HandlerFunc {
	cfg := config.ReadConfig()
	keys := make(map[string]struct{})
	for _, key := range cfg.System.AccessKeys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		keys[key] = struct{}{}
	}

	if len(keys) == 0 {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	return func(c *gin.Context) {
		if !strings.HasPrefix(c.Request.URL.Path, "/api/") {
			c.Next()
			return
		}
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}

		value := strings.TrimSpace(c.GetHeader(accessKeyHeader))
		if value == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "需要访问密钥",
			})
			return
		}
		if _, ok := keys[value]; !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "访问密钥无效",
			})
			return
		}
		c.Next()
	}
}
