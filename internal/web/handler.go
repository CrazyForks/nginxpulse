package web

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/likaia/nginxpulse/internal/analytics"
	"github.com/likaia/nginxpulse/internal/config"
	"github.com/likaia/nginxpulse/internal/ingest"
	"github.com/likaia/nginxpulse/internal/version"
	"github.com/sirupsen/logrus"
)

// 初始化Web路由
func SetupRoutes(
	router *gin.Engine,
	statsFactory *analytics.StatsFactory,
	logParser *ingest.LogParser) {

	// 获取所有网站列表
	router.GET("/api/websites", func(c *gin.Context) {
		websiteIDs := config.GetAllWebsiteIDs()

		websites := make([]map[string]string, 0, len(websiteIDs))
		for _, id := range websiteIDs {
			website, ok := config.GetWebsiteByID(id)
			if !ok {
				continue
			}

			websites = append(websites, map[string]string{
				"id":   id,
				"name": website.Name,
			})
		}

		c.JSON(http.StatusOK, gin.H{
			"websites": websites,
		})
	})

	router.GET("/api/status", func(c *gin.Context) {
		cfg := config.ReadConfig()
		c.JSON(http.StatusOK, gin.H{
			"log_parsing":          ingest.IsIPParsing(),
			"log_parsing_progress": ingest.GetIPParsingProgress(),
			"demo_mode":            cfg.System.DemoMode,
			"version":              version.Version,
			"git_commit":           version.GitCommit,
		})
	})

	router.GET("/api/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version":    version.Version,
			"git_commit": version.GitCommit,
		})
	})

	router.POST("/api/logs/reparse", func(c *gin.Context) {
		type reparseRequest struct {
			ID string `json:"id"`
		}

		var req reparseRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "请求参数错误",
			})
			return
		}

		websiteID := strings.TrimSpace(req.ID)
		if websiteID == "" {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "缺少站点ID",
			})
			return
		}

		if _, ok := config.GetWebsiteByID(websiteID); !ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "站点不存在",
			})
			return
		}

		if err := logParser.TriggerReparse(websiteID); err != nil {
			if errors.Is(err, ingest.ErrParsingInProgress) {
				c.JSON(http.StatusConflict, gin.H{
					"error": err.Error(),
				})
				return
			}
			logrus.WithError(err).Error("触发重新解析失败")
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("重新解析失败: %v", err),
			})
			return
		}

		statsFactory.ClearCache()
		c.JSON(http.StatusOK, gin.H{
			"success": true,
		})
	})

	// 查询接口
	router.GET("/api/stats/:type", func(c *gin.Context) {
		statsType := c.Param("type")
		params := make(map[string]string)
		for key, values := range c.Request.URL.Query() {
			if len(values) > 0 {
				params[key] = values[0]
			}
		}

		query, err := statsFactory.BuildQueryFromRequest(statsType, params)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		// 执行查询
		result, err := statsFactory.QueryStats(statsType, query)
		if err != nil {
			logrus.WithError(err).Errorf("查询统计数据[%s]失败", statsType)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("查询失败: %v", err),
			})
			return
		}

		c.JSON(http.StatusOK, result)
	})

}
