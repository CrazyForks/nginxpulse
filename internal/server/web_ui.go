package server

import (
	"io"
	"io/fs"
	"net/http"
	"path"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/likaia/nginxpulse/internal/webui"
	"github.com/sirupsen/logrus"
)

func attachWebUI(router *gin.Engine) {
	assets, ok := webui.AssetFS()
	if !ok {
		logrus.Info("未检测到内置前端资源，跳过静态页面服务")
		return
	}

	fileServer := http.FileServer(http.FS(assets))

	serveStatic := func(c *gin.Context) {
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Status(http.StatusNotFound)
			return
		}
		if strings.HasPrefix(c.Request.URL.Path, "/api/") || c.Request.URL.Path == "/api" {
			c.Status(http.StatusNotFound)
			return
		}

		cleanPath := path.Clean("/" + c.Request.URL.Path)
		cleanPath = strings.TrimPrefix(cleanPath, "/")
		if cleanPath == "" || cleanPath == "index.html" {
			serveIndex(assets, c)
			return
		}

		if _, err := fs.Stat(assets, cleanPath); err == nil {
			c.Request.URL.Path = "/" + cleanPath
			fileServer.ServeHTTP(c.Writer, c.Request)
			return
		}

		baseName := path.Base(cleanPath)
		isAsset := strings.HasPrefix(cleanPath, "assets/") || strings.Contains(baseName, ".")
		if isAsset {
			c.Status(http.StatusNotFound)
			return
		}

		serveIndex(assets, c)
	}

	router.NoRoute(serveStatic)
}

func serveIndex(assets fs.FS, c *gin.Context) {
	indexPath := "index.html"
	if _, err := fs.Stat(assets, indexPath); err != nil {
		c.Status(http.StatusNotFound)
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if c.Request.Method == http.MethodHead {
		c.Status(http.StatusOK)
		return
	}
	if file, err := assets.Open(indexPath); err == nil {
		defer file.Close()
		_, _ = io.Copy(c.Writer, file)
	} else {
		c.Status(http.StatusNotFound)
	}
}
