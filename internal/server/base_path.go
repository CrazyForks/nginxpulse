package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/likaia/nginxpulse/internal/config"
)

type basePathRewriteContextKey struct{}

func basePathMiddleware(router *gin.Engine) gin.HandlerFunc {
	prefix := config.WebBasePathPrefix()
	if prefix == "" {
		return func(c *gin.Context) {
			c.Next()
		}
	}
	prefixWithSlash := prefix + "/"
	return func(c *gin.Context) {
		if rewritten, ok := c.Request.Context().Value(basePathRewriteContextKey{}).(bool); ok && rewritten {
			c.Next()
			return
		}

		path := c.Request.URL.Path
		if path == prefix {
			c.Redirect(http.StatusFound, prefixWithSlash)
			c.Abort()
			return
		}
		if strings.HasPrefix(path, prefixWithSlash) {
			stripped := strings.TrimPrefix(path, prefix)
			if stripped == "" {
				stripped = "/"
			}
			c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), basePathRewriteContextKey{}, true))
			c.Request.URL.Path = stripped
			if rawPath := c.Request.URL.RawPath; rawPath != "" {
				trimmedRawPath := strings.TrimPrefix(rawPath, prefix)
				if trimmedRawPath == "" {
					trimmedRawPath = "/"
				}
				c.Request.URL.RawPath = trimmedRawPath
			}
			c.Request.RequestURI = stripped
			if rawQuery := c.Request.URL.RawQuery; rawQuery != "" {
				c.Request.RequestURI += "?" + rawQuery
			}
			router.HandleContext(c)
			c.Abort()
			return
		}
		if isSharedAssetPath(path) {
			c.Next()
			return
		}
		c.Status(http.StatusNotFound)
		c.Abort()
	}
}

func isSharedAssetPath(path string) bool {
	switch path {
	case "/app-config.js", "/m/app-config.js", "/favicon.svg", "/brand-mark.svg", "/m/favicon.svg", "/m/brand-mark.svg":
		return true
	}
	return strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "/m/assets/")
}
