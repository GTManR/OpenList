package middlewares

import (
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/abuse"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/gin-gonic/gin"
)

var staticPathPrefixes = []string{
	"/assets/",
	"/images/",
	"/streamer/",
	"/static/",
	"/favicon.ico",
	"/manifest.json",
	"/robots.txt",
	"/ping",
}

// AbuseScanTrack records B2 404/500 responses on non-static routes.
func AbuseScanTrack() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if isStaticAbusePath(c.Request.URL.Path) {
			return
		}
		status := c.Writer.Status()
		if status == 404 || status == 500 {
			abuse.Record(abuse.IPFromGin(c), abuse.BehaviorScan404500)
		}
	}
}

func isStaticAbusePath(path string) bool {
	if conf.URL.Path != "" && conf.URL.Path != "/" {
		path = strings.TrimPrefix(path, conf.URL.Path)
	}
	for _, prefix := range staticPathPrefixes {
		if strings.HasPrefix(path, prefix) || path == strings.TrimSuffix(prefix, "/") {
			return true
		}
	}
	return false
}
