package middlewares

import (
	"net/http"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/abuse"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/OpenList/v4/pkg/sign"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

// DownOpts configures the Down sign-verification middleware.
type DownOpts struct {
	// TrackDownload enables B1 high-frequency download tracking for successful GET 2xx responses.
	TrackDownload bool
}

func PathParse(c *gin.Context) {
	rawPath := parsePath(c.Param("path"))
	common.GinAppendValues(c, conf.PathKey, rawPath)
	c.Next()
}

func Down(verifyFunc func(string, string) error) func(c *gin.Context) {
	return DownWithOpts(verifyFunc, DownOpts{})
}

func DownWithOpts(verifyFunc func(string, string) error, opts DownOpts) func(c *gin.Context) {
	return func(c *gin.Context) {
		rawPath := c.Request.Context().Value(conf.PathKey).(string)
		ip := abuse.IPFromGin(c)
		meta, err := op.GetNearestMeta(rawPath)
		if err != nil && !errors.Is(errors.Cause(err), errs.MetaNotFound) {
			common.ErrorPage(c, err, 500, true)
			return
		}
		common.GinAppendValues(c, conf.MetaKey, meta)
		if needSign(meta, rawPath) {
			s := c.Query("sign")
			if s == "" {
				abuse.Record(ip, abuse.BehaviorMissingSign)
				common.ErrorPage(c, errors.New("sign is required"), 401)
				c.Abort()
				return
			}
			err = verifyFunc(rawPath, strings.TrimSuffix(s, "/"))
			if err != nil {
				if errors.Is(err, sign.ErrSignExpired) {
					abuse.LogSignExpired(ip, rawPath)
				} else {
					abuse.Record(ip, abuse.BehaviorInvalidSign)
				}
				common.ErrorPage(c, err, 401)
				c.Abort()
				return
			}
		}
		c.Next()
		if opts.TrackDownload && c.Request.Method == http.MethodGet {
			status := c.Writer.Status()
			// Category C: normal Range 206 for video playback is not counted.
			if status >= 200 && status < 300 && status != http.StatusPartialContent {
				abuse.Record(ip, abuse.BehaviorHighFreqDownload)
			}
		}
	}
}

// TODO: implement
// path maybe contains # ? etc.
func parsePath(path string) string {
	return utils.FixAndCleanPath(path)
}

func needSign(meta *model.Meta, path string) bool {
	if setting.GetBool(conf.SignAll) {
		return true
	}
	if common.IsStorageSignEnabled(path) {
		return true
	}
	if meta == nil || meta.Password == "" {
		return false
	}
	if !meta.PSub && path != meta.Path {
		return false
	}
	return true
}
