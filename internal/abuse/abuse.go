// Package abuse tracks abusive client behavior and auto-bans IPs via Cloudflare Lists API.
//
// Default thresholds (conservative):
//   - A1 invalid sign (/d/, /p/, /ad/, /ap/, /ae/): 10 in 5 min → permanent ban
//   - A2 missing sign when required: 10 in 5 min → permanent ban
//   - A4 login brute force (HTTP): immediate ban at 5 failures (DefaultMaxAuthRetries)
//   - A5 Turnstile verify fail: 10 in 5 min → permanent ban
//   - A6 wrong share password (/sd/, /sad/, share API): 20 in 5 min → permanent ban
//   - B1 high-frequency downloads (/d/, /p/, /ad/, /ap/ GET 2xx): 30 in 1 min → permanent ban
//   - B2 404/500 scanning (non-static routes): 50 in 5 min → permanent ban
//   - B3 WebDAV/FTP/SFTP auth fail at lockout: immediate ban at 5 failures
//   - B4 guest-disabled 401: 20 in 5 min → permanent ban
//
// Category C (sign expired, normal Range 206) is never counted toward bans.
package abuse

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/cloudflare"
	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/go-cache"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// Behavior identifies an abuse category tracked for auto-ban.
type Behavior string

const (
	BehaviorInvalidSign      Behavior = "invalid_sign"       // A1, A3
	BehaviorMissingSign      Behavior = "missing_sign"       // A2
	BehaviorLoginBruteForce  Behavior = "login_brute_force"  // A4
	BehaviorTurnstileFail    Behavior = "turnstile_fail"     // A5
	BehaviorWrongSharePwd    Behavior = "wrong_share_pwd"    // A6
	BehaviorHighFreqDownload Behavior = "high_freq_download" // B1, permanent
	BehaviorScan404500       Behavior = "scan_404_500"       // B2
	BehaviorProtocolAuthFail Behavior = "protocol_auth_fail" // B3
	BehaviorGuestDisabled    Behavior = "guest_disabled"     // B4
)

const cfSubmitDedupeTTL = 24 * time.Hour

type threshold struct {
	count  int
	window time.Duration
}

var (
	counterCache = cache.NewMemCache[eventWindow](cache.WithShards[eventWindow](32))
	cfDedupe     = cache.NewMemCache[struct{}](cache.WithShards[struct{}](8))
	banMu        sync.Mutex
)

type eventWindow struct {
	timestamps []int64
}

// IPFromRequest returns the client IP using Cloudflare-aware header resolution.
func IPFromRequest(r *http.Request) string {
	return utils.ClientIP(r)
}

// IPFromGin returns the client IP from a Gin context.
func IPFromGin(c *gin.Context) string {
	return IPFromRequest(c.Request)
}

// IPFromAddr normalizes a remote address string (host:port or IP).
func IPFromAddr(addr string) string {
	return utils.ClientIPFromAddr(addr)
}

func thresholdFor(b Behavior) threshold {
	switch b {
	case BehaviorInvalidSign:
		return threshold{setting.GetInt(conf.AbuseInvalidSignThreshold, 10), time.Duration(setting.GetInt(conf.AbuseInvalidSignWindowSec, 300)) * time.Second}
	case BehaviorMissingSign:
		return threshold{setting.GetInt(conf.AbuseMissingSignThreshold, 10), time.Duration(setting.GetInt(conf.AbuseMissingSignWindowSec, 300)) * time.Second}
	case BehaviorTurnstileFail:
		return threshold{setting.GetInt(conf.AbuseTurnstileFailThreshold, 10), time.Duration(setting.GetInt(conf.AbuseTurnstileFailWindowSec, 300)) * time.Second}
	case BehaviorWrongSharePwd:
		return threshold{setting.GetInt(conf.AbuseWrongSharePwdThreshold, 20), time.Duration(setting.GetInt(conf.AbuseWrongSharePwdWindowSec, 300)) * time.Second}
	case BehaviorHighFreqDownload:
		return threshold{setting.GetInt(conf.AbuseHighFreqDownloadThreshold, 30), time.Duration(setting.GetInt(conf.AbuseHighFreqDownloadWindowSec, 60)) * time.Second}
	case BehaviorScan404500:
		return threshold{setting.GetInt(conf.AbuseScanThreshold, 50), time.Duration(setting.GetInt(conf.AbuseScanWindowSec, 300)) * time.Second}
	case BehaviorGuestDisabled:
		return threshold{setting.GetInt(conf.AbuseGuestDisabledThreshold, 20), time.Duration(setting.GetInt(conf.AbuseGuestDisabledWindowSec, 300)) * time.Second}
	default:
		return threshold{count: 1, window: time.Minute}
	}
}

func shouldSkipIP(ip string) bool {
	return ip == "" || utils.IsLocalIPAddr(ip)
}

// Record increments the sliding-window counter for ip+behavior and bans when the threshold is reached.
// Returns true when a ban was triggered.
func Record(ip string, behavior Behavior) bool {
	if shouldSkipIP(ip) {
		return false
	}
	th := thresholdFor(behavior)
	if th.count <= 0 || th.window <= 0 {
		return false
	}
	count := increment(ip, behavior, th.window)
	if count < th.count {
		return false
	}
	permanent := behavior == BehaviorHighFreqDownload || isCategoryA(behavior)
	reason := fmt.Sprintf("%s: %d events in %s", behavior, count, th.window)
	if cloudflare.Enabled() {
		BanIP(ip, reason, permanent)
	} else {
		log.Warnf("[abuse] threshold reached for %s (%s) but CF auto-ban is disabled", ip, reason)
	}
	return true
}

func isCategoryA(b Behavior) bool {
	switch b {
	case BehaviorInvalidSign, BehaviorMissingSign, BehaviorLoginBruteForce,
		BehaviorTurnstileFail, BehaviorWrongSharePwd, BehaviorProtocolAuthFail:
		return true
	default:
		return false
	}
}

func increment(ip string, behavior Behavior, window time.Duration) int {
	now := time.Now().Unix()
	cutoff := now - int64(window.Seconds())
	key := string(behavior) + ":" + ip

	existing, _ := counterCache.Get(key)
	valid := existing.timestamps[:0]
	for _, ts := range existing.timestamps {
		if ts > cutoff {
			valid = append(valid, ts)
		}
	}
	valid = append(valid, now)
	existing.timestamps = valid
	counterCache.Set(key, existing, cache.WithEx[eventWindow](window))
	return len(valid)
}

// OnAuthLockout bans an IP that has reached the shared LoginCache lockout threshold (A4/B3).
func OnAuthLockout(ip, source string) {
	if shouldSkipIP(ip) {
		return
	}
	reason := fmt.Sprintf("%s: %s", BehaviorLoginBruteForce, source)
	if cloudflare.Enabled() {
		BanIP(ip, reason, true)
	} else {
		log.Warnf("[abuse] auth lockout for %s (%s) but CF auto-ban is disabled", ip, reason)
	}
}

// OnProtocolAuthLockout bans an IP locked out from WebDAV/FTP/SFTP (B3).
func OnProtocolAuthLockout(ip, protocol string) {
	if shouldSkipIP(ip) {
		return
	}
	reason := fmt.Sprintf("%s: %s", BehaviorProtocolAuthFail, protocol)
	if cloudflare.Enabled() {
		BanIP(ip, reason, true)
	} else {
		log.Warnf("[abuse] protocol auth lockout for %s (%s) but CF auto-ban is disabled", ip, reason)
	}
}

// BanIP submits ip to the Cloudflare IP list asynchronously.
// permanent is recorded in the comment; there is no auto-unban on the OpenList side.
func BanIP(ip, reason string, permanent bool) {
	if shouldSkipIP(ip) || !cloudflare.Enabled() {
		return
	}
	if _, submitted := cfDedupe.Get(ip); submitted {
		return
	}
	cfDedupe.Set(ip, struct{}{}, cache.WithEx[struct{}](cfSubmitDedupeTTL))

	comment := reason
	if permanent {
		comment = "[permanent] " + reason
	}

	banMu.Lock()
	defer banMu.Unlock()

	go func() {
		if err := cloudflare.AddIPToList(ip, comment); err != nil {
			log.Errorf("[abuse] failed to ban IP %s (%s): %+v", ip, reason, err)
			cfDedupe.Del(ip)
			return
		}
		log.Warnf("[abuse] banned IP %s: %s", ip, reason)
	}()
}

// LogSignExpired logs a sign-expired event without counting toward bans (category C).
func LogSignExpired(ip, path string) {
	log.WithFields(log.Fields{"ip": ip, "path": path}).Warn("[abuse] sign expired (not counted)")
}
