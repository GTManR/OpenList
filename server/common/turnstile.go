package common

import (
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/OpenListTeam/go-cache"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
)

const turnstileSiteVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

var turnstileClient = resty.New().SetTimeout(10 * time.Second)

type turnstileVerifyResponse struct {
	Success bool `json:"success"`
}

func TurnstileRequired() bool {
	return setting.GetStr(conf.TurnstileSecretKey) != ""
}

func VerifyTurnstileToken(token, remoteIP string) bool {
	secret := setting.GetStr(conf.TurnstileSecretKey)
	if secret == "" || token == "" {
		return false
	}
	payload := map[string]string{
		"secret":   secret,
		"response": token,
	}
	if remoteIP != "" {
		payload["remoteip"] = remoteIP
	}
	var result turnstileVerifyResponse
	resp, err := turnstileClient.R().
		SetFormData(payload).
		SetResult(&result).
		Post(turnstileSiteVerifyURL)
	if err != nil || !resp.IsSuccess() {
		return false
	}
	return result.Success
}

// CheckMetaAccess decides whether the user may access reqPath, enforcing the
// meta (folder) password and, when Turnstile is enabled, requiring a captcha
// solve the first time an IP unlocks a password-protected folder.
//
// Behaviour when Turnstile is configured and a password gate applies:
//   - Without a prior verified unlock for this IP + meta path + password, a
//     valid Turnstile token is mandatory (cannot unlock by password alone).
//   - After a successful captcha + password unlock, subsequent requests with
//     the same password skip the captcha for MetaPassVerifiedTTL so browsing
//     child folders stays usable.
//
// On denial it writes the HTTP error response and returns false.
func CheckMetaAccess(c *gin.Context, user *model.User, meta *model.Meta, reqPath, password, turnstileToken string) bool {
	if !TurnstileRequired() {
		if !CanAccess(user, meta, reqPath, password) {
			ErrorStrResp(c, "password is incorrect or you have no permission", 403)
			return false
		}
		return true
	}
	gated := metaPasswordRequired(user, meta, reqPath)
	ip := c.ClientIP()
	if gated {
		verifiedKey := ip + "|" + meta.Path
		stored, hasVerified := model.MetaPassVerified.Get(verifiedKey)
		alreadyUnlocked := hasVerified && stored == password
		if !alreadyUnlocked {
			if !VerifyTurnstileToken(turnstileToken, ip) {
				count, _ := model.MetaPassCache.Get(ip)
				model.MetaPassCache.Set(ip, count+1)
				model.MetaPassCache.Expire(ip, model.DefaultLockDuration)
				ErrorStrResp(c, "请先完成验证码验证", 403)
				return false
			}
		}
		if !CanAccess(user, meta, reqPath, password) {
			count, _ := model.MetaPassCache.Get(ip)
			model.MetaPassCache.Set(ip, count+1)
			model.MetaPassCache.Expire(ip, model.DefaultLockDuration)
			model.MetaPassVerified.Del(verifiedKey)
			ErrorStrResp(c, "password is incorrect or you have no permission", 403)
			return false
		}
		model.MetaPassCache.Del(ip)
		model.MetaPassVerified.Set(verifiedKey, password, cache.WithEx[string](model.MetaPassVerifiedTTL))
		return true
	}
	if !CanAccess(user, meta, reqPath, password) {
		ErrorStrResp(c, "password is incorrect or you have no permission", 403)
		return false
	}
	return true
}
