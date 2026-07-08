package common

import (
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
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
// meta (folder) password and, when Turnstile is enabled, throttling brute-force
// attempts against password-protected folders.
//
// Behaviour when Turnstile is configured and a password gate applies:
//   - Under the per-IP failure threshold, the password is checked directly, so a
//     correct password (including a cached one used for normal browsing) grants
//     access without any captcha.
//   - Once the threshold is reached, a valid Turnstile token is required *before*
//     the password is evaluated, so each further guess costs a fresh challenge
//     solve and the correct password can't be discovered by simply enumerating.
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
		count, _ := model.MetaPassCache.Get(ip)
		if count >= model.DefaultMaxAuthRetries {
			// Require a fresh Turnstile solve before even checking the password,
			// so an attacker can't bypass the gate by hitting the correct value.
			if !VerifyTurnstileToken(turnstileToken, ip) {
				model.MetaPassCache.Expire(ip, model.DefaultLockDuration)
				ErrorStrResp(c, model.TooManyPasswordAttempts, 403)
				return false
			}
		}
		if !CanAccess(user, meta, reqPath, password) {
			model.MetaPassCache.Set(ip, count+1)
			model.MetaPassCache.Expire(ip, model.DefaultLockDuration)
			ErrorStrResp(c, "password is incorrect or you have no permission", 403)
			return false
		}
		model.MetaPassCache.Del(ip)
		return true
	}
	if !CanAccess(user, meta, reqPath, password) {
		ErrorStrResp(c, "password is incorrect or you have no permission", 403)
		return false
	}
	return true
}
