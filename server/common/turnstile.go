package common

import (
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
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
