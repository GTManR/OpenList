// Package cloudflare provides a minimal client for the Cloudflare Account Lists API.
// Users must create a WAF custom rule on their zone, e.g.:
//
//	(ip.src in $openlist_ip_blocklist) → Block
package cloudflare

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/setting"
	"github.com/go-resty/resty/v2"
	log "github.com/sirupsen/logrus"
)

const defaultListsAPIBase = "https://api.cloudflare.com/client/v4"

var listsAPIBase = defaultListsAPIBase

var (
	clientOnce sync.Once
	apiClient  *resty.Client
)

func client() *resty.Client {
	clientOnce.Do(func() {
		apiClient = resty.New().
			SetTimeout(15 * time.Second).
			SetHeader("Content-Type", "application/json")
	})
	return apiClient
}

// Enabled reports whether Cloudflare IP list auto-ban is configured and turned on.
func Enabled() bool {
	if v := strings.TrimSpace(os.Getenv("CF_ABUSE_ENABLED")); v != "" {
		return v == "true" || v == "1"
	}
	if !setting.GetBool(conf.CFAbuseEnabled) {
		return false
	}
	return AccountID() != "" && ListID() != "" && APIToken() != ""
}

func AccountID() string {
	if v := strings.TrimSpace(os.Getenv("CF_ACCOUNT_ID")); v != "" {
		return v
	}
	return strings.TrimSpace(setting.GetStr(conf.CFAccountID))
}

func ZoneID() string {
	if v := strings.TrimSpace(os.Getenv("CF_ZONE_ID")); v != "" {
		return v
	}
	return strings.TrimSpace(setting.GetStr(conf.CFZoneID))
}

func ListID() string {
	if v := strings.TrimSpace(os.Getenv("CF_LIST_ID")); v != "" {
		return v
	}
	return strings.TrimSpace(setting.GetStr(conf.CFListID))
}

func APIToken() string {
	if v := strings.TrimSpace(os.Getenv("CF_API_TOKEN")); v != "" {
		return v
	}
	return strings.TrimSpace(setting.GetStr(conf.CFAPIToken))
}

type listItem struct {
	IP      string `json:"ip"`
	Comment string `json:"comment,omitempty"`
}

type apiResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

// AddIPToList adds an IP to the configured account-level IP list.
// Duplicate or already-existing entries are treated as success.
func AddIPToList(ip, comment string) error {
	if !Enabled() {
		return nil
	}
	accountID := AccountID()
	listID := ListID()
	token := APIToken()
	if accountID == "" || listID == "" || token == "" {
		return fmt.Errorf("cloudflare lists api is not fully configured")
	}

	url := fmt.Sprintf("%s/accounts/%s/rules/lists/%s/items", listsAPIBase, accountID, listID)
	var result apiResponse
	resp, err := client().R().
		SetAuthToken(token).
		SetBody([]listItem{{IP: ip, Comment: comment}}).
		SetResult(&result).
		Post(url)
	if err != nil {
		return err
	}
	if resp.IsSuccess() && result.Success {
		log.Infof("[abuse] added IP %s to Cloudflare list %s: %s", ip, listID, comment)
		return nil
	}
	for _, e := range result.Errors {
		msg := strings.ToLower(e.Message)
		if strings.Contains(msg, "already") || strings.Contains(msg, "duplicate") || strings.Contains(msg, "exists") {
			log.Debugf("[abuse] IP %s already in Cloudflare list %s", ip, listID)
			return nil
		}
	}
	if resp.StatusCode() == 409 {
		return nil
	}
	if len(result.Errors) > 0 {
		return fmt.Errorf("cloudflare lists api error: %s", result.Errors[0].Message)
	}
	return fmt.Errorf("cloudflare lists api request failed with status %d", resp.StatusCode())
}

// ResetClientForTest resets the lazy HTTP client. For use in tests only.
func ResetClientForTest() {
	clientOnce = sync.Once{}
	apiClient = nil
}

// SetListsAPIBaseForTest overrides the Lists API base URL. For use in tests only.
func SetListsAPIBaseForTest(base string) {
	listsAPIBase = base
}
