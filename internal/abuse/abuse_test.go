package abuse

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/cloudflare"
	"github.com/stretchr/testify/require"
)

func resetAbuseState(t *testing.T) {
	t.Helper()
	counterCache.Clear()
	cfDedupe.Clear()
}

func setupCFMock(t *testing.T, onPost func(w http.ResponseWriter, r *http.Request)) (done <-chan struct{}, posts *int) {
	t.Helper()
	setupCFEnv(t)

	var count int
	ch := make(chan struct{}, 1)
	var once sync.Once

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if onPost != nil {
			onPost(w, r)
		} else {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"success":true}`))
		}
		count++
		once.Do(func() { ch <- struct{}{} })
	}))
	t.Cleanup(func() {
		srv.Close()
		cloudflare.ResetClientForTest()
		cloudflare.SetListsAPIBaseForTest(defaultListsAPIBase)
	})

	cloudflare.ResetClientForTest()
	cloudflare.SetListsAPIBaseForTest(srv.URL)
	return ch, &count
}

func setupCFEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CF_ABUSE_ENABLED", "true")
	t.Setenv("CF_ACCOUNT_ID", "test-account")
	t.Setenv("CF_LIST_ID", "test-list")
	t.Setenv("CF_API_TOKEN", "test-token")
}

const defaultListsAPIBase = "https://api.cloudflare.com/client/v4"

func waitForPOST(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for Cloudflare list POST")
	}
}

func TestIncrement_separateBehaviorCounters(t *testing.T) {
	resetAbuseState(t)
	ip := "203.0.113.10"
	window := 5 * time.Minute

	for i := 0; i < 5; i++ {
		require.Equal(t, i+1, increment(ip, BehaviorInvalidSign, window))
		require.Equal(t, i+1, increment(ip, BehaviorMissingSign, window))
	}
}

func TestRecord_thresholdTriggersBan(t *testing.T) {
	resetAbuseState(t)
	done, posts := setupCFMock(t, nil)

	ip := "203.0.113.20"
	require.True(t, Record(ip, BehaviorLoginBruteForce))

	waitForPOST(t, done)
	require.Equal(t, 1, *posts)
}

func TestRecord_skipsLocalIP(t *testing.T) {
	resetAbuseState(t)
	done, posts := setupCFMock(t, nil)

	for i := 0; i < 20; i++ {
		require.False(t, Record("127.0.0.1", BehaviorLoginBruteForce))
		require.False(t, Record("10.0.0.1", BehaviorLoginBruteForce))
	}

	select {
	case <-done:
		t.Fatal("local IP should not trigger Cloudflare POST")
	case <-time.After(100 * time.Millisecond):
	}
	require.Equal(t, 0, *posts)
}

func TestBanIP_dedupeSameIP(t *testing.T) {
	resetAbuseState(t)

	var postCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		postCount++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(func() {
		srv.Close()
		cloudflare.ResetClientForTest()
		cloudflare.SetListsAPIBaseForTest(defaultListsAPIBase)
	})
	setupCFEnv(t)
	cloudflare.ResetClientForTest()
	cloudflare.SetListsAPIBaseForTest(srv.URL)

	ip := "203.0.113.30"
	BanIP(ip, "first ban", true)
	BanIP(ip, "second ban", true)

	time.Sleep(200 * time.Millisecond)
	require.Equal(t, 1, postCount)
}

func TestLogSignExpired_doesNotIncrementCounter(t *testing.T) {
	resetAbuseState(t)
	ip := "203.0.113.40"
	window := 5 * time.Minute

	for i := 0; i < 15; i++ {
		LogSignExpired(ip, "/file.txt")
	}
	require.Equal(t, 1, increment(ip, BehaviorInvalidSign, window))
}

func TestBanIP_postsCorrectPayload(t *testing.T) {
	resetAbuseState(t)

	var gotBody []struct {
		IP      string `json:"ip"`
		Comment string `json:"comment"`
	}
	done := make(chan struct{}, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/accounts/test-account/rules/lists/test-list/items", r.URL.Path)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotBody))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
		done <- struct{}{}
	}))
	t.Cleanup(func() {
		srv.Close()
		cloudflare.ResetClientForTest()
		cloudflare.SetListsAPIBaseForTest(defaultListsAPIBase)
	})
	setupCFEnv(t)
	cloudflare.ResetClientForTest()
	cloudflare.SetListsAPIBaseForTest(srv.URL)

	BanIP("203.0.113.50", "invalid_sign: 10 events in 5m0s", true)
	waitForPOST(t, done)

	require.Len(t, gotBody, 1)
	require.Equal(t, "203.0.113.50", gotBody[0].IP)
	require.Equal(t, "[permanent] invalid_sign: 10 events in 5m0s", gotBody[0].Comment)
}
