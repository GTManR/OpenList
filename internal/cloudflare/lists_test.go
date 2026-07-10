package cloudflare

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func setupCFEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CF_ABUSE_ENABLED", "true")
	t.Setenv("CF_ACCOUNT_ID", "test-account")
	t.Setenv("CF_LIST_ID", "test-list")
	t.Setenv("CF_API_TOKEN", "test-token")
}

func TestAddIPToList_postsCorrectJSON(t *testing.T) {
	setupCFEnv(t)

	var gotPath, gotAuth string
	var gotBody []listItem

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(body, &gotBody))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	t.Cleanup(func() {
		srv.Close()
		ResetClientForTest()
		SetListsAPIBaseForTest(defaultListsAPIBase)
	})

	ResetClientForTest()
	SetListsAPIBaseForTest(srv.URL)

	err := AddIPToList("203.0.113.55", "[permanent] invalid_sign: 10 events in 5m0s")
	require.NoError(t, err)
	require.Equal(t, "/accounts/test-account/rules/lists/test-list/items", gotPath)
	require.Equal(t, "Bearer test-token", gotAuth)
	require.Len(t, gotBody, 1)
	require.Equal(t, "203.0.113.55", gotBody[0].IP)
	require.Equal(t, "[permanent] invalid_sign: 10 events in 5m0s", gotBody[0].Comment)
}

func TestAddIPToList_treatsDuplicateAsSuccess(t *testing.T) {
	setupCFEnv(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10009,"message":"item already exists"}]}`))
	}))
	t.Cleanup(func() {
		srv.Close()
		ResetClientForTest()
		SetListsAPIBaseForTest(defaultListsAPIBase)
	})

	ResetClientForTest()
	SetListsAPIBaseForTest(srv.URL)

	err := AddIPToList("203.0.113.56", "duplicate test")
	require.NoError(t, err)
}

func TestEnabled_respectsEnv(t *testing.T) {
	t.Setenv("CF_ABUSE_ENABLED", "true")
	t.Setenv("CF_ACCOUNT_ID", "acc")
	t.Setenv("CF_LIST_ID", "list")
	t.Setenv("CF_API_TOKEN", "tok")
	require.True(t, Enabled())

	t.Setenv("CF_ABUSE_ENABLED", "false")
	require.False(t, Enabled())
}
