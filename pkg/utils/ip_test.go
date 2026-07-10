package utils

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClientIP_CloudflareHeaders(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.Header.Set("CF-Connecting-IP", "203.0.113.1")
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	r.RemoteAddr = "192.0.2.1:1234"
	require.Equal(t, "203.0.113.1", ClientIP(r))

	r = &http.Request{Header: http.Header{}}
	r.Header.Set("True-Client-IP", "203.0.113.2")
	r.Header.Set("X-Forwarded-For", "198.51.100.1")
	require.Equal(t, "203.0.113.2", ClientIP(r))

	r = &http.Request{Header: http.Header{}}
	r.Header.Set("X-Forwarded-For", "198.51.100.1, 10.0.0.1")
	require.Equal(t, "198.51.100.1", ClientIP(r))

	r = &http.Request{Header: http.Header{}}
	r.Header.Set("X-Real-Ip", "203.0.113.3")
	require.Equal(t, "203.0.113.3", ClientIP(r))

	r = &http.Request{RemoteAddr: "192.0.2.5:4321"}
	require.Equal(t, "192.0.2.5", ClientIP(r))
}

func TestClientIPFromAddr(t *testing.T) {
	require.Equal(t, "10.0.0.5", ClientIPFromAddr("10.0.0.5:2121"))
	require.Equal(t, "10.0.0.6", ClientIPFromAddr("10.0.0.6"))
}

func TestIsLocalIPAddr(t *testing.T) {
	require.True(t, IsLocalIPAddr("127.0.0.1"))
	require.True(t, IsLocalIPAddr("10.1.2.3"))
	require.False(t, IsLocalIPAddr("8.8.8.8"))
}
