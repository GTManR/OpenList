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

func TestPeerIP_IgnoresSpoofedHeaders(t *testing.T) {
	r := &http.Request{Header: http.Header{}, RemoteAddr: "8.8.8.8:443"}
	r.Header.Set("CF-Connecting-IP", "192.168.1.10")
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	require.Equal(t, "8.8.8.8", PeerIP(r))
	require.Equal(t, "192.168.1.10", ClientIP(r))

	r = &http.Request{RemoteAddr: "192.168.31.5:52345"}
	require.Equal(t, "192.168.31.5", PeerIP(r))
}

func TestShouldBypassTurnstile(t *testing.T) {
	require.False(t, ShouldBypassTurnstile("192.168.1.1", false, ""))
	require.True(t, ShouldBypassTurnstile("192.168.1.1", true, ""))
	require.True(t, ShouldBypassTurnstile("127.0.0.1", true, ""))
	require.False(t, ShouldBypassTurnstile("8.8.8.8", true, ""))

	// CIDR allowlist is stricter: only listed ranges, not all private nets.
	require.True(t, ShouldBypassTurnstile("192.168.31.9", true, "192.168.31.0/24"))
	require.False(t, ShouldBypassTurnstile("10.0.0.1", true, "192.168.31.0/24"))
	require.False(t, ShouldBypassTurnstile("8.8.8.8", true, "192.168.31.0/24"))
}

func TestParseCIDRList(t *testing.T) {
	cidrs := ParseCIDRList("192.168.31.0/24, 10.1.0.0/16\nnot-a-cidr")
	require.Len(t, cidrs, 2)
	require.True(t, IPInCIDRs("192.168.31.2", cidrs))
	require.True(t, IPInCIDRs("10.1.2.3", cidrs))
	require.False(t, IPInCIDRs("10.2.0.1", cidrs))
}
