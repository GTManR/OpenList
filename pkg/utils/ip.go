package utils

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP resolves the client IP with Cloudflare-aware header priority:
// CF-Connecting-IP → True-Client-IP → X-Forwarded-For (first) → X-Real-Ip → RemoteAddr.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}

	for _, header := range []string{"CF-Connecting-IP", "True-Client-IP"} {
		if ip := parseIP(strings.TrimSpace(r.Header.Get(header))); ip != "" {
			return ip
		}
	}

	xForwardedFor := r.Header.Get("X-Forwarded-For")
	ip := strings.TrimSpace(strings.Split(xForwardedFor, ",")[0])
	if ip = parseIP(ip); ip != "" {
		return ip
	}

	ip = parseIP(strings.TrimSpace(r.Header.Get("X-Real-Ip")))
	if ip != "" {
		return ip
	}

	if ip, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr)); err == nil {
		return parseIP(ip)
	}

	return parseIP(strings.TrimSpace(r.RemoteAddr))
}

// ClientIPFromAddr extracts an IP from a host:port or bare IP address string.
func ClientIPFromAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return parseIP(host)
	}
	return parseIP(addr)
}

// PeerIP returns the TCP peer address from RemoteAddr only.
// It ignores CF-Connecting-IP / X-Forwarded-For so callers cannot spoof
// intranet identity for auth bypass decisions.
func PeerIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	return ClientIPFromAddr(r.RemoteAddr)
}

// IPInCIDRs reports whether ipStr falls in any of the given CIDR networks.
func IPInCIDRs(ipStr string, cidrs []*net.IPNet) bool {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return false
	}
	for _, n := range cidrs {
		if n != nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseCIDRList parses a comma / newline / space separated CIDR list.
// Invalid entries are skipped.
func ParseCIDRList(raw string) []*net.IPNet {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';' || r == ' ' || r == '\t'
	})
	out := make([]*net.IPNet, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		_, network, err := net.ParseCIDR(f)
		if err != nil {
			continue
		}
		out = append(out, network)
	}
	return out
}

func parseIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	return parsed.String()
}

func IsLocalIPAddr(ip string) bool {
	return IsLocalIP(net.ParseIP(ip))
}

// ShouldBypassTurnstile decides intranet Turnstile skip from peer IP + policy.
// peer must be the TCP RemoteAddr IP (not spoofable proxy headers).
func ShouldBypassTurnstile(peer string, enabled bool, cidrRaw string) bool {
	if !enabled || peer == "" {
		return false
	}
	if cidrs := ParseCIDRList(cidrRaw); len(cidrs) > 0 {
		return IPInCIDRs(peer, cidrs)
	}
	return IsLocalIPAddr(peer)
}

func IsLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}

	return ip4[0] == 10 || // 10.0.0.0/8
		(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || // 172.16.0.0/12
		(ip4[0] == 169 && ip4[1] == 254) || // 169.254.0.0/16
		(ip4[0] == 192 && ip4[1] == 168) // 192.168.0.0/16
}
