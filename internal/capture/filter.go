// Package capture 保存有界流量快照，并生成保留真实值的公开视图。
package capture

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"netlens/internal/model"
)

// MatchHost compares a hostname or hostname:port with an exact name, "*", or a
// wildcard suffix such as "*.example.com". A suffix wildcard requires at least
// one subdomain and does not match example.com itself. A port in the pattern
// must also match; a pattern without a port matches any port.
func MatchHost(host, pattern string) bool {
	if pattern == "*" {
		return host != ""
	}
	h, hp := splitHost(host)
	p, pp := splitHost(pattern)
	if h == "" || p == "" || (pp != "" && hp != pp) {
		return false
	}
	if strings.HasPrefix(p, "*.") {
		suffix := p[1:]
		return len(h) > len(suffix) && strings.HasSuffix(h, suffix)
	}
	return h == p
}

func splitHost(s string) (host, port string) {
	s = strings.TrimSpace(s)
	if h, p, err := net.SplitHostPort(s); err == nil {
		return strings.TrimSuffix(strings.ToLower(h), "."), p
	}
	if strings.Count(s, ":") == 1 {
		if i := strings.LastIndexByte(s, ':'); i >= 0 {
			return strings.TrimSuffix(strings.ToLower(s[:i]), "."), s[i+1:]
		}
	}
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	return strings.TrimSuffix(strings.ToLower(s), "."), ""
}

// ValidateFilter rejects malformed host patterns, HTTP methods and ranges.
// Filter matching never changes which requests the proxy forwards.
func ValidateFilter(f model.Filter) error {
	if len(f.Hosts) > 64 || len(f.ExcludeHosts) > 64 || len(f.Methods) > 64 {
		return fmt.Errorf("hosts, exclude_hosts and methods must each contain at most 64 entries")
	}
	if len(f.URLContains) > 4096 {
		return fmt.Errorf("url_contains must not exceed 4096 bytes")
	}
	for _, group := range [][]string{f.Hosts, f.ExcludeHosts} {
		for _, pattern := range group {
			if err := validateHostPattern(pattern); err != nil {
				return err
			}
		}
	}
	for _, method := range f.Methods {
		if method == "" || len(method) > 64 || method != strings.TrimSpace(method) {
			return fmt.Errorf("filter method must be a nonempty HTTP token of at most 64 bytes")
		}
		for _, ch := range method {
			if !isHTTPToken(ch) {
				return fmt.Errorf("filter method must be an HTTP token")
			}
		}
	}
	if (f.StatusMin != 0 && (f.StatusMin < 100 || f.StatusMin > 599)) ||
		(f.StatusMax != 0 && (f.StatusMax < 100 || f.StatusMax > 599)) {
		return fmt.Errorf("status bounds must be 100..599, or 0 for no bound")
	}
	if f.StatusMin != 0 && f.StatusMax != 0 && f.StatusMin > f.StatusMax {
		return fmt.Errorf("status_min must not exceed status_max")
	}
	if f.MinDurationMS < 0 || math.IsNaN(f.MinDurationMS) || math.IsInf(f.MinDurationMS, 0) {
		return fmt.Errorf("min_duration_ms must be a finite nonnegative number")
	}
	return nil
}

func validateHostPattern(pattern string) error {
	if len(pattern) > 512 {
		return fmt.Errorf("host filter pattern must not exceed 512 bytes")
	}
	if pattern == "*" {
		return nil
	}
	if pattern == "" || pattern != strings.TrimSpace(pattern) || strings.ContainsAny(pattern, "/\\?#@ \t\r\n") {
		return fmt.Errorf("host filter must be a hostname, hostname:port, or *.domain suffix")
	}
	host, port := splitHost(pattern)
	if strings.HasPrefix(pattern, "[") {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("brackets in a host filter are only valid for an IP address")
		}
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("host filter port must be 1..65535")
		}
	} else if strings.HasSuffix(pattern, ":") {
		return fmt.Errorf("host filter must not have an empty port")
	}
	if strings.HasPrefix(host, "*.") {
		host = host[2:]
	}
	if host == "" || strings.ContainsRune(host, '*') {
		return fmt.Errorf("wildcards are supported only as * or *.domain")
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("host filter contains an invalid hostname label")
		}
		for _, ch := range label {
			if !unicode.IsLetter(ch) && !unicode.IsDigit(ch) && ch != '-' && ch != '_' {
				return fmt.Errorf("host filter contains an invalid hostname character")
			}
		}
	}
	if len(host) > 253 {
		return fmt.Errorf("host filter hostname is too long")
	}
	return nil
}

func isHTTPToken(ch rune) bool {
	return ch >= '0' && ch <= '9' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || strings.ContainsRune("!#$%&'*+-.^_`|~", ch)
}

// Matches applies AND between filter fields and OR within hosts and methods.
// OnlyErrors includes network failures and HTTP status codes 400 and above.
func Matches(flow model.Flow, f model.Filter) bool {
	host := flow.Host
	if host == "" {
		if u, err := url.Parse(flow.URL); err == nil {
			host = u.Host
		}
	}
	for _, pattern := range f.ExcludeHosts {
		if MatchHost(host, pattern) {
			return false
		}
	}
	if len(f.Hosts) > 0 {
		found := false
		for _, pattern := range f.Hosts {
			if MatchHost(host, pattern) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(f.Methods) > 0 {
		found := false
		for _, method := range f.Methods {
			if strings.EqualFold(flow.Method, method) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.URLContains != "" && !strings.Contains(flow.URL, f.URLContains) {
		return false
	}
	if f.StatusMin != 0 && flow.StatusCode < f.StatusMin || f.StatusMax != 0 && flow.StatusCode > f.StatusMax {
		return false
	}
	if flow.Timings.TotalMS < f.MinDurationMS {
		return false
	}
	if f.OnlyErrors && flow.Error == "" && flow.StatusCode < http.StatusBadRequest {
		return false
	}
	return true
}
