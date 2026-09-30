package app

import (
	"net/url"
	"strings"
	"testing"
)

func TestBrowserURLKeepsCredentialOutOfHTTPRequest(t *testing.T) {
	for _, address := range []string{"127.0.0.1:9090", "[::1]:9090"} {
		token := strings.Repeat("a", 32) + "+/&=#%"
		target, err := url.Parse(browserURL(address, token))
		if err != nil {
			t.Fatal(err)
		}
		if target.Host != address || target.Scheme != "http" || target.RequestURI() != "/" {
			t.Fatalf("unexpected browser target: %s", target.Redacted())
		}
		// 浏览器 location.hash 返回已转义的片段，不能使用 Go 已解码的 Fragment 模拟。
		values, err := url.ParseQuery(target.EscapedFragment())
		if err != nil || values.Get("token") != token {
			t.Fatal("startup token did not round-trip through fragment encoding")
		}
	}
}
