package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"image"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"netlens/internal/model"
)

func TestHTTPSDecryptionScope(t *testing.T) {
	p, err := New(Options{CA: testCA(t), MITM: true, MITMRequireHosts: true})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for _, tc := range []struct {
		host   string
		filter model.Filter
		want   bool
	}{
		{"api.bilibili.com:443", model.Filter{}, false},
		{"api.bilibili.com:443", model.Filter{Hosts: []string{"app.melands.cn"}}, false},
		{"app.melands.cn:443", model.Filter{Hosts: []string{"app.melands.cn"}, Methods: []string{"POST"}, URLContains: "/login"}, true},
		{"api.example.test:443", model.Filter{Hosts: []string{"*.example.test"}}, true},
		{"example.test:443", model.Filter{Hosts: []string{"*.example.test"}}, false},
		{"api.example.test:443", model.Filter{Hosts: []string{"*"}, ExcludeHosts: []string{"api.example.test"}}, false},
		{"api.example.test:443", model.Filter{Hosts: []string{"api.example.test:8443"}}, false},
	} {
		if got := p.shouldIntercept(tc.host, tc.filter); got != tc.want {
			t.Fatalf("主机 %s 解密=%t，预期 %t", tc.host, got, tc.want)
		}
	}
}

func TestNonTargetHTTPSKeepsOriginalTLSLoginCookiesAndQRCodeViaUpstream(t *testing.T) {
	var imageBytes bytes.Buffer
	png.Encode(&imageBytes, image.NewRGBA(image.Rect(0, 0, 2, 2)))
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/session" {
			http.SetCookie(w, &http.Cookie{Name: "auth", Value: "login-fixture", Path: "/", Secure: true, HttpOnly: true})
			io.WriteString(w, "session-created")
			return
		}
		cookie, err := r.Cookie("auth")
		if err != nil || cookie.Value != "login-fixture" {
			http.Error(w, "login cookie missing", 401)
			return
		}
		if r.URL.Path == "/qr.png" {
			w.Header().Set("Content-Type", "image/png")
			w.Write(imageBytes.Bytes())
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"isLogin":true}`)
	}))
	origin.EnableHTTP2 = true
	origin.StartTLS()
	defer origin.Close()
	ca := testCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	roots.AppendCertsFromPEM(ca.CertificatePEM())
	_, upstream, _, upstreamRecorder := startTestProxy(t, Options{}, nil)
	p, _, client, _ := startTestProxy(t, Options{CA: ca, MITM: true, MITMRequireHosts: true, GetCapture: func() model.CaptureConfig {
		return model.CaptureConfig{Enabled: true, Filter: model.Filter{Hosts: []string{"app.melands.cn"}}}
	}}, roots)
	p.SetUpstream(upstream.URL)
	client.Transport.(*http.Transport).ForceAttemptHTTP2 = true
	client.Jar, _ = cookiejar.New(nil)
	for _, path := range []string{"/session", "/nav", "/qr.png"} {
		resp, err := client.Get(origin.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 || resp.TLS == nil || !bytes.Equal(resp.TLS.PeerCertificates[0].Raw, origin.Certificate().Raw) || resp.ProtoMajor != 2 {
			t.Fatalf("非目标站点的原始 TLS、HTTP/2 或登录会话发生变化：%s", resp.Status)
		}
		data := readResponse(t, resp)
		if path == "/qr.png" && !bytes.Equal(data, imageBytes.Bytes()) || path == "/nav" && string(data) != `{"isLogin":true}` {
			t.Fatal("二维码图片或登录结果未完整保留")
		}
	}
	client.Transport.(*http.Transport).CloseIdleConnections()
	if flow := upstreamRecorder.final(t); flow.Method != "CONNECT" || flow.StatusCode != 200 || flow.ResponseBody.Size == 0 {
		t.Fatal("流量绕过了上游代理")
	}
}

func TestMITMPreservesDefaultPortHostAndCookies(t *testing.T) {
	originCA, localCA := testCA(t), testCA(t)
	cert, err := originCA.certificateFor("login.example.test")
	if err != nil {
		t.Fatal(err)
	}
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "login.example.test" || r.Header.Get("Cookie") != "auth=fixture; another=value" || r.Header.Get("Origin") != "https://login.example.test" || r.Header.Get("Referer") != "https://login.example.test/" {
			http.Error(w, "original host or login headers changed", 400)
			return
		}
		w.Header().Add("Set-Cookie", "auth=next; Secure; HttpOnly; Path=/; SameSite=None")
		w.Header().Add("Set-Cookie", "other=next; Secure; Path=/")
		io.WriteString(w, "qr-image-payload")
	}))
	origin.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
	origin.StartTLS()
	defer origin.Close()
	originRoots, localRoots := x509.NewCertPool(), x509.NewCertPool()
	originRoots.AppendCertsFromPEM(originCA.CertificatePEM())
	localRoots.AppendCertsFromPEM(localCA.CertificatePEM())
	p, _, client, recorder := startTestProxy(t, Options{CA: localCA, MITM: true, UpstreamTLSConfig: &tls.Config{RootCAs: originRoots}}, localRoots)
	// 测试主机的 443 端口映射到本地随机端口，不访问外部登录服务。
	p.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
	}
	req, _ := http.NewRequest("GET", "https://login.example.test/qr", nil)
	req.Header.Set("Cookie", "auth=fixture; another=value")
	req.Header.Set("Origin", "https://login.example.test")
	req.Header.Set("Referer", "https://login.example.test/")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || string(readResponse(t, resp)) != "qr-image-payload" || len(resp.Header.Values("Set-Cookie")) != 2 {
		t.Fatal("Host、Cookie 或二维码正文发生改变")
	}
	if flow := recorder.final(t); flow.RequestHeaders.Get("Host") != "login.example.test" || flow.RequestHeaders.Get("Cookie") != req.Header.Get("Cookie") {
		t.Fatal("登录请求的实际转发证据不正确")
	}
}

func TestScopeChangeFinishesActiveResponseThenReturnsToOriginalTLS(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/active" {
			close(started)
			<-release
		}
		io.WriteString(w, "complete-response")
	}))
	defer origin.Close()
	ca := testCA(t)
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	roots.AppendCertsFromPEM(ca.CertificatePEM())
	u, _ := url.Parse(origin.URL)
	var scopeMu sync.RWMutex
	filter := model.Filter{Hosts: []string{u.Host}}
	p, _, client, _ := startTestProxy(t, Options{CA: ca, MITM: true, MITMRequireHosts: true, UpstreamTLSConfig: &tls.Config{RootCAs: roots}, GetCapture: func() model.CaptureConfig {
		scopeMu.RLock()
		defer scopeMu.RUnlock()
		return model.CaptureConfig{Enabled: true, Filter: filter}
	}}, roots)
	result := make(chan error, 1)
	go func() {
		resp, err := client.Get(origin.URL + "/active")
		if err == nil {
			data, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			if readErr != nil || string(data) != "complete-response" {
				err = fmt.Errorf("当前响应被范围变更截断：%v", readErr)
			}
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("目标请求没有到达")
	}
	scopeMu.Lock()
	filter = model.Filter{}
	scopeMu.Unlock()
	p.RefreshMITMScope()
	releaseOnce.Do(func() { close(release) })
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(origin.URL + "/next")
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, resp)
	if !bytes.Equal(resp.TLS.PeerCertificates[0].Raw, origin.Certificate().Raw) {
		t.Fatal("已排除站点仍复用旧解密连接")
	}
}

func TestTunnelOutlivesHTTPRequestTimeout(t *testing.T) {
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	go func() {
		conn, err := origin.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()
	_, proxyServer, _, _ := startTestProxy(t, Options{Timeout: 50 * time.Millisecond}, nil)
	u, _ := url.Parse(proxyServer.URL)
	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin.Addr(), origin.Addr())
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("隧道建立失败：%v", err)
	}
	<-time.After(120 * time.Millisecond)
	if _, err := io.WriteString(conn, "still-alive"); err != nil {
		t.Fatal(err)
	}
	data := make([]byte, len("still-alive"))
	if _, err := io.ReadFull(reader, data); err != nil || strings.TrimSpace(string(data)) != "still-alive" {
		t.Fatalf("隧道被单个请求超时切断：%v", err)
	}
}
