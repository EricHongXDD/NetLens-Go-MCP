package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"netlens/internal/model"
)

type flowRecorder struct {
	mu     sync.Mutex
	flows  map[string]model.Flow
	finals chan model.Flow
}

func newFlowRecorder() *flowRecorder {
	return &flowRecorder{flows: make(map[string]model.Flow), finals: make(chan model.Flow, 2048)}
}

func (r *flowRecorder) record(flow model.Flow) {
	r.mu.Lock()
	r.flows[flow.ID] = flow
	r.mu.Unlock()
	if flow.Completed {
		r.finals <- flow
	}
}

func (r *flowRecorder) final(t *testing.T) model.Flow {
	t.Helper()
	select {
	case flow := <-r.finals:
		return flow
	case <-time.After(5 * time.Second):
		t.Fatal("no completed capture arrived")
		return model.Flow{}
	}
}

func startTestProxy(t *testing.T, opts Options, downstreamRoots *x509.CertPool) (*Proxy, *httptest.Server, *http.Client, *flowRecorder) {
	t.Helper()
	recorder := newFlowRecorder()
	opts.Record = recorder.record
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	p, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(p)
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.Start()
	p.SetListenAddr(server.Listener.Addr())
	proxyURL, _ := url.Parse(server.URL)
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL), DisableCompression: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: downstreamRoots},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = p.Close()
		server.Close()
	})
	return p, server, client, recorder
}

func readResponse(t *testing.T, response *http.Response) []byte {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestHTTPProxyStreamsAndBoundsCaptureWithoutChangingTraffic(t *testing.T) {
	t.Parallel()
	requestPayload := strings.Repeat("request-token-sensitive-", 12000)
	responsePayload := strings.Repeat("response-secret-", 32768)
	seen := make(chan http.Header, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil || string(body) != requestPayload {
			t.Errorf("origin received wrong request body: bytes=%d err=%v", len(body), err)
		}
		seen <- r.Header.Clone()
		w.Header().Set("Connection", "X-Remove-Response")
		w.Header().Set("X-Remove-Response", "must not survive")
		w.Header().Set("X-Keep", "keep")
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = io.WriteString(w, responsePayload)
	}))
	defer origin.Close()
	_, _, client, recorder := startTestProxy(t, Options{BodyLimit: 123}, nil)
	request, _ := http.NewRequest(http.MethodPost, origin.URL+"/upload?token=actual", strings.NewReader(requestPayload))
	request.Header.Set("Connection", "X-Remove-Request, Keep-Alive")
	request.Header.Set("X-Remove-Request", "must not survive")
	request.Header.Set("Proxy-Authorization", "Bearer proxy-only")
	request.Header.Set("Authorization", "Bearer origin-secret")
	request.Header.Set("Cookie", "session=original")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if body := readResponse(t, response); string(body) != responsePayload {
		t.Fatalf("forwarded response changed: bytes=%d", len(body))
	}
	if response.Header.Get("X-Remove-Response") != "" || response.Header.Get("X-Keep") != "keep" {
		t.Fatal("response hop-by-hop headers were not removed correctly")
	}
	headers := <-seen
	if headers.Get("X-Remove-Request") != "" || headers.Get("Proxy-Authorization") != "" || headers.Get("Authorization") != "Bearer origin-secret" || headers.Get("Cookie") != "session=original" {
		t.Fatalf("forwarded headers incorrect: %v", headers)
	}
	flow := recorder.final(t)
	if flow.Source != "proxy" || !flow.RawAvailable || flow.StatusCode != 200 || flow.Error != "" {
		t.Fatalf("unexpected flow metadata: %+v", flow)
	}
	if flow.RequestBody.Size != int64(len(requestPayload)) || flow.ResponseBody.Size != int64(len(responsePayload)) {
		t.Fatalf("body byte counts wrong: request=%d response=%d", flow.RequestBody.Size, flow.ResponseBody.Size)
	}
	if !flow.RequestBody.Truncated || !flow.ResponseBody.Truncated || len(flow.RequestBody.Data) != 123 || len(flow.ResponseBody.Data) != 123 {
		t.Fatal("body capture did not retain exactly the configured prefix")
	}
	if string(flow.RequestBody.Data) != requestPayload[:123] || string(flow.ResponseBody.Data) != responsePayload[:123] {
		t.Fatal("captured prefix differs from raw traffic")
	}
	// Windows 回环请求可能小于时钟分辨率，零毫秒也是有效耗时。
	if flow.Timings.TotalMS < 0 || flow.Timings.TTFBMS < 0 || flow.Timings.ConnectMS < 0 || runtime.GOOS != "windows" && (flow.Timings.TotalMS == 0 || flow.Timings.TTFBMS == 0 || flow.Timings.ConnectMS == 0) {
		t.Fatalf("missing transport timing: %+v", flow.Timings)
	}
}

func TestTraceRecordsConnectAndFirstByteEvents(t *testing.T) {
	trace := newTrace(time.Now().Add(-time.Second))
	callbacks := trace.clientTrace()
	callbacks.ConnectStart("tcp", "127.0.0.1:80")
	if len(trace.connectStarts) != 1 {
		t.Fatal("connect start event was not recorded")
	}
	// 固定起点可验证真实事件采集，不依赖操作系统计时精度或额外等待。
	trace.connectStarts["tcp 127.0.0.1:80"] = time.Now().Add(-time.Second)
	callbacks.ConnectDone("tcp", "127.0.0.1:80", nil)
	callbacks.GotFirstResponseByte()
	timings := trace.snapshot()
	if len(trace.connectStarts) != 0 || !trace.firstByteSeen || timings.ConnectMS < 900 || timings.TTFBMS < 900 {
		t.Fatalf("trace events were lost: %+v", timings)
	}
}

func TestSSEIsAvailableBeforeOriginFinishes(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "data: last\n\n")
	}))
	defer origin.Close()
	_, _, client, recorder := startTestProxy(t, Options{}, nil)
	response, err := client.Get(origin.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	first, err := reader.ReadString('\n')
	if err != nil || first != "data: first\n" {
		t.Fatalf("first SSE event was buffered or changed: %q, %v", first, err)
	}
	select {
	case flow := <-recorder.finals:
		t.Fatalf("SSE completed before origin was released: %+v", flow)
	default:
	}
	unblock()
	if _, err := io.Copy(io.Discard, reader); err != nil {
		t.Fatal(err)
	}
	flow := recorder.final(t)
	if string(flow.ResponseBody.Data) != "data: first\n\ndata: last\n\n" || flow.ResponseBody.Truncated {
		t.Fatalf("incorrect SSE capture: %+v", flow.ResponseBody)
	}
}

func TestMITMUsesTrustedLocalCAAndVerifiedUpstreamTLS(t *testing.T) {
	t.Parallel()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", r.URL.Path)
		_, _ = io.WriteString(w, "decrypted HTTPS content")
	}))
	defer origin.Close()
	ca := testCA(t)
	downstreamRoots := x509.NewCertPool()
	downstreamRoots.AppendCertsFromPEM(ca.CertificatePEM())
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(origin.Certificate())
	_, _, client, recorder := startTestProxy(t, Options{CA: ca, MITM: true, UpstreamTLSConfig: &tls.Config{RootCAs: upstreamRoots}}, downstreamRoots)
	for i := 0; i < 2; i++ {
		response, err := client.Get(origin.URL + "/secure")
		if err != nil {
			t.Fatal(err)
		}
		if string(readResponse(t, response)) != "decrypted HTTPS content" || response.Header.Get("X-Origin") != "/secure" {
			t.Fatal("HTTPS payload or headers changed")
		}
		if response.TLS == nil || response.TLS.NegotiatedProtocol == "h2" {
			t.Fatal("MITM downstream was not a TLS HTTP/1.1 connection")
		}
		if !bytes.Equal(response.TLS.PeerCertificates[0].RawIssuer, ca.cert.RawSubject) {
			t.Fatal("downstream certificate was not signed by the installation CA")
		}
		flow := recorder.final(t)
		if !flow.RawAvailable || flow.Method != "GET" || flow.URL != origin.URL+"/secure" || flow.Source != "proxy" || flow.Error != "" {
			t.Fatalf("incorrect intercepted flow: %+v", flow)
		}
		if i == 0 && flow.Timings.TLSMS <= 0 {
			t.Fatal("upstream TLS timing not recorded")
		}
		if i == 1 && !flow.Timings.ConnectionReused {
			t.Fatal("upstream connection was not reused")
		}
	}

	// Trusting the local MITM CA does not grant trust to an unrelated upstream
	// certificate. The proxy must fail at upstream authentication.
	_, _, rejectingClient, rejectingRecorder := startTestProxy(t, Options{CA: ca, MITM: true}, downstreamRoots)
	response, err := rejectingClient.Get(origin.URL + "/must-reject")
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, response)
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("untrusted upstream was accepted: %d", response.StatusCode)
	}
	if flow := rejectingRecorder.final(t); !strings.Contains(flow.Error, "certificate") {
		t.Fatalf("upstream verification failure not captured: %+v", flow)
	}
}

func TestConnectTunnelPreservesPipelinedBytesAndCapturesMetadataOnly(t *testing.T) {
	t.Parallel()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	upstreamDone := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			upstreamDone <- err
			return
		}
		defer conn.Close()
		data := make([]byte, len("pipelined"))
		_, err = io.ReadFull(conn, data)
		if err == nil && string(data) != "pipelined" {
			err = fmt.Errorf("wrong upstream bytes: %q", data)
		}
		if err == nil {
			_, err = conn.Write([]byte("reply:" + string(data)))
		}
		upstreamDone <- err
	}()
	_, server, _, recorder := startTestProxy(t, Options{}, nil)
	client, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\npipelined", upstream.Addr(), upstream.Addr())
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT response: %v, %v", response, err)
	}
	responseBytes := make([]byte, len("reply:pipelined"))
	if _, err := io.ReadFull(reader, responseBytes); err != nil || string(responseBytes) != "reply:pipelined" {
		t.Fatalf("tunnel lost buffered bytes: %q, %v", responseBytes, err)
	}
	_ = client.Close()
	if err := <-upstreamDone; err != nil {
		t.Fatal(err)
	}
	flow := recorder.final(t)
	if flow.Source != "tunnel" || flow.RawAvailable || len(flow.RequestBody.Data) != 0 || len(flow.ResponseBody.Data) != 0 {
		t.Fatalf("opaque tunnel claimed HTTP content: %+v", flow)
	}
	if flow.RequestBody.Size != int64(len("pipelined")) || flow.ResponseBody.Size != int64(len("reply:pipelined")) {
		t.Fatalf("incorrect tunnel wire-byte counts: %+v", flow)
	}
}

func TestProxyCloseClosesActiveHijackedTunnel(t *testing.T) {
	t.Parallel()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "alive")
	}))
	defer origin.Close()
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	p, _, client, recorder := startTestProxy(t, Options{}, roots)
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(readResponse(t, response)) != "alive" {
		t.Fatal("TLS tunnel changed content")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	flow := recorder.final(t)
	if flow.Source != "tunnel" || flow.RawAvailable {
		t.Fatalf("wrong final tunnel metadata: %+v", flow)
	}
	if err := p.Close(); err != nil {
		t.Fatal("second Close was not idempotent")
	}
}

func TestReplayPreservesSourceAndRejectsUnsafeOrIncompleteRequests(t *testing.T) {
	t.Parallel()
	seen := make(chan *http.Request, 8)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		copy := r.Clone(context.Background())
		copy.Body = io.NopCloser(bytes.NewReader(body))
		seen <- copy
		if r.URL.Path == "/redirect" {
			w.Header().Set("Location", "/other")
			w.WriteHeader(http.StatusFound)
			return
		}
		_, _ = w.Write(body)
	}))
	defer origin.Close()
	p, server, client, recorder := startTestProxy(t, Options{BodyLimit: 4}, nil)
	request, _ := http.NewRequest(http.MethodPost, origin.URL+"/original", strings.NewReader("long-original-body"))
	request.Header.Set("Authorization", "Bearer original")
	request.Header.Set("Content-Encoding", "gzip")
	request.Header.Set("Digest", "old-checksum")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, response)
	<-seen
	original := recorder.final(t)
	if _, err := p.Replay(context.Background(), original, model.ReplayOptions{}); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("truncated request replay was allowed: %v", err)
	}
	replacement := "new"
	replayed, err := p.Replay(context.Background(), original, model.ReplayOptions{URL: origin.URL + "/edited", Body: &replacement, SetHeaders: map[string]string{"X-Replay": "yes"}})
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Source != "replay" || replayed.ParentID != original.ID || replayed.ID == original.ID || string(replayed.ResponseBody.Data) != "new" {
		t.Fatalf("wrong replay metadata: %+v", replayed)
	}
	if replayed.RequestBody.Truncated || string(replayed.RequestBody.Data) != "new" {
		t.Fatal("replacement body was not recorded accurately")
	}
	actual := <-seen
	if actual.Header.Get("Authorization") != "Bearer original" || actual.Header.Get("X-Replay") != "yes" || actual.Header.Get("Content-Encoding") != "" || actual.Header.Get("Digest") != "" || actual.ContentLength != 3 {
		t.Fatalf("replay headers were not rebuilt safely: %v", actual.Header)
	}
	for _, target := range []string{server.URL + "/cross-port", strings.Replace(origin.URL, "http:", "https:", 1), "http://user:secret@" + strings.TrimPrefix(origin.URL, "http://"), "file:///etc/passwd"} {
		if _, err := p.Replay(context.Background(), original, model.ReplayOptions{URL: target, Body: &replacement}); err == nil {
			t.Errorf("unsafe replay target accepted: %s", target)
		}
	}
	if _, err := p.Replay(context.Background(), original, model.ReplayOptions{Body: &replacement, SetHeaders: map[string]string{"Host": "other.example"}}); err == nil {
		t.Fatal("Host override bypassed same-origin replay restriction")
	}
	unavailable := original
	unavailable.RawAvailable = false
	if _, err := p.Replay(context.Background(), unavailable, model.ReplayOptions{Body: &replacement}); err == nil {
		t.Fatal("replay accepted a public/redacted-only capture")
	}
	replayed, err = p.Replay(context.Background(), original, model.ReplayOptions{URL: origin.URL + "/redirect", Body: &replacement})
	if err != nil || replayed.StatusCode != http.StatusFound {
		t.Fatalf("replay followed a redirect or failed: status=%d, err=%v", replayed.StatusCode, err)
	}
	if actual := <-seen; actual.URL.Path != "/redirect" {
		t.Fatal("unexpected replay target")
	}
	select {
	case extra := <-seen:
		t.Fatalf("replay followed redirect to %s", extra.URL)
	default:
	}
}

func TestRulesApplyInOrderAndDelayCanBeCanceled(t *testing.T) {
	t.Parallel()
	rules := []model.Rule{
		{ID: "first", Enabled: true, Match: model.RuleMatch{Hosts: []string{"example.invalid"}}, Action: model.RuleAction{SetRequestHeaders: map[string]string{"X-First": "one", "X-Remove": "gone"}}},
		{ID: "mock", Enabled: true, Match: model.RuleMatch{URLContains: "/mock"}, Action: model.RuleAction{SetRequestHeaders: map[string]string{"X-First": "two"}, RemoveRequestHeaders: []string{"X-Remove"}, Mock: &model.MockResponse{Status: 201, Headers: map[string]string{"X-Mock": "yes"}, Body: "mocked body"}}},
		{ID: "delay", Enabled: true, Match: model.RuleMatch{URLContains: "/delay"}, Action: model.RuleAction{DelayMS: 1000}},
	}
	p, _, client, recorder := startTestProxy(t, Options{GetRules: func() []model.Rule { return rules }, Timeout: 100 * time.Millisecond}, nil)
	response, err := client.Post("http://example.invalid/mock", "text/plain", strings.NewReader("input"))
	if err != nil {
		t.Fatal(err)
	}
	if string(readResponse(t, response)) != "mocked body" || response.StatusCode != 201 || response.Header.Get("X-Mock") != "yes" {
		t.Fatal("mock response incorrect")
	}
	flow := recorder.final(t)
	if flow.Source != "mock" || strings.Join(flow.RuleIDs, ",") != "first,mock" || flow.RequestHeaders.Get("X-First") != "two" || flow.RequestHeaders.Get("X-Remove") != "" || string(flow.RequestBody.Data) != "input" {
		t.Fatalf("ordered request mutations or capture incorrect: %+v", flow)
	}
	started := time.Now()
	flow.URL = "http://example.invalid/delay"
	_, err = p.Replay(context.Background(), flow, model.ReplayOptions{})
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 800*time.Millisecond {
		t.Fatalf("rule delay did not honor timeout: elapsed=%s err=%v", time.Since(started), err)
	}
}

func TestResponseFailureAbortsChunkedStreamAndRecordsError(t *testing.T) {
	t.Parallel()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		conn, writer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		_, _ = writer.WriteString("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/event-stream\r\n\r\n5\r\nhello\r\n")
		_ = writer.Flush()
		// Deliberately close without the required zero-length terminating chunk.
	}))
	defer origin.Close()
	_, _, client, recorder := startTestProxy(t, Options{}, nil)
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err == nil || string(data) != "hello" {
		t.Fatalf("truncated upstream was incorrectly presented as complete: %q err=%v", data, err)
	}
	flow := recorder.final(t)
	if flow.Error == "" || !flow.ResponseBody.Truncated || string(flow.ResponseBody.Data) != "hello" {
		t.Fatalf("response failure was not captured: %+v", flow)
	}
}

func TestResponseHeadersAreBounded(t *testing.T) {
	t.Parallel()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Too-Large", strings.Repeat("x", 70<<10))
		_, _ = io.WriteString(w, "untrusted large header")
	}))
	defer origin.Close()
	_, _, client, recorder := startTestProxy(t, Options{}, nil)
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, response)
	if response.StatusCode != http.StatusBadGateway || recorder.final(t).Error == "" {
		t.Fatal("oversized upstream response headers were accepted")
	}
}

func TestCaptureFiltersDoNotBlockForwarding(t *testing.T) {
	t.Parallel()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	defer origin.Close()
	_, _, client, recorder := startTestProxy(t, Options{GetCapture: func() model.CaptureConfig {
		return model.CaptureConfig{Enabled: true, Filter: model.Filter{StatusMin: 500}}
	}}, nil)
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, response)
	if response.StatusCode != 204 {
		t.Fatalf("capture filter blocked forwarding: %d", response.StatusCode)
	}
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if len(recorder.flows) != 0 {
		t.Fatal("outcome filter left an unmatched incomplete flow in storage")
	}
}

func TestInvalidTargetsAndSelfLoopsAreRejected(t *testing.T) {
	t.Parallel()
	p, server, client, recorder := startTestProxy(t, Options{}, nil)
	response, err := client.Get(server.URL + "/loop")
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, response)
	if response.StatusCode != http.StatusBadGateway || !strings.Contains(recorder.final(t).Error, "back to this proxy") {
		t.Fatal("proxy recursively connected to itself")
	}
	original := model.Flow{ID: "self", Completed: true, RawAvailable: true, Source: "proxy", Method: "GET", URL: server.URL + "/replay-loop"}
	if _, err := p.Replay(context.Background(), original, model.ReplayOptions{}); err == nil || !strings.Contains(err.Error(), "back to this proxy") {
		t.Fatalf("tool-initiated replay bypassed self-loop protection: %v", err)
	}
	for _, target := range []string{"ftp://example.com/file", "http://user:secret@example.com/", "http://example.com:0/", "/origin-form"} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		writer := httptest.NewRecorder()
		p.ServeHTTP(writer, request)
		if writer.Code != http.StatusBadRequest {
			t.Errorf("invalid target %q returned %d", target, writer.Code)
		}
	}
	request := httptest.NewRequest(http.MethodGet, "http://example.com/socket", nil)
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "websocket")
	writer := httptest.NewRecorder()
	p.ServeHTTP(writer, request)
	if writer.Code != http.StatusNotImplemented {
		t.Fatal("unsupported WebSocket upgrade did not receive an explicit error")
	}
	if _, err := New(Options{UpstreamTLSConfig: &tls.Config{InsecureSkipVerify: true}}); err == nil {
		t.Fatal("insecure upstream TLS configuration was accepted")
	}
	if _, err := New(Options{UpstreamTLSConfig: &tls.Config{ServerName: "unrelated.example"}}); err == nil {
		t.Fatal("a static TLS name was allowed to replace target hostname verification")
	}
}

func TestReplayOriginComparisonUsesWebOriginBoundaries(t *testing.T) {
	original, _ := url.Parse("https://example.com/path")
	for _, target := range []string{"https://example.com./path", "https://other.example/path", "http://example.com/path", "https://example.com:8443/path"} {
		edited, _ := url.Parse(target)
		if sameOrigin(original, edited) {
			t.Errorf("different web origins were merged: %s", target)
		}
	}
	for _, target := range []string{"https://EXAMPLE.COM/path", "https://example.com:443/another"} {
		edited, _ := url.Parse(target)
		if !sameOrigin(original, edited) {
			t.Errorf("equivalent web origin was rejected: %s", target)
		}
	}
}

func TestConcurrentCaptureAndConnectionReuse(t *testing.T) {
	t.Parallel()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, strings.Repeat("body", 4096))
	}))
	defer origin.Close()
	_, _, client, recorder := startTestProxy(t, Options{BodyLimit: 31}, nil)
	const count = 96
	var workers sync.WaitGroup
	errorsCh := make(chan error, count)
	for i := 0; i < count; i++ {
		workers.Go(func() {
			response, err := client.Post(origin.URL, "text/plain", strings.NewReader(strings.Repeat("req", 512)))
			if err == nil {
				_, err = io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
			}
			if err != nil {
				errorsCh <- err
			}
		})
	}
	workers.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Error(err)
	}
	for i := 0; i < count; i++ {
		flow := recorder.final(t)
		if len(flow.RequestBody.Data) != 31 || len(flow.ResponseBody.Data) != 31 || flow.RequestBody.Size != 1536 || flow.ResponseBody.Size != 16384 || flow.Error != "" {
			t.Fatalf("concurrent capture was corrupted: %+v", flow)
		}
	}
}
