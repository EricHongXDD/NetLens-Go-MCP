package app

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"netlens/internal/model"
)

const integrationToken = "netlens-integration-control-token-0123456789abcdef"

type integrationHarness struct {
	service *Service
	control *httptest.Server
	proxy   *httptest.Server
	client  *http.Client
}

func newIntegrationHarness(t *testing.T, allowMutations bool) *integrationHarness {
	t.Helper()
	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.ProxyAddr = "127.0.0.1:0"
	cfg.ControlAddr = "127.0.0.1:0"
	cfg.Token = integrationToken
	cfg.Timeout = 5 * time.Second
	cfg.AllowReplay, cfg.AllowRules = allowMutations, allowMutations
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	control := httptest.NewUnstartedServer(s.Handler())
	proxyServer := httptest.NewUnstartedServer(s.Proxy)
	s.mu.Lock()
	s.controlAddr = control.Listener.Addr().String()
	s.proxyAddr = proxyServer.Listener.Addr().String()
	s.mu.Unlock()
	s.Proxy.SetListenAddr(proxyServer.Listener.Addr())
	control.Start()
	proxyServer.Start()
	proxyURL, _ := url.Parse(proxyServer.URL)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	h := &integrationHarness{
		service: s, control: control, proxy: proxyServer,
		client: &http.Client{Transport: transport, Timeout: 8 * time.Second},
	}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = s.Close()
		proxyServer.Close()
		control.Close()
	})
	return h
}

type integrationBearerTransport struct {
	base http.RoundTripper
}

func (t integrationBearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	copy := r.Clone(r.Context())
	copy.Header.Set("Authorization", "Bearer "+integrationToken)
	return t.base.RoundTrip(copy)
}

func (h *integrationHarness) connectMCP(t *testing.T) (*mcp.ClientSession, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	client := mcp.NewClient(&mcp.Implementation{Name: "netlens-app-integration", Version: "1"}, &mcp.ClientOptions{
		Capabilities: &mcp.ClientCapabilities{},
	})
	httpClient := &http.Client{
		Transport: integrationBearerTransport{base: h.control.Client().Transport},
		Timeout:   10 * time.Second,
	}
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: h.control.URL + "/mcp", HTTPClient: httpClient, DisableStandaloneSSE: true,
	}, &mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"})
	if err != nil {
		t.Fatalf("MCP initialize through authenticated application handler: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session, ctx
}

func integrationCall(t *testing.T, ctx context.Context, session *mcp.ClientSession, name string, args any, wantError bool) *mcp.CallToolResult {
	t.Helper()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s returned a protocol error: %v", name, err)
	}
	if result.IsError != wantError {
		b, _ := json.Marshal(result)
		t.Fatalf("%s isError=%t, want %t; result=%s", name, result.IsError, wantError, b)
	}
	return result
}

func integrationDecode[T any](t *testing.T, result *mcp.CallToolResult) T {
	t.Helper()
	b, err := json.Marshal(result.StructuredContent)
	if err != nil || result.StructuredContent == nil {
		t.Fatalf("missing/invalid structuredContent: %v", err)
	}
	var value T
	if err := json.Unmarshal(b, &value); err != nil {
		t.Fatalf("decode structuredContent: %v", err)
	}
	return value
}

func integrationResultText(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	b, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, secret := range []string{integrationToken} {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatalf("工具结果意外包含 NetLens 控制令牌")
		}
	}
	return text
}

// Wait on completed snapshots, since response bytes may reach a client just
// before the proxy publishes its final accounting snapshot.
func integrationFlows(t *testing.T, ctx context.Context, session *mcp.ClientSession, count int) model.QueryResult {
	t.Helper()
	waitCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		result := integrationCall(t, ctx, session, "flows_list", map[string]any{"limit": 100}, false)
		flows := integrationDecode[model.QueryResult](t, result)
		complete := flows.Matched == count && len(flows.Items) == count
		for _, f := range flows.Items {
			complete = complete && f.Completed
		}
		if complete {
			return flows
		}
		select {
		case <-waitCtx.Done():
			t.Fatalf("expected %d completed captures; got %+v", count, flows)
		case <-ticker.C:
		}
	}
}

func integrationRequest(t *testing.T, h *integrationHarness, method, target, body string, headers map[string]string) (int, http.Header, string) {
	t.Helper()
	req, err := http.NewRequest(method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("request through explicit proxy: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	return resp.StatusCode, resp.Header, string(data)
}

func TestIntegrationControlAccess(t *testing.T) {
	h := newIntegrationHarness(t, false)
	_, port, _ := net.SplitHostPort(h.control.Listener.Addr().String())
	for _, path := range []string{"/api/status", "/mcp"} {
		for _, tc := range []struct {
			name, token, origin, host, query string
			status                           int
		}{
			{name: "missing credential", status: http.StatusUnauthorized},
			{name: "incorrect credential", token: "wrong", status: http.StatusUnauthorized},
			{name: "credential in query is rejected", query: "?token=" + integrationToken, status: http.StatusUnauthorized},
			{name: "cross origin", token: integrationToken, origin: "https://attacker.invalid", status: http.StatusForbidden},
			{name: "opaque origin", token: integrationToken, origin: "null", status: http.StatusForbidden},
			{name: "mismatched origin port", token: integrationToken, origin: "http://127.0.0.1:1", status: http.StatusForbidden},
			{name: "DNS rebinding host", token: integrationToken, host: "attacker.invalid:" + port, status: http.StatusForbidden},
			{name: "different loopback port", token: integrationToken, host: "127.0.0.1:1", status: http.StatusForbidden},
		} {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				req, _ := http.NewRequest(http.MethodGet, h.control.URL+path+tc.query, nil)
				if tc.token != "" {
					req.Header.Set("Authorization", "Bearer "+tc.token)
				}
				if tc.origin != "" {
					req.Header.Set("Origin", tc.origin)
				}
				if tc.host != "" {
					req.Host = tc.host
				}
				resp, err := h.control.Client().Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(resp.Body)
				if resp.StatusCode != tc.status {
					t.Fatalf("status=%d, want %d; response=%s", resp.StatusCode, tc.status, body)
				}
				if strings.Contains(string(body), integrationToken) {
					t.Fatal("access rejection echoed control credential")
				}
			})
		}
	}
	// A same-origin authenticated API request and a real MCP initialize must work.
	req, _ := http.NewRequest(http.MethodGet, h.control.URL+"/api/status", nil)
	req.Header.Set("Authorization", "Bearer "+integrationToken)
	req.Header.Set("Origin", h.control.URL)
	resp, err := h.control.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("valid same-origin request rejected: %d", resp.StatusCode)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	session, ctx := h.connectMCP(t)
	integrationResultText(t, integrationCall(t, ctx, session, "capture_status", map[string]any{}, false))
}

func TestIntegrationDefaultMutationGates(t *testing.T) {
	h := newIntegrationHarness(t, false)
	session, ctx := h.connectMCP(t)
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"message":"real upstream"}`)
	}))
	defer upstream.Close()
	status, _, _ := integrationRequest(t, h, http.MethodGet, upstream.URL+"/gate", "", nil)
	if status != http.StatusOK {
		t.Fatalf("initial capture failed: %d", status)
	}
	flow := integrationFlows(t, ctx, session, 1).Items[0]
	replay := integrationCall(t, ctx, session, "requests_replay", map[string]any{"flow_id": flow.ID, "confirm": true}, true)
	if !strings.Contains(integrationResultText(t, replay), "disabled") || hits.Load() != 1 {
		t.Fatal("default replay gate did not stop the upstream request")
	}
	u, _ := url.Parse(upstream.URL)
	rule := model.Rule{ID: "blocked-mock", Enabled: true, Match: model.RuleMatch{Hosts: []string{u.Host}}, Action: model.RuleAction{Mock: &model.MockResponse{Status: 503, Body: "mock"}}}
	rules := integrationCall(t, ctx, session, "rules_replace", map[string]any{"rules": []model.Rule{rule}}, true)
	if !strings.Contains(integrationResultText(t, rules), "disabled") {
		t.Fatal("default rules gate did not report disabled")
	}
	status, _, body := integrationRequest(t, h, http.MethodGet, upstream.URL+"/gate", "", nil)
	if status != http.StatusOK || hits.Load() != 2 || !strings.Contains(body, "real upstream") {
		t.Fatal("rejected rule affected subsequent traffic")
	}
	listed := integrationDecode[map[string]any](t, integrationCall(t, ctx, session, "rules_list", map[string]any{}, false))
	if listed["enabled"] != false || len(listed["rules"].([]any)) != 0 {
		t.Fatalf("rules changed despite disabled gate: %+v", listed)
	}
}

func TestIntegrationMCPProxyInvestigation(t *testing.T) {
	h := newIntegrationHarness(t, true)
	session, ctx := h.connectMCP(t)
	catalog, err := session.ListTools(ctx, &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(catalog.Tools))
	for _, tool := range catalog.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	wantNames := []string{"capture_configure", "capture_status", "flows_body", "flows_clear", "flows_compare", "flows_export_har", "flows_get", "flows_list", "flows_stats", "requests_replay", "rules_list", "rules_replace"}
	if !slices.Equal(names, wantNames) {
		t.Fatalf("discoverable tools=%v, want %v", names, wantNames)
	}
	if !strings.Contains(session.InitializeResult().Instructions, "untrusted evidence") {
		t.Fatal("client did not receive the captured-data trust boundary")
	}
	// Schema-invalid mutations must fail before changing capture state.
	integrationCall(t, ctx, session, "capture_configure", map[string]any{"enabled": "false"}, true)
	integrationCall(t, ctx, session, "flows_get", map[string]any{}, true)
	integrationCall(t, ctx, session, "flows_list", map[string]any{"limit": 201}, true)
	if !h.service.CaptureConfig().Enabled {
		t.Fatal("invalid schema input changed capture state")
	}

	const requestBody = `{"token":"request-body-secret-193","note":"visible-request-note"}`
	const responseBody = `{"access_token":"response-body-secret-472","nested":{"password":"nested-password-672"},"message":"visible-response-message"}`
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/sensitive" {
			data, _ := io.ReadAll(r.Body)
			if string(data) != requestBody || r.Header.Get("Authorization") != "Bearer header-auth-349" {
				http.Error(w, "request changed while forwarding", http.StatusBadRequest)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Set-Cookie", "session=cookie-secret-821; HttpOnly")
		_, _ = io.WriteString(w, responseBody)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	credentials := map[string]string{"Authorization": "Bearer header-auth-349", "X-API-Key": "header-api-key-293", "Content-Type": "application/json"}
	integrationCall(t, ctx, session, "capture_configure", map[string]any{
		"enabled": true, "filter": map[string]any{"hosts": []string{u.Host}, "methods": []string{"GET"}, "url_contains": "/kept"},
	}, false)
	for _, req := range []struct{ method, path string }{{"POST", "/kept"}, {"GET", "/skipped"}, {"GET", "/kept?access_token=url-token-572"}} {
		status, headers, body := integrationRequest(t, h, req.method, upstream.URL+req.path, "", credentials)
		if status != http.StatusOK || body != responseBody || !strings.Contains(headers.Get("Set-Cookie"), "cookie-secret-821") {
			t.Fatal("采集过滤改变了实际转发内容")
		}
	}
	flows := integrationFlows(t, ctx, session, 1)
	sourceID := flows.Items[0].ID
	if hits.Load() != 3 || flows.Items[0].Method != "GET" || !strings.Contains(flows.Items[0].URL, "/kept") {
		t.Fatal("capture filter did not retain only its matching request")
	}
	for _, name := range []string{"flows_list", "flows_stats"} {
		integrationResultText(t, integrationCall(t, ctx, session, name, map[string]any{}, false))
	}
	get := integrationCall(t, ctx, session, "flows_get", map[string]any{"id": sourceID}, false)
	if !strings.Contains(integrationResultText(t, get), "visible-response-message") {
		t.Fatal("真实 JSON 响应未保留诊断字段")
	}

	integrationCall(t, ctx, session, "capture_configure", map[string]any{"enabled": false}, false)
	status, _, _ := integrationRequest(t, h, http.MethodGet, upstream.URL+"/kept/paused", "", nil)
	if status != http.StatusOK || hits.Load() != 4 {
		t.Fatal("pausing recording stopped forwarding")
	}
	integrationFlows(t, ctx, session, 1)
	integrationCall(t, ctx, session, "capture_configure", map[string]any{"enabled": true, "filter": map[string]any{}}, false)
	status, _, _ = integrationRequest(t, h, http.MethodPost, upstream.URL+"/sensitive", requestBody, credentials)
	if status != http.StatusOK {
		t.Fatalf("raw request body/headers were not preserved upstream: %d", status)
	}
	flows = integrationFlows(t, ctx, session, 2)
	postID := flows.Items[0].ID
	postView := integrationCall(t, ctx, session, "flows_get", map[string]any{"id": postID}, false)
	if !strings.Contains(integrationResultText(t, postView), "visible-request-note") {
		t.Fatal("清除采集过滤或读取原始请求正文失败")
	}
	integrationResultText(t, integrationCall(t, ctx, session, "flows_export_har", map[string]any{}, false))

	// A confirmation failure and a cross-origin override must produce no request.
	integrationCall(t, ctx, session, "requests_replay", map[string]any{"flow_id": sourceID, "confirm": false}, true)
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { otherHits.Add(1) }))
	defer other.Close()
	integrationCall(t, ctx, session, "requests_replay", map[string]any{"flow_id": sourceID, "confirm": true, "overrides": map[string]any{"url": other.URL + "/credential-target"}}, true)
	if hits.Load() != 5 || otherHits.Load() != 0 {
		t.Fatal("replay confirmation/origin policy allowed a forbidden request")
	}
	replayed := integrationCall(t, ctx, session, "requests_replay", map[string]any{"flow_id": sourceID, "confirm": true}, false)
	integrationResultText(t, replayed)
	replayView := integrationDecode[map[string]any](t, replayed)
	if hits.Load() != 6 || replayView["parent_id"] != sourceID || replayView["source"] != "replay" || replayView["completed"] != true {
		t.Fatalf("replay did not create one completed linked request: hits=%d view=%+v", hits.Load(), replayView)
	}
	flows = integrationFlows(t, ctx, session, 3)
	replayID := replayView["id"].(string)
	integrationResultText(t, integrationCall(t, ctx, session, "flows_compare", map[string]any{"left_id": sourceID, "right_id": replayID}, false))

	// 启用限定主机的 Mock，确认匹配请求不会到达上游；规则列表返回原始配置。
	const mockBody = `{"token":"mock-body-secret-931","message":"synthetic-response"}`
	rule := model.Rule{
		ID: "simulate-unavailable", Enabled: true,
		Match: model.RuleMatch{Hosts: []string{u.Host}, Methods: []string{"GET"}, URLContains: "/mock"},
		Action: model.RuleAction{
			SetRequestHeaders: map[string]string{"Authorization": "Bearer rule-secret-362"},
			Mock:              &model.MockResponse{Status: http.StatusServiceUnavailable, Headers: map[string]string{"Content-Type": "application/json", "X-Mock-Source": "netlens"}, Body: mockBody},
		},
	}
	for _, name := range []string{"rules_replace", "rules_list"} {
		args := map[string]any{}
		if name == "rules_replace" {
			args["rules"] = []model.Rule{rule}
		}
		integrationResultText(t, integrationCall(t, ctx, session, name, args, false))
	}
	status, headers, body := integrationRequest(t, h, http.MethodGet, upstream.URL+"/mock", "", nil)
	if status != http.StatusServiceUnavailable || body != mockBody || headers.Get("X-Mock-Source") != "netlens" || hits.Load() != 6 {
		t.Fatal("enabled mock rule did not intercept its matching upstream request")
	}
	flows = integrationFlows(t, ctx, session, 4)
	if flows.Items[0].Source != "mock" || flows.Items[0].StatusCode != http.StatusServiceUnavailable {
		t.Fatal("mock response was not visible as a captured diagnostic flow")
	}
	integrationCall(t, ctx, session, "rules_replace", map[string]any{"rules": []model.Rule{}}, false)
	status, _, _ = integrationRequest(t, h, http.MethodGet, upstream.URL+"/mock", "", nil)
	if status != http.StatusOK || hits.Load() != 7 {
		t.Fatal("removing rules did not restore normal forwarding")
	}
	integrationFlows(t, ctx, session, 5)
	integrationCall(t, ctx, session, "flows_clear", map[string]any{"confirm": false}, true)
	integrationFlows(t, ctx, session, 5)
	cleared := integrationDecode[map[string]any](t, integrationCall(t, ctx, session, "flows_clear", map[string]any{"confirm": true}, false))
	if cleared["removed"] != float64(5) {
		t.Fatalf("clear removed count=%v, want 5", cleared["removed"])
	}
	integrationFlows(t, ctx, session, 0)
}

// Browsers omit HTTP's default port from Host/Origin even when the listener was
// explicitly configured as :80. No privileged port is bound in this test.
func TestIntegrationDefaultHTTPPortAuthority(t *testing.T) {
	h := newIntegrationHarness(t, false)
	h.service.mu.Lock()
	h.service.controlAddr = "127.0.0.1:80"
	h.service.mu.Unlock()
	handler := h.service.Handler()
	for _, tc := range []struct{ host, origin string }{
		{host: "127.0.0.1", origin: "http://127.0.0.1"},
		{host: "127.0.0.1:80", origin: "http://127.0.0.1"},
		{host: "127.0.0.1", origin: "http://127.0.0.1:80"},
	} {
		t.Run(tc.host+"/"+tc.origin, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+tc.host+"/api/status", nil)
			req.Header.Set("Authorization", "Bearer "+integrationToken)
			req.Header.Set("Origin", tc.origin)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if response.Code != http.StatusOK {
				t.Fatalf("equivalent default-port authorities rejected: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestIntegrationInvalidHeaderRulesPreserveExistingRules(t *testing.T) {
	h := newIntegrationHarness(t, true)
	session, ctx := h.connectMCP(t)
	original := model.Rule{
		ID: "preserve-existing", Enabled: true,
		Match:  model.RuleMatch{Hosts: []string{"127.0.0.1"}},
		Action: model.RuleAction{Mock: &model.MockResponse{Status: 503, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{}`}},
	}
	integrationCall(t, ctx, session, "rules_replace", map[string]any{"rules": []model.Rule{original}}, false)
	before := h.service.Rules()
	for _, tc := range []struct {
		name   string
		action model.RuleAction
	}{
		{name: "control byte in request header", action: model.RuleAction{SetRequestHeaders: map[string]string{"X-Debug": "prefix\x01suffix"}}},
		{name: "DEL in mock response header", action: model.RuleAction{Mock: &model.MockResponse{Status: 200, Headers: map[string]string{"X-Debug": "prefix\x7fsuffix"}, Body: `{}`}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			valid := original
			valid.ID = "would-replace-existing"
			invalid := model.Rule{ID: "invalid-header", Enabled: true, Match: original.Match, Action: tc.action}
			result := integrationCall(t, ctx, session, "rules_replace", map[string]any{"rules": []model.Rule{valid, invalid}}, true)
			if !strings.Contains(integrationResultText(t, result), "control character") {
				t.Fatal("invalid HTTP header value was not rejected explicitly")
			}
			if got := h.service.Rules(); !reflect.DeepEqual(got, before) {
				t.Fatalf("failed replacement changed existing rules: got=%+v want=%+v", got, before)
			}
		})
	}
}

func TestIntegrationReplayFailureReceiptWhenCapturePaused(t *testing.T) {
	h := newIntegrationHarness(t, true)
	session, ctx := h.connectMCP(t)
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"message":"source request"}`)
	}))
	defer upstream.Close()
	status, _, _ := integrationRequest(t, h, http.MethodGet, upstream.URL+"/failure-receipt", "", nil)
	if status != http.StatusOK {
		t.Fatalf("source capture failed: %d", status)
	}
	source := integrationFlows(t, ctx, session, 1).Items[0]
	integrationCall(t, ctx, session, "capture_configure", map[string]any{"enabled": false}, false)

	connect := integrationCall(t, ctx, session, "requests_replay", map[string]any{
		"flow_id": source.ID, "confirm": true, "overrides": map[string]any{"method": "CONNECT"},
	}, true)
	connectText := integrationResultText(t, connect)
	if !strings.Contains(connectText, "other than CONNECT") || strings.Contains(connectText, "flow_id=") || hits.Load() != 1 {
		t.Fatalf("CONNECT was not clearly rejected before attempting a request: %s", connectText)
	}

	// Close the actual captured upstream and retry the retained GET. There must
	// be an execution receipt even though capture pause prevents its retention.
	upstream.Close()
	failed := integrationCall(t, ctx, session, "requests_replay", map[string]any{"flow_id": source.ID, "confirm": true}, true)
	payload := integrationDecode[map[string]any](t, failed)
	message, _ := payload["error"].(string)
	_, afterID, found := strings.Cut(message, "flow_id=")
	newID, _, _ := strings.Cut(afterID, ";")
	if !found || newID == "" || newID == source.ID || !strings.Contains(message, "retained=false") {
		t.Fatalf("failed replay lost its identity/retention receipt: %s", message)
	}
	if _, retained := h.service.Store.Get(newID); retained {
		t.Fatal("replay result claims retained=false but flow exists")
	}
	integrationFlows(t, ctx, session, 1)
}
