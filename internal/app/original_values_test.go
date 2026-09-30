package app

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"netlens/internal/model"
)

func TestMCPOriginalAuthorizationAndCompleteBodyComparison(t *testing.T) {
	h := newIntegrationHarness(t, true)
	session, ctx := h.connectMCP(t)
	makeFlow := func(id, auth, tail string) model.Flow {
		body := []byte(`{"token":"body-secret","padding":"` + strings.Repeat("x", 16000) + `","tail":"` + tail + `"}`)
		return model.Flow{ID: id, Method: "POST", URL: "https://app.example.test/login?token=query-secret", Host: "app.example.test", Completed: true, RawAvailable: true,
			RequestHeaders: http.Header{"Authorization": {auth}, "Cookie": {"session=request-cookie-secret"}, "Content-Type": {"application/json"}}, RequestBody: model.Body{Data: body, Size: int64(len(body))},
			ResponseHeaders: http.Header{"Set-Cookie": {"session=response-cookie-secret; HttpOnly; Secure"}, "Location": {"https://app.example.test/?token=redirect-secret"}},
			ResponseBody:    model.Body{Data: []byte("plain-secret"), Size: 12}, Error: "original error with token=error-secret"}
	}
	left, right := makeFlow("left", "Bearer first-secret", "A"), makeFlow("right", "Bearer second-secret", "B")
	h.service.Store.Put(left)
	h.service.Store.Put(right)
	view := integrationResultText(t, integrationCall(t, ctx, session, "flows_get", map[string]any{"id": "left", "body_limit": 32768}, false))
	for _, value := range []string{"first-secret", "query-secret", "body-secret", "request-cookie-secret", "response-cookie-secret", "redirect-secret", "error-secret", "plain-secret"} {
		if !strings.Contains(view, value) {
			t.Fatalf("详情缺少真实值 %s", value)
		}
	}
	comparison := integrationDecode[map[string]any](t, integrationCall(t, ctx, session, "flows_compare", map[string]any{"left_id": "left", "right_id": "right"}, false))
	diffs := comparison["differences"].(map[string]any)
	data, _ := json.Marshal(diffs["request_headers"])
	if !strings.Contains(string(data), "first-secret") || !strings.Contains(string(data), "second-secret") || diffs["request_body"] == nil {
		t.Fatal("认证头变化或预览之后的正文变化被漏报")
	}
	checks := comparison["body_comparison"].(map[string]any)["request_body"].(map[string]any)
	if checks["captured_bytes_equal"] != false || checks["complete"] != true {
		t.Fatal("完整原始正文比较状态不正确")
	}
	har := integrationResultText(t, integrationCall(t, ctx, session, "flows_export_har", map[string]any{}, false))
	for _, value := range []string{"first-secret", "second-secret", "query-secret", "body-secret", "request-cookie-secret", "response-cookie-secret", "error-secret"} {
		if !strings.Contains(har, value) {
			t.Fatalf("HAR 缺少真实值 %s", value)
		}
	}
	rules := []model.Rule{{ID: "original-rule", Enabled: true, Match: model.RuleMatch{Hosts: []string{"app.example.test"}}, Action: model.RuleAction{SetRequestHeaders: map[string]string{"Authorization": "Bearer rule-secret"}, Mock: &model.MockResponse{Status: 200, Body: `{"token":"mock-secret"}`, Headers: map[string]string{"Set-Cookie": "session=rule-cookie"}}}}}
	integrationCall(t, ctx, session, "rules_replace", map[string]any{"rules": rules}, false)
	listed := integrationResultText(t, integrationCall(t, ctx, session, "rules_list", map[string]any{}, false))
	if !strings.Contains(listed, "rule-secret") || !strings.Contains(listed, "mock-secret") || !strings.Contains(listed, "rule-cookie") {
		t.Fatal("规则仍有脱敏值")
	}
	if strings.Contains(view+har+listed, "[REDACTED]") {
		t.Fatal("仍出现脱敏占位符")
	}
	left.RequestBody.Truncated = true
	h.service.Store.Put(left)
	comparison = integrationDecode[map[string]any](t, integrationCall(t, ctx, session, "flows_compare", map[string]any{"left_id": "left", "right_id": "right"}, false))
	if comparison["body_comparison"].(map[string]any)["request_body"].(map[string]any)["complete"] != false {
		t.Fatal("不完整采集被声称为完整比较")
	}
	left.Method, left.RequestBody = "CONNECT", model.Body{}
	h.service.Store.Put(left)
	comparison = integrationDecode[map[string]any](t, integrationCall(t, ctx, session, "flows_compare", map[string]any{"left_id": "left", "right_id": "right"}, false))
	if comparison["body_comparison"].(map[string]any)["request_body"].(map[string]any)["complete"] != false {
		t.Fatal("加密隧道被声称为完整明文比较")
	}
}
