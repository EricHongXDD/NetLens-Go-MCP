package app

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netlens/internal/model"
)

func TestFullBodyThroughProxyMCPAndAPI(t *testing.T) {
	h := newIntegrationHarness(t, false)
	session, ctx := h.connectMCP(t)
	data := `<html><body>业务失败：smallCode 已使用；` + strings.Repeat("完整正文🙂", 8000) + ` END-OF-BODY token=fixture-secret</body></html>`
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		io.WriteString(w, data)
	}))
	defer origin.Close()
	status, _, forwarded := integrationRequest(t, h, http.MethodPost, origin.URL, "smallCode=same-code", map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if status != 200 || forwarded != data {
		t.Fatal("完整正文读取改变了代理转发")
	}
	id := integrationFlows(t, ctx, session, 1).Items[0].ID
	var joined strings.Builder
	for offset := 0; ; {
		result := integrationCall(t, ctx, session, "flows_body", map[string]any{"id": id, "offset": offset, "limit": 32768}, false)
		b, _ := json.Marshal(result.StructuredContent)
		if len(b) > 256<<10 {
			t.Fatal("正文分页突破 MCP 输出预算")
		}
		page := integrationDecode[struct {
			Text       string `json:"text"`
			NextOffset int    `json:"next_offset"`
			HasMore    bool   `json:"has_more"`
			Truncated  bool   `json:"capture_truncated"`
		}](t, result)
		if page.Truncated {
			t.Fatal("默认采集预算仍截断大于 64 KiB 的错误正文")
		}
		joined.WriteString(page.Text)
		if !page.HasMore {
			break
		}
		offset = page.NextOffset
	}
	if joined.String() != data {
		t.Fatal("实际 HTML 正文未完整返回")
	}
	request := integrationDecode[map[string]any](t, integrationCall(t, ctx, session, "flows_body", map[string]any{"id": id, "side": "request"}, false))
	if request["text"] != "smallCode=same-code" || request["redaction"] != "none" {
		t.Fatal("请求正文未原样读取")
	}
	for _, args := range []map[string]any{{"id": id, "side": "bad"}, {"id": id, "offset": -1}, {"id": id, "offset": len(data) + 1}, {"id": id, "limit": 32769}, {"id": "missing"}} {
		integrationCall(t, ctx, session, "flows_body", args, true)
	}
	url := h.control.URL + "/api/body?id=" + id + "&side=request"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("完整正文 API 未要求访问令牌")
	}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+integrationToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "smallCode=same-code") {
		t.Fatalf("已授权 API 未返回完整正文：%s", b)
	}
	h.service.Store.Put(model.Flow{ID: "tunnel", Completed: true})
	if _, err := h.service.Body(BodyInput{ID: "tunnel"}); err == nil {
		t.Fatal("未采集的隧道伪装为完整空正文")
	}
	// 最坏的 JSON 转义也必须保持单页结果在工具预算内。
	h.service.Store.Put(model.Flow{ID: "escaped", Completed: true, RawAvailable: true, ResponseBody: model.Body{Data: []byte(strings.Repeat("\x01", 32768))}})
	integrationCall(t, ctx, session, "flows_body", map[string]any{"id": "escaped", "limit": 32768}, false)
}
