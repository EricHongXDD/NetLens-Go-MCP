package capture

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"netlens/internal/model"
)

func TestMislabeledJSONRemainsStructuredAndRedacted(t *testing.T) {
	for _, contentType := range []string{"text/html;charset=utf-8", "text/plain; charset=utf-8"} {
		t.Run(contentType, func(t *testing.T) {
			data := []byte(`{"success":false,"message":"授权失败","token":"secret","nested":[{"password":"secret"}]}`)
			flow := model.Flow{ResponseHeaders: http.Header{"Content-Type": {contentType}}, ResponseBody: model.Body{Data: data, Size: int64(len(data))}}
			view := PublicFlow(flow, 4096)["response_body"].(map[string]any)
			if view["hidden"] != false || view["format"] != "json" || view["content_type_mismatch"] != true {
				t.Fatalf("错标 JSON 未生成带格式标记的结构化视图：%#v", view)
			}
			text := view["text"].(string)
			if !json.Valid([]byte(text)) || !strings.Contains(text, "授权失败") || strings.Contains(text, "secret") {
				t.Fatalf("诊断消息缺失或敏感字段未脱敏：%s", text)
			}
			if string(flow.ResponseBody.Data) != string(data) || flow.ResponseHeaders.Get("Content-Type") != contentType {
				t.Fatal("展示流程改变了转发内容")
			}
		})
	}
}

func TestMislabeledJSONWithBOM(t *testing.T) {
	data := append([]byte{0xef, 0xbb, 0xbf}, []byte(`{"message":"业务错误","token":"secret"}`)...)
	view := publicBody(model.Body{Data: data}, http.Header{"Content-Type": {"text/html"}}, 4096)
	if view["hidden"] != false || strings.Contains(view["text"].(string), "secret") || !strings.Contains(view["text"].(string), "业务错误") {
		t.Fatalf("BOM 导致错标 JSON 隐藏或未脱敏：%#v", view)
	}
}

func TestMislabeledJSONRejectsUnsafeOrIncompleteBodies(t *testing.T) {
	cases := []struct {
		name, data, encoding string
		truncated            bool
	}{
		{"html", `<html>{"token":"secret"}</html>`, "", false},
		{"text", `token=secret`, "", false},
		{"scalar", `"secret"`, "", false},
		{"malformed", `{"token":"secret"`, "", false},
		{"trailing", `{"ok":true}{"token":"secret"}`, "", false},
		{"truncated", `{"token":"secret"}`, "", true},
		{"compressed", `{"token":"secret"}`, "gzip", false},
		{"binary", "\xff\x00secret", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{"Content-Type": {"text/html"}, "Content-Encoding": {tc.encoding}}
			view := publicBody(model.Body{Data: []byte(tc.data), Size: int64(len(tc.data)), Truncated: tc.truncated}, headers, 4096)
			if view["hidden"] != true {
				t.Fatalf("不支持的正文被展示：%#v", view)
			}
			if _, ok := view["text"]; ok {
				t.Fatal("隐藏正文仍包含文本")
			}
		})
	}
}
