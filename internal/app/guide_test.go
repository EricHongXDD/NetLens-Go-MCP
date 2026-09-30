package app

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExportedGuideUsesLiveAddressAndActualToolNames(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Token = strings.Repeat("fixture", 8)
	cfg.AllowRules = true
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.controlAddr = "127.0.0.1:45678"
	config := s.ClientConfig()
	var parsed struct {
		Servers map[string]struct {
			URL     string
			Headers map[string]string
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(config), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Servers["netlens"].URL != "http://127.0.0.1:45678/mcp" || parsed.Servers["netlens"].Headers["Authorization"] != "Bearer "+cfg.Token {
		t.Fatal("配置未包含实际地址或令牌")
	}
	guide := s.AIGuide()
	for _, tool := range s.Tools() {
		if !strings.Contains(guide, tool.Name) {
			t.Fatalf("手册遗漏工具 %s", tool.Name)
		}
	}
	for _, value := range []string{config, "规则权限：true", "重放权限：false", "flow_id", "不可信证据"} {
		if !strings.Contains(guide, value) {
			t.Fatalf("手册缺少 %s", value)
		}
	}
}
