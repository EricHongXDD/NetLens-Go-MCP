//go:build windows

package desktop

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"netlens/internal/model"
	"netlens/internal/systemproxy"
)

type isolatedProxyBackend struct{ settings systemproxy.Settings }

func (b *isolatedProxyBackend) Read() (systemproxy.Settings, error) { return b.settings, nil }
func (b *isolatedProxyBackend) Write(s systemproxy.Settings) error  { b.settings = s; return nil }
func (*isolatedProxyBackend) Lock() (func(), error)                 { return func() {}, nil }
func isolatedProxyManager(dir string) *systemproxy.Manager {
	return systemproxy.New(filepath.Join(dir, "isolated-proxy-backup.json"), &isolatedProxyBackend{settings: systemproxy.Settings{Flags: 9, PAC: "https://example.invalid/proxy.pac"}})
}

func writeTestResult(path string, testErr error) error {
	result := map[string]any{"success": testErr == nil, "version": model.Version,
		"checks": []string{"native_window", "proxy_capture", "redacted_details", "native_filtering", "pause_resume", "har_export", "no_web_ui", "service_shutdown", "proxy_restore", "mcp_config", "ai_guide"}}
	if testErr != nil {
		result["error"] = testErr.Error()
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		return err
	}
	return testErr
}

func (w *window) selfTest() error {
	if w.mw.Handle() == 0 || w.table.Handle() == 0 || w.tabs.Pages().Len() != 5 || w.runtime == nil {
		return errors.New("native controls or shared service were not created")
	}
	// 验证新操作的恢复与导出逻辑，但不改变真实系统代理或信任存储。
	proxyBefore, err := w.systemProxy.Status()
	if err != nil {
		return err
	}
	s := w.runtime.Service
	status := s.Status()
	proxyAddress := status["proxy_addr"].(string)
	controlAddress := status["control_addr"].(string)
	if err := w.systemProxy.Enable(proxyAddress); err != nil {
		return err
	}
	w.proxyManaged = true
	if state, err := w.systemProxy.Status(); err != nil || !state.Owned {
		return errors.New("system proxy manager did not take ownership")
	}
	config := s.ClientConfig()
	if !json.Valid([]byte(config)) || !strings.Contains(config, controlAddress) {
		return errors.New("MCP configuration is invalid")
	}
	guidePath := filepath.Join(w.cfg.DataDir, "NetLens-AI-Guide.private.md")
	if err := w.saveAIGuide(guidePath); err != nil {
		return err
	}
	guide, err := os.ReadFile(guidePath)
	if err != nil || !strings.Contains(string(guide), "requests_replay") || !strings.Contains(string(guide), controlAddress) {
		return errors.New("AI guide export failed")
	}
	proxyURL, _ := url.Parse("http://" + proxyAddress)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	origin := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		io.WriteString(rw, `{"ok":true,"api_key":"desktop-fixture-secret"}`)
	}))
	defer origin.Close()
	request := func(path string) error {
		req, _ := http.NewRequest(http.MethodGet, origin.URL+path, nil)
		req.Header.Set("Authorization", "Bearer desktop-fixture-secret")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("proxy response status: %d", resp.StatusCode)
		}
		return nil
	}
	if err := request("/health?token=desktop-fixture-secret"); err != nil {
		return err
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		flows := s.Store.Query(model.Query{Limit: 100})
		if len(flows.Items) == 1 && flows.Items[0].Completed {
			break
		}
		if time.Now().After(deadline) {
			return errors.New("proxy capture did not complete")
		}
		time.Sleep(10 * time.Millisecond)
	}
	w.refresh()
	if w.model.RowCount() != 1 {
		return errors.New("captured flow did not appear in native table")
	}
	w.table.SetCurrentIndex(0)
	w.selectFlow()
	detail := w.json.Text() + w.request.Text() + w.response.Text()
	if !strings.Contains(detail, "REDACTED") || strings.Contains(detail, "desktop-fixture-secret") {
		return errors.New("native details did not redact fixture credentials")
	}
	w.url.SetText("/not-matched")
	w.applyFilter()
	if w.model.RowCount() != 0 {
		return errors.New("native filter did not change table contents")
	}
	w.resetFilter()
	if w.model.RowCount() != 1 {
		return errors.New("native filter reset failed")
	}
	w.toggleCapture()
	if s.CaptureConfig().Enabled {
		return errors.New("native pause did not pause shared capture")
	}
	if err := request("/paused"); err != nil {
		return err
	}
	if s.Store.Query(model.Query{}).Matched != 1 {
		return errors.New("paused capture retained a new request")
	}
	w.toggleCapture()
	if err := request("/resumed"); err != nil {
		return err
	}
	deadline = time.Now().Add(3 * time.Second)
	for s.Store.Query(model.Query{}).Matched != 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Store.Query(model.Query{}).Matched != 2 {
		return errors.New("native resume did not resume capture")
	}
	path := filepath.Join(w.cfg.DataDir, "desktop-self-test.har")
	if err := w.saveHAR(path); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil || !json.Valid(data) || strings.Contains(string(data), "desktop-fixture-secret") {
		return errors.New("desktop HAR export failed validation")
	}
	controlTransport := &http.Transport{}
	defer controlTransport.CloseIdleConnections()
	controlClient := &http.Client{Transport: controlTransport, Timeout: time.Second}
	response, err := controlClient.Get("http://" + controlAddress + "/")
	if err != nil {
		return err
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNotFound {
		return errors.New("control port still exposes Web UI")
	}
	w.stopService()
	if after, err := w.systemProxy.Status(); err != nil || after.Current != proxyBefore.Current || after.HasBackup {
		return errors.New("stopping desktop did not restore original proxy")
	}
	for _, address := range []string{proxyAddress, controlAddress} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return fmt.Errorf("desktop service did not release %s: %w", address, err)
		}
		listener.Close()
	}
	return nil
}
