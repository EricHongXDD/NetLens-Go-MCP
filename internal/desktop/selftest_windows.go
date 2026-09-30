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

	"github.com/lxn/walk"
	"github.com/lxn/win"

	"netlens/internal/model"
	"netlens/internal/proxy"
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
		"checks": []string{"native_window", "native_layout", "styled_controls", "upstream_chain", "proxy_capture", "redacted_details", "native_filtering", "pause_resume", "har_export", "no_web_ui", "service_shutdown", "proxy_restore", "mcp_config", "ai_guide"}}
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
	if err := w.verifyLayoutAndControls(); err != nil {
		return err
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
	upstreamProxy, err := proxy.New(proxy.Options{})
	if err != nil {
		return err
	}
	defer upstreamProxy.Close()
	upstream := httptest.NewServer(upstreamProxy)
	upstreamProxy.SetListenAddr(upstream.Listener.Addr())
	defer upstream.Close()
	// 关闭的本地端口模拟 Clash 未启动，不得产生系统代理备份或修改路由。
	unavailable := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	unavailableAddress := unavailable.URL
	unavailable.Close()
	if err := w.activateSystemProxy(unavailableAddress, proxyAddress); err == nil {
		return errors.New("unavailable upstream accepted")
	}
	if state, err := w.systemProxy.Status(); err != nil || state.Current != proxyBefore.Current || state.HasBackup || s.Proxy.Upstream() != "" {
		return errors.New("failed upstream check changed system proxy or routing")
	}
	if err := w.activateSystemProxy(upstream.URL, proxyAddress); err != nil {
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

// 检查关键操作真实可见且未超出任何父控件，防止只通过消息循环却仍被裁切。
func (w *window) verifyLayoutAndControls() error {
	var visit func(walk.Window) error
	visit = func(window walk.Window) error {
		if !window.Visible() {
			return nil
		}
		if _, ok := window.(walk.Widget); ok {
			var rect win.RECT
			win.GetWindowRect(window.Handle(), &rect)
			if rect.Right > rect.Left && rect.Bottom > rect.Top {
				for parent := win.GetParent(window.Handle()); parent != 0; parent = win.GetParent(parent) {
					var bounds win.RECT
					win.GetWindowRect(parent, &bounds)
					if rect.Left < bounds.Left-1 || rect.Top < bounds.Top-1 || rect.Right > bounds.Right+1 || rect.Bottom > bounds.Bottom+1 {
						return fmt.Errorf("control %T %q is clipped by %s: %v outside %v", window, window.Name(), windowClass(parent), rect, bounds)
					}
				}
			}
		}
		if container, ok := window.(walk.Container); ok {
			for i := 0; i < container.Children().Len(); i++ {
				if err := visit(container.Children().At(i)); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(w.mw); err != nil {
		return err
	}
	// 原生键盘选择和开关操作必须继续工作，重绘不能替代真实控件语义。
	w.method.SetCurrentIndex(0)
	win.SendMessage(w.method.Handle(), win.WM_KEYDOWN, win.VK_DOWN, 0)
	if w.method.CurrentIndex() != 1 {
		return errors.New("dropdown keyboard navigation failed")
	}
	w.method.SetCurrentIndex(0)
	before := w.auto.Checked()
	win.SendMessage(w.auto.Handle(), win.BM_CLICK, 0, 0)
	if w.auto.Checked() == before {
		return errors.New("styled switch did not toggle")
	}
	w.auto.SetChecked(before)
	w.tabs.SetCurrentIndex(1)
	if w.tabs.CurrentIndex() != 1 || !w.request.Visible() {
		return errors.New("styled detail tabs did not switch")
	}
	w.tabs.SetCurrentIndex(0)
	w.slow.SetText("NaN")
	if _, err := w.readFilter(); err == nil {
		return errors.New("invalid duration accepted")
	}
	w.slow.SetText("100.5")
	if filter, err := w.readFilter(); err != nil || filter.MinDurationMS != 100.5 {
		return errors.New("duration filter failed")
	}
	w.slow.SetText("0")
	return nil
}
