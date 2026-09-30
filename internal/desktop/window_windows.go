//go:build windows

// Package desktop 提供 Windows 原生控件界面，直接访问共享采集服务。
package desktop

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/lxn/walk"
	d "github.com/lxn/walk/declarative"

	"netlens/internal/app"
	"netlens/internal/capture"
	"netlens/internal/model"
)

type window struct {
	mw            *walk.MainWindow
	cfg           app.Config
	runtime       *app.Runtime
	settings      *walk.Composite
	proxyAddr     *walk.LineEdit
	controlAddr   *walk.LineEdit
	mitm          *walk.CheckBox
	rules         *walk.CheckBox
	replay        *walk.CheckBox
	persist       *walk.CheckBox
	serverButton  *walk.PushButton
	pauseButton   *walk.PushButton
	auto          *walk.CheckBox
	status        *walk.Label
	notice        *walk.Label
	hosts         *walk.LineEdit
	url           *walk.LineEdit
	method        *walk.ComboBox
	statusFilter  *walk.ComboBox
	slow          *walk.NumberEdit
	errorsOnly    *walk.CheckBox
	table         *walk.TableView
	model         *flowModel
	tabs          *walk.TabWidget
	overview      *walk.TextEdit
	request       *walk.TextEdit
	response      *walk.TextEdit
	json          *walk.TextEdit
	stats         *walk.TextEdit
	next          *walk.PushButton
	previous      *walk.PushButton
	pageLabel     *walk.Label
	query         model.Query
	nextCursor    uint64
	cursors       []uint64
	selectedID    string
	baselineID    string
	detail        any
	refreshing    bool
	replayBusy    bool
	closing       atomic.Bool
	refreshQueued atomic.Bool
	done          chan struct{}
}

type flowModel struct {
	walk.TableModelBase
	items []model.Summary
}

func (m *flowModel) RowCount() int { return len(m.items) }

func (m *flowModel) Value(row, col int) any {
	f := m.items[row]
	switch col {
	case 0:
		return f.Sequence
	case 1:
		return f.Method
	case 2:
		if !f.Completed {
			return "进行中"
		}
		if f.StatusCode == 0 {
			return "隧道/错误"
		}
		return f.StatusCode
	case 3:
		return f.URL
	case 4:
		return fmt.Sprintf("%.1f ms", f.DurationMS)
	case 5:
		return fmt.Sprintf("%.1f KB", float64(f.RequestBytes+f.ResponseBytes)/1024)
	case 6:
		return f.StartedAt.Local().Format("15:04:05")
	}
	return ""
}

func Run(cfg app.Config, testResult string) error {
	w := &window{cfg: cfg, model: &flowModel{}, query: model.Query{Limit: 100}, done: make(chan struct{})}
	if err := w.create(); err != nil {
		return err
	}
	defer w.mw.Dispose()
	w.mw.Closing().Attach(func(_ *bool, _ walk.CloseReason) {
		if w.closing.CompareAndSwap(false, true) {
			close(w.done)
			w.stopService()
		}
	})
	if err := w.startService(); err != nil {
		if testResult != "" {
			return writeTestResult(testResult, err)
		}
		w.fail(err)
	}
	w.mw.Show()
	if testResult != "" {
		// 测试在原生窗口消息循环内执行，覆盖真实控件和共享代理服务。
		var result error
		w.mw.Synchronize(func() {
			result = writeTestResult(testResult, w.selfTest())
			w.mw.Close()
		})
		w.mw.Run()
		return result
	}
	go w.refreshLoop()
	w.mw.Run()
	return nil
}

func (w *window) create() error {
	mono := d.Font{Family: "Consolas", PointSize: 10}
	textPage := func(title string, target **walk.TextEdit) d.TabPage {
		return d.TabPage{Title: title, Layout: d.VBox{}, Children: []d.Widget{
			d.TextEdit{AssignTo: target, ReadOnly: true, VScroll: true, HScroll: true, Font: mono, MaxLength: 1 << 20},
		}}
	}
	return (d.MainWindow{
		AssignTo: &w.mw, Title: "NetLens " + model.Version + " · 网络流量调试",
		Size: d.Size{Width: 1380, Height: 850}, MinSize: d.Size{Width: 1100, Height: 700}, Font: d.Font{Family: "Microsoft YaHei UI", PointSize: 10},
		Layout: d.VBox{Margins: d.Margins{Left: 16, Top: 14, Right: 16, Bottom: 12}, Spacing: 10},
		Children: []d.Widget{
			d.Composite{Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
				d.Label{Text: "NetLens", Font: d.Font{Family: "Segoe UI", PointSize: 22, Bold: true}},
				d.Label{Text: "HTTP / HTTPS 流量调试", StretchFactor: 1},
				d.Label{AssignTo: &w.status, Text: "服务尚未启动"},
			}},
			d.Composite{AssignTo: &w.settings, Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
				d.Label{Text: "代理"}, d.LineEdit{AssignTo: &w.proxyAddr, Text: w.cfg.ProxyAddr, MinSize: d.Size{Width: 145, Height: 0}, MaxSize: d.Size{Width: 185, Height: 0}},
				d.Label{Text: "MCP / API"}, d.LineEdit{AssignTo: &w.controlAddr, Text: w.cfg.ControlAddr, MinSize: d.Size{Width: 145, Height: 0}, MaxSize: d.Size{Width: 185, Height: 0}},
				d.CheckBox{AssignTo: &w.mitm, Text: "HTTPS 解密", Checked: w.cfg.MITM, ToolTipText: "测试客户端需信任本实例 CA"},
				d.CheckBox{AssignTo: &w.rules, Text: "启用规则", Checked: w.cfg.AllowRules},
				d.CheckBox{AssignTo: &w.replay, Text: "启用重放", Checked: w.cfg.AllowReplay},
				d.CheckBox{AssignTo: &w.persist, Text: "保存脱敏日志", Checked: w.cfg.Persist},
			}},
			d.Composite{Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
				d.PushButton{AssignTo: &w.serverButton, Text: "启动服务", OnClicked: w.toggleService},
				d.PushButton{AssignTo: &w.pauseButton, Text: "暂停采集", OnClicked: w.toggleCapture},
				d.PushButton{Text: "清空记录", OnClicked: w.clearFlows},
				d.PushButton{Text: "导出 HAR", OnClicked: w.exportHAR},
				d.PushButton{Text: "规则管理", OnClicked: w.manageRules},
				d.PushButton{Text: "MCP 连接", OnClicked: w.connectionInfo},
				d.HSpacer{},
				d.CheckBox{AssignTo: &w.auto, Text: "每秒刷新", Checked: true},
				d.PushButton{Text: "刷新", OnClicked: w.refresh},
			}},
			d.GroupBox{Title: "查找流量", Layout: d.VBox{Spacing: 8}, Children: []d.Widget{
				d.Composite{Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
					d.Label{Text: "主机"}, d.LineEdit{AssignTo: &w.hosts, CueBanner: "example.com, *.example.com", StretchFactor: 1},
					d.Label{Text: "URL"}, d.LineEdit{AssignTo: &w.url, CueBanner: "路径或查询字符串", StretchFactor: 2},
					d.ComboBox{AssignTo: &w.method, Model: []string{"全部方法", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT"}, CurrentIndex: 0, MinSize: d.Size{Width: 100, Height: 0}},
					d.ComboBox{AssignTo: &w.statusFilter, Model: []string{"全部状态", "2xx", "3xx", "4xx", "5xx"}, CurrentIndex: 0, MinSize: d.Size{Width: 95, Height: 0}},
					d.Label{Text: "慢于"}, d.NumberEdit{AssignTo: &w.slow, MinValue: 0, MaxValue: 600000, Suffix: " ms", MinSize: d.Size{Width: 105, Height: 0}},
				}},
				d.Composite{Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
					d.CheckBox{AssignTo: &w.errorsOnly, Text: "只看错误"},
					d.PushButton{Text: "筛选", OnClicked: w.applyFilter},
					d.PushButton{Text: "重置", OnClicked: w.resetFilter},
					d.HSpacer{},
					d.PushButton{Text: "同时应用为采集条件", OnClicked: w.applyCaptureFilter},
					d.PushButton{Text: "采集所有主机", OnClicked: w.clearCaptureFilter},
				}},
			}},
			d.HSplitter{StretchFactor: 1, Children: []d.Widget{
				d.Composite{StretchFactor: 3, Layout: d.VBox{MarginsZero: true}, Children: []d.Widget{
					d.TableView{AssignTo: &w.table, Model: w.model, AlternatingRowBG: true, ColumnsSizable: true, NotSortableByHeaderClick: true,
						OnCurrentIndexChanged: w.selectFlow, Columns: []d.TableViewColumn{
							{Title: "序号", Width: 55}, {Title: "方法", Width: 75}, {Title: "状态", Width: 90},
							{Title: "URL", Width: 380}, {Title: "耗时", Width: 90}, {Title: "大小", Width: 80}, {Title: "时间", Width: 85},
						}, StyleCell: func(style *walk.CellStyle) {
							if style.Row() >= 0 && style.Row() < len(w.model.items) && style.Col() == 2 && w.model.items[style.Row()].StatusCode >= 400 {
								style.TextColor = walk.RGB(180, 35, 45)
							}
						}},
					d.Composite{Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
						d.Label{AssignTo: &w.pageLabel, Text: "暂无记录", StretchFactor: 1},
						d.PushButton{Text: "最新", OnClicked: func() { w.query.BeforeSequence = 0; w.cursors = nil; w.refresh() }},
						d.PushButton{AssignTo: &w.previous, Text: "上一页", OnClicked: w.previousPage},
						d.PushButton{AssignTo: &w.next, Text: "下一页", OnClicked: w.nextPage},
					}},
				}},
				d.Composite{StretchFactor: 2, Layout: d.VBox{MarginsZero: true}, Children: []d.Widget{
					d.TabWidget{AssignTo: &w.tabs, Pages: []d.TabPage{
						textPage("概览", &w.overview), textPage("请求", &w.request), textPage("响应", &w.response), textPage("JSON", &w.json), textPage("统计", &w.stats),
					}},
					d.Composite{Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
						d.PushButton{Text: "复制详情", OnClicked: w.copyDetail},
						d.PushButton{Text: "设为基准", OnClicked: w.setBaseline},
						d.PushButton{Text: "对比", OnClicked: w.compare},
						d.PushButton{Text: "重放", OnClicked: w.replaySelected},
					}},
				}},
			}},
			d.Label{AssignTo: &w.notice, Text: "将待调试应用的代理设为 127.0.0.1:8080，流量会显示在列表中。详情自动脱敏。"},
		},
	}).Create()
}

func (w *window) startService() error {
	w.cfg.ProxyAddr, w.cfg.ControlAddr = strings.TrimSpace(w.proxyAddr.Text()), strings.TrimSpace(w.controlAddr.Text())
	w.cfg.MITM, w.cfg.AllowRules = w.mitm.Checked(), w.rules.Checked()
	w.cfg.AllowReplay, w.cfg.Persist = w.replay.Checked(), w.persist.Checked()
	r, err := app.Start(context.Background(), w.cfg, log.New(io.Discard, "", 0))
	if err != nil {
		return fmt.Errorf("无法启动采集服务，请检查端口是否被占用或使用其他端口：%w", err)
	}
	w.runtime = r
	w.replayBusy = false
	w.selectedID, w.baselineID, w.detail = "", "", nil
	w.query.BeforeSequence, w.cursors = 0, nil
	w.settings.SetEnabled(false)
	w.serverButton.SetText("停止服务")
	w.pauseButton.SetEnabled(true)
	w.refresh()
	return nil
}

func (w *window) stopService() {
	if w.runtime != nil {
		_ = w.runtime.Close()
		w.runtime = nil
	}
	if w.closing.Load() {
		return
	}
	w.settings.SetEnabled(true)
	w.serverButton.SetText("启动服务")
	w.pauseButton.SetEnabled(false)
	w.status.SetText("服务已停止")
	w.notice.SetText("修改上方配置后点击“启动服务”，开始新的采集会话。")
}

func (w *window) toggleService() {
	if w.runtime != nil {
		if walk.MsgBox(w.mw, "停止采集服务", "停止服务会结束当前采集会话。再次启动会创建空的内存记录。是否继续？", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes {
			w.stopService()
		}
		return
	}
	if err := w.startService(); err != nil {
		w.fail(err)
	}
}

func (w *window) refreshLoop() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-w.done:
			return
		case <-ticker.C:
			if w.refreshQueued.CompareAndSwap(false, true) {
				w.mw.Synchronize(func() {
					defer w.refreshQueued.Store(false)
					if !w.closing.Load() && w.auto.Checked() {
						w.refresh()
					}
				})
			}
		}
	}
}

func (w *window) refresh() {
	if w.runtime == nil || w.refreshing {
		return
	}
	select {
	case <-w.runtime.Done():
		err := w.runtime.Err()
		w.stopService()
		if err != nil {
			w.fail(err)
		}
		return
	default:
	}
	w.refreshing = true
	s := w.runtime.Service
	q := s.Store.Query(w.query)
	w.model.items = q.Items
	w.model.PublishRowsReset()
	w.nextCursor = q.NextBeforeSequence
	w.next.SetEnabled(w.nextCursor != 0)
	w.previous.SetEnabled(len(w.cursors) > 0)
	w.pageLabel.SetText(fmt.Sprintf("显示 %d 条 · 本页范围匹配 %d 条", len(q.Items), q.Matched))
	index := -1
	for i, item := range q.Items {
		if item.ID == w.selectedID {
			index = i
			break
		}
	}
	w.table.SetCurrentIndex(index)
	w.refreshing = false
	w.selectFlow()
	w.stats.SetText(pretty(s.Store.Stats(w.query.Filter)))
	status := s.Status()
	state := "采集中"
	if !s.CaptureConfig().Enabled {
		state = "已暂停记录"
		w.pauseButton.SetText("恢复采集")
	} else {
		w.pauseButton.SetText("暂停采集")
	}
	w.status.SetText(fmt.Sprintf("%s · 代理 %s", state, status["proxy_addr"]))
}

func (w *window) selectFlow() {
	if w.refreshing || w.runtime == nil {
		return
	}
	index := w.table.CurrentIndex()
	if index < 0 || index >= len(w.model.items) {
		w.selectedID, w.detail = "", nil
		w.overview.SetText("选择左侧流量，查看脱敏请求、响应和时间信息。\r\n\r\n暂无流量时，请检查待调试应用的代理配置。")
		w.request.SetText("")
		w.response.SetText("")
		w.json.SetText("")
		return
	}
	w.selectedID = w.model.items[index].ID
	detail, err := w.runtime.Service.Get(app.GetInput{ID: w.selectedID, BodyLimit: 8192})
	if err != nil {
		w.overview.SetText("该记录已被内存预算淘汰，请刷新列表。")
		w.request.SetText("")
		w.response.SetText("")
		w.json.SetText("")
		w.detail = nil
		return
	}
	w.detail = detail
	flow := detail.(map[string]any)
	brief := make(map[string]any)
	for _, key := range []string{"id", "sequence", "method", "url", "host", "status_code", "completed", "error", "source", "timings", "rule_ids", "parent_id"} {
		if value, ok := flow[key]; ok {
			brief[key] = value
		}
	}
	w.overview.SetText(pretty(brief))
	w.request.SetText("请求头\r\n" + pretty(flow["request_headers"]) + "\r\n\r\n请求正文\r\n" + pretty(flow["request_body"]))
	w.response.SetText("响应头\r\n" + pretty(flow["response_headers"]) + "\r\n\r\n响应正文\r\n" + pretty(flow["response_body"]))
	w.json.SetText(pretty(detail))
}

func (w *window) readFilter() (model.Filter, error) {
	f := model.Filter{URLContains: strings.TrimSpace(w.url.Text()), MinDurationMS: w.slow.Value(), OnlyErrors: w.errorsOnly.Checked()}
	for _, host := range strings.Split(w.hosts.Text(), ",") {
		if host = strings.TrimSpace(host); host != "" {
			f.Hosts = append(f.Hosts, host)
		}
	}
	if w.method.CurrentIndex() > 0 {
		f.Methods = []string{w.method.Text()}
	}
	if w.statusFilter.CurrentIndex() > 0 {
		n, _ := strconv.Atoi(w.statusFilter.Text()[:1])
		f.StatusMin, f.StatusMax = n*100, n*100+99
	}
	return f, capture.ValidateFilter(f)
}

func (w *window) applyFilter() {
	f, err := w.readFilter()
	if err != nil {
		w.fail(err)
		return
	}
	w.query = model.Query{Filter: f, Limit: 100}
	w.cursors = nil
	w.refresh()
}

func (w *window) resetFilter() {
	w.hosts.SetText("")
	w.url.SetText("")
	w.method.SetCurrentIndex(0)
	w.statusFilter.SetCurrentIndex(0)
	w.slow.SetValue(0)
	w.errorsOnly.SetChecked(false)
	w.applyFilter()
}

func (w *window) applyCaptureFilter() {
	if !w.requireService() {
		return
	}
	f, err := w.readFilter()
	if err == nil {
		_, err = w.runtime.Service.Configure(app.CaptureInput{Filter: &f})
	}
	if err != nil {
		w.fail(err)
		return
	}
	w.notice.SetText("采集条件已更新，将只记录符合条件的后续流量；代理继续转发其他请求。")
	w.refresh()
}

func (w *window) clearCaptureFilter() {
	if !w.requireService() {
		return
	}
	_, err := w.runtime.Service.Configure(app.CaptureInput{Filter: &model.Filter{}})
	if err != nil {
		w.fail(err)
		return
	}
	w.notice.SetText("已清除采集条件，将采集所有后续流量。")
}

func (w *window) toggleCapture() {
	if !w.requireService() {
		return
	}
	enabled := !w.runtime.Service.CaptureConfig().Enabled
	_, err := w.runtime.Service.Configure(app.CaptureInput{Enabled: &enabled})
	if err != nil {
		w.fail(err)
		return
	}
	w.refresh()
}

func (w *window) nextPage() {
	if w.nextCursor == 0 {
		return
	}
	w.cursors = append(w.cursors, w.query.BeforeSequence)
	w.query.BeforeSequence = w.nextCursor
	w.refresh()
}

func (w *window) previousPage() {
	if len(w.cursors) == 0 {
		return
	}
	w.query.BeforeSequence = w.cursors[len(w.cursors)-1]
	w.cursors = w.cursors[:len(w.cursors)-1]
	w.refresh()
}

func (w *window) requireService() bool {
	if w.runtime == nil {
		w.notice.SetText("请先启动采集服务。")
		return false
	}
	return true
}

func (w *window) fail(err error) {
	walk.MsgBox(w.mw, "NetLens", err.Error(), walk.MsgBoxIconError)
}

func pretty(value any) string {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return "无法显示该数据"
	}
	return strings.ReplaceAll(string(data), "\n", "\r\n")
}
