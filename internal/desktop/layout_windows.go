//go:build windows

package desktop

import (
	"github.com/lxn/walk"
	d "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
	"netlens/internal/model"
	"unsafe"
)

// 配色取自 LabRemote 的深蓝工作区、绿色主操作与青色辅助操作。
var (
	bg          = walk.RGB(7, 16, 28)
	panel       = walk.RGB(12, 23, 38)
	panelRaised = walk.RGB(17, 30, 46)
	line        = walk.RGB(34, 51, 74)
	ink         = walk.RGB(220, 232, 243)
	muted       = walk.RGB(135, 151, 172)
	green       = walk.RGB(78, 225, 160)
	cyan        = walk.RGB(66, 199, 233)
	danger      = walk.RGB(255, 113, 130)
)

func brush(color walk.Color) d.Brush { return d.SolidColorBrush{Color: color} }
func label(text string) d.Label      { return d.Label{Text: text, TextColor: ink} }
func caption(text string) d.Label {
	return d.Label{Text: text, TextColor: muted, EllipsisMode: d.EllipsisEnd, Font: d.Font{Family: "Microsoft YaHei UI", PointSize: 9}}
}
func action(text, name string, fn func()) d.PushButton {
	button := d.PushButton{Text: text, Name: name, OnClicked: fn, MinSize: d.Size{Height: 32}}
	if text == "安装" || text == "检查" || text == "移除" {
		button.MaxSize = d.Size{Width: 76}
	}
	return button
}
func card(title string, items ...d.Widget) d.Composite {
	return d.Composite{Name: "card", Background: brush(panel), Layout: d.VBox{Spacing: 6, Margins: d.Margins{Left: 12, Top: 8, Right: 12, Bottom: 8}},
		Children: append([]d.Widget{d.Label{Text: title, TextColor: ink, Font: d.Font{Family: "Microsoft YaHei UI", PointSize: 10, Bold: true}}}, items...)}
}
func row(items ...d.Widget) d.Composite {
	return d.Composite{Layout: d.HBox{MarginsZero: true, Spacing: 8}, Children: items}
}

func input(target **walk.LineEdit, text, cue string, stretch int) d.Composite {
	return d.Composite{Name: "input-shell", StretchFactor: stretch, Background: brush(panelRaised), MinSize: d.Size{Height: 32},
		Layout: d.HBox{Margins: d.Margins{Left: 12, Top: 5, Right: 12, Bottom: 5}}, Children: []d.Widget{
			d.LineEdit{AssignTo: target, Text: text, CueBanner: cue, StretchFactor: 1, Background: brush(panelRaised), TextColor: ink},
		}}
}

func (w *window) create() error {
	start := action("启动服务", "primary", w.toggleService)
	start.AssignTo = &w.serverButton
	pause := action("暂停采集", "secondary", w.toggleCapture)
	pause.AssignTo = &w.pauseButton
	restore := action("恢复原代理", "secondary", w.restoreSystemProxy)
	restore.AssignTo = &w.restoreProxyButton
	previous := action("上一页", "", w.previousPage)
	previous.AssignTo = &w.previous
	next := action("下一页", "", w.nextPage)
	next.AssignTo = &w.next
	textPage := func(title string, target **walk.TextEdit) d.TabPage {
		return d.TabPage{Title: title, Background: brush(bg), Layout: d.VBox{MarginsZero: true}, Children: []d.Widget{
			d.TextEdit{AssignTo: target, Background: brush(panel), TextColor: ink, ReadOnly: true, VScroll: true, HScroll: false, MaxLength: 16 << 20, Font: d.Font{Family: "Consolas", PointSize: 10}},
		}}
	}
	err := (d.MainWindow{
		AssignTo: &w.mw, Title: "NetLens " + model.Version + " · 网络调试工作区", Background: brush(bg),
		Size: d.Size{Width: 1360, Height: 820}, MinSize: d.Size{Width: 1100, Height: 740}, Font: d.Font{Family: "Microsoft YaHei UI", PointSize: 9},
		Layout: d.VBox{MarginsZero: true, Spacing: 1}, Children: []d.Widget{
			d.Composite{Background: brush(panel), Layout: d.HBox{Spacing: 14, Margins: d.Margins{Left: 24, Top: 14, Right: 24, Bottom: 14}}, Children: []d.Widget{
				d.Label{Name: "brand", Text: "N", TextColor: bg, Background: brush(green), MinSize: d.Size{Width: 42, Height: 42}, TextAlignment: d.AlignCenter, Font: d.Font{Family: "Segoe UI", PointSize: 21, Bold: true}},
				d.Composite{Layout: d.VBox{MarginsZero: true, Spacing: 1}, Children: []d.Widget{
					d.Label{Text: "NetLens", TextColor: ink, Font: d.Font{Family: "Segoe UI", PointSize: 16, Bold: true}}, d.Label{Text: "网络调试 · 本地 MCP · AI 协作", TextColor: muted, MinSize: d.Size{Width: 240}, Font: d.Font{Family: "Microsoft YaHei UI", PointSize: 9}},
				}},
				d.HSpacer{}, d.Label{AssignTo: &w.status, Text: "服务尚未启动", TextColor: green},
				action("导出 HAR", "secondary", w.exportHAR), action("规则管理", "", w.manageRules),
			}},
			d.Composite{StretchFactor: 1, Layout: d.HBox{MarginsZero: true, Spacing: 12, Alignment: d.AlignHNearVNear}, Children: []d.Widget{
				d.Composite{Background: brush(bg), MinSize: d.Size{Width: 296}, MaxSize: d.Size{Width: 296}, Layout: d.VBox{Spacing: 8, Margins: d.Margins{Left: 12, Top: 12, Right: 0, Bottom: 12}}, Children: []d.Widget{
					card("采集服务",
						d.Composite{AssignTo: &w.settings, Layout: d.VBox{MarginsZero: true, Spacing: 7}, Children: []d.Widget{
							row(caption("代理"), input(&w.proxyAddr, w.cfg.ProxyAddr, "127.0.0.1:8080", 1)),
							row(caption("MCP"), input(&w.controlAddr, w.cfg.ControlAddr, "127.0.0.1:9090", 1)),
							row(d.CheckBox{AssignTo: &w.mitm, Text: "目标 HTTPS", Checked: w.cfg.MITM, ToolTipText: "仅解密采集主机。填写主机后点击“同时应用为采集条件”，或由 MCP 设置 hosts；其他网站透传原始 TLS。"}, d.CheckBox{AssignTo: &w.persist, Text: "原始日志", Checked: w.cfg.Persist}),
							row(d.CheckBox{AssignTo: &w.rules, Text: "启用规则", Checked: w.cfg.AllowRules}, d.CheckBox{AssignTo: &w.replay, Text: "启用重放", Checked: w.cfg.AllowReplay}),
						}}, row(start, pause)),
					card("系统代理", d.Label{AssignTo: &w.proxyStatus, Text: "系统代理 · 未接管", TextColor: muted},
						row(caption("上游"), input(&w.upstreamAddr, "127.0.0.1:7890", "留空使用直连", 1)),
						row(action("开启系统代理", "primary", w.enableSystemProxy), restore)),
					card("HTTPS 证书", d.Label{AssignTo: &w.certStatus, Text: "正在检查本实例 CA", TextColor: muted},
						row(action("安装", "secondary", w.installCertificate), action("检查", "", w.checkCertificate), action("移除", "danger", w.removeCertificate))),
					card("本地 MCP / AI", d.Label{AssignTo: &w.mcpAddress, Text: "MCP 服务尚未启动", TextColor: cyan, Font: d.Font{Family: "Consolas", PointSize: 8}, EllipsisMode: d.EllipsisEnd},
						action("复制 MCP 配置", "primary", w.copyMCPConfig), row(action("导出 AI 手册", "secondary", w.exportAIGuide), action("连接详情", "", w.connectionInfo))),
					d.VSpacer{},
				}},
				d.Composite{AssignTo: &w.workspace, StretchFactor: 1, Background: brush(bg), Layout: d.VBox{Spacing: 12, Margins: d.Margins{Top: 12, Right: 12, Bottom: 12}}, Children: []d.Widget{
					d.Composite{Name: "card", Background: brush(panel), Layout: d.VBox{Spacing: 12, Margins: d.Margins{Left: 16, Top: 12, Right: 12, Bottom: 12}}, Children: []d.Widget{
						row(d.Label{Text: "流量工作区", TextColor: ink, Font: d.Font{Family: "Microsoft YaHei UI", PointSize: 11, Bold: true}}, d.HSpacer{},
							d.Label{AssignTo: &w.trafficSummary, Text: "暂无流量", TextColor: muted}, d.CheckBox{AssignTo: &w.auto, Text: "每秒刷新", Checked: true}, action("刷新", "", w.refresh)),
						row(label("主机"), input(&w.hosts, "", "example.com, *.example.com", 1),
							label("URL"), input(&w.url, "", "搜索路径或查询字符串…", 2)),
						row(d.ComboBox{AssignTo: &w.method, Model: []string{"全部方法", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT"}, CurrentIndex: 0, Background: brush(panelRaised), MinSize: d.Size{Width: 118, Height: 36}},
							d.ComboBox{AssignTo: &w.statusFilter, Model: []string{"全部状态", "2xx", "3xx", "4xx", "5xx"}, CurrentIndex: 0, Background: brush(panelRaised), MinSize: d.Size{Width: 112, Height: 36}},
							label("慢于"), d.Composite{Name: "input-shell", Background: brush(panelRaised), MinSize: d.Size{Width: 90, Height: 36}, MaxSize: d.Size{Width: 110}, Layout: d.HBox{Margins: d.Margins{Left: 12, Top: 8, Right: 12, Bottom: 8}}, Children: []d.Widget{d.LineEdit{AssignTo: &w.slow, Text: "0", StretchFactor: 1}, caption("ms")}},
							d.CheckBox{AssignTo: &w.errorsOnly, Text: "只看错误"}, d.HSpacer{}, action("筛选", "primary", w.applyFilter), action("重置", "", w.resetFilter)),
						row(action("同时应用为采集条件", "secondary", w.applyCaptureFilter), action("采集所有主机", "", w.clearCaptureFilter), d.HSpacer{}, action("清空记录", "danger", w.clearFlows)),
					}},
					d.VSplitter{StretchFactor: 1, Background: brush(bg), Children: []d.Widget{
						d.Composite{Name: "card", StretchFactor: 3, Background: brush(panel), Layout: d.VBox{Margins: d.Margins{Left: 12, Top: 12, Right: 12, Bottom: 12}, Spacing: 10}, Children: []d.Widget{
							d.TableView{AssignTo: &w.table, Model: w.model, Background: brush(panel), CustomHeaderHeight: 36, CustomRowHeight: 34, ColumnsSizable: true, OnCurrentIndexChanged: w.selectFlow,
								Columns:   []d.TableViewColumn{{Title: "#", Width: 40}, {Title: "方法", Width: 60}, {Title: "状态", Width: 60}, {Title: "URL", Width: 310}, {Title: "耗时", Width: 80}, {Title: "大小", Width: 70}, {Title: "时间", Width: 75}},
								StyleCell: w.styleFlowCell},
							row(d.Label{AssignTo: &w.pageLabel, Text: "暂无记录", TextColor: muted, StretchFactor: 1}, action("最新", "", func() { w.query.BeforeSequence = 0; w.cursors = nil; w.refresh() }), previous, next),
						}},
						d.Composite{Name: "card", StretchFactor: 2, Background: brush(panel), Layout: d.VBox{Margins: d.Margins{Left: 12, Top: 12, Right: 12, Bottom: 12}, Spacing: 10}, Children: []d.Widget{
							d.TabWidget{AssignTo: &w.tabs, Background: brush(panel), Pages: []d.TabPage{textPage("概览", &w.overview), textPage("请求", &w.request), textPage("响应", &w.response), textPage("JSON", &w.json), textPage("统计", &w.stats)}},
							row(d.CheckBox{AssignTo: &w.fullBody, Text: "完整正文", Checked: true, OnCheckedChanged: w.selectFlow}, action("导出正文", "secondary", w.exportBody), action("复制", "", w.copyDetail), action("设为基准", "", w.setBaseline), action("对比", "secondary", w.compare), action("重放", "danger", w.replaySelected)),
						}},
					}},
				}},
			}},
			d.Composite{Background: brush(panel), Layout: d.HBox{Margins: d.Margins{Left: 18, Top: 8, Right: 18, Bottom: 8}}, Children: []d.Widget{
				d.Label{AssignTo: &w.notice, Text: "请求／响应默认显示完整正文；关闭“完整正文”切换长度预览，所有字段均为真实值。", TextColor: muted, EllipsisMode: d.EllipsisEnd, StretchFactor: 1},
				d.Label{Text: "LOCAL ONLY  ·  " + model.Version, TextColor: cyan, Font: d.Font{Family: "Consolas", PointSize: 8}},
			}},
		},
	}).Create()
	if err != nil {
		return err
	}
	w.fitWorkArea()
	if w.cfg.MITMAllHosts {
		w.mitm.SetText("全部 HTTPS")
		w.mitm.SetToolTipText("已显式启用 --mitm-all：未筛选主机时解密所有 HTTPS，可能影响站点登录。")
	}
	return applyTheme(w.mw)
}

// 初始窗口按可用工作区收缩，侧栏使用紧凑布局，流量与详情上下分区。
func (w *window) fitWorkArea() {
	var area win.RECT
	const spiGetWorkArea = 0x0030
	if !win.SystemParametersInfo(spiGetWorkArea, 0, unsafe.Pointer(&area), 0) {
		return
	}
	width, height := int(area.Right-area.Left)-32, int(area.Bottom-area.Top)-32
	if width <= 0 || height <= 0 {
		return
	}
	dpi := w.mw.DPI()
	w.mw.SetMinMaxSizePixels(walk.Size{Width: min(1100*dpi/96, width), Height: min(740*dpi/96, height)}, walk.Size{})
	size := w.mw.SizePixels()
	size.Width, size.Height = min(size.Width, width), min(size.Height, height)
	w.mw.SetBoundsPixels(walk.Rectangle{X: int(area.Left) + (int(area.Right-area.Left)-size.Width)/2, Y: int(area.Top) + (int(area.Bottom-area.Top)-size.Height)/2, Width: size.Width, Height: size.Height})
}
