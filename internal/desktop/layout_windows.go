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
	return d.Label{Text: text, TextColor: muted, Font: d.Font{PointSize: 9}}
}
func action(text, name string, fn func()) d.PushButton {
	return d.PushButton{Text: text, Name: name, OnClicked: fn, MinSize: d.Size{Height: 32}}
}
func card(title string, items ...d.Widget) d.Composite {
	return d.Composite{Background: brush(panel), Layout: d.VBox{Spacing: 8, Margins: d.Margins{Left: 14, Top: 12, Right: 14, Bottom: 12}},
		Children: append([]d.Widget{d.Label{Text: title, TextColor: ink, Font: d.Font{PointSize: 10, Bold: true}}}, items...)}
}
func row(items ...d.Widget) d.Composite {
	return d.Composite{Layout: d.HBox{MarginsZero: true, Spacing: 6}, Children: items}
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
			d.TextEdit{AssignTo: target, Background: brush(bg), TextColor: ink, ReadOnly: true, VScroll: true, HScroll: true, MaxLength: 1 << 20, Font: d.Font{Family: "Consolas", PointSize: 10}},
		}}
	}
	err := (d.MainWindow{
		AssignTo: &w.mw, Title: "NetLens " + model.Version + " · 网络调试工作区", Background: brush(bg),
		Size: d.Size{Width: 1360, Height: 820}, MinSize: d.Size{Width: 1100, Height: 680}, Font: d.Font{Family: "Microsoft YaHei UI", PointSize: 9},
		Layout: d.VBox{MarginsZero: true, Spacing: 1}, Children: []d.Widget{
			d.Composite{Background: brush(panel), Layout: d.HBox{Spacing: 14, Margins: d.Margins{Left: 20, Top: 12, Right: 20, Bottom: 12}}, Children: []d.Widget{
				d.Label{Text: "NL", TextColor: green, Font: d.Font{Family: "Segoe UI", PointSize: 22, Bold: true}},
				d.Composite{Layout: d.VBox{MarginsZero: true, Spacing: 1}, Children: []d.Widget{
					d.Label{Text: "NetLens", TextColor: ink, Font: d.Font{Family: "Segoe UI", PointSize: 16, Bold: true}}, caption("NETWORK DEBUGGING WORKSPACE"),
				}},
				d.HSpacer{}, d.Label{AssignTo: &w.status, Text: "服务尚未启动", TextColor: green},
				action("导出 HAR", "secondary", w.exportHAR), action("规则管理", "", w.manageRules),
			}},
			d.Composite{StretchFactor: 1, Layout: d.HBox{MarginsZero: true, Spacing: 10}, Children: []d.Widget{
				d.ScrollView{HorizontalFixed: true, Background: brush(bg), MinSize: d.Size{Width: 270}, MaxSize: d.Size{Width: 290}, Layout: d.VBox{Spacing: 10, Margins: d.Margins{Left: 10, Top: 10, Right: 0, Bottom: 10}}, Children: []d.Widget{
					card("采集服务",
						d.Composite{AssignTo: &w.settings, Layout: d.VBox{MarginsZero: true, Spacing: 7}, Children: []d.Widget{
							row(caption("代理"), d.LineEdit{AssignTo: &w.proxyAddr, Text: w.cfg.ProxyAddr, Background: brush(bg), TextColor: ink, StretchFactor: 1}),
							row(caption("MCP/API"), d.LineEdit{AssignTo: &w.controlAddr, Text: w.cfg.ControlAddr, Background: brush(bg), TextColor: ink, StretchFactor: 1}),
							row(d.CheckBox{AssignTo: &w.mitm, Text: "HTTPS 解密", Checked: w.cfg.MITM}, d.CheckBox{AssignTo: &w.persist, Text: "脱敏日志", Checked: w.cfg.Persist}),
							row(d.CheckBox{AssignTo: &w.rules, Text: "启用规则", Checked: w.cfg.AllowRules}, d.CheckBox{AssignTo: &w.replay, Text: "启用重放", Checked: w.cfg.AllowReplay}),
						}}, row(start, pause),
						caption("停止服务后可调整端口和权限")),
					card("系统代理", d.Label{AssignTo: &w.proxyStatus, Text: "系统代理 · 未接管", TextColor: muted},
						row(action("开启系统代理", "primary", w.enableSystemProxy), restore), caption("原配置会备份，正常退出自动恢复")),
					card("HTTPS 证书", d.Label{AssignTo: &w.certStatus, Text: "正在检查本实例 CA", TextColor: muted},
						row(action("安装", "secondary", w.installCertificate), action("检查", "", w.checkCertificate), action("移除", "danger", w.removeCertificate)),
						caption("仅管理本实例的用户级证书信任")),
					card("本地 MCP / AI", d.Label{AssignTo: &w.mcpAddress, Text: "MCP 服务尚未启动", TextColor: cyan, Font: d.Font{Family: "Consolas", PointSize: 8}, EllipsisMode: d.EllipsisEnd},
						action("复制 MCP 配置", "primary", w.copyMCPConfig), action("导出 AI 操作手册", "secondary", w.exportAIGuide),
						action("连接与证书详情", "", w.connectionInfo), caption("配置和手册包含本机访问令牌")),
					d.VSpacer{},
				}},
				d.Composite{StretchFactor: 1, Background: brush(bg), Layout: d.VBox{Spacing: 10, Margins: d.Margins{Top: 10, Right: 10, Bottom: 10}}, Children: []d.Widget{
					d.Composite{Background: brush(panel), Layout: d.VBox{Spacing: 8, Margins: d.Margins{Left: 14, Top: 12, Right: 14, Bottom: 12}}, Children: []d.Widget{
						row(d.Label{Text: "流量工作区", TextColor: ink, Font: d.Font{PointSize: 11, Bold: true}}, d.HSpacer{},
							d.Label{AssignTo: &w.trafficSummary, Text: "暂无流量", TextColor: muted}, d.CheckBox{AssignTo: &w.auto, Text: "每秒刷新", Checked: true}, action("刷新", "", w.refresh)),
						row(label("主机"), d.LineEdit{AssignTo: &w.hosts, CueBanner: "example.com, *.example.com", StretchFactor: 1, Background: brush(bg), TextColor: ink},
							label("URL"), d.LineEdit{AssignTo: &w.url, CueBanner: "路径或查询字符串", StretchFactor: 2, Background: brush(bg), TextColor: ink}),
						row(d.ComboBox{AssignTo: &w.method, Model: []string{"全部方法", "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT"}, CurrentIndex: 0, MinSize: d.Size{Width: 95}},
							d.ComboBox{AssignTo: &w.statusFilter, Model: []string{"全部状态", "2xx", "3xx", "4xx", "5xx"}, CurrentIndex: 0, MinSize: d.Size{Width: 90}},
							label("慢于"), d.NumberEdit{AssignTo: &w.slow, MinValue: 0, MaxValue: 600000, Suffix: " ms", MinSize: d.Size{Width: 90}},
							d.CheckBox{AssignTo: &w.errorsOnly, Text: "只看错误"}, d.HSpacer{}, action("筛选", "primary", w.applyFilter), action("重置", "", w.resetFilter)),
						row(action("同时应用为采集条件", "secondary", w.applyCaptureFilter), action("采集所有主机", "", w.clearCaptureFilter), d.HSpacer{}, action("清空记录", "danger", w.clearFlows)),
					}},
					d.HSplitter{StretchFactor: 1, Background: brush(panel), Children: []d.Widget{
						d.Composite{StretchFactor: 3, Background: brush(panel), Layout: d.VBox{MarginsZero: true, Spacing: 8}, Children: []d.Widget{
							d.TableView{AssignTo: &w.table, Model: w.model, Background: brush(bg), ColumnsSizable: true, NotSortableByHeaderClick: true, OnCurrentIndexChanged: w.selectFlow,
								Columns: []d.TableViewColumn{{Title: "#", Width: 40}, {Title: "方法", Width: 60}, {Title: "状态", Width: 60}, {Title: "URL", Width: 310}, {Title: "耗时", Width: 80}, {Title: "大小", Width: 70}, {Title: "时间", Width: 75}},
								StyleCell: func(style *walk.CellStyle) {
									style.TextColor = ink
									if style.Row() >= 0 {
										style.BackgroundColor = bg
										if style.Row()%2 == 1 {
											style.BackgroundColor = panel
										}
										if style.Row() < len(w.model.items) && style.Col() == 2 && w.model.items[style.Row()].StatusCode >= 400 {
											style.TextColor = danger
										}
									}
								}},
							row(d.Label{AssignTo: &w.pageLabel, Text: "暂无记录", TextColor: muted, StretchFactor: 1}, action("最新", "", func() { w.query.BeforeSequence = 0; w.cursors = nil; w.refresh() }), previous, next),
						}},
						d.Composite{StretchFactor: 2, Background: brush(panel), Layout: d.VBox{MarginsZero: true, Spacing: 8}, Children: []d.Widget{
							d.TabWidget{AssignTo: &w.tabs, Background: brush(panel), Pages: []d.TabPage{textPage("概览", &w.overview), textPage("请求", &w.request), textPage("响应", &w.response), textPage("JSON", &w.json), textPage("统计", &w.stats)}},
							row(action("复制", "", w.copyDetail), action("设为基准", "", w.setBaseline), action("对比", "secondary", w.compare), action("重放", "danger", w.replaySelected)),
						}},
					}},
				}},
			}},
			d.Composite{Background: brush(panel), Layout: d.HBox{Margins: d.Margins{Left: 18, Top: 8, Right: 18, Bottom: 8}}, Children: []d.Widget{
				d.Label{AssignTo: &w.notice, Text: "开启系统代理或配置应用代理后开始采集；请求和响应详情自动脱敏。", TextColor: muted, EllipsisMode: d.EllipsisEnd, StretchFactor: 1},
				d.Label{Text: "LOCAL ONLY  ·  " + model.Version, TextColor: cyan, Font: d.Font{Family: "Consolas", PointSize: 8}},
			}},
		},
	}).Create()
	if err != nil {
		return err
	}
	w.fitWorkArea()
	return applyTheme(w.mw)
}

// 初始窗口按可用工作区收缩，较小屏幕通过侧栏滚动保持功能可达。
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
	w.mw.SetMinMaxSizePixels(walk.Size{Width: min(1100*dpi/96, width), Height: min(680*dpi/96, height)}, walk.Size{})
	size := w.mw.SizePixels()
	size.Width, size.Height = min(size.Width, width), min(size.Height, height)
	w.mw.SetBoundsPixels(walk.Rectangle{X: int(area.Left) + (int(area.Right-area.Left)-size.Width)/2, Y: int(area.Top) + (int(area.Bottom-area.Top)-size.Height)/2, Width: size.Width, Height: size.Height})
}
