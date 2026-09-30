//go:build windows

package desktop

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lxn/walk"
	d "github.com/lxn/walk/declarative"

	"netlens/internal/app"
	"netlens/internal/model"
)

func (w *window) clearFlows() {
	if !w.requireService() {
		return
	}
	if walk.MsgBox(w.mw, "清空记录", "确定清空当前会话的内存记录？已经导出的 HAR 和磁盘日志会保留。", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	if _, err := w.runtime.Service.Clear(true); err != nil {
		w.fail(err)
		return
	}
	w.selectedID, w.baselineID = "", ""
	w.query.BeforeSequence, w.cursors = 0, nil
	w.refresh()
}

func (w *window) exportHAR() {
	if !w.requireService() {
		return
	}
	dlg := walk.FileDialog{Title: "导出脱敏 HAR", Filter: "HAR 文件 (*.har)|*.har", FilePath: "netlens-" + time.Now().Format("20060102-150405") + ".har"}
	accepted, err := dlg.ShowSave(w.mw)
	if err != nil {
		w.fail(err)
		return
	}
	if !accepted {
		return
	}
	if filepath.Ext(dlg.FilePath) == "" {
		dlg.FilePath += ".har"
	}
	if err := w.saveHAR(dlg.FilePath); err != nil {
		w.fail(err)
		return
	}
	w.notice.SetText("已导出当前筛选下最近最多 100 条脱敏记录。")
}

func (w *window) saveHAR(path string) error {
	value, err := w.runtime.Service.Export(app.ExportInput{Filter: w.query.Filter, Limit: 100, BodyLimit: 8192})
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

func (w *window) copyDetail() {
	if w.detail == nil {
		w.notice.SetText("请先选择一条流量记录。")
		return
	}
	text := pretty(w.detail)
	if w.tabs.CurrentIndex() == 1 {
		text = w.request.Text()
	} else if w.tabs.CurrentIndex() == 2 {
		text = w.response.Text()
	}
	if err := walk.Clipboard().SetText(text); err != nil {
		w.fail(err)
		return
	}
	w.notice.SetText("已复制当前详情；请求／响应复制遵循完整正文开关。")
}

func (w *window) exportBody() {
	if !w.requireService() || w.selectedID == "" {
		w.notice.SetText("请先选择一条流量记录。")
		return
	}
	flow, ok := w.runtime.Service.Store.Get(w.selectedID)
	if !ok || !flow.RawAvailable {
		w.notice.SetText("该记录的原始正文不可用。")
		return
	}
	body, side := flow.ResponseBody, "response"
	if w.tabs.CurrentIndex() == 1 {
		body, side = flow.RequestBody, "request"
	}
	dlg := walk.FileDialog{Title: "导出完整原始正文（未脱敏）", Filter: "正文文件 (*.body)|*.body|所有文件 (*.*)|*.*", FilePath: "netlens-" + side + "-" + flow.ID + ".body"}
	accepted, err := dlg.ShowSave(w.mw)
	if err != nil {
		w.fail(err)
		return
	}
	if !accepted {
		return
	}
	// 原始正文按字节写出，保留服务器编码及压缩形式，不做字符编码转换。
	if err := os.WriteFile(dlg.FilePath, body.Data, 0600); err != nil {
		w.fail(err)
		return
	}
	w.notice.SetText(fmt.Sprintf("已导出 %s 正文 %d 字节（未脱敏）", side, len(body.Data)))
	if body.Truncated || body.Size > int64(len(body.Data)) {
		w.notice.SetText("已导出保留的原始字节；采集已截断，缺失部分无法恢复。")
	}
}

func (w *window) setBaseline() {
	if w.selectedID == "" {
		w.notice.SetText("请先选择一条流量记录。")
		return
	}
	w.baselineID = w.selectedID
	w.notice.SetText("已设置对比基准，请选择另一条记录后点击“对比”。")
}

func (w *window) compare() {
	if !w.requireService() {
		return
	}
	if w.baselineID == "" || w.selectedID == "" || w.baselineID == w.selectedID {
		w.notice.SetText("先将一条请求设为基准，再选择另一条请求进行对比。")
		return
	}
	value, err := w.runtime.Service.Compare(app.CompareInput{LeftID: w.baselineID, RightID: w.selectedID})
	if err != nil {
		w.fail(err)
		return
	}
	w.showText("请求对比 · 脱敏可见字段", pretty(value))
}

func (w *window) replaySelected() {
	if !w.requireService() || w.replayBusy {
		return
	}
	if !w.runtime.Service.Config.AllowReplay {
		w.notice.SetText("重放尚未启用。停止服务后勾选“启用重放”，再启动服务。")
		return
	}
	if w.selectedID == "" {
		w.notice.SetText("请先选择一条已经完成的请求。")
		return
	}
	if walk.MsgBox(w.mw, "重放请求", "将使用保留的原始请求向相同来源发送一次真实请求，可能修改测试服务状态。确定重放？", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	r, id := w.runtime, w.selectedID
	w.replayBusy = true
	w.notice.SetText("正在重放请求…")
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), w.cfg.Timeout)
		defer cancel()
		value, err := r.Service.Replay(ctx, app.ReplayInput{FlowID: id, Confirm: true})
		if w.closing.Load() {
			return
		}
		w.mw.Synchronize(func() {
			if w.closing.Load() || w.runtime != r {
				return
			}
			w.replayBusy = false
			w.refresh()
			if err != nil {
				w.fail(err)
				return
			}
			w.showText("重放结果", pretty(value))
		})
	}()
}

func (w *window) connectionInfo() {
	if !w.requireService() {
		return
	}
	s := w.runtime.Service
	text := "连接正在运行的桌面软件，请在 MCP 客户端使用以下 HTTP 配置。\r\n\r\n" + strings.ReplaceAll(s.ClientConfig(), "\n", "\r\n") +
		"\r\n\r\n用户数据目录：" + w.cfg.DataDir + "\r\nCA 证书：" + s.CA.CertPath() +
		"\r\n\r\nHTTPS 解密需要测试客户端信任此 CA。可以使用左侧证书和系统代理按钮管理本机配置。"
	w.showText("MCP 连接与证书", text)
}

func (w *window) showText(title, text string) {
	var dialog *walk.Dialog
	var closeButton *walk.PushButton
	err := (d.Dialog{
		AssignTo: &dialog, Title: title, Background: brush(panel), Size: d.Size{Width: 800, Height: 600}, MinSize: d.Size{Width: 650, Height: 450},
		CancelButton: &closeButton, Layout: d.VBox{}, Font: d.Font{Family: "Microsoft YaHei UI", PointSize: 10},
		Children: []d.Widget{
			d.TextEdit{Text: text, ReadOnly: true, VScroll: true, HScroll: true, MaxLength: 1 << 20, Font: d.Font{Family: "Consolas", PointSize: 10}},
			d.Composite{Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
				d.PushButton{Text: "复制", OnClicked: func() {
					if err := walk.Clipboard().SetText(text); err != nil {
						walk.MsgBox(dialog, "复制失败", err.Error(), walk.MsgBoxIconError)
					}
				}},
				d.HSpacer{}, d.PushButton{AssignTo: &closeButton, Text: "关闭", OnClicked: func() { dialog.Cancel() }},
			}},
		},
	}).Create(w.mw)
	if err != nil {
		w.fail(err)
		return
	}
	defer dialog.Dispose()
	if err := applyTheme(dialog); err != nil {
		w.fail(err)
		return
	}
	dialog.Run()
}

func (w *window) manageRules() {
	if !w.requireService() {
		return
	}
	if !w.runtime.Service.Config.AllowRules {
		w.notice.SetText("规则尚未启用。停止服务后勾选“启用规则”，再启动服务。")
		return
	}
	var dialog *walk.Dialog
	var editor *walk.TextEdit
	var cancel *walk.PushButton
	err := (d.Dialog{
		AssignTo: &dialog, Title: "规则管理", Background: brush(panel), Size: d.Size{Width: 900, Height: 750}, MinSize: d.Size{Width: 750, Height: 600},
		CancelButton: &cancel, Layout: d.VBox{}, Font: d.Font{Family: "Microsoft YaHei UI", PointSize: 10},
		Children: []d.Widget{
			d.Label{Text: "当前规则（脱敏预览）"},
			d.TextEdit{Text: pretty(w.runtime.Service.PublicRules()), ReadOnly: true, VScroll: true, MaxLength: 2 << 20},
			d.Label{Text: "新的完整规则数组：应用后替换全部规则；[] 表示移除全部规则。每条规则必须限定目标主机。"},
			d.TextEdit{AssignTo: &editor, Text: "[]", VScroll: true, MaxLength: 2 << 20, Font: d.Font{Family: "Consolas", PointSize: 10}},
			d.Composite{Layout: d.HBox{MarginsZero: true}, Children: []d.Widget{
				d.PushButton{Text: "填入 Mock 示例", OnClicked: func() {
					editor.SetText(pretty([]model.Rule{{ID: "example-mock", Enabled: true, Match: model.RuleMatch{Hosts: []string{"api.example.com"}, URLContains: "/health"},
						Action: model.RuleAction{Mock: &model.MockResponse{Status: 503, Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"error":"mock unavailable"}`}}}}))
				}},
				d.HSpacer{}, d.PushButton{Text: "应用规则", OnClicked: func() {
					var rules []model.Rule
					if err := json.Unmarshal([]byte(editor.Text()), &rules); err != nil {
						walk.MsgBox(dialog, "规则格式错误", "请输入有效的 JSON 规则数组。", walk.MsgBoxIconError)
						return
					}
					if walk.MsgBox(dialog, "替换规则", "将替换全部已有规则，并影响后续匹配请求。是否应用？", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
						return
					}
					if _, err := w.runtime.Service.ReplaceRules(app.RulesInput{Rules: rules}); err != nil {
						walk.MsgBox(dialog, "规则被拒绝", err.Error(), walk.MsgBoxIconError)
						return
					}
					w.notice.SetText(fmt.Sprintf("已应用 %d 条规则。", len(rules)))
					dialog.Accept()
				}},
				d.PushButton{AssignTo: &cancel, Text: "取消", OnClicked: func() { dialog.Cancel() }},
			}},
		},
	}).Create(w.mw)
	if err != nil {
		w.fail(err)
		return
	}
	defer dialog.Dispose()
	if err := applyTheme(dialog); err != nil {
		w.fail(err)
		return
	}
	dialog.Run()
}
