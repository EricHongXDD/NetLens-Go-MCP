//go:build windows

package desktop

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lxn/walk"
	"netlens/internal/proxy"
	"netlens/internal/systemproxy"
	"netlens/internal/wincert"
)

func (w *window) certificate() (*wincert.Certificate, error) {
	if w.runtime != nil {
		return wincert.Parse(w.runtime.Service.CA.CertificatePEM())
	}
	ca, err := proxy.LoadOrCreateCA(filepath.Join(w.cfg.DataDir, "ca"))
	if err != nil {
		return nil, err
	}
	return wincert.Parse(ca.CertificatePEM())
}

func (w *window) refreshIntegration() {
	if cert, err := w.certificate(); err == nil {
		state, err := cert.Check()
		if err != nil {
			w.certStatus.SetText("证书状态读取失败")
		} else if state.User {
			w.certStatus.SetText("本实例 CA · 用户已信任")
		} else if state.Machine {
			w.certStatus.SetText("本实例 CA · 机器已信任")
		} else {
			w.certStatus.SetText("本实例 CA · 尚未安装")
		}
	} else {
		w.certStatus.SetText("CA 尚未就绪")
	}
	if w.systemProxy == nil {
		w.proxyStatus.SetText("代理设置不可用")
		return
	}
	state, err := w.systemProxy.Status()
	if err != nil {
		w.proxyStatus.SetText("无法读取系统代理")
		return
	}
	w.restoreProxyButton.SetEnabled(state.HasBackup)
	if state.Owned {
		if w.runtime != nil && w.runtime.Service.Proxy.Upstream() != "" {
			w.proxyStatus.SetText("已开启 · 经上游代理联网")
		} else {
			w.proxyStatus.SetText("系统代理 · NetLens 已开启")
		}
	} else if state.HasBackup {
		w.proxyStatus.SetText("存在恢复备份 · 当前代理已变更")
	} else {
		w.proxyStatus.SetText("系统代理 · 未接管")
	}
}

func (w *window) checkCertificate() {
	cert, err := w.certificate()
	if err != nil {
		w.fail(err)
		return
	}
	state, err := cert.Check()
	if err != nil {
		w.fail(err)
		return
	}
	w.refreshIntegration()
	w.showText("本实例证书检查", fmt.Sprintf("主题：%s\r\nSHA-256：%s\r\n有效期：%s 至 %s\r\n\r\n当前用户信任：%t\r\n机器级信任：%t\r\n\r\n证书文件：%s\r\n\r\n安装只加入当前用户根证书存储。移除只删除此证书的用户级信任，不处理机器级信任或其他证书。自带信任库／证书锁定的应用可能仍需单独配置。", cert.Cert.Subject.String(), cert.Fingerprint(), cert.Cert.NotBefore.Local().Format("2006-01-02"), cert.Cert.NotAfter.Local().Format("2006-01-02"), state.User, state.Machine, filepath.Join(w.cfg.DataDir, "ca", "ca.pem")))
}

func (w *window) installCertificate() {
	cert, err := w.certificate()
	if err != nil {
		w.fail(err)
		return
	}
	if walk.MsgBox(w.mw, "安装 NetLens 根证书", "将把本实例的公开 CA 加入当前用户的受信任根证书，使使用该信任库的应用允许 NetLens 解密 HTTPS。\r\n\r\nSHA-256："+cert.Fingerprint()+"\r\n\r\n不导入私钥，不修改机器级证书。是否安装？", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	if err := cert.Install(); err != nil {
		w.fail(err)
		return
	}
	w.refreshIntegration()
	w.notice.SetText("本实例 CA 已加入用户信任。停止服务后勾选 HTTPS 解密并重新启动即可使用。")
}

func (w *window) removeCertificate() {
	cert, err := w.certificate()
	if err != nil {
		w.fail(err)
		return
	}
	if walk.MsgBox(w.mw, "移除 NetLens 根证书", "仅移除本实例 CA 的用户级信任，其他证书和本地 CA 文件会保留。依赖此 CA 的 HTTPS 解密将不再受信任。\r\n\r\nSHA-256："+cert.Fingerprint()+"\r\n\r\n是否移除？", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	if err := cert.Remove(); err != nil {
		w.fail(err)
		return
	}
	w.refreshIntegration()
	w.notice.SetText("已移除本实例 CA 的用户级信任；若机器级仍信任此 CA，请由系统管理员处理。")
}

func (w *window) enableSystemProxy() {
	if !w.requireService() || w.systemProxy == nil {
		return
	}
	address := w.runtime.Service.Status()["proxy_addr"].(string)
	upstream := strings.TrimSpace(w.upstreamAddr.Text())
	route := "直连网络"
	if upstream != "" {
		route = "经上游 " + upstream + " 联网，保留 Clash 的规则和节点选择"
	}
	if walk.MsgBox(w.mw, "开启系统代理", "流量路径：应用 → NetLens ("+address+") → "+route+"。\r\n\r\n原 Windows 代理配置会备份，停止服务或关闭窗口时恢复。使用独立代理设置或 TUN 的流量可能不经过系统代理。是否开启？", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	if err := w.activateSystemProxy(upstream, address); err != nil {
		w.fail(err)
		return
	}
	w.proxyManaged = true
	w.upstreamAddr.SetEnabled(false)
	w.refreshIntegration()
	w.notice.SetText("系统代理已开启：应用 → NetLens → " + route + "。原配置已备份，退出自动恢复。")
}

// 先验证上游，再接管系统代理；失败时还原路由并保留原 Windows 设置。
func (w *window) activateSystemProxy(upstream, address string) error {
	p := w.runtime.Service.Proxy
	previous := p.Upstream()
	if err := p.SetUpstream(upstream); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	err := p.CheckUpstream(ctx)
	cancel()
	if err != nil {
		p.SetUpstream(previous)
		return fmt.Errorf("未开启系统代理，请先确认 Clash 正在监听上游端口：%w", err)
	}
	if err := w.systemProxy.Enable(address); err != nil {
		p.SetUpstream(previous)
		return err
	}
	return nil
}

func (w *window) restoreSystemProxy() {
	if w.systemProxy == nil {
		return
	}
	err := w.systemProxy.Restore(false)
	if errors.Is(err, systemproxy.ErrChanged) {
		if walk.MsgBox(w.mw, "代理设置已变更", "其他程序已经修改系统代理。恢复备份会覆盖当前代理设置。是否仍恢复 NetLens 开启前的配置？", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
			return
		}
		err = w.systemProxy.Restore(true)
	}
	if err != nil {
		w.fail(err)
		return
	}
	w.proxyManaged = false
	w.upstreamAddr.SetEnabled(true)
	w.refreshIntegration()
	w.notice.SetText("已恢复 NetLens 开启前的 Windows 系统代理配置。")
}

func (w *window) restoreOnStop() error {
	if w.systemProxy == nil || !w.proxyManaged {
		return nil
	}
	err := w.systemProxy.Restore(false)
	// 外部设置已接管时保留其配置和恢复备份，不阻碍停止本地服务。
	if errors.Is(err, systemproxy.ErrChanged) {
		w.proxyManaged = false
		return nil
	}
	if err == nil {
		w.proxyManaged = false
	}
	return err
}

func (w *window) copyMCPConfig() {
	if !w.requireService() {
		return
	}
	if err := walk.Clipboard().SetText(w.runtime.Service.ClientConfig()); err != nil {
		w.fail(err)
		return
	}
	w.notice.SetText("MCP JSON 配置已复制，包含当前地址和访问令牌，可直接粘贴到本机 MCP 客户端。")
}

func (w *window) exportAIGuide() {
	if !w.requireService() {
		return
	}
	if walk.MsgBox(w.mw, "导出 AI 操作手册", "Markdown 将包含当前 MCP 地址、访问令牌、工具说明和 AI 操作步骤。文件等同于本机访问凭据，请仅交给授权客户端并妥善保管。是否继续？", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	dialog := walk.FileDialog{Title: "导出 NetLens AI 操作手册", Filter: "Markdown 文件 (*.md)|*.md", FilePath: "NetLens-AI-Guide.private.md"}
	accepted, err := dialog.ShowSave(w.mw)
	if err != nil {
		w.fail(err)
		return
	}
	if !accepted {
		return
	}
	path := dialog.FilePath
	if strings.EqualFold(filepath.Ext(path), "") {
		path += ".md"
	}
	if err := w.saveAIGuide(path); err != nil {
		w.fail(err)
		return
	}
	w.notice.SetText("AI 操作手册已导出，包含当前连接配置、11 个工具和权限说明。")
}

func (w *window) saveAIGuide(path string) error {
	return os.WriteFile(path, []byte(w.runtime.Service.AIGuide()), 0600)
}
