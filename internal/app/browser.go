package app

import (
	"net/url"
	"os/exec"
	"runtime"
)

func browserURL(controlAddr, token string) string {
	// fragment 不会发送给 HTTP 服务；前端读取后立即从地址栏和当前历史项移除。
	u := url.URL{Scheme: "http", Host: controlAddr, Path: "/"}
	return u.String() + "#" + url.Values{"token": []string{token}}.Encode()
}

func openBrowser(target string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", target)
	case "darwin":
		command = exec.Command("open", target)
	default:
		command = exec.Command("xdg-open", target)
	}
	if err := command.Start(); err != nil {
		return err
	}
	// 回收启动器进程，避免阻塞代理服务或遗留僵尸进程。
	go func() { _ = command.Wait() }()
	return nil
}
