//go:build windows

package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/lxn/walk"

	"netlens/internal/app"
	"netlens/internal/desktop"
)

func main() {
	runtime.LockOSThread()
	cfg := app.DefaultConfig()
	if dir, err := os.UserConfigDir(); err == nil {
		cfg.DataDir = filepath.Join(dir, "NetLens")
	}
	flag.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "user data directory")
	flag.StringVar(&cfg.ProxyAddr, "proxy", cfg.ProxyAddr, "loopback proxy address")
	flag.StringVar(&cfg.ControlAddr, "control", cfg.ControlAddr, "loopback API/MCP address")
	flag.BoolVar(&cfg.MITM, "mitm", false, "enable HTTPS decryption")
	flag.BoolVar(&cfg.MITMAllHosts, "mitm-all", false, "with --mitm, decrypt all hosts when unfiltered")
	flag.BoolVar(&cfg.AllowRules, "allow-rules", false, "enable rewrite/mock rules")
	flag.BoolVar(&cfg.AllowReplay, "allow-replay", false, "enable confirmed same-origin replay")
	flag.BoolVar(&cfg.Persist, "persist", false, "persist original capture values")
	selfTest := flag.String("self-test-result", "", "run desktop integration test and write JSON result")
	selfTestWidth := flag.Int("self-test-width", 0, "desktop self-test window width")
	selfTestHeight := flag.Int("self-test-height", 0, "desktop self-test window height")
	flag.Parse()
	cfg.Token = os.Getenv("NETLENS_TOKEN")
	if *selfTest != "" {
		cfg.ProxyAddr, cfg.ControlAddr = "127.0.0.1:0", "127.0.0.1:0"
	}
	err := desktop.Run(cfg, *selfTest, walk.Size{Width: *selfTestWidth, Height: *selfTestHeight})
	if err != nil {
		if *selfTest == "" {
			walk.MsgBox(nil, "NetLens 启动失败", fmt.Sprint(err), walk.MsgBoxIconError)
		}
		os.Exit(1)
	}
}
