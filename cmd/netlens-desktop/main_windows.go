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
	flag.BoolVar(&cfg.AllowRules, "allow-rules", false, "enable rewrite/mock rules")
	flag.BoolVar(&cfg.AllowReplay, "allow-replay", false, "enable confirmed same-origin replay")
	flag.BoolVar(&cfg.Persist, "persist", false, "persist redacted captures")
	selfTest := flag.String("self-test-result", "", "run desktop integration test and write JSON result")
	flag.Parse()
	cfg.Token = os.Getenv("NETLENS_TOKEN")
	if *selfTest != "" {
		cfg.ProxyAddr, cfg.ControlAddr = "127.0.0.1:0", "127.0.0.1:0"
	}
	err := desktop.Run(cfg, *selfTest)
	if err != nil {
		if *selfTest == "" {
			walk.MsgBox(nil, "NetLens 启动失败", fmt.Sprint(err), walk.MsgBoxIconError)
		}
		os.Exit(1)
	}
}
