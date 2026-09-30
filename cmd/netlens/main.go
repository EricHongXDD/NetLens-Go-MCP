package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	"netlens/internal/app"
	"netlens/internal/model"
	"netlens/internal/proxy"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "netlens:", err)
		os.Exit(1)
	}
}
func run() error {
	command := "serve"
	args := os.Args[1:]
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		command = args[0]
		args = args[1:]
	}
	if command == "version" {
		fmt.Println("NetLens", model.Version)
		return nil
	}
	if command == "ca" {
		fs := flag.NewFlagSet("ca", flag.ContinueOnError)
		dataDir := fs.String("data-dir", defaultDataDir(), "private runtime data directory")
		if err := fs.Parse(args); err != nil {
			return err
		}
		ca, err := proxy.LoadOrCreateCA(filepath.Join(*dataDir, "ca"))
		if err != nil {
			return err
		}
		fmt.Println(ca.CertPath())
		return nil
	}
	if command != "serve" && command != "mcp" {
		return fmt.Errorf("unknown command %q (use serve, mcp, ca or version)", command)
	}
	cfg := app.DefaultConfig()
	cfg.DataDir = defaultDataDir()
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.StringVar(&cfg.ProxyAddr, "proxy", cfg.ProxyAddr, "explicit proxy listen address (loopback only)")
	fs.StringVar(&cfg.ControlAddr, "control", cfg.ControlAddr, "API and MCP HTTP listen address (loopback only)")
	fs.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "private runtime data directory; use an absolute path in MCP clients")
	fs.BoolVar(&cfg.MITM, "mitm", false, "decrypt HTTPS for configured capture hosts; other sites use original TLS tunnels")
	fs.BoolVar(&cfg.MITMAllHosts, "mitm-all", false, "with --mitm, also decrypt all hosts when no capture host filter is configured")
	fs.BoolVar(&cfg.AllowReplay, "allow-replay", false, "allow explicit, confirmed same-origin request replays")
	fs.BoolVar(&cfg.AllowRules, "allow-rules", false, "allow request rewriting, delay and mock rules")
	fs.BoolVar(&cfg.Persist, "persist", false, "write redacted completed flows to rotating JSONL logs")
	fs.IntVar(&cfg.BodyLimit, "body-limit", cfg.BodyLimit, "captured bytes per request/response body (1024..1048576)")
	fs.IntVar(&cfg.MaxFlows, "max-flows", cfg.MaxFlows, "maximum retained flow count")
	fs.Int64Var(&cfg.MaxBytes, "max-memory", cfg.MaxBytes, "maximum retained flow memory budget in bytes")
	fs.Int64Var(&cfg.LogMaxBytes, "log-max-bytes", cfg.LogMaxBytes, "rotation threshold for redacted JSONL logs")
	fs.IntVar(&cfg.LogBackups, "log-backups", cfg.LogBackups, "rotated JSONL backup count")
	fs.DurationVar(&cfg.Timeout, "timeout", cfg.Timeout, "timeout per HTTP request and tunnel establishment; established CONNECT tunnels stay open")
	stdio := fs.Bool("stdio", command == "mcp", "also serve MCP over stdin/stdout; all logs go to stderr")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if command == "mcp" {
		*stdio = true
	}
	cfg.Token = os.Getenv("NETLENS_TOKEN")
	abs, err := filepath.Abs(cfg.DataDir)
	if err != nil {
		return err
	}
	cfg.DataDir = abs
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx, cfg, *stdio, log.New(os.Stderr, "netlens: ", log.LstdFlags))
}

func defaultDataDir() string {
	// Windows 从开始菜单启动时不依赖工作目录，并将凭据放在当前用户目录。
	if runtime.GOOS == "windows" {
		if dir, err := os.UserConfigDir(); err == nil {
			return filepath.Join(dir, "NetLens")
		}
	}
	return ".netlens"
}
