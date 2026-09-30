package app

import (
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRuntimeSharesServiceAndReleasesPorts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.ProxyAddr, cfg.ControlAddr = "127.0.0.1:0", "127.0.0.1:0"
	r, err := Start(context.Background(), cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	status := r.Service.Status()
	control := status["control_addr"].(string)
	client := &http.Client{Transport: &http.Transport{}, Timeout: time.Second}
	resp, err := client.Get("http://" + control + "/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatal("control listener still exposes a browser UI")
	}
	paused := false
	if _, err := r.Service.Configure(CaptureInput{Enabled: &paused}); err != nil || r.Service.CaptureConfig().Enabled {
		t.Fatal("desktop service did not share capture configuration")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{control, status["proxy_addr"].(string)} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatalf("closed runtime retained listener %s: %v", address, err)
		}
		listener.Close()
	}
}
