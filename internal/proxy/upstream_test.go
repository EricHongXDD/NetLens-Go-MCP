package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestUpstreamHTTPDoesNotResolveTargetLocally(t *testing.T) {
	t.Parallel()
	var called atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)
		if r.URL.String() != "http://route.invalid/proof" {
			t.Errorf("upstream target: %s", r.URL)
		}
		io.WriteString(w, "via-clash")
	}))
	defer upstream.Close()
	p, _, client, recorder := startTestProxy(t, Options{}, nil)
	if err := p.SetUpstream(upstream.URL); err != nil {
		t.Fatal(err)
	}
	response, err := client.Get("http://route.invalid/proof")
	if err != nil {
		t.Fatal(err)
	}
	if body := string(readResponse(t, response)); body != "via-clash" || called.Load() != 1 {
		t.Fatalf("route bypassed: %q calls=%d", body, called.Load())
	}
	if flow := recorder.final(t); flow.StatusCode != 200 || string(flow.ResponseBody.Data) != "via-clash" {
		t.Fatalf("missing capture: %+v", flow)
	}
}

func TestUpstreamConcurrentRouteChange(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer upstream.Close()
	p, _, client, _ := startTestProxy(t, Options{}, nil)
	p.SetUpstream(upstream.URL)
	var group sync.WaitGroup
	group.Go(func() {
		for range 50 {
			if err := p.SetUpstream(upstream.URL); err != nil {
				t.Error(err)
			}
		}
	})
	for range 4 {
		group.Go(func() {
			for range 20 {
				response, err := client.Get("http://route.invalid/proof")
				if err != nil {
					t.Error(err)
					continue
				}
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode != 200 {
					t.Error(response.Status)
				}
			}
		})
	}
	group.Wait()
}

func TestUpstreamTunnelPreservesHalfClose(t *testing.T) {
	t.Parallel()
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()
	finished := make(chan error, 1)
	go func() {
		conn, err := origin.Accept()
		if err != nil {
			finished <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(3 * time.Second))
		data, err := io.ReadAll(conn)
		if err == nil {
			_, err = conn.Write(append([]byte("received:"), data...))
		}
		finished <- err
	}()
	_, upstream, _, _ := startTestProxy(t, Options{}, nil)
	p, downstream, _, _ := startTestProxy(t, Options{}, nil)
	p.SetUpstream(upstream.URL)
	conn, err := net.DialTimeout("tcp", downstream.Listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin.Addr(), origin.Addr()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != 200 {
		t.Fatalf("CONNECT: response=%v err=%v", response, err)
	}
	conn.Write([]byte("payload"))
	conn.(*net.TCPConn).CloseWrite()
	data, err := io.ReadAll(reader)
	if err != nil || string(data) != "received:payload" {
		t.Fatalf("half-close lost response: %q %v", data, err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
}

func TestUpstreamHTTPSCaptureAndTunnel(t *testing.T) {
	for _, mitm := range []bool{false, true} {
		t.Run(map[bool]string{false: "tunnel", true: "decryption"}[mitm], func(t *testing.T) {
			t.Parallel()
			origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "https-through-clash") }))
			defer origin.Close()
			originRoots := x509.NewCertPool()
			originRoots.AddCert(origin.Certificate())
			_, upstream, _, upstreamRecorder := startTestProxy(t, Options{}, nil)
			ca, err := LoadOrCreateCA(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			clientRoots := originRoots
			if mitm {
				clientRoots = x509.NewCertPool()
				clientRoots.AppendCertsFromPEM(ca.CertificatePEM())
			}
			p, _, client, recorder := startTestProxy(t, Options{CA: ca, MITM: mitm, UpstreamTLSConfig: &tls.Config{RootCAs: originRoots, MinVersion: tls.VersionTLS12}}, clientRoots)
			if err := p.SetUpstream(upstream.URL); err != nil {
				t.Fatal(err)
			}
			response, err := client.Get(origin.URL + "/proof")
			if err != nil {
				t.Fatal(err)
			}
			if body := string(readResponse(t, response)); body != "https-through-clash" {
				t.Fatal(body)
			}
			client.Transport.(*http.Transport).CloseIdleConnections()
			flow := recorder.final(t)
			if mitm {
				if flow.Source != "proxy" || string(flow.ResponseBody.Data) != "https-through-clash" {
					t.Fatalf("decryption capture failed: %+v", flow)
				}
			} else if flow.Source != "tunnel" || flow.StatusCode != 200 {
				t.Fatalf("tunnel capture failed: %+v", flow)
			}
			// 解密分支的 HTTP 连接池必须关闭，才会产生上游隧道的最终记录。
			p.transport.CloseIdleConnections()
			if flow := upstreamRecorder.final(t); flow.Source != "tunnel" || flow.StatusCode != 200 {
				t.Fatalf("upstream was bypassed: %+v", flow)
			}
		})
	}
}

func TestUpstreamLoopInvalidAddressAndNoFallback(t *testing.T) {
	t.Parallel()
	p, server, client, _ := startTestProxy(t, Options{}, nil)
	for _, address := range []string{server.URL, "socks5://127.0.0.1:7890", "http://user:password@127.0.0.1:7890", "127.0.0.1:70000", "http://127.0.0.1:7890/path"} {
		if err := p.SetUpstream(address); err == nil {
			t.Errorf("invalid upstream accepted: %s", address)
		}
	}
	originCalls := atomic.Int32{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { originCalls.Add(1) }))
	defer origin.Close()
	failed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unavailable", 503) }))
	address := failed.URL
	failed.Close()
	if err := p.SetUpstream(address); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := p.CheckUpstream(ctx); err == nil {
		t.Fatal("unreachable upstream passed readiness check")
	}
	response, err := client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, response)
	if response.StatusCode != 502 || originCalls.Load() != 0 {
		t.Fatal("failed upstream silently bypassed VPN")
	}
	if err := p.SetUpstream(""); err != nil {
		t.Fatal(err)
	}
	response, err = client.Get(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	readResponse(t, response)
	if originCalls.Load() != 1 {
		t.Fatal("explicit direct mode failed")
	}
}

func TestUpstreamCONNECTRejectionAndHeaderLimit(t *testing.T) {
	for _, oversize := range []bool{false, true} {
		t.Run(map[bool]string{false: "reject", true: "large-header"}[oversize], func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if oversize {
					w.Header().Set("X-Large", strings.Repeat("x", 70<<10))
				}
				http.Error(w, "upstream rejected", http.StatusProxyAuthRequired)
			}))
			defer upstream.Close()
			p, _, _, _ := startTestProxy(t, Options{}, nil)
			p.SetUpstream(upstream.URL)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if conn, err := p.dialTunnel(ctx, "route.invalid:443"); err == nil {
				conn.Close()
				t.Fatal("failed CONNECT accepted")
			}
		})
	}
}
