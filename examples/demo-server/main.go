// Demo-server provides repeatable local HTTP(S) traffic for NetLens.
// Its optional CA is independent of the NetLens interception CA.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	httpAddr := flag.String("http", "127.0.0.1:18080", "local HTTP listen address")
	httpsAddr := flag.String("https", "", "optional local HTTPS address, e.g. 127.0.0.1:18443")
	tlsDir := flag.String("tls-dir", ".demo-tls", "directory for independent demo TLS certificates")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	for _, addr := range []string{*httpAddr, *httpsAddr} {
		if addr == "" {
			continue
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil || (host != "localhost" && !net.ParseIP(host).IsLoopback()) {
			return errors.New("demo listeners must use loopback host:port")
		}
	}
	if *httpAddr == "" && *httpsAddr == "" {
		return errors.New("enable at least one listener")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var servers []*http.Server
	errCh := make(chan error, 2)
	handler := demoHandler()
	start := func(addr, certPath, keyPath string) error {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
		if certPath != "" {
			pair, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				listener.Close()
				return err
			}
			server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
			listener = tls.NewListener(listener, server.TLSConfig)
		}
		servers = append(servers, server)
		scheme := "http"
		if certPath != "" {
			scheme = "https"
		}
		log.Printf("demo listening at %s://%s", scheme, listener.Addr())
		go func() { errCh <- server.Serve(listener) }()
		return nil
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		for _, server := range servers {
			_ = server.Shutdown(shutdownCtx)
			_ = server.Close()
		}
	}()
	if *httpsAddr != "" {
		cert, key, ca, err := ensureDemoTLS(*tlsDir)
		if err != nil {
			return err
		}
		log.Printf("demo upstream CA: %s", ca)
		if err := start(*httpsAddr, cert, key); err != nil {
			return err
		}
	}
	if *httpAddr != "" {
		if err := start(*httpAddr, "", ""); err != nil {
			return err
		}
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func demoHandler() http.Handler {
	var requests atomic.Uint64
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, status int, value any) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(value)
	}
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		write(w, http.StatusOK, map[string]any{"status": "ok", "service": "netlens-demo"})
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			write(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "demo body limit is 1 MiB"})
			return
		}
		var data any
		if len(body) > 0 && json.Unmarshal(body, &data) != nil {
			data = string(body)
		}
		write(w, http.StatusOK, map[string]any{"method": r.Method, "path": r.URL.Path, "query": r.URL.Query(), "headers": r.Header, "body": data})
	})
	mux.HandleFunc("/error", func(w http.ResponseWriter, r *http.Request) {
		status := 503
		if value := r.URL.Query().Get("status"); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 400 || n > 599 {
				write(w, 400, map[string]any{"error": "status must be 400..599"})
				return
			}
			status = n
		}
		write(w, status, map[string]any{"error": "intentional demo failure", "retryable": status >= 500})
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		delay := 800
		if value := r.URL.Query().Get("ms"); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil || n < 0 || n > 10000 {
				write(w, 400, map[string]any{"error": "ms must be 0..10000"})
				return
			}
			delay = n
		}
		timer := time.NewTimer(time.Duration(delay) * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
			write(w, 200, map[string]any{"status": "ok", "intentional_delay_ms": delay})
		case <-r.Context().Done():
		}
	})
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		controller := http.NewResponseController(w)
		for i := 1; i <= 5; i++ {
			if _, err := fmt.Fprintf(w, "event: tick\ndata: {\"sequence\":%d}\n\n", i); err != nil {
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-timer.C:
			case <-r.Context().Done():
				timer.Stop()
				return
			}
		}
	})
	mux.HandleFunc("/large", func(w http.ResponseWriter, r *http.Request) {
		write(w, 200, map[string]any{"description": "body capture limit demo", "padding": strings.Repeat("x", 128<<10)})
	})
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/health")
		write(w, http.StatusFound, map[string]any{"redirect": "/health"})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Request-ID", fmt.Sprintf("demo-%06d", requests.Add(1)))
		mux.ServeHTTP(w, r)
	})
}

// A demo root signs a localhost leaf. Its signing key is discarded immediately;
// only the leaf key is stored. Existing files are reused on subsequent runs.
func ensureDemoTLS(dir string) (certPath, keyPath, caPath string, err error) {
	dir, err = filepath.Abs(dir)
	if err != nil {
		return
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return
	}
	certPath, keyPath, caPath = filepath.Join(dir, "server.pem"), filepath.Join(dir, "server-key.pem"), filepath.Join(dir, "ca.pem")
	paths := []string{certPath, keyPath, caPath}
	exists := 0
	for _, path := range paths {
		if _, e := os.Stat(path); e == nil {
			exists++
		} else if !errors.Is(e, os.ErrNotExist) {
			err = e
			return
		}
	}
	if exists == len(paths) {
		_, err = tls.LoadX509KeyPair(certPath, keyPath)
		return
	}
	if exists != 0 {
		err = errors.New("incomplete demo TLS files: use a new --tls-dir")
		return
	}
	rootKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		err = e
		return
	}
	leafKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		err = e
		return
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		err = e
		return
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "NetLens local demo upstream CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(1, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if e != nil {
		err = e
		return
	}
	leaf := &x509.Certificate{SerialNumber: new(big.Int).Add(serial, big.NewInt(1)), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(0, 1, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, e := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	if e != nil {
		err = e
		return
	}
	keyDER, e := x509.MarshalPKCS8PrivateKey(leafKey)
	if e != nil {
		err = e
		return
	}
	for _, file := range []struct {
		path string
		kind string
		der  []byte
		mode os.FileMode
	}{{keyPath, "PRIVATE KEY", keyDER, 0600}, {certPath, "CERTIFICATE", leafDER, 0644}, {caPath, "CERTIFICATE", rootDER, 0644}} {
		var f *os.File
		f, err = os.OpenFile(file.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, file.mode)
		if err != nil {
			return
		}
		err = pem.Encode(f, &pem.Block{Type: file.kind, Bytes: file.der})
		closeErr := f.Close()
		if err != nil {
			return
		}
		if closeErr != nil {
			err = closeErr
			return
		}
	}
	return
}
