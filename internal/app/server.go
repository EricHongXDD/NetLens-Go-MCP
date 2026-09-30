package app

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"netlens/internal/model"
)

//go:embed ui.html
var webFiles embed.FS

func validateListenAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return errors.New("listen address must be host:port")
	}
	if host != "localhost" {
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return errors.New("listeners must use a literal loopback IP or localhost; use an authenticated tunnel for remote access")
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 0 || p > 65535 {
		return errors.New("invalid port")
	}
	return nil
}

// EnsureToken creates a private local credential. Credentials are never printed by the server.
func EnsureToken(dataDir, supplied string) (token, tokenPath string, err error) {
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		return "", "", err
	}
	if err = os.Chmod(dataDir, 0700); err != nil {
		return "", "", err
	}
	if supplied != "" {
		if len(supplied) < 32 || strings.ContainsAny(supplied, " \t\r\n") {
			return "", "", errors.New("NETLENS_TOKEN must contain at least 32 non-whitespace characters")
		}
		return supplied, "NETLENS_TOKEN environment variable", nil
	}
	path := filepath.Join(dataDir, "control.token")
	if info, e := os.Lstat(path); e == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return "", "", errors.New("control.token must be a regular private file")
	}
	b, e := os.ReadFile(path)
	if e == nil {
		t := strings.TrimSpace(string(b))
		if len(t) < 32 || strings.ContainsAny(t, " \t\r\n") {
			return "", "", errors.New("control.token is invalid")
		}
		if e = os.Chmod(path, 0600); e != nil {
			return "", "", e
		}
		return t, path, nil
	}
	if !errors.Is(e, os.ErrNotExist) {
		return "", "", e
	}
	var secret [32]byte
	if _, e = rand.Read(secret[:]); e != nil {
		return "", "", e
	}
	t := hex.EncodeToString(secret[:])
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(e, os.ErrExist) {
		return EnsureToken(dataDir, "")
	}
	if e != nil {
		return "", "", e
	}
	_, writeErr := io.WriteString(f, t+"\n")
	closeErr := f.Close()
	if writeErr != nil {
		return "", "", writeErr
	}
	if closeErr != nil {
		return "", "", closeErr
	}
	return t, path, nil
}

// The control listener serves HTTP. Browsers omit :80 from Host and Origin.
func httpAuthority(value string) (string, string, error) {
	host, port, err := net.SplitHostPort(value)
	if err == nil {
		return host, port, nil
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		host = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
		if net.ParseIP(host) != nil {
			return host, "80", nil
		}
	}
	if value != "" && !strings.ContainsAny(value, ":/[]@?#\\ \t\r\n") {
		return value, "80", nil
	}
	return "", "", errors.New("invalid HTTP authority")
}

func sameAuthority(a, b string) bool {
	ah, ap, ae := httpAuthority(a)
	bh, bp, be := httpAuthority(b)
	return ae == nil && be == nil && strings.EqualFold(ah, bh) && ap == bp
}

func (s *Service) validHost(host string) bool {
	h, p, err := httpAuthority(host)
	if err != nil {
		return false
	}
	ip := net.ParseIP(h)
	if h != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return false
	}
	s.mu.RLock()
	_, port, err := net.SplitHostPort(s.controlAddr)
	s.mu.RUnlock()
	return err == nil && p == port
}

func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/mcp", s.requireToken(http.MaxBytesHandler(s.MCP.HTTPHandler(), 2<<20)))
	mux.Handle("/api/", s.requireToken(http.HandlerFunc(s.api)))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" || r.Method != "GET" {
			http.NotFound(w, r)
			return
		}
		html, err := webFiles.ReadFile("ui.html")
		if err != nil {
			http.Error(w, "UI unavailable", 500)
			return
		}
		var b [18]byte
		if _, err := rand.Read(b[:]); err != nil {
			http.Error(w, "UI unavailable", 500)
			return
		}
		nonce := base64.RawStdEncoding.EncodeToString(b[:])
		page := strings.ReplaceAll(string(html), "<script>", "<script nonce=\""+nonce+"\">")
		page = strings.ReplaceAll(page, "<style>", "<style nonce=\""+nonce+"\">")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'nonce-"+nonce+"'; style-src 'nonce-"+nonce+"'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		if !s.validHost(r.Host) {
			http.Error(w, "invalid Host", http.StatusForbidden)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			if err != nil || u.Scheme != scheme || !sameAuthority(u.Host, r.Host) || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
				http.Error(w, "invalid Origin", http.StatusForbidden)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Service) requireToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get("Authorization")
		actual := ""
		if strings.HasPrefix(v, "Bearer ") {
			actual = strings.TrimPrefix(v, "Bearer ")
		}
		if s.Config.Token == "" || subtle.ConstantTimeCompare([]byte(actual), []byte(s.Config.Token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="netlens"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}
func requestJSON[T any](w http.ResponseWriter, r *http.Request) (T, error) {
	var in T
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&in); err != nil {
		return in, errors.New("invalid JSON request body")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return in, errors.New("only one JSON value is allowed")
	}
	return in, nil
}
func parseQuery(v url.Values) (model.Query, error) {
	q := model.Query{}
	for _, name := range []string{"hosts", "exclude_hosts", "methods"} {
		items := []string{}
		for _, x := range strings.Split(v.Get(name), ",") {
			if x = strings.TrimSpace(x); x != "" {
				items = append(items, x)
			}
		}
		switch name {
		case "hosts":
			q.Hosts = items
		case "exclude_hosts":
			q.ExcludeHosts = items
		case "methods":
			q.Methods = items
		}
	}
	q.URLContains = v.Get("url_contains")
	for name, ptr := range map[string]*int{"limit": &q.Limit, "status_min": &q.StatusMin, "status_max": &q.StatusMax} {
		if x := v.Get(name); x != "" {
			n, e := strconv.Atoi(x)
			if e != nil {
				return q, errors.New("invalid numeric query parameter")
			}
			*ptr = n
		}
	}
	if x := v.Get("before_sequence"); x != "" {
		n, e := strconv.ParseUint(x, 10, 64)
		if e != nil {
			return q, errors.New("invalid before_sequence")
		}
		q.BeforeSequence = n
	}
	if x := v.Get("min_duration_ms"); x != "" {
		n, e := strconv.ParseFloat(x, 64)
		if e != nil {
			return q, errors.New("invalid min_duration_ms")
		}
		q.MinDurationMS = n
	}
	if x := v.Get("only_errors"); x != "" {
		b, e := strconv.ParseBool(x)
		if e != nil {
			return q, errors.New("invalid only_errors")
		}
		q.OnlyErrors = b
	}
	return normalizeQuery(q)
}

func (s *Service) api(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/api/status" && r.Method == "GET":
		writeJSON(w, s.Status(), nil)
	case r.URL.Path == "/api/capture" && r.Method == "POST":
		in, err := requestJSON[CaptureInput](w, r)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		v, err := s.Configure(in)
		writeJSON(w, v, err)
	case r.URL.Path == "/api/flows" && r.Method == "GET":
		q, err := parseQuery(r.URL.Query())
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		writeJSON(w, s.Store.Query(q), nil)
	case strings.HasPrefix(r.URL.Path, "/api/flows/") && r.Method == "GET":
		limit := 8192
		if x := r.URL.Query().Get("body_limit"); x != "" {
			n, e := strconv.Atoi(x)
			if e != nil {
				writeJSON(w, nil, errors.New("invalid body_limit"))
				return
			}
			limit = n
		}
		v, err := s.Get(GetInput{ID: strings.TrimPrefix(r.URL.Path, "/api/flows/"), BodyLimit: limit})
		writeJSON(w, v, err)
	case r.URL.Path == "/api/stats" && r.Method == "GET":
		q, err := parseQuery(r.URL.Query())
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		writeJSON(w, s.Store.Stats(q.Filter), nil)
	case r.URL.Path == "/api/rules" && r.Method == "GET":
		writeJSON(w, s.PublicRules(), nil)
	case r.URL.Path == "/api/rules" && r.Method == "PUT":
		in, err := requestJSON[RulesInput](w, r)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		v, err := s.ReplaceRules(in)
		writeJSON(w, v, err)
	case r.URL.Path == "/api/replay" && r.Method == "POST":
		in, err := requestJSON[ReplayInput](w, r)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		v, err := s.Replay(r.Context(), in)
		writeJSON(w, v, err)
	case r.URL.Path == "/api/clear" && r.Method == "POST":
		in, err := requestJSON[struct {
			Confirm bool `json:"confirm"`
		}](w, r)
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		if !in.Confirm {
			writeJSON(w, nil, errors.New("confirm=true is required"))
			return
		}
		n := s.Store.Clear()
		s.recordAction("flows_clear", map[string]any{"removed": n})
		writeJSON(w, map[string]any{"removed": n, "scope": "in-memory only"}, nil)
	case r.URL.Path == "/api/export/har" && r.Method == "GET":
		q, err := parseQuery(r.URL.Query())
		if err != nil {
			writeJSON(w, nil, err)
			return
		}
		v, err := s.Export(ExportInput{Filter: q.Filter, Limit: q.Limit, BodyLimit: 8192})
		if err == nil {
			w.Header().Set("Content-Disposition", `attachment; filename="netlens-redacted.har"`)
		}
		writeJSON(w, v, err)
	default:
		http.NotFound(w, r)
	}
}

// Run starts both listeners; stdio mode shares their live engine and exits on client disconnect.
func Run(ctx context.Context, cfg Config, stdio bool, logger *log.Logger) error {
	if logger == nil {
		logger = log.New(os.Stderr, "netlens: ", log.LstdFlags)
	}
	token, tokenPath, err := EnsureToken(cfg.DataDir, cfg.Token)
	if err != nil {
		return err
	}
	cfg.Token = token
	s, err := New(cfg)
	if err != nil {
		return err
	}
	defer s.Close()
	pl, err := net.Listen("tcp", cfg.ProxyAddr)
	if err != nil {
		return fmt.Errorf("proxy listen: %w", err)
	}
	cl, err := net.Listen("tcp", cfg.ControlAddr)
	if err != nil {
		pl.Close()
		return fmt.Errorf("control listen: %w", err)
	}
	s.mu.Lock()
	s.proxyAddr = pl.Addr().String()
	s.controlAddr = cl.Addr().String()
	s.mu.Unlock()
	s.Proxy.SetListenAddr(pl.Addr())
	proxyServer := &http.Server{Handler: s.Proxy, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 64 << 10, ErrorLog: logger}
	controlServer := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: logger}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errCh := make(chan error, 3)
	go func() { errCh <- proxyServer.Serve(pl) }()
	go func() { errCh <- controlServer.Serve(cl) }()
	logger.Printf("proxy=http://%s UI=http://%s MCP=http://%s/mcp", pl.Addr(), cl.Addr(), cl.Addr())
	logger.Printf("control credential: %s", tokenPath)
	logger.Printf("MITM=%t CA certificate: %s; replay=%t rules=%t", cfg.MITM, s.CA.CertPath(), cfg.AllowReplay, cfg.AllowRules)
	if cfg.OpenBrowser {
		if err := openBrowser(browserURL(cl.Addr().String(), token)); err != nil {
			// 浏览器失败不影响采集；日志中不输出包含令牌的启动地址。
			logger.Printf("could not open browser; open http://%s/ and use the control credential file", cl.Addr())
		}
	}
	if stdio {
		go func() { errCh <- s.MCP.RunStdio(ctx) }()
	}
	select {
	case <-ctx.Done():
		err = nil
	case err = <-errCh:
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, context.Canceled) {
			err = nil
		}
	}
	cancel()
	// Close hijacked CONNECT connections before waiting for normal HTTP handlers.
	_ = s.Proxy.Close()
	shutdownCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	_ = proxyServer.Shutdown(shutdownCtx)
	_ = controlServer.Shutdown(shutdownCtx)
	_ = proxyServer.Close()
	_ = controlServer.Close()
	return err
}
