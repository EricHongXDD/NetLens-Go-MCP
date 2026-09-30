// Package proxy implements a streaming, explicit HTTP debugging proxy.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netlens/internal/capture"
	"netlens/internal/model"
)

// Options configures an explicit proxy. UpstreamTLSConfig is intended for
// additional trusted test roots; disabling upstream verification is rejected.
// Record receives independent snapshots and must be safe for concurrent calls.
type Options struct {
	CA                *CA
	MITM              bool
	BodyLimit         int
	Timeout           time.Duration
	Record            func(model.Flow)
	GetCapture        func() model.CaptureConfig
	GetRules          func() []model.Rule
	UpstreamTLSConfig *tls.Config
}

type Proxy struct {
	opts      Options
	transport *http.Transport
	rootCtx   context.Context
	cancel    context.CancelFunc
	mu        sync.Mutex
	closed    bool
	conns     map[net.Conn]struct{}
	listeners []net.Addr
	localIPs  []net.IP
}

func New(opts Options) (*Proxy, error) {
	if opts.MITM && opts.CA == nil {
		return nil, errors.New("MITM requires a local CA")
	}
	if opts.BodyLimit < 0 {
		return nil, errors.New("body limit cannot be negative")
	}
	if opts.BodyLimit == 0 {
		opts.BodyLimit = 256 << 10
	}
	if opts.Timeout < 0 {
		return nil, errors.New("timeout cannot be negative")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Minute
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.UpstreamTLSConfig != nil {
		tlsConfig = opts.UpstreamTLSConfig.Clone()
		if tlsConfig.InsecureSkipVerify {
			return nil, errors.New("upstream TLS verification cannot be disabled")
		}
		if tlsConfig.ServerName != "" {
			return nil, errors.New("upstream TLS server name must be derived from each request target")
		}
		if tlsConfig.MinVersion < tls.VersionTLS12 {
			tlsConfig.MinVersion = tls.VersionTLS12
		}
	}
	rootCtx, cancel := context.WithCancel(context.Background())
	p := &Proxy{opts: opts, rootCtx: rootCtx, cancel: cancel, conns: make(map[net.Conn]struct{})}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ip, _, err := net.ParseCIDR(a.String()); err == nil {
				p.localIPs = append(p.localIPs, ip)
			}
		}
	}
	p.transport = &http.Transport{
		Proxy:                  nil, // Never inherit HTTP_PROXY or HTTPS_PROXY.
		DialContext:            p.dialContext,
		TLSClientConfig:        tlsConfig,
		ForceAttemptHTTP2:      true,
		DisableCompression:     true, // Capture the actual forwarded representation.
		MaxIdleConns:           128,
		MaxIdleConnsPerHost:    16,
		MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    min(10*time.Second, opts.Timeout),
		ResponseHeaderTimeout:  opts.Timeout,
		ExpectContinueTimeout:  time.Second,
	}
	return p, nil
}

// SetListenAddr registers the proxy's bound listener address. ServeHTTP also
// uses the incoming connection's local address. Registering the listener makes
// the same loop protection apply to tool-initiated Replay calls.
func (p *Proxy) SetListenAddr(addr net.Addr) {
	if addr == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, existing := range p.listeners {
		if existing.Network() == addr.Network() && existing.String() == addr.String() {
			return
		}
	}
	p.listeners = append(p.listeners, addr)
}

// Close cancels active work, closes hijacked CONNECT connections, and releases
// idle upstream connections. The owner should also close its http.Server.
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	p.cancel()
	p.transport.CloseIdleConnections()
	for _, c := range conns {
		_ = c.Close()
	}
	return nil
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.rootCtx.Err() != nil {
		http.Error(w, "proxy is closed", http.StatusServiceUnavailable)
		return
	}
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	if err := validateURL(r.URL); err != nil {
		http.Error(w, "invalid proxy target: "+err.Error(), http.StatusBadRequest)
		return
	}
	if wantsUpgrade(r.Header) {
		http.Error(w, "protocol upgrades (including WebSocket) are not supported by this version", http.StatusNotImplemented)
		return
	}
	flow, err := p.forward(r.Context(), r, "proxy", "", w)
	if err != nil && flow.StatusCode != 0 {
		// Once response headers have been sent, a normal handler return would
		// incorrectly terminate a damaged chunked response as a successful one.
		// forward has already published its final failure snapshot.
		panic(http.ErrAbortHandler)
	}
}

// Replay sends a request through the same instrumentation and rules.
// Redirects are returned to the caller. URL edits are restricted to the original
// origin, so retained credentials can never be inherited by another origin.
func (p *Proxy) Replay(ctx context.Context, original model.Flow, edits model.ReplayOptions) (model.Flow, error) {
	if !original.Completed {
		return model.Flow{}, errors.New("cannot replay a request that is still in progress")
	}
	if !original.RawAvailable || original.Source == "tunnel" || original.Method == http.MethodConnect {
		return model.Flow{}, errors.New("raw HTTP request is unavailable; encrypted CONNECT tunnels cannot be replayed")
	}
	originalURL, err := url.Parse(original.URL)
	if err != nil || validateURL(originalURL) != nil {
		return model.Flow{}, errors.New("the original request has an invalid absolute HTTP(S) URL")
	}
	target := originalURL
	if edits.URL != "" {
		target, err = url.Parse(edits.URL)
		if err != nil {
			return model.Flow{}, fmt.Errorf("invalid replay URL: %w", err)
		}
	}
	if err := validateURL(target); err != nil {
		return model.Flow{}, fmt.Errorf("invalid replay URL: %w", err)
	}
	if !sameOrigin(originalURL, target) {
		return model.Flow{}, errors.New("replay URL must have the same scheme, hostname, and effective port as the captured request")
	}
	var body []byte
	if edits.Body != nil {
		body = []byte(*edits.Body)
	} else {
		if original.RequestBody.Truncated || int64(len(original.RequestBody.Data)) != original.RequestBody.Size {
			return model.Flow{}, errors.New("captured request body is incomplete; supply a complete replacement body to replay")
		}
		body = append([]byte(nil), original.RequestBody.Data...)
	}
	method := original.Method
	if edits.Method != "" {
		method = edits.Method
	}
	if strings.EqualFold(method, http.MethodConnect) || !validToken(method) {
		return model.Flow{}, errors.New("replay method must be a valid HTTP method other than CONNECT")
	}
	req, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return model.Flow{}, err
	}
	req.Header = original.RequestHeaders.Clone()
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	// These values are derived from the edited URL and actual body, never from
	// stale capture headers. Host cannot be used to bypass the origin check.
	for _, key := range []string{"Host", "Content-Length", "Transfer-Encoding", "Trailer"} {
		req.Header.Del(key)
	}
	if edits.Body != nil {
		// The replacement is a new plain byte sequence. Old representation
		// encodings and body checksums no longer describe it. Explicit edits
		// below may provide new values if the caller also supplied encoded data.
		for _, key := range []string{"Content-Encoding", "Content-MD5", "Digest", "Content-Digest", "Repr-Digest"} {
			req.Header.Del(key)
		}
	}
	if wantsUpgrade(req.Header) {
		return model.Flow{}, errors.New("protocol upgrades cannot be replayed")
	}
	if err := mutateHeaders(req.Header, edits.SetHeaders, edits.RemoveHeaders); err != nil {
		return model.Flow{}, err
	}
	stripHopHeaders(req.Header)
	return p.forward(ctx, req, "replay", original.ID, nil)
}

func (p *Proxy) requestContext(parent context.Context, limited bool) (context.Context, func()) {
	var ctx context.Context
	var cancel context.CancelFunc
	if limited {
		ctx, cancel = context.WithTimeout(parent, p.opts.Timeout)
	} else {
		ctx, cancel = context.WithCancel(parent)
	}
	stop := context.AfterFunc(p.rootCtx, cancel)
	return ctx, func() { stop(); cancel() }
}

func (p *Proxy) forward(parent context.Context, in *http.Request, source, parentID string, w http.ResponseWriter) (flow model.Flow, resultErr error) {
	ctx, cancel := p.requestContext(parent, true)
	defer cancel()
	if w != nil {
		// An upstream may produce a response before a streaming upload finishes.
		// Keep net/http from draining the upload before it writes that response.
		_ = http.NewResponseController(w).EnableFullDuplex()
		if deadline, ok := ctx.Deadline(); ok {
			controller := http.NewResponseController(w)
			_ = controller.SetReadDeadline(deadline)
			_ = controller.SetWriteDeadline(deadline)
			defer func() {
				_ = controller.SetReadDeadline(time.Time{})
				_ = controller.SetWriteDeadline(time.Time{})
			}()
		}
	}
	req := in.Clone(ctx)
	u := *in.URL
	req.URL = &u
	req.RequestURI = ""
	req.Host = req.URL.Host
	req.Close = false
	// A transparent Transport retry must not open an uncaptured replacement
	// body. Calls with a body can be retried explicitly by the tool caller.
	req.GetBody = nil
	req.TransferEncoding = nil
	req.Trailer = nil
	if req.Header == nil {
		req.Header = make(http.Header)
	}
	stripHopHeaders(req.Header)
	flow = model.Flow{
		ID: model.NewID(), StartedAt: time.Now().UTC(), Method: req.Method,
		URL: req.URL.String(), Host: req.URL.Host, Protocol: in.Proto,
		RemoteAddr: in.RemoteAddr, RequestHeaders: requestHeaders(req),
		ResponseHeaders: make(http.Header), Source: source, ParentID: parentID,
		RawAvailable: true,
	}
	if flow.Protocol == "" {
		flow.Protocol = "HTTP/1.1"
	}
	trace := newTrace(flow.StartedAt)
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace.clientTrace()))
	if w != nil && req.Body != nil && req.Body != http.NoBody {
		// net/http's inbound Body.Close may drain the client body. In particular,
		// an upstream dial failure must not wait for a client still expecting
		// 100 Continue. The server owns inbound body cleanup when we return.
		ownedBody := &outboundBodyReader{body: req.Body}
		req.Body = ownedBody
		defer ownedBody.Close()
	}
	requestBody := newBodyCapture(req.Body, req.ContentLength, p.opts.BodyLimit)
	if req.Body != nil && req.Body != http.NoBody {
		req.Body = requestBody
	}
	var responseBody *bodyCapture
	cfg := p.captureConfig()
	p.publish(flow, cfg)
	defer func() {
		if w != nil && in.Body != nil && !requestBody.fullyConsumed() {
			// The server would otherwise try to drain an unfinished small body
			// after this handler returns, when its deadline has been cleared.
			// Interrupt pending reads, close that body within a bounded deadline,
			// and then let net/http send or finish the response normally.
			_ = http.NewResponseController(w).SetReadDeadline(time.Now())
			cancel()
			_ = in.Body.Close()
		}
		flow.RequestBody = requestBody.snapshot()
		if responseBody != nil {
			flow.ResponseBody = responseBody.snapshot()
		}
		flow.Timings = trace.snapshot()
		flow.Completed = true
		if resultErr != nil {
			flow.Error = resultErr.Error()
		}
		p.publish(flow, cfg)
	}()

	mock, err := p.applyRules(req, &flow)
	flow.RequestHeaders = requestHeaders(req)
	if err != nil {
		resultErr = err
		if w != nil {
			http.Error(w, "request interrupted: "+err.Error(), http.StatusBadGateway)
		}
		return flow, resultErr
	}
	stripHopHeaders(req.Header)
	flow.RequestHeaders = requestHeaders(req)
	if wantsUpgrade(req.Header) {
		resultErr = errors.New("a rule requested an unsupported protocol upgrade")
		if w != nil {
			http.Error(w, resultErr.Error(), http.StatusNotImplemented)
		}
		return flow, resultErr
	}
	if mock != nil {
		// Consume the request incrementally, keeping only its configured prefix.
		// The per-request read deadline also bounds a slow request body.
		if req.Body != nil {
			_, err = io.Copy(io.Discard, &contextReader{ctx: ctx, r: requestBody})
			_ = req.Body.Close()
			if err != nil {
				resultErr = fmt.Errorf("read mocked request body: %w", err)
				if w != nil {
					http.Error(w, resultErr.Error(), http.StatusBadGateway)
				}
				return flow, resultErr
			}
		}
		flow.Source = "mock"
		flow.StatusCode = mock.Status
		flow.ResponseHeaders = make(http.Header, len(mock.Headers)+2)
		for key, value := range mock.Headers {
			flow.ResponseHeaders.Set(key, value)
		}
		stripHopHeaders(flow.ResponseHeaders)
		if flow.ResponseHeaders.Get("Content-Type") == "" {
			flow.ResponseHeaders.Set("Content-Type", "text/plain; charset=utf-8")
		}
		body := mock.Body
		if mock.Status == http.StatusNoContent || mock.Status == http.StatusNotModified {
			body = ""
			flow.ResponseHeaders.Del("Content-Length")
		} else {
			flow.ResponseHeaders.Set("Content-Length", strconv.Itoa(len(body)))
		}
		if req.Method == http.MethodHead {
			body = ""
		}
		responseBody = newBodyCapture(io.NopCloser(strings.NewReader(body)), int64(len(body)), p.opts.BodyLimit)
		trace.firstByte()
		flow.Timings = trace.snapshot()
		p.publish(flow, cfg)
		resultErr = copyResponse(w, flow.StatusCode, flow.ResponseHeaders, responseBody)
		return flow, resultErr
	}

	resp, err := p.transport.RoundTrip(req)
	if err != nil {
		resultErr = fmt.Errorf("upstream request: %w", err)
		if w != nil {
			http.Error(w, resultErr.Error(), http.StatusBadGateway)
		}
		return flow, resultErr
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		resultErr = errors.New("upstream protocol switching is unsupported")
		if w != nil {
			http.Error(w, resultErr.Error(), http.StatusBadGateway)
		}
		return flow, resultErr
	}
	stripHopHeaders(resp.Header)
	flow.StatusCode = resp.StatusCode
	flow.ResponseHeaders = resp.Header.Clone()
	if resp.ContentLength >= 0 && flow.ResponseHeaders.Get("Content-Length") == "" && req.Method != http.MethodHead && resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotModified {
		flow.ResponseHeaders.Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	expectedResponseSize := resp.ContentLength
	if req.Method == http.MethodHead || resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotModified {
		expectedResponseSize = 0
	}
	responseBody = newBodyCapture(resp.Body, expectedResponseSize, p.opts.BodyLimit)
	flow.RequestBody = requestBody.snapshot()
	flow.Timings = trace.snapshot()
	p.publish(flow, cfg)
	if err := copyResponse(w, resp.StatusCode, flow.ResponseHeaders, responseBody); err != nil {
		resultErr = fmt.Errorf("stream response: %w", err)
	}
	return flow, resultErr
}

func copyResponse(w http.ResponseWriter, status int, headers http.Header, body io.Reader) error {
	if w == nil {
		_, err := io.Copy(io.Discard, body)
		return err
	}
	for key, values := range headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(status)
	// Flush headers and each bounded chunk, including long-lived SSE streams.
	// An HTTP/1.1 downstream remains compatible with HTTP/2 upstream responses.
	fw := &flushingWriter{writer: w, controller: http.NewResponseController(w)}
	if err := fw.controller.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return err
	}
	_, err := io.CopyBuffer(fw, body, make([]byte, 32<<10))
	return err
}

type flushingWriter struct {
	writer     io.Writer
	controller *http.ResponseController
}

func (w *flushingWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	if err == nil {
		if flushErr := w.controller.Flush(); flushErr != nil && !errors.Is(flushErr, http.ErrNotSupported) {
			err = flushErr
		}
	}
	return n, err
}

func (p *Proxy) captureConfig() model.CaptureConfig {
	if p.opts.GetCapture == nil {
		return model.CaptureConfig{Enabled: true}
	}
	return p.opts.GetCapture()
}

func (p *Proxy) publish(flow model.Flow, cfg model.CaptureConfig) {
	if p.opts.Record == nil || !cfg.Enabled {
		return
	}
	// Outcome-dependent filters cannot safely admit an unfinished flow: it may
	// ultimately fail the filter, and Record intentionally has no delete API.
	if !flow.Completed && (cfg.Filter.StatusMin != 0 || cfg.Filter.StatusMax != 0 || cfg.Filter.MinDurationMS != 0 || cfg.Filter.OnlyErrors) {
		return
	}
	if !capture.Matches(flow, cfg.Filter) {
		return
	}
	flow.RequestHeaders = flow.RequestHeaders.Clone()
	flow.ResponseHeaders = flow.ResponseHeaders.Clone()
	flow.RequestBody.Data = append([]byte(nil), flow.RequestBody.Data...)
	flow.ResponseBody.Data = append([]byte(nil), flow.ResponseBody.Data...)
	flow.RuleIDs = append([]string(nil), flow.RuleIDs...)
	p.opts.Record(flow)
}

func (p *Proxy) applyRules(req *http.Request, flow *model.Flow) (*model.MockResponse, error) {
	if p.opts.GetRules == nil {
		return nil, nil
	}
	for _, rule := range p.opts.GetRules() {
		if !rule.Enabled || !ruleMatches(rule.Match, req) {
			continue
		}
		flow.RuleIDs = append(flow.RuleIDs, rule.ID)
		if err := mutateHeaders(req.Header, rule.Action.SetRequestHeaders, rule.Action.RemoveRequestHeaders); err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		if rule.Action.DelayMS > 0 {
			timer := time.NewTimer(time.Duration(rule.Action.DelayMS) * time.Millisecond)
			select {
			case <-req.Context().Done():
				timer.Stop()
				return nil, req.Context().Err()
			case <-timer.C:
			}
		}
		if rule.Action.Mock != nil {
			if rule.Action.Mock.Status < 200 || rule.Action.Mock.Status > 599 {
				return nil, errors.New("mock status must be between 200 and 599")
			}
			return rule.Action.Mock, nil
		}
	}
	return nil, req.Context().Err()
}

func ruleMatches(match model.RuleMatch, req *http.Request) bool {
	if len(match.Hosts) > 0 {
		matched := false
		for _, host := range match.Hosts {
			if capture.MatchHost(req.URL.Host, host) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(match.Methods) > 0 {
		matched := false
		for _, method := range match.Methods {
			if strings.EqualFold(req.Method, method) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return match.URLContains == "" || strings.Contains(req.URL.String(), match.URLContains)
}

func mutateHeaders(headers http.Header, set map[string]string, remove []string) error {
	for key, value := range set {
		if !validToken(key) || strings.ContainsAny(value, "\r\n\x00") {
			return fmt.Errorf("invalid request header %q", key)
		}
		switch strings.ToLower(key) {
		case "host", "content-length", "transfer-encoding", "trailer", "connection", "upgrade", "proxy-authorization", "proxy-connection":
			return fmt.Errorf("request header %q is controlled by the proxy", key)
		}
		headers.Set(key, value)
	}
	for _, key := range remove {
		if !validToken(key) {
			return fmt.Errorf("invalid request header %q", key)
		}
		headers.Del(key)
	}
	return nil
}

func requestHeaders(req *http.Request) http.Header {
	headers := req.Header.Clone()
	if headers == nil {
		headers = make(http.Header)
	}
	headers.Set("Host", req.Host)
	if req.ContentLength > 0 {
		headers.Set("Content-Length", strconv.FormatInt(req.ContentLength, 10))
	}
	return headers
}

func stripHopHeaders(headers http.Header) {
	for _, value := range headers.Values("Connection") {
		for _, key := range strings.Split(value, ",") {
			headers.Del(strings.TrimSpace(key))
		}
	}
	for _, key := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		headers.Del(key)
	}
}

func wantsUpgrade(headers http.Header) bool {
	if headers.Get("Upgrade") != "" {
		return true
	}
	for _, value := range headers.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

func validToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func validateURL(u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Opaque != "" {
		return errors.New("an absolute http:// or https:// URL is required")
	}
	if u.User != nil {
		return errors.New("URL userinfo is not allowed; supply credentials using explicit headers")
	}
	if u.Fragment != "" {
		return errors.New("URL fragments are not sent in HTTP requests")
	}
	if u.Hostname() == "" || strings.ContainsAny(u.Host, "\r\n\t /\\#?@") {
		return errors.New("invalid target hostname")
	}
	if strings.HasSuffix(u.Host, ":") {
		return errors.New("empty target port")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("target port must be between 1 and 65535")
		}
	}
	return nil
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && canonicalHost(a.Hostname()) == canonicalHost(b.Hostname()) && effectivePort(a) == effectivePort(b)
}

func canonicalHost(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	// A trailing DNS dot remains part of a web origin even when DNS resolves
	// both spellings to the same server. Do not inherit credentials across it.
	return strings.ToLower(host)
}

func effectivePort(u *url.URL) string {
	if port := u.Port(); port != "" {
		// A leading-zero spelling does not create a different origin.
		if n, err := strconv.Atoi(port); err == nil {
			return strconv.Itoa(n)
		}
		return port
	}
	if u.Scheme == "https" {
		return "443"
	}
	return "80"
}

func (p *Proxy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if p.rootCtx.Err() != nil {
		return nil, errors.New("proxy is closed")
	}
	if p.isSelfAddress(ctx, address) {
		return nil, errors.New("refusing a connection back to this proxy")
	}
	dialer := &net.Dialer{Timeout: min(10*time.Second, p.opts.Timeout), KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	// Check the actual connected IP as well, catching host aliases and DNS
	// rebinding without doing a separate, potentially stale DNS lookup.
	if p.isSelfAddress(ctx, conn.RemoteAddr().String()) {
		_ = conn.Close()
		return nil, errors.New("refusing a connection back to this proxy")
	}
	return conn, nil
}

func (p *Proxy) isSelfAddress(ctx context.Context, target string) bool {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil && strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		ip = net.ParseIP("127.0.0.1")
	}
	if ip == nil {
		return false
	}
	p.mu.Lock()
	listeners := append([]net.Addr(nil), p.listeners...)
	p.mu.Unlock()
	if addr, ok := ctx.Value(http.LocalAddrContextKey).(net.Addr); ok {
		listeners = append(listeners, addr)
	}
	for _, addr := range listeners {
		listenHost, listenPort, err := net.SplitHostPort(addr.String())
		if err != nil || listenPort != port {
			continue
		}
		listenIP := net.ParseIP(listenHost)
		if listenIP == nil || listenIP.IsUnspecified() {
			if ip.IsLoopback() || ip.IsUnspecified() {
				return true
			}
			for _, local := range p.localIPs {
				if local.Equal(ip) {
					return true
				}
			}
		} else if listenIP.Equal(ip) {
			return true
		}
	}
	return false
}

func (p *Proxy) trackConn(conn net.Conn) bool {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = conn.Close()
		return false
	}
	p.conns[conn] = struct{}{}
	p.mu.Unlock()
	return true
}

func (p *Proxy) untrackConn(conn net.Conn) {
	p.mu.Lock()
	delete(p.conns, conn)
	p.mu.Unlock()
}

// bodyCapture counts every byte consumed without accumulating the full stream.
// Snapshots have independent backing arrays, including while HTTP/2 writes a
// request body concurrently with an early response.
type bodyCapture struct {
	body     io.ReadCloser
	expected int64
	limit    int
	mu       sync.Mutex
	data     []byte
	size     int64
	eof      bool
	readErr  bool
}

func newBodyCapture(body io.ReadCloser, expected int64, limit int) *bodyCapture {
	if body == nil || body == http.NoBody {
		return &bodyCapture{body: http.NoBody, expected: 0, limit: limit, eof: true}
	}
	return &bodyCapture{body: body, expected: expected, limit: limit}
}

func (b *bodyCapture) Read(data []byte) (int, error) {
	n, err := b.body.Read(data)
	b.mu.Lock()
	if n > 0 {
		b.size += int64(n)
		if remaining := b.limit - len(b.data); remaining > 0 {
			b.data = append(b.data, data[:min(n, remaining)]...)
		}
	}
	if errors.Is(err, io.EOF) {
		b.eof = true
	} else if err != nil {
		b.readErr = true
	}
	b.mu.Unlock()
	return n, err
}

func (b *bodyCapture) Close() error { return b.body.Close() }

func (b *bodyCapture) snapshot() model.Body {
	b.mu.Lock()
	defer b.mu.Unlock()
	complete := !b.readErr && (b.eof || (b.expected >= 0 && b.size == b.expected))
	return model.Body{Data: append([]byte(nil), b.data...), Size: b.size, Truncated: b.size > int64(len(b.data)) || !complete}
}

func (b *bodyCapture) fullyConsumed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return !b.readErr && (b.eof || (b.expected >= 0 && b.size == b.expected))
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

type outboundBodyReader struct {
	body   io.ReadCloser
	closed atomic.Bool
}

func (r *outboundBodyReader) Read(data []byte) (int, error) {
	if r.closed.Load() {
		return 0, errors.New("outbound request body is closed")
	}
	return r.body.Read(data)
}

func (r *outboundBodyReader) Close() error {
	r.closed.Store(true)
	return nil
}

func (r *contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(data)
}

type traceState struct {
	mu            sync.Mutex
	started       time.Time
	dnsStarted    time.Time
	tlsStarted    time.Time
	connectStarts map[string]time.Time
	timings       model.Timings
	firstByteSeen bool
}

func newTrace(started time.Time) *traceState {
	return &traceState{started: started, connectStarts: make(map[string]time.Time)}
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}

func (t *traceState) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			t.mu.Lock()
			t.dnsStarted = time.Now()
			t.mu.Unlock()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			t.mu.Lock()
			if !t.dnsStarted.IsZero() {
				t.timings.DNSMS += milliseconds(time.Since(t.dnsStarted))
			}
			t.mu.Unlock()
		},
		ConnectStart: func(network, address string) {
			t.mu.Lock()
			t.connectStarts[network+" "+address] = time.Now()
			t.mu.Unlock()
		},
		ConnectDone: func(network, address string, _ error) {
			t.mu.Lock()
			key := network + " " + address
			if started, ok := t.connectStarts[key]; ok {
				t.timings.ConnectMS += milliseconds(time.Since(started))
				delete(t.connectStarts, key)
			}
			t.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			t.mu.Lock()
			t.tlsStarted = time.Now()
			t.mu.Unlock()
		},
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			t.mu.Lock()
			if !t.tlsStarted.IsZero() {
				t.timings.TLSMS += milliseconds(time.Since(t.tlsStarted))
			}
			t.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			t.mu.Lock()
			t.timings.ConnectionReused = info.Reused
			t.mu.Unlock()
		},
		GotFirstResponseByte: t.firstByte,
	}
}

func (t *traceState) firstByte() {
	t.mu.Lock()
	if !t.firstByteSeen {
		t.timings.TTFBMS = milliseconds(time.Since(t.started))
		t.firstByteSeen = true
	}
	t.mu.Unlock()
}

func (t *traceState) snapshot() model.Timings {
	t.mu.Lock()
	defer t.mu.Unlock()
	result := t.timings
	result.TotalMS = milliseconds(time.Since(t.started))
	return result
}
