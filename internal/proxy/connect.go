package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"netlens/internal/model"
)

func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	host, _, err := net.SplitHostPort(authority)
	if err != nil || host == "" || strings.ContainsAny(authority, "/\\@?# \r\n\t") {
		http.Error(w, "CONNECT requires a valid host:port authority", http.StatusBadRequest)
		return
	}
	target := &url.URL{Scheme: "https", Host: authority}
	if err := validateURL(target); err != nil {
		http.Error(w, "invalid CONNECT target: "+err.Error(), http.StatusBadRequest)
		return
	}
	if p.opts.MITM {
		p.serveMITM(w, r, authority)
	} else {
		p.serveTunnel(w, r, authority)
	}
}

func connectFlow(r *http.Request, authority, source string) model.Flow {
	return model.Flow{
		ID: model.NewID(), StartedAt: time.Now().UTC(), Method: http.MethodConnect,
		URL: "https://" + authority, Host: authority, Protocol: r.Proto,
		RemoteAddr: r.RemoteAddr, RequestHeaders: r.Header.Clone(),
		ResponseHeaders: make(http.Header), Source: source, RawAvailable: false,
	}
}

func (p *Proxy) serveTunnel(w http.ResponseWriter, r *http.Request, authority string) {
	ctx, cancel := p.requestContext(r.Context(), true)
	defer cancel()
	flow := connectFlow(r, authority, "tunnel")
	trace := newTrace(flow.StartedAt)
	ctx = httptrace.WithClientTrace(ctx, trace.clientTrace())
	cfg := p.captureConfig()
	p.publish(flow, cfg)
	defer func() {
		flow.Completed = true
		flow.Timings = trace.snapshot()
		p.publish(flow, cfg)
	}()
	upstream, err := p.dialTunnel(ctx, authority)
	if err != nil {
		flow.Error = "CONNECT upstream: " + err.Error()
		http.Error(w, flow.Error, http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	if !p.trackConn(upstream) {
		flow.Error = "proxy is closed"
		http.Error(w, flow.Error, http.StatusServiceUnavailable)
		return
	}
	defer p.untrackConn(upstream)
	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		flow.Error = "CONNECT requires HTTP/1.1 connection hijacking"
		http.Error(w, flow.Error, http.StatusNotImplemented)
		return
	}
	defer client.Close()
	if !p.trackConn(client) {
		flow.Error = "proxy is closed"
		return
	}
	defer p.untrackConn(client)
	stop := context.AfterFunc(ctx, func() {
		_ = upstream.Close()
		_ = client.Close()
	})
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = upstream.SetDeadline(deadline)
		_ = client.SetDeadline(deadline)
	}
	if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		flow.Error = "write CONNECT response: " + err.Error()
		return
	}
	flow.StatusCode = http.StatusOK
	trace.firstByte()
	flow.Timings = trace.snapshot()
	p.publish(flow, cfg)
	type copyResult struct {
		upstream bool
		size     int64
		err      error
	}
	results := make(chan copyResult, 2)
	go func() {
		// The buffered reader may already contain bytes sent immediately after
		// CONNECT. Reading the raw socket here would silently discard them.
		n, err := io.Copy(upstream, &bufferedConn{Conn: client, reader: buffered.Reader})
		closeWrite(upstream)
		results <- copyResult{upstream: true, size: n, err: err}
	}()
	go func() {
		n, err := io.Copy(client, upstream)
		closeWrite(client)
		results <- copyResult{size: n, err: err}
	}()
	for i := 0; i < 2; i++ {
		result := <-results
		if result.upstream {
			// These are tunnel wire-byte counts, never decoded HTTP bodies.
			flow.RequestBody = model.Body{Size: result.size, Truncated: result.size > 0}
		} else {
			flow.ResponseBody = model.Body{Size: result.size, Truncated: result.size > 0}
		}
		if result.err != nil && !errors.Is(result.err, net.ErrClosed) {
			flow.Error = result.err.Error()
			_ = client.Close()
			_ = upstream.Close()
		}
	}
	if err := ctx.Err(); err != nil {
		flow.Error = err.Error()
	}
}

func closeWrite(conn net.Conn) {
	if conn, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = conn.CloseWrite()
	}
}

func (p *Proxy) serveMITM(w http.ResponseWriter, r *http.Request, authority string) {
	ctx, cancel := p.requestContext(r.Context(), false)
	defer cancel()
	flow := connectFlow(r, authority, "proxy")
	recordFailure := func(err error) {
		flow.Error = err.Error()
		flow.Completed = true
		flow.Timings.TotalMS = milliseconds(time.Since(flow.StartedAt))
		p.publish(flow, p.captureConfig())
	}
	cert, err := p.opts.CA.certificateFor(authority)
	if err != nil {
		recordFailure(fmt.Errorf("issue interception certificate: %w", err))
		http.Error(w, "cannot issue interception certificate", http.StatusBadGateway)
		return
	}
	if p.isSelfAddress(ctx, authority) {
		err := errors.New("refusing a CONNECT tunnel back to this proxy")
		recordFailure(err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	client, buffered, err := http.NewResponseController(w).Hijack()
	if err != nil {
		recordFailure(errors.New("MITM requires HTTP/1.1 connection hijacking"))
		http.Error(w, "MITM requires HTTP/1.1 connection hijacking", http.StatusNotImplemented)
		return
	}
	defer client.Close()
	if !p.trackConn(client) {
		recordFailure(errors.New("proxy is closed"))
		return
	}
	defer p.untrackConn(client)
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	if _, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err == nil {
		err = buffered.Flush()
	}
	if err != nil {
		recordFailure(fmt.Errorf("write CONNECT response: %w", err))
		return
	}
	// Preserve pipelined TLS bytes already read by net/http's CONNECT parser.
	tlsConn := tls.Server(&bufferedConn{Conn: client, reader: buffered.Reader}, &tls.Config{
		Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	handshakeCtx, stopHandshake := context.WithTimeout(ctx, min(p.opts.Timeout, 10*time.Second))
	err = tlsConn.HandshakeContext(handshakeCtx)
	stopHandshake()
	if err != nil {
		recordFailure(fmt.Errorf("client TLS handshake: %w", err))
		return
	}
	listener := newSingleConnListener(tlsConn)
	defer listener.Close()
	connectURL := &url.URL{Scheme: "https", Host: authority}
	server := &http.Server{
		ReadHeaderTimeout: min(p.opts.Timeout, 10*time.Second),
		IdleTimeout:       min(p.opts.Timeout, 30*time.Second),
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
		TLSNextProto:      make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ConnState: func(_ net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				_ = listener.Close()
			}
		},
		Handler: http.HandlerFunc(func(innerW http.ResponseWriter, innerR *http.Request) {
			if innerR.Method == http.MethodConnect {
				http.Error(innerW, "nested CONNECT is not supported", http.StatusMethodNotAllowed)
				return
			}
			if wantsUpgrade(innerR.Header) {
				http.Error(innerW, "protocol upgrades (including WebSocket) are not supported by this version", http.StatusNotImplemented)
				return
			}
			if innerR.URL.IsAbs() {
				if err := validateURL(innerR.URL); err != nil || !sameOrigin(connectURL, innerR.URL) {
					http.Error(innerW, "HTTPS request target must match its CONNECT origin", http.StatusBadRequest)
					return
				}
			}
			innerHostURL := &url.URL{Scheme: "https", Host: innerR.Host}
			if err := validateURL(innerHostURL); err != nil || !sameOrigin(connectURL, innerHostURL) {
				http.Error(innerW, "HTTPS Host must match its CONNECT origin", http.StatusBadRequest)
				return
			}
			u := *innerR.URL
			u.Scheme = "https"
			u.Host = authority
			innerR.URL = &u
			innerR.Host = authority
			flow, err := p.forward(innerR.Context(), innerR, "proxy", "", innerW)
			if err != nil && flow.StatusCode != 0 {
				panic(http.ErrAbortHandler)
			}
		}),
	}
	defer server.Close()
	if err := server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		recordFailure(fmt.Errorf("serve intercepted HTTPS: %w", err))
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// 串联隧道也要保留 TCP 半关闭，允许上传结束后继续读取响应。
func (c *bufferedConn) CloseWrite() error {
	if conn, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return conn.CloseWrite()
	}
	return nil
}

func (c *bufferedConn) Read(data []byte) (int, error) {
	if buffered := c.reader.Buffered(); buffered > 0 {
		// Consume only bytes net/http read before Hijack. Continuing to use its
		// connReader for new socket reads would cancel the original request
		// context on a TCP half-close and truncate the other tunnel direction.
		return c.reader.Read(data[:min(len(data), buffered)])
	}
	return c.Conn.Read(data)
}

// The second Accept waits for the actual connection to close. Returning EOF
// immediately would let http.Server.Serve return before it finishes a request.
type singleConnListener struct {
	conn     net.Conn
	mu       sync.Mutex
	accepted bool
	done     chan struct{}
	once     sync.Once
}

func newSingleConnListener(conn net.Conn) *singleConnListener {
	return &singleConnListener{conn: conn, done: make(chan struct{})}
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if !l.accepted {
		l.accepted = true
		l.mu.Unlock()
		return l.conn, nil
	}
	l.mu.Unlock()
	<-l.done
	return nil, net.ErrClosed
}

func (l *singleConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }
