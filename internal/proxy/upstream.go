package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// SetUpstream 将 HTTP、HTTPS 解密和 CONNECT 隧道统一串联至显式上游。
// 地址为空时直连，始终不读取环境变量或系统代理，避免代理回环。
func (p *Proxy) SetUpstream(address string) error {
	var upstream *url.URL
	if address = strings.TrimSpace(address); address != "" {
		if !strings.Contains(address, "://") {
			address = "http://" + address
		}
		var err error
		upstream, err = url.Parse(address)
		if err != nil || upstream.Scheme != "http" || upstream.Hostname() == "" || upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" || (upstream.Path != "" && upstream.Path != "/") {
			return errors.New("上游请输入 HTTP 代理地址，例如 127.0.0.1:7890")
		}
		port := upstream.Port()
		if port == "" {
			port = "80"
		}
		if number, err := strconv.Atoi(port); err != nil || number < 1 || number > 65535 {
			return errors.New("上游端口必须在 1–65535 之间")
		}
		upstream.Host = net.JoinHostPort(upstream.Hostname(), port)
		upstream.Path = ""
		if p.isSelfAddress(context.Background(), upstream.Host) {
			return errors.New("上游不能指向 NetLens 自身")
		}
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return errors.New("proxy is closed")
	}
	p.upstream.Store(upstream)
	p.mu.Unlock()
	p.transport.CloseIdleConnections()
	return nil
}

func (p *Proxy) Upstream() string {
	if value := p.upstream.Load(); value != nil {
		return value.String()
	}
	return ""
}

func (p *Proxy) upstreamForRequest(req *http.Request) (*url.URL, error) {
	target := net.JoinHostPort(req.URL.Hostname(), effectivePort(req.URL))
	if p.isSelfAddress(req.Context(), target) {
		return nil, errors.New("refusing a request back to this proxy")
	}
	return p.upstream.Load(), nil
}

// 检查端口可达性，不修改系统配置，也不向公网发送测试请求。
func (p *Proxy) CheckUpstream(ctx context.Context) error {
	upstream := p.upstream.Load()
	if upstream == nil {
		return nil
	}
	conn, err := p.dialContext(ctx, "tcp", upstream.Host)
	if err != nil {
		return fmt.Errorf("无法连接上游 %s：%w", upstream.Host, err)
	}
	return conn.Close()
}

func (p *Proxy) dialTunnel(ctx context.Context, authority string) (net.Conn, error) {
	if p.isSelfAddress(ctx, authority) {
		return nil, errors.New("refusing a CONNECT tunnel back to this proxy")
	}
	upstream := p.upstream.Load()
	if upstream == nil {
		return p.dialContext(ctx, "tcp", authority)
	}
	conn, err := p.dialContext(ctx, "tcp", upstream.Host)
	if err != nil {
		return nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			conn.Close()
		}
	}()
	deadline := time.Now().Add(min(10*time.Second, p.opts.Timeout))
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: authority}, Host: authority, Header: make(http.Header)}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	// 限制代理握手头部，保留握手后提前到达的隧道数据。
	reader := bufio.NewReaderSize(conn, 64<<10)
	var header strings.Builder
	for header.Len() <= 64<<10 {
		line, err := reader.ReadSlice('\n')
		if err != nil {
			return nil, err
		}
		header.Write(line)
		if string(line) == "\r\n" {
			break
		}
	}
	if header.Len() > 64<<10 {
		return nil, errors.New("upstream CONNECT headers exceed limit")
	}
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(header.String())), req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream CONNECT rejected: %s", resp.Status)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	succeeded = true
	return &bufferedConn{Conn: conn, reader: reader}, nil
}
