package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"netlens/internal/model"
)

// The client deliberately sends no body until it receives 100 Continue. Closing
// the inbound body from Transport's error path used to wait for the entire
// proxy timeout before a connection failure could reach this client.
func TestProxyExpectContinueDialFailureReturnsPromptly(t *testing.T) {
	t.Parallel()
	p, err := New(Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	p.transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("intentional upstream dial failure")
	}
	regressionUnsentBodyResponse(t, p, "http://upstream.example/rejected", http.StatusBadGateway, true)
}

func TestProxyIncompletePostDialFailureReturnsPromptly(t *testing.T) {
	t.Parallel()
	p, err := New(Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	p.transport.DialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("intentional upstream dial failure")
	}
	// Without Expect, net/http's final response handling may drain a small
	// unread body. It must not do so after the proxy has cleared its deadline.
	regressionUnsentBodyResponse(t, p, "http://upstream.example/rejected", http.StatusBadGateway, false)
}

func TestProxyExpectContinueEarlyRejectionReturnsPromptly(t *testing.T) {
	t.Parallel()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			serverResult <- err
			return
		}
		if req.Header.Get("Expect") != "100-continue" || req.ContentLength != 3 {
			serverResult <- errors.New("upstream did not receive the expected request headers")
			return
		}
		// Reject solely from the headers; never request or read the upload.
		_, err = io.WriteString(conn, "HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		serverResult <- err
	}()
	p, err := New(Options{Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	regressionUnsentBodyResponse(t, p, "http://"+upstream.Addr().String()+"/rejected", http.StatusRequestEntityTooLarge, true)
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream rejection handler did not finish")
	}
}

func regressionUnsentBodyResponse(t *testing.T, p *Proxy, target string, wantStatus int, expectContinue bool) {
	t.Helper()
	server := httptest.NewServer(p)
	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		_ = p.Close()
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = p.Close()
		server.Close()
	})
	// This deadline is intentionally shorter than the proxy's three-second
	// deadline. An immediate failure must not wait for the upload timeout.
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	expect := ""
	if expectContinue {
		expect = "Expect: 100-continue\r\n"
	}
	if _, err := fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: ignored.example\r\nContent-Length: 3\r\n%s\r\n", target, expect); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("proxy failed to return an immediate response with an unsent body (Expect=%v): %v", expectContinue, err)
	}
	defer response.Body.Close()
	if response.StatusCode != wantStatus {
		t.Fatalf("status=%d, want %d", response.StatusCode, wantStatus)
	}
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		t.Fatalf("failure response was incomplete: %v", err)
	}
}

// A bytes.Reader gives Replay's outgoing request a GetBody function. Transport
// can use it to retry a stale pooled connection. Such a replacement body must
// either be captured too, or the request must fail for an explicit caller retry.
// A successful response with an empty capture for a transmitted body is invalid.
func TestReplayReconnectionCannotLoseCapturedBody(t *testing.T) {
	t.Parallel()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverResult := make(chan error, 1)
	sawFailedAttempt := make(chan struct{})
	go func() {
		serverResult <- regressionStaleConnectionUpstream(upstream, sawFailedAttempt)
	}()
	p, err := New(Options{Timeout: 2 * time.Second})
	if err != nil {
		_ = upstream.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = p.Close()
		_ = upstream.Close()
	})
	original := model.Flow{
		ID: "source-flow", Completed: true, RawAvailable: true,
		Method: http.MethodGet, URL: "http://" + upstream.Addr().String() + "/replay",
	}
	if _, err := p.Replay(context.Background(), original, model.ReplayOptions{}); err != nil {
		t.Fatalf("prime pooled connection: %v", err)
	}
	original.RequestHeaders = http.Header{"Expect": {"100-continue"}}
	original.RequestBody = model.Body{Data: []byte("abc"), Size: 3}
	flow, replayErr := p.Replay(context.Background(), original, model.ReplayOptions{})
	_ = upstream.Close() // Releases Accept if automatic retry was disabled.
	select {
	case <-sawFailedAttempt:
	case <-time.After(time.Second):
		t.Fatal("the test did not exercise failure on the reused connection")
	}
	select {
	case err := <-serverResult:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("stale-connection test server did not terminate")
	}
	if replayErr != nil {
		return // Explicit retry is allowed; an unrecorded automatic body is not.
	}
	if flow.StatusCode != http.StatusOK {
		t.Fatalf("unexpected successful replay status: %d", flow.StatusCode)
	}
	if flow.RequestBody.Truncated || flow.RequestBody.Size != 3 || !bytes.Equal(flow.RequestBody.Data, []byte("abc")) {
		t.Fatalf("successful retry lost its captured request body: data=%q size=%d truncated=%v",
			flow.RequestBody.Data, flow.RequestBody.Size, flow.RequestBody.Truncated)
	}
}

func regressionStaleConnectionUpstream(listener net.Listener, sawFailedAttempt chan<- struct{}) error {
	first, err := listener.Accept()
	if err != nil {
		return err
	}
	defer first.Close()
	_ = first.SetDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(first)
	prime, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("read prime request: %w", err)
	}
	if _, err := io.Copy(io.Discard, prime.Body); err != nil {
		return err
	}
	if _, err := io.WriteString(first, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
		return err
	}
	req, err := http.ReadRequest(reader)
	if err != nil {
		return fmt.Errorf("read pooled-connection request: %w", err)
	}
	if req.ContentLength != 3 || req.Header.Get("Expect") != "100-continue" {
		return errors.New("unexpected headers on the pooled-connection request")
	}
	close(sawFailedAttempt)
	_ = first.Close() // Lose this attempt before asking for the body.
	second, err := listener.Accept()
	if errors.Is(err, net.ErrClosed) {
		return nil // The caller explicitly declined an automatic retry.
	}
	if err != nil {
		return err
	}
	defer second.Close()
	_ = second.SetDeadline(time.Now().Add(3 * time.Second))
	retry, err := http.ReadRequest(bufio.NewReader(second))
	if err != nil {
		return fmt.Errorf("read automatic retry: %w", err)
	}
	if _, err := io.WriteString(second, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
		return err
	}
	body, err := io.ReadAll(retry.Body)
	if err != nil {
		return err
	}
	if string(body) != "abc" {
		return fmt.Errorf("automatic retry body=%q, want abc", body)
	}
	_, err = io.WriteString(second, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	return err
}

func TestConnectClientHalfCloseStillReceivesCompleteResponse(t *testing.T) {
	t.Parallel()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	serverResult := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		// The target waits for EOF before producing any response. A full Close
		// in place of CloseWrite would destroy the response direction here.
		body, err := io.ReadAll(conn)
		if err != nil {
			serverResult <- err
			return
		}
		if string(body) != "half-closed request" {
			serverResult <- fmt.Errorf("wrong tunnel body: %q", body)
			return
		}
		_, err = io.WriteString(conn, "complete response after EOF")
		serverResult <- err
	}()
	final := make(chan model.Flow, 1)
	p, err := New(Options{Timeout: 3 * time.Second, Record: func(flow model.Flow) {
		if flow.Completed {
			final <- flow
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(p)
	conn, err := net.DialTimeout("tcp", server.Listener.Addr().String(), time.Second)
	if err != nil {
		_ = p.Close()
		server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		_ = p.Close()
		server.Close()
	})
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nhalf-closed request", upstream.Addr(), upstream.Addr()); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT handshake: response=%v err=%v", response, err)
	}
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil || string(body) != "complete response after EOF" {
		t.Fatalf("half-close lost the response: body=%q err=%v", body, err)
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
	select {
	case flow := <-final:
		if flow.Error != "" || flow.RequestBody.Size != int64(len("half-closed request")) || flow.ResponseBody.Size != int64(len(body)) {
			t.Fatalf("incorrect completed half-close tunnel capture: %+v", flow)
		}
	case <-time.After(time.Second):
		t.Fatal("half-closed tunnel handler did not finish")
	}
}
