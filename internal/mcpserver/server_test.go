package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Exercise the public transport with the official client, including the legacy
// initialize handshake and the current discovery-based protocol.
func TestHTTPClientCompatibility(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			var calls atomic.Int32
			server := New([]Tool{
				{
					Name:        "capture.inspect",
					Description: "Inspect captured data without changing it.",
					ReadOnly:    true,
					InputSchema: map[string]any{
						"type": "object",
						"properties": map[string]any{
							"id": map[string]any{"type": "string", "minLength": 1},
						},
						"required":             []string{"id"},
						"additionalProperties": false,
					},
					Handler: func(_ context.Context, raw json.RawMessage) (any, error) {
						calls.Add(1)
						var args struct {
							ID string `json:"id"`
						}
						if err := json.Unmarshal(raw, &args); err != nil {
							return nil, err
						}
						return map[string]any{"id": args.ID, "body": "untrusted captured text"}, nil
					},
				},
				{
					Name:        "capture.clear",
					Description: "Delete captured records.",
					Destructive: true,
					InputSchema: map[string]any{"type": "object", "additionalProperties": false},
					Handler: func(context.Context, json.RawMessage) (any, error) {
						return nil, errors.New("capture is still active")
					},
				},
			})
			httpServer := httptest.NewServer(server.HTTPHandler())
			defer httpServer.Close()
			client := mcp.NewClient(&mcp.Implementation{Name: "netlens-test", Version: "1"}, &mcp.ClientOptions{
				Capabilities: &mcp.ClientCapabilities{},
			})
			session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
				Endpoint:             httpServer.URL,
				HTTPClient:           httpServer.Client(),
				DisableStandaloneSSE: true,
			}, &mcp.ClientSessionOptions{ProtocolVersion: version})
			if err != nil {
				t.Fatalf("connect/initialize: %v", err)
			}
			defer session.Close()

			init := session.InitializeResult()
			if init.ProtocolVersion != version {
				t.Fatalf("protocol version = %q, want %q", init.ProtocolVersion, version)
			}
			if !strings.Contains(init.Instructions, "untrusted evidence") {
				t.Fatal("initialize/discover did not include captured-data trust instructions")
			}
			caps := init.Capabilities
			if caps.Tools == nil || caps.Tools.ListChanged || caps.Resources != nil || caps.Prompts != nil || caps.Logging != nil || caps.Completions != nil {
				t.Fatalf("unexpected advertised capabilities: %+v", caps)
			}

			catalog, err := session.ListTools(ctx, &mcp.ListToolsParams{})
			if err != nil || len(catalog.Tools) != 2 {
				t.Fatalf("tools/list: catalog=%+v err=%v", catalog, err)
			}
			byName := make(map[string]*mcp.Tool)
			for _, tool := range catalog.Tools {
				byName[tool.Name] = tool
			}
			inspect := byName["capture.inspect"]
			if inspect == nil || inspect.Annotations == nil || !inspect.Annotations.ReadOnlyHint || inspect.Annotations.DestructiveHint == nil || *inspect.Annotations.DestructiveHint || inspect.Annotations.OpenWorldHint == nil || *inspect.Annotations.OpenWorldHint {
				t.Fatalf("incorrect read-only tool annotations: %+v", inspect)
			}
			clear := byName["capture.clear"]
			if clear == nil || clear.Annotations.ReadOnlyHint || clear.Annotations.DestructiveHint == nil || !*clear.Annotations.DestructiveHint {
				t.Fatalf("incorrect destructive tool annotations: %+v", clear)
			}

			result, err := session.CallTool(ctx, &mcp.CallToolParams{
				Name:      "capture.inspect",
				Arguments: map[string]any{"id": "flow-1"},
			})
			if err != nil || result.IsError {
				t.Fatalf("tools/call: result=%+v err=%v", result, err)
			}
			payload := assertJSONResult(t, result)
			if payload["id"] != "flow-1" || payload["body"] != "untrusted captured text" {
				t.Fatalf("tool payload = %+v", payload)
			}

			for _, args := range []map[string]any{{}, {"id": 7}, {"id": "flow-1", "unknown": true}, {"id": ""}} {
				result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "capture.inspect", Arguments: args})
				if err != nil || !result.IsError {
					t.Fatalf("invalid arguments %v: result=%+v err=%v", args, result, err)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("invalid arguments reached handler: calls=%d", calls.Load())
			}

			result, err = session.CallTool(ctx, &mcp.CallToolParams{Name: "capture.clear"})
			if err != nil || !result.IsError {
				t.Fatalf("execution error must be a tool result: result=%+v err=%v", result, err)
			}
			payload = assertJSONResult(t, result)
			if payload["error"] != "capture is still active" {
				t.Fatalf("tool error payload = %+v", payload)
			}

			if _, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "missing.tool"}); err == nil {
				t.Fatal("unknown tool must return a protocol error")
			}
		})
	}
}

func assertJSONResult(t *testing.T, result *mcp.CallToolResult) map[string]any {
	t.Helper()
	if result.StructuredContent == nil || len(result.Content) != 1 {
		t.Fatalf("expected structured content and one text fallback: %+v", result)
	}
	text, ok := result.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("result content type = %T", result.Content[0])
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(text.Text), &payload); err != nil {
		t.Fatalf("text fallback is not JSON: %v", err)
	}
	structured, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("encode structured content: %v", err)
	}
	if string(structured) != text.Text {
		t.Fatalf("structured and text payloads differ: structured=%s text=%s", structured, text.Text)
	}
	return payload
}
