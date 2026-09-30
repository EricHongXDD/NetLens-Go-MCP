// Package model defines the immutable snapshots exchanged between capture, proxy and MCP.
package model

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

// Version 可通过构建参数注入，使桌面软件、CLI、API 与 MCP 使用同一发布版本。
var Version = "0.4.0"

type Body struct {
	Data      []byte `json:"-"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated"`
}

type Timings struct {
	DNSMS            float64 `json:"dns_ms"`
	ConnectMS        float64 `json:"connect_ms"`
	TLSMS            float64 `json:"tls_ms"`
	TTFBMS           float64 `json:"ttfb_ms"`
	TotalMS          float64 `json:"total_ms"`
	ConnectionReused bool    `json:"connection_reused"`
}

type Flow struct {
	ID              string      `json:"id"`
	Sequence        uint64      `json:"sequence"`
	StartedAt       time.Time   `json:"started_at"`
	Method          string      `json:"method"`
	URL             string      `json:"url"`
	Host            string      `json:"host"`
	Protocol        string      `json:"protocol"`
	RemoteAddr      string      `json:"remote_addr,omitempty"`
	RequestHeaders  http.Header `json:"request_headers"`
	RequestBody     Body        `json:"request_body"`
	StatusCode      int         `json:"status_code"`
	ResponseHeaders http.Header `json:"response_headers"`
	ResponseBody    Body        `json:"response_body"`
	Timings         Timings     `json:"timings"`
	Error           string      `json:"error,omitempty"`
	Source          string      `json:"source"`
	ParentID        string      `json:"parent_id,omitempty"`
	RuleIDs         []string    `json:"rule_ids,omitempty"`
	Completed       bool        `json:"completed"`
	RawAvailable    bool        `json:"-"`
}

func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

type Filter struct {
	Hosts         []string `json:"hosts,omitempty" jsonschema:"Exact hostnames or wildcard suffixes such as *.example.com"`
	ExcludeHosts  []string `json:"exclude_hosts,omitempty"`
	Methods       []string `json:"methods,omitempty"`
	URLContains   string   `json:"url_contains,omitempty"`
	StatusMin     int      `json:"status_min,omitempty"`
	StatusMax     int      `json:"status_max,omitempty"`
	MinDurationMS float64  `json:"min_duration_ms,omitempty"`
	OnlyErrors    bool     `json:"only_errors,omitempty"`
}

type CaptureConfig struct {
	Enabled bool   `json:"enabled"`
	Filter  Filter `json:"filter"`
}

type Query struct {
	Filter
	Limit          int    `json:"limit,omitempty"`
	BeforeSequence uint64 `json:"before_sequence,omitempty"`
}

type Summary struct {
	ID            string    `json:"id"`
	Sequence      uint64    `json:"sequence"`
	StartedAt     time.Time `json:"started_at"`
	Method        string    `json:"method"`
	URL           string    `json:"url"`
	Host          string    `json:"host"`
	StatusCode    int       `json:"status_code"`
	DurationMS    float64   `json:"duration_ms"`
	RequestBytes  int64     `json:"request_bytes"`
	ResponseBytes int64     `json:"response_bytes"`
	Completed     bool      `json:"completed"`
	Error         string    `json:"error,omitempty"`
	Source        string    `json:"source"`
	ParentID      string    `json:"parent_id,omitempty"`
}

type QueryResult struct {
	Items              []Summary `json:"items"`
	Matched            int       `json:"matched"`
	NextBeforeSequence uint64    `json:"next_before_sequence,omitempty"`
}

type RuleMatch struct {
	Hosts       []string `json:"hosts,omitempty"`
	Methods     []string `json:"methods,omitempty"`
	URLContains string   `json:"url_contains,omitempty"`
}

type MockResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body"`
}

type RuleAction struct {
	SetRequestHeaders    map[string]string `json:"set_request_headers,omitempty"`
	RemoveRequestHeaders []string          `json:"remove_request_headers,omitempty"`
	DelayMS              int               `json:"delay_ms,omitempty"`
	Mock                 *MockResponse     `json:"mock,omitempty"`
}

type Rule struct {
	ID      string     `json:"id"`
	Enabled bool       `json:"enabled"`
	Match   RuleMatch  `json:"match"`
	Action  RuleAction `json:"action"`
}

type ReplayOptions struct {
	URL           string            `json:"url,omitempty"`
	Method        string            `json:"method,omitempty"`
	SetHeaders    map[string]string `json:"set_headers,omitempty"`
	RemoveHeaders []string          `json:"remove_headers,omitempty"`
	Body          *string           `json:"body,omitempty"`
}
