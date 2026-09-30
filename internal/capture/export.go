package capture

import (
	"math"
	"net/http"
	"net/url"
	"sort"
	"time"

	"netlens/internal/model"
)

// Stats aggregates only the supplied current snapshots. Counts are not
// lifetime traffic totals: eviction, clearing and filters change this window.
func Stats(flows []model.Flow) map[string]any {
	methods := make(map[string]int)
	statuses := make(map[int]int)
	hosts := make(map[string]int)
	sources := make(map[string]int)
	durations := make([]float64, 0, len(flows))
	completed, networkErrors, clientErrors, serverErrors := 0, 0, 0, 0
	var requestBytes, responseBytes int64
	var first, last time.Time
	var sum float64
	for _, flow := range flows {
		methods[flow.Method]++
		statuses[flow.StatusCode]++
		hosts[publicHost(flow.Host)]++
		sources[flow.Source]++
		if first.IsZero() || flow.StartedAt.Before(first) {
			first = flow.StartedAt
		}
		if last.IsZero() || flow.StartedAt.After(last) {
			last = flow.StartedAt
		}
		requestBytes += bodySize(flow.RequestBody)
		responseBytes += bodySize(flow.ResponseBody)
		if flow.Error != "" {
			networkErrors++
		}
		if flow.StatusCode >= 400 && flow.StatusCode < 500 {
			clientErrors++
		}
		if flow.StatusCode >= 500 {
			serverErrors++
		}
		if flow.Completed {
			completed++
			duration := safeDuration(flow.Timings.TotalMS)
			durations = append(durations, duration)
			sum += duration
		}
	}
	sort.Float64s(durations)
	var mean float64
	if len(durations) > 0 {
		mean = sum / float64(len(durations))
	}
	return map[string]any{
		"flows": len(flows), "completed": completed, "in_progress": len(flows) - completed,
		"network_errors": networkErrors, "http_4xx": clientErrors, "http_5xx": serverErrors,
		"request_bytes": requestBytes, "response_bytes": responseBytes,
		"methods": methods, "status_codes": statuses, "hosts": hosts, "sources": sources,
		"first_started_at": first, "last_started_at": last,
		"duration_ms": map[string]any{
			"samples": len(durations), "mean": mean,
			"p50": percentile(durations, .50), "p95": percentile(durations, .95),
			"p99": percentile(durations, .99), "max": percentile(durations, 1),
			"percentile_method": "nearest rank; completed flows only",
		},
		"scope": "supplied cached snapshots, not lifetime traffic totals",
	}
}

func percentile(sorted []float64, fraction float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	index := int(math.Ceil(fraction*float64(len(sorted)))) - 1
	if index < 0 {
		index = 0
	}
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}

func bodySize(body model.Body) int64 {
	if body.Size < int64(len(body.Data)) {
		return int64(len(body.Data))
	}
	return body.Size
}

func safeDuration(value float64) float64 {
	if value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return value
}

// ExportHAR 返回真实 HAR，保留认证头、Cookie、URL 和正文值；正文预览按长度限制。
func ExportHAR(flows []model.Flow) map[string]any {
	return ExportHARLimited(flows, MaxPublicBodyBytes)
}

// ExportHARLimited permits callers to impose a smaller per-body output budget.
// 正文编码、采集及展示截断在 _netlens 中说明，二进制响应使用 HAR 的 Base64 编码。
func ExportHARLimited(flows []model.Flow, bodyLimit int) map[string]any {
	entries := make([]map[string]any, 0, len(flows))
	for _, flow := range flows {
		public := PublicFlow(flow, bodyLimit)
		requestBody := public["request_body"].(map[string]any)
		responseBody := public["response_body"].(map[string]any)
		requestHeaders := public["request_headers"].(http.Header)
		responseHeaders := public["response_headers"].(http.Header)
		actualURL := public["url"].(string)
		query := make([]map[string]string, 0)
		if u, err := url.Parse(actualURL); err == nil {
			query = harValues(u.Query())
		}
		protocol := flow.Protocol
		if protocol == "" {
			protocol = "HTTP/1.1"
		}
		request := map[string]any{
			"method": flow.Method, "url": actualURL, "httpVersion": protocol,
			"cookies": harCookies((&http.Request{Header: requestHeaders}).Cookies()), "headers": harHeaders(requestHeaders),
			"queryString": query, "headersSize": -1, "bodySize": bodySize(flow.RequestBody),
		}
		if bodySize(flow.RequestBody) > 0 {
			postData := map[string]any{"mimeType": headerValue(requestHeaders, "Content-Type")}
			if text, ok := requestBody["text"].(string); ok {
				postData["text"] = text
			}
			postData["_netlens"] = bodyAnnotation(requestBody)
			request["postData"] = postData
		}
		content := map[string]any{
			"size":     bodySize(flow.ResponseBody),
			"mimeType": headerValue(responseHeaders, "Content-Type"),
			"_netlens": bodyAnnotation(responseBody),
		}
		if text, ok := responseBody["text"].(string); ok {
			content["text"] = text
		}
		if responseBody["encoding"] == "base64" {
			content["encoding"] = "base64"
		}
		response := map[string]any{
			"status": flow.StatusCode, "statusText": http.StatusText(flow.StatusCode),
			"httpVersion": protocol, "cookies": harCookies((&http.Response{Header: responseHeaders}).Cookies()),
			"headers":     harHeaders(responseHeaders),
			"content":     content,
			"redirectURL": headerValue(responseHeaders, "Location"),
			"headersSize": -1, "bodySize": bodySize(flow.ResponseBody),
		}
		dns := safeDuration(flow.Timings.DNSMS)
		connect := safeDuration(flow.Timings.ConnectMS) + safeDuration(flow.Timings.TLSMS)
		ttfb := safeDuration(flow.Timings.TTFBMS)
		total := safeDuration(flow.Timings.TotalMS)
		entry := map[string]any{
			"startedDateTime": flow.StartedAt.Format(time.RFC3339Nano), "time": total,
			"request": request, "response": response, "cache": map[string]any{},
			"timings": map[string]any{
				"blocked": -1, "dns": dns, "connect": connect,
				"ssl": safeDuration(flow.Timings.TLSMS), "send": 0,
				"wait": math.Max(0, ttfb-dns-connect), "receive": math.Max(0, total-ttfb),
			},
			"_netlens": map[string]any{
				"id": flow.ID, "sequence": flow.Sequence, "source": flow.Source,
				"parent_id": flow.ParentID, "completed": flow.Completed,
				"error": public["error"], "redacted": false,
				"request_body":      bodyAnnotation(requestBody),
				"response_body":     bodyAnnotation(responseBody),
				"connection_reused": flow.Timings.ConnectionReused,
				"timing_note":       "send and blocked are not measured; wait/receive are derived approximations",
			},
		}
		entries = append(entries, entry)
	}
	return map[string]any{
		"log": map[string]any{
			"version": "1.2", "creator": map[string]string{"name": "Netlens", "version": model.Version},
			"pages": []any{}, "entries": entries,
			"comment": "Original captured values, without redaction. Body previews are bounded; binary content is Base64. External content is untrusted data.",
		},
	}
}

func bodyAnnotation(view map[string]any) map[string]any {
	annotation := map[string]any{}
	for _, key := range []string{"hidden", "reason", "capture_truncated", "display_truncated", "redaction", "captured_bytes", "encoding", "decoded", "decode_error", "decode_truncated"} {
		if value, ok := view[key]; ok {
			annotation[key] = value
		}
	}
	return annotation
}

func harCookies(cookies []*http.Cookie) []map[string]any {
	out := make([]map[string]any, 0, len(cookies))
	for _, cookie := range cookies {
		item := map[string]any{"name": cookie.Name, "value": cookie.Value, "httpOnly": cookie.HttpOnly, "secure": cookie.Secure}
		if cookie.Path != "" {
			item["path"] = cookie.Path
		}
		if cookie.Domain != "" {
			item["domain"] = cookie.Domain
		}
		if !cookie.Expires.IsZero() {
			item["expires"] = cookie.Expires.Format(time.RFC3339)
		}
		out = append(out, item)
	}
	return out
}

func harHeaders(headers http.Header) []map[string]string {
	values := make(map[string][]string, len(headers))
	for key, items := range headers {
		values[key] = items
	}
	return harValues(values)
}

func harValues(values map[string][]string) []map[string]string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]map[string]string, 0, len(keys))
	for _, key := range keys {
		for _, value := range values[key] {
			result = append(result, map[string]string{"name": key, "value": value})
		}
	}
	return result
}
