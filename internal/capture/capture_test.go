package capture

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"netlens/internal/model"
)

func sampleFlow(id string) model.Flow {
	request := []byte(`{"name":"alice","password":"request-secret","nested":{"access_token":"nested-secret","ok":true}}`)
	response := []byte(`{"result":"ok","apiKey":"response-secret","items":[{"client_secret":"array-secret"}]}`)
	return model.Flow{
		ID: id, StartedAt: time.Date(2026, 9, 30, 1, 2, 3, 0, time.UTC),
		Method: "POST", URL: "https://alice:user-secret@api.example.com/resource?api_key=url-secret&q=hello#fragment-secret",
		Host: "api.example.com", Protocol: "HTTP/1.1", Source: "proxy", Completed: true, RawAvailable: true,
		RequestHeaders: http.Header{"Authorization": {"Bearer header-secret"}, "Content-Type": {"application/json"}, "X-Request-Id": {"visible"}},
		RequestBody:    model.Body{Data: request, Size: int64(len(request))},
		StatusCode:     200, ResponseHeaders: http.Header{"Content-Type": {"application/json"}, "Set-Cookie": {"sid=cookie-secret"}},
		ResponseBody: model.Body{Data: response, Size: int64(len(response))},
		Timings:      model.Timings{TotalMS: 10, TTFBMS: 8, ConnectMS: 2}, RuleIDs: []string{"rule-1"},
	}
}

func testStore(t *testing.T, options Options) *Store {
	t.Helper()
	store, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestDeepCopyAndStableSequence(t *testing.T) {
	store := testStore(t, Options{MaxFlows: 3})
	input := sampleFlow("one")
	input.Completed = false
	store.Put(input)
	input.RequestHeaders.Set("Authorization", "changed-by-caller")
	input.RequestBody.Data[0] = 'X'
	input.RuleIDs[0] = "changed-rule"
	got, ok := store.Get("one")
	if !ok || got.RequestHeaders.Get("Authorization") != "Bearer header-secret" || got.RequestBody.Data[0] != '{' || got.RuleIDs[0] != "rule-1" {
		t.Fatalf("stored raw snapshot shared caller state: %#v", got)
	}
	sequence := got.Sequence
	got.ResponseHeaders.Set("X-Mutated", "yes")
	got.ResponseBody.Data[0] = 'Y'
	again, _ := store.Get("one")
	if again.ResponseHeaders.Get("X-Mutated") != "" || again.ResponseBody.Data[0] != '{' {
		t.Fatal("Get leaked mutable cache state")
	}
	store.Put(sampleFlow("two"))
	update := sampleFlow("one")
	update.StatusCode = 503
	update.Sequence = 100000
	store.Put(update)
	updated, _ := store.Get("one")
	if updated.Sequence != sequence || updated.StatusCode != 503 || !updated.Completed {
		t.Fatalf("upsert lost original sequence or final state: %#v", updated)
	}
	page := store.Query(model.Query{Limit: 1})
	if page.Items[0].ID != "two" || page.NextBeforeSequence == 0 || page.Matched != 2 {
		t.Fatalf("query is not ordered by insertion sequence: %#v", page)
	}
	store.Put(sampleFlow("three"))
	next := store.Query(model.Query{Limit: 1, BeforeSequence: page.NextBeforeSequence})
	if len(next.Items) != 1 || next.Items[0].ID != "one" || next.NextBeforeSequence != 0 {
		t.Fatalf("new insertion shifted stable cursor: %#v", next)
	}
	snapshot := store.Snapshot(model.Filter{})
	snapshot[0].RequestHeaders.Set("X-Snapshot", "changed")
	untouched, _ := store.Get(snapshot[0].ID)
	if untouched.RequestHeaders.Get("X-Snapshot") != "" {
		t.Fatal("Snapshot leaked mutable headers")
	}
}

func TestCountByteBudgetsClearAndRawFlag(t *testing.T) {
	store := testStore(t, Options{MaxFlows: 2, MaxBytes: 6000})
	for _, id := range []string{"one", "two", "three"} {
		flow := sampleFlow(id)
		flow.RequestHeaders = nil
		flow.ResponseHeaders = nil
		flow.RequestBody = model.Body{}
		flow.ResponseBody = model.Body{}
		flow.RawAvailable = false
		store.Put(flow)
	}
	if _, ok := store.Get("one"); ok {
		t.Fatal("oldest flow was not evicted at count limit")
	}
	flow, _ := store.Get("three")
	if flow.RawAvailable {
		t.Fatal("store changed raw availability of a tunnel snapshot")
	}
	large := sampleFlow("three")
	large.URL = "https://example.com/" + strings.Repeat("x", 7000)
	store.Put(large)
	if _, ok := store.Get("three"); ok {
		t.Fatal("oversized metadata remained cached or retained stale upsert")
	}
	info := store.Info()
	if info["memory_bytes"].(int64) > 6000 || info["dropped_oversize"].(uint64) != 1 {
		t.Fatalf("byte budget or drop accounting failed: %#v", info)
	}
	before := info["next_sequence"].(uint64)
	if store.Clear() != 1 || store.Info()["memory_bytes"].(int64) != 0 {
		t.Fatal("Clear did not remove cached records and bytes")
	}
	store.Put(sampleFlow("after-clear"))
	after, ok := store.Get("after-clear")
	if !ok || after.Sequence != before {
		t.Fatalf("Clear reset stable sequence: %#v", after)
	}
}

func TestByteBudgetIncludesHeadersAndUpserts(t *testing.T) {
	flow := sampleFlow("a")
	base := estimateFlowBytes(flow)
	store := testStore(t, Options{MaxFlows: 100, MaxBytes: base*2 + 100})
	store.Put(flow)
	store.Put(sampleFlow("b"))
	flow.ResponseHeaders.Set("X-Large", strings.Repeat("x", 1000))
	store.Put(flow)
	if store.Info()["stored_flows"].(int) != 1 {
		t.Fatal("header growth did not evict an entry to honor the byte limit")
	}
	if _, ok := store.Get("a"); ok {
		t.Fatal("updating an old entry unexpectedly changed its eviction position")
	}
	if store.Info()["memory_bytes"].(int64) > base*2+100 {
		t.Fatal("store exceeded configured retained-byte budget")
	}
}

func TestPublicViewsPreserveEveryOriginalSurface(t *testing.T) {
	flow := sampleFlow("original")
	flow.Error = `Get "https://example.com?token=error-secret": original network failure`
	flow.ResponseHeaders.Set("Location", "https://redirect.example.com/?access_token=redirect-secret")
	flow.RequestHeaders.Set("Cookie", "id=request-cookie-secret")
	for name, value := range map[string]any{"flow": PublicFlow(flow, 4096), "har": ExportHARLimited([]model.Flow{flow}, 4096)} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"request-secret", "nested-secret", "response-secret", "array-secret", "user-secret", "url-secret", "fragment-secret", "header-secret", "cookie-secret", "error-secret", "redirect-secret", "request-cookie-secret"} {
			if !strings.Contains(string(data), secret) {
				t.Errorf("%s 丢失原始值 %q", name, secret)
			}
		}
		if strings.Contains(string(data), "[REDACTED]") {
			t.Fatal("仍有脱敏占位符")
		}
	}
	view := PublicFlow(flow, 4096)
	view["request_headers"].(http.Header).Set("Authorization", "changed")
	if flow.RequestHeaders.Get("Authorization") != "Bearer header-secret" {
		t.Fatal("输出共享可变 Header")
	}
	store := testStore(t, Options{})
	store.Put(flow)
	summary := store.Query(model.Query{}).Items[0]
	if summary.URL != flow.URL || summary.Error != flow.Error {
		t.Fatal("摘要未返回原始 URL 或错误")
	}
}

func TestBodyPolicyAndDisplayLimit(t *testing.T) {
	for _, data := range []string{`{"password":"secret"}`, `password=secret`, `<html>secret</html>`, `"secret"`, `{"token":"secret"`, `user%5Bpassword%5D=secret`, "\xff\x00secret"} {
		view := publicBody(model.Body{Data: []byte(data)}, nil, 1024)
		got := []byte(view["text"].(string))
		if view["encoding"] == "base64" {
			var err error
			got, err = base64.StdEncoding.DecodeString(string(got))
			if err != nil {
				t.Fatal(err)
			}
		}
		if view["hidden"] != false || string(got) != data || view["redaction"] != "none" {
			t.Fatal("正文被替换或隐藏")
		}
	}
	body := []byte(strings.Repeat("你好", 20000))
	view := publicBody(model.Body{Data: body}, nil, 100)
	text := view["text"].(string)
	if len(text) > 103 || !utf8.ValidString(text) || view["display_truncated"] != true || view["capture_truncated"] != false {
		t.Fatal("预览边界未标注或拆分 UTF-8")
	}
	view = publicBody(model.Body{Data: []byte("prefix"), Size: 100}, nil, 1024)
	if view["hidden"] != false || view["text"] != "prefix" || view["capture_truncated"] != true {
		t.Fatal("采集前缀未真实返回")
	}
}

func TestOriginalURLCases(t *testing.T) {
	for _, raw := range []string{
		"https://example.com?token=%ZZsecret",
		"https://example.com?password=secret&name=alice",
		"https://example.com/token/secret",
		"https://example.com?next=" + url.QueryEscape("https://other.com/?api_key=secret"),
		"https://alice:secret@example.com/a#secret",
		"http://[invalid/secret",
		"data:text/plain,secret",
	} {
		if result := PublicSummary(model.Flow{URL: raw}).URL; result != raw {
			t.Errorf("URL 原始值被改变: %q -> %q", raw, result)
		}
	}
	if result := PublicSummary(model.Flow{URL: "https://example.com/path?q=hello&limit=10"}).URL; !strings.Contains(result, "q=hello") || !strings.Contains(result, "limit=10") {
		t.Fatalf("URL 原始查询参数丢失: %q", result)
	}
}

func TestHostAndFilterMatching(t *testing.T) {
	for _, tc := range []struct {
		host, pattern string
		match         bool
	}{
		{"API.Example.COM.:443", "api.example.com", true},
		{"api.example.com:443", "api.example.com:443", true},
		{"api.example.com:443", "api.example.com:80", false},
		{"a.b.example.com", "*.example.com", true},
		{"example.com", "*.example.com", false},
		{"evil-example.com", "*.example.com", false},
		{"example.com.evil", "*.example.com", false},
		{"[::1]:443", "::1", true},
		{"[::1]:443", "[::1]:443", true},
		{"localhost", "*", true},
	} {
		if MatchHost(tc.host, tc.pattern) != tc.match {
			t.Errorf("MatchHost(%q, %q) != %v", tc.host, tc.pattern, tc.match)
		}
	}
	for _, filter := range []model.Filter{
		{Hosts: []string{"https://example.com"}}, {Hosts: []string{"bad*example.com"}},
		{Hosts: []string{"example.com:99999"}}, {Hosts: []string{"example.com:"}},
		{Hosts: []string{"[invalid-domain]"}},
		{Hosts: []string{"*."}}, {Methods: []string{"GET POST"}},
		{StatusMin: 99}, {StatusMin: 500, StatusMax: 400}, {MinDurationMS: -1}, {MinDurationMS: math.NaN()},
		{Hosts: make([]string, 65)}, {ExcludeHosts: make([]string, 65)}, {Methods: make([]string, 65)},
		{Methods: []string{strings.Repeat("G", 65)}}, {URLContains: strings.Repeat("x", 4097)},
		{Hosts: []string{"fe80::1%" + strings.Repeat("a", 512)}},
	} {
		if ValidateFilter(filter) == nil {
			t.Errorf("accepted invalid filter %#v", filter)
		}
	}
	filter := model.Filter{Hosts: []string{"*.example.com"}, ExcludeHosts: []string{"blocked.example.com"}, Methods: []string{"post"}, URLContains: "resource", StatusMin: 400, StatusMax: 599, MinDurationMS: 5, OnlyErrors: true}
	if err := ValidateFilter(filter); err != nil {
		t.Fatal(err)
	}
	flow := sampleFlow("filter")
	flow.StatusCode = 503
	if !Matches(flow, filter) {
		t.Fatal("matching request was excluded")
	}
	flow.Host = "blocked.example.com"
	if Matches(flow, filter) {
		t.Fatal("excluded host matched")
	}
	flow.Host = ""
	if !Matches(flow, filter) {
		t.Fatal("URL host fallback did not work")
	}
}

func TestPersistenceIsOriginalCompletedRotatingAndNeverRestored(t *testing.T) {
	dir := t.TempDir()
	store := testStore(t, Options{LogDir: dir, LogMaxBytes: 6000, LogBackups: 2})
	inProgress := sampleFlow("first")
	inProgress.Completed = false
	store.Put(inProgress)
	initial, err := os.ReadFile(filepath.Join(dir, "flows.jsonl"))
	if err != nil || len(initial) != 0 {
		t.Fatalf("in-progress snapshot was journaled: %s, %v", initial, err)
	}
	for i := 0; i < 12; i++ {
		store.Put(sampleFlow(fmt.Sprintf("flow-%d", i)))
	}
	if store.Info()["persistence"].(map[string]any)["written_records"].(uint64) != 12 {
		t.Fatalf("did not write all completed snapshots: %#v", store.Info())
	}
	store.Clear()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil || len(files) != 3 {
		t.Fatalf("unexpected rotated file count: %v, %v", files, err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 6000 || len(data) == 0 {
			t.Fatalf("journal file violated size budget: %s (%d bytes)", file, len(data))
		}
		if !strings.Contains(string(data), "header-secret") || !strings.Contains(string(data), "request-secret") {
			t.Fatalf("journal lost original values: %s", data)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if !json.Valid([]byte(line)) {
				t.Fatalf("rotation split a JSONL record: %s", line)
			}
		}
		// Windows 的文件权限由 ACL 控制，Go 的 POSIX 权限位不能表示该权限。
		if info, err := os.Stat(file); err != nil || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			t.Fatalf("journal must have private file permissions: %v, %v", info, err)
		}
	}
	reopened := testStore(t, Options{LogDir: dir, LogMaxBytes: 6000, LogBackups: 2})
	if reopened.Info()["stored_flows"].(int) != 0 {
		t.Fatal("persisted traffic was restored as replayable raw data")
	}
}

func TestPersistenceErrorsAndCloseAreObservable(t *testing.T) {
	store := testStore(t, Options{LogDir: t.TempDir(), LogMaxBytes: 10})
	store.Put(sampleFlow("too-large-for-journal"))
	info := store.Info()["persistence"].(map[string]any)
	if info["write_errors"].(uint64) != 1 || info["last_error"] == "" {
		t.Fatalf("persistence failure was hidden: %#v", info)
	}
	if _, ok := store.Get("too-large-for-journal"); !ok {
		t.Fatal("persistence failure discarded in-memory capture")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store.Put(sampleFlow("closed"))
	if store.Info()["dropped_after_close"].(uint64) != 1 {
		t.Fatal("Put after Close was not observable")
	}
}

func TestHARAndStats(t *testing.T) {
	flows := []model.Flow{sampleFlow("1"), sampleFlow("2"), sampleFlow("3")}
	flows[0].Timings.TotalMS = 10
	flows[1].Timings.TotalMS = 20
	flows[1].StatusCode = 500
	flows[2].Completed = false
	stats := Stats(flows)
	durations := stats["duration_ms"].(map[string]any)
	if stats["completed"] != 2 || stats["in_progress"] != 1 || stats["http_5xx"] != 1 || durations["mean"] != float64(15) || durations["p95"] != float64(20) {
		t.Fatalf("bad snapshot statistics: %#v", stats)
	}
	store := testStore(t, Options{})
	for _, flow := range flows {
		store.Put(flow)
	}
	if filtered := store.Stats(model.Filter{StatusMin: 500}); filtered["flows"] != 1 || filtered["http_5xx"] != 1 {
		t.Fatalf("metadata-only Store.Stats differs: %#v", filtered)
	}
	har := ExportHARLimited(flows, 20)
	entries := har["log"].(map[string]any)["entries"].([]map[string]any)
	if len(entries) != 3 {
		t.Fatal("HAR lost flows")
	}
	content := entries[0]["response"].(map[string]any)["content"].(map[string]any)
	if len(content["text"].(string)) > 20 || content["_netlens"].(map[string]any)["display_truncated"] != true {
		t.Fatalf("HAR did not mark bounded displayed body: %#v", content)
	}
	if _, ok := content["encoding"]; ok {
		t.Fatal("public HAR unexpectedly exported a base64 bypass")
	}
}

func TestConcurrentPutReadClearClose(t *testing.T) {
	store := testStore(t, Options{MaxFlows: 20, MaxBytes: 100000})
	var wg sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				id := fmt.Sprintf("%d-%d", worker, i%10)
				flow := sampleFlow(id)
				flow.Completed = i%2 == 0
				store.Put(flow)
				store.Get(id)
				store.Query(model.Query{Limit: 3})
				store.Stats(model.Filter{})
				store.Snapshot(model.Filter{OnlyErrors: true})
				store.Info()
				if worker == 0 && i%20 == 0 {
					store.Clear()
				}
				if worker == 7 && i == 75 {
					_ = store.Close()
				}
			}
		}(worker)
	}
	wg.Wait()
	info := store.Info()
	if info["stored_flows"].(int) > 20 || info["memory_bytes"].(int64) > 100000 {
		t.Fatalf("concurrent activity exceeded bounds: %#v", info)
	}
}
