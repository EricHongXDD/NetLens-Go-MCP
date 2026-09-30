package capture

import (
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

func TestPublicViewsRedactEverySurface(t *testing.T) {
	flow := sampleFlow("secrets")
	flow.Error = `Get "https://example.com?token=error-secret": x509: certificate signed by unknown authority`
	flow.ResponseHeaders.Set("Location", "https://redirect.example.com/?access_token=redirect-secret")
	flow.ResponseHeaders.Set("Content-Type", "application/json; token=content-type-secret")
	flow.RequestHeaders.Set("X-Auth", "auth-secret")
	flow.RequestHeaders.Set("X-Debug", `{"api_key":"custom-header-secret","ok":true}`)
	flow.RequestHeaders.Set("X-API-Key", "api-header-secret")
	flow.RequestHeaders.Set("Ocp-Apim-Subscription-Key", "subscription-header-secret")
	flow.RequestHeaders.Set("X-Custom-Url", "https://example.com?token=custom-url-secret")
	flow.RequestHeaders.Set("Proxy-Authorization", "Basic proxy-secret")
	flow.RequestHeaders.Set("Cookie", "id=request-cookie-secret")
	flow.RequestHeaders.Set("X-Request-Id", "visible-id")
	for name, value := range map[string]any{
		"flow": PublicFlow(flow, 4096), "summary": PublicSummary(flow), "har": ExportHARLimited([]model.Flow{flow}, 4096),
	} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"request-secret", "nested-secret", "response-secret", "array-secret", "user-secret", "url-secret", "fragment-secret", "header-secret", "cookie-secret", "error-secret", "redirect-secret", "content-type-secret", "auth-secret", "custom-header-secret", "api-header-secret", "subscription-header-secret", "custom-url-secret", "proxy-secret", "request-cookie-secret"} {
			if strings.Contains(string(data), secret) {
				t.Errorf("%s leaked %q: %s", name, secret, data)
			}
		}
		if name != "summary" && !strings.Contains(string(data), "visible-id") {
			t.Errorf("%s hid benign diagnostic header", name)
		}
	}
	if flow.RequestHeaders.Get("Authorization") != "Bearer header-secret" || !strings.Contains(string(flow.RequestBody.Data), "request-secret") {
		t.Fatal("public redaction mutated raw request needed for forwarding/replay")
	}
	store := testStore(t, Options{})
	store.Put(flow)
	data, _ := json.Marshal(store.Query(model.Query{}))
	if strings.Contains(string(data), "url-secret") || strings.Contains(string(data), "error-secret") {
		t.Fatal("Query exposed raw URL or error text")
	}
}

func TestBodyPolicyAndDisplayLimit(t *testing.T) {
	cases := []struct {
		name, contentType, contentEncoding, body string
		truncated                                bool
		hidden                                   bool
	}{
		{"json", "application/problem+json", "", `{"message":"hello","credentials":{"username":"alice","password":"secret"}}`, false, false},
		{"form", "application/x-www-form-urlencoded", "", "user%5Bpassword%5D=secret&token=secret&name=alice", false, false},
		{"plain", "text/plain", "", "password=secret", false, true},
		{"missing-type", "", "", `{"password":"secret"}`, false, true},
		{"malformed", "application/json", "", `{"password":"secret"`, false, true},
		{"trailing", "application/json", "", `{"ok":true}{"password":"secret"}`, false, true},
		{"truncated-valid-prefix", "application/json", "", `{"password":"secret"}`, true, true},
		{"gzip", "application/json", "gzip", `{"password":"secret"}`, false, true},
		{"json-string", "application/json", "", `"unlabeled-secret"`, false, true},
		{"invalid-form", "application/x-www-form-urlencoded", "", "password=%ZZ", false, true},
		{"binary", "application/json", "", "\xff\x00secret", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{"Content-Type": {tc.contentType}}
			if tc.contentEncoding != "" {
				headers.Set("Content-Encoding", tc.contentEncoding)
			}
			view := publicBody(model.Body{Data: []byte(tc.body), Size: int64(len(tc.body)), Truncated: tc.truncated}, headers, 1024)
			if view["hidden"] != tc.hidden {
				t.Fatalf("unexpected hidden state: %#v", view)
			}
			if strings.Contains(fmt.Sprint(view["text"]), "secret") {
				t.Fatalf("body view leaked a secret: %#v", view)
			}
			if tc.hidden {
				if _, ok := view["text"]; ok || view["reason"] == nil {
					t.Fatal("hidden body has visible text or lacks explanation")
				}
			}
		})
	}
	body := []byte(`{"text":"` + strings.Repeat("你好", 20000) + `","password":"secret"}`)
	view := publicBody(model.Body{Data: body, Size: int64(len(body))}, http.Header{"Content-Type": {"application/json"}}, 100)
	text := view["text"].(string)
	if len(text) > 100 || !utf8.ValidString(text) || view["display_truncated"] != true || view["capture_truncated"] != false {
		t.Fatalf("display truncation is not bounded/marked/UTF8 safe: %#v", view)
	}
	view = publicBody(model.Body{Data: body, Size: int64(len(body))}, http.Header{"Content-Type": {"application/json"}}, 1<<20)
	if len(view["text"].(string)) > MaxPublicBodyBytes {
		t.Fatal("public body limit exceeded hard cap")
	}
	view = publicBody(model.Body{Data: []byte(`{"ok":true}`), Size: 100}, http.Header{"Content-Type": {"application/json"}}, 1024)
	if view["hidden"] != true {
		t.Fatal("missing captured bytes were not treated as an incomplete structure")
	}
}

func TestRedactURLCases(t *testing.T) {
	for _, raw := range []string{
		"https://example.com?token=%ZZsecret",
		"https://example.com?password=secret&name=alice",
		"https://example.com/token/secret",
		"https://example.com?next=" + url.QueryEscape("https://other.com/?api_key=secret"),
		"https://alice:secret@example.com/a#secret",
		"http://[invalid/secret",
		"data:text/plain,secret",
	} {
		if result := RedactURL(raw); strings.Contains(result, "secret") {
			t.Errorf("URL leaked secret: %q -> %q", raw, result)
		}
	}
	if result := RedactURL("https://example.com/path?q=hello&limit=10"); !strings.Contains(result, "q=hello") || !strings.Contains(result, "limit=10") {
		t.Fatalf("URL hid non-sensitive query parameters: %q", result)
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

func TestPersistenceIsRedactedCompletedRotatingAndNeverRestored(t *testing.T) {
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
		if strings.Contains(string(data), "-secret") {
			t.Fatalf("journal retained raw secret: %s", data)
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
		t.Fatal("redacted persisted traffic was restored as replayable raw data")
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
