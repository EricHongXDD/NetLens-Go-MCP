package capture

import (
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"netlens/internal/model"
)

const (
	defaultMaxFlows    = 1000
	defaultMaxBytes    = 64 << 20
	defaultLogMaxBytes = 16 << 20
)

type Options struct {
	MaxFlows    int
	MaxBytes    int64
	LogDir      string
	LogMaxBytes int64
	// LogBackups counts rotated files in addition to the active file. Zero
	// keeps only the active file. Existing journal files are never restored.
	LogBackups int
}

type entry struct {
	flow    model.Flow
	bytes   int64
	element *list.Element
}

// Store keeps a ring ordered by the sequence assigned at first insertion.
// Upserts preserve both sequence and position. All returned raw snapshots are
// deep copies; no caller may mutate the cache through a shared header or body.
type Store struct {
	mu           sync.RWMutex
	opts         Options
	entries      map[string]*entry
	order        *list.List
	bytes        int64
	sequence     uint64
	puts         uint64
	evictions    uint64
	oversized    uint64
	closedPuts   uint64
	closed       bool
	log          *os.File
	logBytes     int64
	logRecords   uint64
	logErrors    uint64
	lastLogError string
}

func New(opts Options) (*Store, error) {
	if opts.MaxFlows < 0 || opts.MaxBytes < 0 || opts.LogMaxBytes < 0 || opts.LogBackups < 0 {
		return nil, errors.New("capture size limits and log backups must be nonnegative")
	}
	if opts.MaxFlows == 0 {
		opts.MaxFlows = defaultMaxFlows
	}
	if opts.MaxBytes == 0 {
		opts.MaxBytes = defaultMaxBytes
	}
	if opts.LogMaxBytes == 0 {
		opts.LogMaxBytes = defaultLogMaxBytes
	}
	s := &Store{opts: opts, entries: make(map[string]*entry), order: list.New()}
	if opts.LogDir != "" {
		abs, err := filepath.Abs(opts.LogDir)
		if err != nil {
			return nil, fmt.Errorf("capture log directory: %w", err)
		}
		s.opts.LogDir = abs
		if err := os.MkdirAll(abs, 0700); err != nil {
			return nil, fmt.Errorf("create capture log directory: %w", err)
		}
		if err := s.openLog(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Put stores an internal raw snapshot. Only completed snapshots are appended to
// the optional redacted JSONL journal. The journal is an append-only history of
// completed upserts, so an ID can appear more than once after a final revision.
// A snapshot larger than the entire byte budget is dropped without retaining
// an outdated version of that same ID. Persistence never controls forwarding.
func (s *Store) Put(flow model.Flow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		s.closedPuts++
		return
	}
	s.puts++
	if flow.ID == "" {
		flow.ID = model.NewID()
	}
	previous := s.entries[flow.ID]
	if previous != nil {
		flow.Sequence = previous.flow.Sequence
	} else {
		s.sequence++
		flow.Sequence = s.sequence
	}
	size := estimateFlowBytes(flow)
	if size > s.opts.MaxBytes {
		if previous != nil {
			s.remove(previous)
		}
		s.oversized++
		// Skip copying an oversized snapshot into the cache. Its redacted
		// final view may still fit the independently bounded journal.
		if flow.Completed {
			s.appendLog(flow)
		}
		return
	}
	snapshot := cloneFlow(flow)
	if previous != nil {
		s.bytes -= previous.bytes
		previous.flow = snapshot
		previous.bytes = size
		s.bytes += size
	} else {
		item := &entry{flow: snapshot, bytes: size}
		item.element = s.order.PushBack(item)
		s.entries[snapshot.ID] = item
		s.bytes += size
	}
	for len(s.entries) > s.opts.MaxFlows || s.bytes > s.opts.MaxBytes {
		front := s.order.Front()
		if front == nil {
			break
		}
		s.remove(front.Value.(*entry))
		s.evictions++
	}
	if flow.Completed {
		s.appendLog(snapshot)
	}
}

func (s *Store) remove(item *entry) {
	delete(s.entries, item.flow.ID)
	s.order.Remove(item.element)
	s.bytes -= item.bytes
}

// Get returns a deep-copied raw internal snapshot. External APIs must call
// PublicFlow or PublicSummary before serializing any captured content.
func (s *Store) Get(id string) (model.Flow, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.entries[id]
	if !ok {
		return model.Flow{}, false
	}
	return cloneFlow(item.flow), true
}

// Query returns redacted summaries newest first. Matched counts matching
// records below the optional cursor. A new insertion cannot shift a cursor
// page because cursors use a monotonically increasing insertion sequence.
func (s *Store) Query(query model.Query) model.QueryResult {
	limit := query.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	result := model.QueryResult{Items: make([]model.Summary, 0, limit)}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for elem := s.order.Back(); elem != nil; elem = elem.Prev() {
		flow := elem.Value.(*entry).flow
		if query.BeforeSequence != 0 && flow.Sequence >= query.BeforeSequence || !Matches(flow, query.Filter) {
			continue
		}
		result.Matched++
		if len(result.Items) < limit {
			result.Items = append(result.Items, PublicSummary(flow))
		}
	}
	if result.Matched > len(result.Items) && len(result.Items) > 0 {
		result.NextBeforeSequence = result.Items[len(result.Items)-1].Sequence
	}
	return result
}

// Snapshot returns deep-copied raw matching flows in oldest-first sequence
// order, suitable for internal aggregation and redacted export helpers.
func (s *Store) Snapshot(filter model.Filter) []model.Flow {
	s.mu.RLock()
	defer s.mu.RUnlock()
	flows := make([]model.Flow, 0, len(s.entries))
	for elem := s.order.Front(); elem != nil; elem = elem.Next() {
		flow := elem.Value.(*entry).flow
		if Matches(flow, filter) {
			flows = append(flows, cloneFlow(flow))
		}
	}
	return flows
}

// Stats avoids copying captured body and header payloads during a dashboard
// poll. Only the immutable metadata required by the aggregator is retained.
func (s *Store) Stats(filter model.Filter) map[string]any {
	s.mu.RLock()
	flows := make([]model.Flow, 0, len(s.entries))
	for elem := s.order.Front(); elem != nil; elem = elem.Next() {
		flow := elem.Value.(*entry).flow
		if !Matches(flow, filter) {
			continue
		}
		flows = append(flows, model.Flow{
			StartedAt: flow.StartedAt, Method: flow.Method, Host: flow.Host,
			StatusCode: flow.StatusCode, Completed: flow.Completed,
			Error: flow.Error, Source: flow.Source, Timings: flow.Timings,
			RequestBody:  model.Body{Size: bodySize(flow.RequestBody)},
			ResponseBody: model.Body{Size: bodySize(flow.ResponseBody)},
		})
	}
	s.mu.RUnlock()
	return Stats(flows)
}

// Clear removes cached raw traffic. It does not delete the optional journal,
// reset the monotonic cursor, or interrupt requests already in flight.
func (s *Store) Clear() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := len(s.entries)
	s.entries = make(map[string]*entry)
	s.order.Init()
	s.bytes = 0
	return count
}

// Close waits for a Put already holding the store lock, then syncs and closes
// the journal. Puts after Close are rejected and observable in Info.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.log == nil {
		return nil
	}
	err := errors.Join(s.log.Sync(), s.log.Close())
	s.log = nil
	if err != nil {
		s.recordLogError(err)
	}
	return err
}

// Info makes cache limits, dropped snapshots and persistence failures visible.
// memory_bytes is conservative retained-size accounting, including payloads,
// header allocations, maps, list nodes, string/slice headers and entry structs;
// it is not the Go process heap or an allocator/RSS measurement.
func (s *Store) Info() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]any{
		"stored_flows": len(s.entries), "max_flows": s.opts.MaxFlows,
		"memory_bytes": s.bytes, "max_bytes": s.opts.MaxBytes,
		"memory_accounting": "conservative retained-size estimate, not process RSS",
		"next_sequence":     s.sequence + 1, "puts": s.puts,
		"evicted_flows": s.evictions, "dropped_oversize": s.oversized,
		"dropped_after_close": s.closedPuts, "closed": s.closed,
		"persistence": map[string]any{
			"enabled": s.opts.LogDir != "", "log_dir": s.opts.LogDir,
			"active_bytes": s.logBytes, "max_file_bytes": s.opts.LogMaxBytes,
			"backups": s.opts.LogBackups, "written_records": s.logRecords,
			"write_errors": s.logErrors, "last_error": s.lastLogError,
			"format":            "redacted completed snapshots in rotating JSONL",
			"restores_on_start": false, "clear_deletes_logs": false,
		},
	}
}

func cloneFlow(flow model.Flow) model.Flow {
	flow.ID = strings.Clone(flow.ID)
	flow.Method = strings.Clone(flow.Method)
	flow.URL = strings.Clone(flow.URL)
	flow.Host = strings.Clone(flow.Host)
	flow.Protocol = strings.Clone(flow.Protocol)
	flow.RemoteAddr = strings.Clone(flow.RemoteAddr)
	flow.Error = strings.Clone(flow.Error)
	flow.Source = strings.Clone(flow.Source)
	flow.ParentID = strings.Clone(flow.ParentID)
	flow.RequestHeaders = cloneHeaders(flow.RequestHeaders)
	flow.ResponseHeaders = cloneHeaders(flow.ResponseHeaders)
	flow.RequestBody.Data = append([]byte(nil), flow.RequestBody.Data...)
	flow.ResponseBody.Data = append([]byte(nil), flow.ResponseBody.Data...)
	rules := make([]string, len(flow.RuleIDs))
	for i, id := range flow.RuleIDs {
		rules[i] = strings.Clone(id)
	}
	flow.RuleIDs = rules
	return flow
}

func cloneHeaders(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	out := make(http.Header, len(headers))
	for key, values := range headers {
		vv := make([]string, len(values))
		for i, value := range values {
			vv[i] = strings.Clone(value)
		}
		out[strings.Clone(key)] = vv
	}
	return out
}

func estimateFlowBytes(flow model.Flow) int64 {
	// The extra fixed allowance covers the list node, map slot, allocations
	// and map slack. Copies use lengths instead of retaining caller capacities.
	total := int64(unsafe.Sizeof(entry{})) + 256
	for _, value := range []string{flow.ID, flow.Method, flow.URL, flow.Host, flow.Protocol, flow.RemoteAddr, flow.Error, flow.Source, flow.ParentID} {
		total += roundedAllocation(len(value))
	}
	total += roundedAllocation(len(flow.RequestBody.Data)) + roundedAllocation(len(flow.ResponseBody.Data))
	for _, headers := range []http.Header{flow.RequestHeaders, flow.ResponseHeaders} {
		if headers == nil {
			continue
		}
		total += 128
		for key, values := range headers {
			total += 96 + roundedAllocation(len(key)) + int64(len(values))*int64(unsafe.Sizeof(""))
			for _, value := range values {
				total += roundedAllocation(len(value))
			}
		}
	}
	total += int64(len(flow.RuleIDs)) * int64(unsafe.Sizeof(""))
	for _, rule := range flow.RuleIDs {
		total += roundedAllocation(len(rule))
	}
	return total
}

func roundedAllocation(n int) int64 {
	if n == 0 {
		return 0
	}
	// Conservative allocator slack avoids presenting payload bytes alone as
	// total cache usage. An absolute process-memory guarantee needs OS limits.
	return (int64(n)+15)/16*16 + int64(n)/4 + 16
}

func (s *Store) activeLogPath() string { return filepath.Join(s.opts.LogDir, "flows.jsonl") }

func (s *Store) openLog() error {
	path := s.activeLogPath()
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return errors.New("capture journal must be a regular non-symlink file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect capture journal: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open capture journal: %w", err)
	}
	if err = file.Chmod(0600); err != nil {
		_ = file.Close()
		return fmt.Errorf("protect capture journal: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("stat capture journal: %w", err)
	}
	s.log = file
	s.logBytes = info.Size()
	return nil
}

func (s *Store) appendLog(flow model.Flow) {
	if s.opts.LogDir == "" {
		return
	}
	data, err := json.Marshal(PublicFlow(flow, MaxPublicBodyBytes))
	if err != nil {
		s.recordLogError(errors.New("serialize redacted capture journal record failed"))
		return
	}
	data = append(data, '\n')
	if int64(len(data)) > s.opts.LogMaxBytes {
		s.recordLogError(errors.New("redacted capture record exceeds maximum journal file size; record skipped"))
		return
	}
	if s.log == nil {
		if err := s.openLog(); err != nil {
			s.recordLogError(err)
			return
		}
	}
	if s.logBytes+int64(len(data)) > s.opts.LogMaxBytes {
		if err := s.rotateLog(); err != nil {
			s.recordLogError(err)
			return
		}
	}
	n, err := s.log.Write(data)
	s.logBytes += int64(n)
	if err == nil && n != len(data) {
		err = errors.New("short capture journal write")
	}
	if err != nil {
		s.recordLogError(err)
		return
	}
	s.logRecords++
}

func (s *Store) rotateLog() error {
	if s.log != nil {
		err := errors.Join(s.log.Sync(), s.log.Close())
		s.log = nil
		if err != nil {
			return fmt.Errorf("close capture journal for rotation: %w", err)
		}
	}
	if s.opts.LogBackups == 0 {
		if err := os.Remove(s.activeLogPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("rotate capture journal: %w", err)
		}
	} else {
		oldest := filepath.Join(s.opts.LogDir, fmt.Sprintf("flows.%d.jsonl", s.opts.LogBackups))
		if err := os.Remove(oldest); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove oldest capture journal: %w", err)
		}
		for i := s.opts.LogBackups - 1; i >= 1; i-- {
			src := filepath.Join(s.opts.LogDir, fmt.Sprintf("flows.%d.jsonl", i))
			dst := filepath.Join(s.opts.LogDir, fmt.Sprintf("flows.%d.jsonl", i+1))
			if err := os.Rename(src, dst); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("rotate backup capture journal: %w", err)
			}
		}
		if err := os.Rename(s.activeLogPath(), filepath.Join(s.opts.LogDir, "flows.1.jsonl")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("rotate active capture journal: %w", err)
		}
	}
	s.logBytes = 0
	return s.openLog()
}

func (s *Store) recordLogError(err error) {
	s.logErrors++
	s.lastLogError = err.Error()
}
