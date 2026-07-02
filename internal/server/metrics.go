package server

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Metrics is a deliberately small, dependency-free Prometheus text
// exposition: counters for requests and verdicts, sum/count pairs for
// latency. Label cardinality is bounded by endpointLabel, never by raw
// paths. Served on its own listener (CERBERUS_METRICS_ADDR), not on the
// public API port: request rates and verdict mixes are operational data
// nobody else needs to see.
type Metrics struct {
	mu       sync.Mutex
	requests map[[2]string]int64 // {endpoint, code} -> count
	durNanos map[string]int64    // endpoint -> total duration
	durCount map[string]int64    // endpoint -> observations
	verdicts map[[2]string]int64 // {endpoint, result} -> count

	version string
	started time.Time
}

func NewMetrics(version string) *Metrics {
	return &Metrics{
		requests: make(map[[2]string]int64),
		durNanos: make(map[string]int64),
		durCount: make(map[string]int64),
		verdicts: make(map[[2]string]int64),
		version:  version,
		started:  time.Now(),
	}
}

// ObserveRequest records one finished HTTP request. Nil-safe so the
// middleware can call it unconditionally.
func (m *Metrics) ObserveRequest(path string, code int, dur time.Duration) {
	if m == nil {
		return
	}
	ep := endpointLabel(path)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests[[2]string{ep, strconv.Itoa(code)}]++
	m.durNanos[ep] += int64(dur)
	m.durCount[ep]++
}

// ObserveVerdict records one signed license decision: result is "valid" or
// the failure reason. Wired into the service via Options.OnVerdict.
func (m *Metrics) ObserveVerdict(endpoint, result string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verdicts[[2]string{endpoint, result}]++
}

// endpointLabel folds request paths into a fixed label set so metric
// cardinality cannot grow with traffic shape.
func endpointLabel(path string) string {
	switch {
	case path == "/v1/client/validate":
		return "client_validate"
	case path == "/v1/client/redeem":
		return "client_redeem"
	case strings.HasPrefix(path, "/v1/client/apps/"):
		return "client_pubkey"
	case strings.HasPrefix(path, "/v1/admin/"):
		return "admin"
	case path == "/healthz":
		return "healthz"
	default:
		return "other"
	}
}

// ServeHTTP writes the Prometheus text format, deterministically ordered.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var b strings.Builder

	b.WriteString("# HELP cerberus_http_requests_total Finished HTTP requests.\n")
	b.WriteString("# TYPE cerberus_http_requests_total counter\n")
	for _, k := range sortedKeys2(m.requests) {
		fmt.Fprintf(&b, "cerberus_http_requests_total{endpoint=%q,code=%q} %d\n", k[0], k[1], m.requests[k])
	}

	b.WriteString("# HELP cerberus_http_request_duration_seconds Total request time, summed per endpoint.\n")
	b.WriteString("# TYPE cerberus_http_request_duration_seconds summary\n")
	for _, ep := range sortedKeys1(m.durCount) {
		fmt.Fprintf(&b, "cerberus_http_request_duration_seconds_sum{endpoint=%q} %.6f\n", ep, float64(m.durNanos[ep])/1e9)
		fmt.Fprintf(&b, "cerberus_http_request_duration_seconds_count{endpoint=%q} %d\n", ep, m.durCount[ep])
	}

	b.WriteString("# HELP cerberus_verdicts_total Signed license verdicts by result.\n")
	b.WriteString("# TYPE cerberus_verdicts_total counter\n")
	for _, k := range sortedKeys2(m.verdicts) {
		fmt.Fprintf(&b, "cerberus_verdicts_total{endpoint=%q,result=%q} %d\n", k[0], k[1], m.verdicts[k])
	}

	b.WriteString("# HELP cerberus_build_info Build metadata; value is always 1.\n")
	b.WriteString("# TYPE cerberus_build_info gauge\n")
	fmt.Fprintf(&b, "cerberus_build_info{version=%q} 1\n", m.version)

	b.WriteString("# HELP cerberus_uptime_seconds Seconds since process start.\n")
	b.WriteString("# TYPE cerberus_uptime_seconds gauge\n")
	fmt.Fprintf(&b, "cerberus_uptime_seconds %.0f\n", time.Since(m.started).Seconds())

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func sortedKeys2(m map[[2]string]int64) [][2]string {
	keys := make([][2]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	return keys
}

func sortedKeys1(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
