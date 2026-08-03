package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/griffithind/orbit/internal/wire"
)

// logBuf collects structured log records for assertions.
//
// Locked because the records are written from the server's handler goroutine
// and read from the test's.
type logBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// records parses the accumulated JSON lines.
func (l *logBuf) records(t *testing.T) []map[string]any {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(l.buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not JSON: %v (%q)", err, line)
		}
		out = append(out, rec)
	}
	return out
}

func (l *logBuf) find(t *testing.T, msg string) map[string]any {
	t.Helper()
	for _, rec := range l.records(t) {
		if rec["msg"] == msg {
			return rec
		}
	}
	t.Fatalf("no %q log record in:\n%s", msg, l.buf.String())
	return nil
}

// observed serves mux over a real socket with the production middleware, so the
// tests exercise the wire behaviour a client actually sees rather than an
// in-process ResponseRecorder.
func observed(t *testing.T, mux *http.ServeMux) (*httptest.Server, *logBuf) {
	t.Helper()
	lb := &logBuf{}
	log := slog.New(slog.NewJSONHandler(lb, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ts := httptest.NewServer(Observe(log, mux))
	t.Cleanup(ts.Close)
	return ts, lb
}

// TestPanicBecomesWireError is the regression this middleware exists for: with
// only net/http's per-connection recovery, a panicking handler closes the
// connection and the client sees a truncated read instead of the error document
// every other failure produces.
func TestPanicBecomesWireError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /boom/{id}", func(http.ResponseWriter, *http.Request) {
		panic("handler exploded")
	})
	ts, lb := observed(t, mux)

	resp, err := ts.Client().Get(ts.URL + "/boom/42")
	if err != nil {
		t.Fatalf("request failed (connection dropped instead of answered): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q, want application/json", ct)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var werr wire.Error
	if err := json.Unmarshal(body, &werr); err != nil {
		t.Fatalf("body is not a wire.Error: %v (%q)", err, body)
	}
	if werr.Error == "" {
		t.Fatalf("wire.Error has no message: %q", body)
	}

	// The panic must reach the structured logger, with the stack: the value
	// alone does not say which handler produced it.
	rec := lb.find(t, "panic serving request")
	if rec["level"] != "ERROR" {
		t.Errorf("panic logged at %v, want ERROR", rec["level"])
	}
	if s, _ := rec["panic"].(string); !strings.Contains(s, "handler exploded") {
		t.Errorf("panic value not logged: %v", rec["panic"])
	}
	if s, _ := rec["stack"].(string); !strings.Contains(s, "middleware_test.go") {
		t.Errorf("stack does not include the panicking frame: %v", rec["stack"])
	}

	// And the request line still exists, graded by the status the recoverer
	// wrote. This is what the ordering in Observe buys.
	req := lb.find(t, "request")
	if req["level"] != "ERROR" {
		t.Errorf("request line level = %v, want ERROR for a 500", req["level"])
	}
	if req["status"] != float64(http.StatusInternalServerError) {
		t.Errorf("request line status = %v, want 500", req["status"])
	}
	if req["route"] != "GET /boom/{id}" {
		t.Errorf("route = %v, want the registered pattern", req["route"])
	}
}

// TestAbortHandlerIsNotSwallowed guards the one panic that must pass through:
// http.ErrAbortHandler is how a handler drops a connection on purpose.
func TestAbortHandlerIsNotSwallowed(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /abort", func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	})
	ts, lb := observed(t, mux)

	resp, err := ts.Client().Get(ts.URL + "/abort")
	if err == nil {
		resp.Body.Close()
		t.Fatalf("got status %d, want a dropped connection", resp.StatusCode)
	}

	for _, rec := range lb.records(t) {
		if rec["msg"] == "panic serving request" {
			t.Fatalf("ErrAbortHandler was recovered and logged as a panic: %v", rec)
		}
	}
}

// TestPanicAfterPartialWriteAborts covers the case where the status is already
// on the wire: appending an error document there would corrupt the body, so the
// connection is dropped instead — but the panic is still logged.
func TestPanicAfterPartialWriteAborts(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /partial", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"partial":`))
		panic("exploded mid-body")
	})
	ts, lb := observed(t, mux)

	resp, err := ts.Client().Get(ts.URL + "/partial")
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if err == nil {
		t.Fatal("want a truncated response, got a clean read")
	}

	rec := lb.find(t, "panic serving request")
	if s, _ := rec["panic"].(string); !strings.Contains(s, "exploded mid-body") {
		t.Errorf("panic value not logged: %v", rec["panic"])
	}
}

// TestRequestLogging covers the levels and the fields. The level matters: a
// request line emitted at Debug is dropped by the default Info logger, which
// makes the whole access log silent in production.
func TestRequestLogging(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /ok", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, wire.Error{Error: "fine"})
	})
	mux.HandleFunc("GET /denied", func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusUnauthorized, "nope")
	})

	for _, tc := range []struct {
		path      string
		status    float64
		level     string
		wantRoute string
	}{
		{"/ok", 200, "INFO", "GET /ok"},
		// A caller's mistake, not the server's: it must not be a Warn on an
		// internet-facing listener.
		{"/denied", 401, "INFO", "GET /denied"},
		// Nothing matched, so there is no pattern to report.
		{"/nope", 404, "INFO", ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			ts, lb := observed(t, mux)
			resp, err := ts.Client().Get(ts.URL + tc.path)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			resp.Body.Close()

			rec := lb.find(t, "request")
			if rec["status"] != tc.status {
				t.Errorf("status = %v, want %v", rec["status"], tc.status)
			}
			if rec["level"] != tc.level {
				t.Errorf("level = %v, want %v", rec["level"], tc.level)
			}
			if rec["route"] != tc.wantRoute {
				t.Errorf("route = %v, want %q", rec["route"], tc.wantRoute)
			}
			if _, ok := rec["durationMs"]; !ok {
				t.Errorf("no durationMs in %v", rec)
			}
		})
	}
}

// TestObserveDoesNotBufferTheResponse: the recorder must stay a pass-through,
// or a long poll would deliver its answer only once the handler returned.
func TestObserveDoesNotBufferTheResponse(t *testing.T) {
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("GET /stream", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("first"))
		http.NewResponseController(w).Flush()
		<-release
	})
	ts, _ := observed(t, mux)

	resp, err := ts.Client().Get(ts.URL + "/stream")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() {
		close(release)
		resp.Body.Close()
	}()

	// Reads before the handler has returned, which only works if both the flush
	// reached the wire through the wrapper and nothing is buffering.
	got := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, got); err != nil {
		t.Fatalf("read while the handler is still running: %v", err)
	}
	if string(got) != "first" {
		t.Fatalf("got %q, want %q", got, "first")
	}
}
