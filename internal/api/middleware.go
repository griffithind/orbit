package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// Observe wraps a mux with the middleware every listener needs in production.
//
// It exists because the listeners are built by the caller (see the package doc:
// production mounts EnrollRoutes, AgentRoutes, and AdminRoutes on separate
// muxes), so there is no single place inside this package that can guarantee a
// raw mux is ever wrapped. Without this, an orbitd built from raw muxes emits no
// request log at all and turns a handler panic into a truncated response.
//
// Order matters, and it is this way round for two reasons:
//
//   - recoverer must be inside so it is the first frame the panic unwinds
//     through. Outside, the panic would blow past logging's log call and the
//     request would go unrecorded.
//   - logging must be outside so it observes the 500 the recoverer writes. A
//     panicking request is exactly the one worth having a request line for.
func Observe(log *slog.Logger, next http.Handler) http.Handler {
	return logging(log, recoverer(log, next))
}

// recoverer turns a handler panic into an ordinary 500.
//
// net/http already recovers per connection, but it logs to the server's
// ErrorLog rather than to the structured logger, and it closes the connection
// without a response — so the caller sees a truncated read where every other
// failure in this API produces a wire.Error document. That difference is what
// makes a panic hard to recognise from the client side.
func recoverer(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		defer func() {
			v := recover()
			if v == nil {
				return
			}
			// http.ErrAbortHandler is the documented way for a handler to drop a
			// connection deliberately, and net/http suppresses it on purpose.
			// Recovering it would convert an intended abort into a 500 and hide
			// the intent, so it goes back up untouched and unlogged.
			if err, ok := v.(error); ok && errors.Is(err, http.ErrAbortHandler) {
				panic(v)
			}

			// Both the value and the stack: the value alone rarely says which
			// handler produced it, and this is the only record that will exist.
			log.Error("panic serving request",
				"method", r.Method, "path", r.URL.Path, "route", r.Pattern,
				"panic", fmt.Sprint(v), "stack", string(debug.Stack()))

			if rec.wrote {
				// The response is already committed: the status is on the wire
				// and an error document appended here would corrupt a partial
				// body. Abort instead, which closes the connection and tells the
				// client the body is truncated. ErrAbortHandler rather than a
				// re-panic so net/http stays quiet — this panic is already
				// logged above, in full, with structure.
				panic(http.ErrAbortHandler)
			}
			writeErr(rec, http.StatusInternalServerError, "internal error")
		}()
		next.ServeHTTP(rec, r)
	})
}

func logging(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &responseRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		// route is r.Pattern: the registered pattern ("GET /v1/hosts/{id}")
		// rather than the path, filled in by ServeMux on the way in. It is a
		// closed set, so it is safe to group or alert on; path is caller-chosen
		// and is here for reading, not for aggregating. Empty means no route
		// matched, which is itself the interesting part of a 404.
		log.Log(r.Context(), levelFor(rec.status), "request",
			"method", r.Method, "path", r.URL.Path, "route", r.Pattern,
			"status", rec.status, "durationMs", time.Since(start).Milliseconds())
	})
}

// levelFor grades a response.
//
// 5xx is Error because it is the control plane's own fault and every log
// pipeline can already route on level=ERROR; the handler that caused it usually
// logs the cause too, and the two lines complement each other (cause there,
// status and route and duration here).
//
// 4xx stays at Info alongside 2xx. It is the caller's mistake, not the server's,
// and the public listener is internet-facing: promoting scanner 404s and expired
// enrollment 401s to Warn would mean an operator's warnings are mostly other
// people's typos. The cases that genuinely need attention — rate limiting, a
// network with no active CA — are logged by their handlers at the level they
// deserve.
func levelFor(status int) slog.Level {
	if status >= 500 {
		return slog.LevelError
	}
	return slog.LevelInfo
}

// responseRecorder observes the status and whether the response has started.
//
// wrote is what lets the recoverer tell "nothing written yet, a 500 is still
// possible" from "half a body is already on the wire".
type responseRecorder struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (r *responseRecorder) WriteHeader(code int) {
	// First write wins, matching net/http: a superfluous WriteHeader changes
	// nothing on the wire, so it must not change what gets logged either.
	if !r.wrote {
		r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	// A body written without WriteHeader commits an implicit 200.
	r.wrote = true
	return r.ResponseWriter.Write(b)
}

// Unwrap keeps http.ResponseController working through the wrapper, so a future
// handler can still reach the underlying flush and deadline controls.
func (r *responseRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
