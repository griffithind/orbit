package web

import (
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// Server-sent events, and the thing about them that is easy to get wrong.
//
// AN EPOCH ADVANCE IS NOT THE ONLY THING THAT CHANGES. The Postgres NOTIFY this
// stream is built on fires from store.Tx.BumpEpoch — a config change, a
// revocation, a CA promotion. But last_seen_at and applied_config_epoch move
// when an AGENT REPORTS, and RecordAgentReport issues no notification at all. So
// convergence — the number the incident core is actually watching — changes
// continuously with no event behind it.
//
// The obvious fix is wrong. Adding a NOTIFY per report means one notification
// per host per poll interval: on a thousand-host fleet that is a constant
// broadcast to every listener in the deployment, on the same connection agents'
// renewals depend on, to tell watchers something that four of them care about.
//
// So the model is split, and each half does the thing it is good at:
//
//	SSE says     "an epoch moved, refetch"     — instant, rare, exact
//	a 10s timer  covers convergence drift      — cheap, approximate, always
//
// The timer lives in app.js and pauses on visibilitychange, so a tab left open
// on a second monitor costs nothing. The stream is the latency win for the
// events that matter; the timer is the correctness floor for the ones that
// produce no event.
//
// FAIL SOFT, ALWAYS. Over the connection cap, notifier absent, stream dropped —
// every one of those leaves the page working on its timer. A live view that
// stops updating during an incident without saying so is worse than one that
// never claimed to be live, which is why the client marks the page stale rather
// than silently freezing.

const (
	// eventHeartbeat keeps the connection from being reaped by an idle proxy and
	// is how the server notices a client that vanished without closing: the write
	// fails and the handler returns.
	eventHeartbeat = 25 * time.Second

	// sessionRecheck is how often the stream re-validates its session.
	//
	// Without this, revoking a token or signing out leaves a LIVE DATA FEED open:
	// the cookie was checked once, when the stream opened, and an SSE connection
	// can then sit there for days pushing fleet state to a browser whose access
	// was withdrawn. Sixty seconds bounds that at a minute, and costs one indexed
	// lookup per stream per minute — with the stream cap, a rounding error.
	sessionRecheck = 60 * time.Second

	// maxStreamAge caps a single connection's lifetime. EventSource reconnects
	// automatically, so recycling costs the client nothing and it stops a stream
	// from outliving the process's assumptions about it — including a session
	// whose expiry the recheck would only notice at the next tick.
	maxStreamAge = 30 * time.Minute
)

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) error {
	networkID, err := uuid.Parse(r.URL.Query().Get("network"))
	if err != nil {
		http.Error(w, "network query parameter must be a uuid", http.StatusBadRequest)
		return nil
	}

	if s.cfg.Notifier == nil {
		// 501 rather than a stream that never delivers. The client reads a
		// non-200 as "no push here" and stays on its timer, which is exactly
		// right; a silent empty stream would look live and never update.
		http.Error(w, "push is not enabled on this replica", http.StatusNotImplemented)
		return nil
	}

	// The cap. Checked with an add-then-check rather than a check-then-add so two
	// simultaneous opens cannot both see room for one.
	if n := s.streams.Add(1); n > int64(s.cfg.MaxStreams) {
		s.streams.Add(-1)
		s.log.Warn("ui event stream refused: at capacity",
			"limit", s.cfg.MaxStreams, "path", r.URL.Path)
		// 503 with Retry-After. The client falls back to its timer and tries the
		// stream again later; nothing about the page degrades.
		w.Header().Set("Retry-After", "60")
		http.Error(w, "too many event streams open", http.StatusServiceUnavailable)
		return nil
	}
	defer s.streams.Add(-1)

	rc := http.NewResponseController(w)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	// Named explicitly because an SSE stream behind a buffering proxy is a stream
	// that delivers everything at once when it closes, which is indistinguishable
	// from a broken feature.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	// The retry hint the browser uses when it reconnects. Three seconds rather
	// than EventSource's default so a control plane restart does not have every
	// open tab reconnecting in the same instant.
	if _, err := fmt.Fprintf(w, "retry: 3000\n\n"); err != nil {
		return err
	}
	if err := rc.Flush(); err != nil {
		// No flush support means every event would sit in a buffer. Better to
		// end now and let the client use its timer.
		return err
	}

	events, release := s.cfg.Notifier.Subscribe(networkID)
	defer release()

	cookie := cookieFrom(r.Context())
	heartbeat := time.NewTicker(eventHeartbeat)
	defer heartbeat.Stop()
	recheck := time.NewTicker(sessionRecheck)
	defer recheck.Stop()
	deadline := time.NewTimer(maxStreamAge)
	defer deadline.Stop()

	for {
		select {
		case <-r.Context().Done():
			return nil

		case <-deadline.C:
			// A clean close. EventSource reconnects on its own.
			return nil

		case ev := <-events:
			// The payload is the epoch and its kind, and deliberately nothing
			// else. The client's response is to refetch the page it is on, so
			// pushing state down this channel would be a second, unversioned copy
			// of what the page already renders — and the first thing to go stale.
			if _, err := fmt.Fprintf(w, "event: epoch\ndata: {\"kind\":%q,\"epoch\":%d}\n\n",
				ev.Kind, ev.Epoch); err != nil {
				return err
			}
			if err := rc.Flush(); err != nil {
				return err
			}

		case <-recheck.C:
			if _, err := s.sessions.Resolve(r.Context(), cookie); err != nil {
				// Revoked, expired, or the database is unreachable. All three end
				// the stream: the first two must, and for the third a client on
				// its timer is no worse off than one being fed by a server that
				// cannot read the database anyway.
				s.log.Info("ui event stream closed: session no longer valid")
				// A named event, so the client can stop retrying and send the
				// operator to the login page rather than reconnecting forever
				// against a session that will never come back.
				_, _ = fmt.Fprint(w, "event: expired\ndata: {}\n\n")
				_ = rc.Flush()
				return nil
			}

		case <-heartbeat.C:
			// A comment frame. Invisible to EventSource, but it is a write, and a
			// write is the only way to discover a peer that went away.
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return err
			}
			if err := rc.Flush(); err != nil {
				return err
			}
		}
	}
}
