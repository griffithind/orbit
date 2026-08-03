package api

import (
	"net/http"
	"strconv"
	"time"
)

// Watch defaults.
//
// HoldFor must stay comfortably below the shortest idle timeout anywhere in the
// path. Thirty seconds clears the common proxy and NAT defaults; a longer hold
// buys almost nothing (the response is immediate once an epoch moves) and
// starts getting connections severed by middleboxes, which looks to an agent
// exactly like a control plane failure.
const (
	DefaultWatchHold = 30 * time.Second
	MaxWatchHold     = 5 * time.Minute
)

// handleAgentWatch is the push half of update distribution.
//
// It is a long poll rather than a stream because the payload is a full
// generation, not a delta: an agent that misses events loses nothing, since it
// re-reads current state on every wake. That property is what lets the notifier
// coalesce aggressively and lets a dropped connection be harmless.
//
// The subscription is taken BEFORE reading current state. Doing it the other
// way round leaves a window in which an epoch advances between the read and the
// subscribe, and the agent then waits the full hold period for a change that
// has already happened.
func (s *Server) handleAgentWatch(w http.ResponseWriter, r *http.Request) {
	id, ok := s.agentIdentity(w, r)
	if !ok {
		return
	}
	if s.cfg.Notifier == nil {
		writeErr(w, http.StatusServiceUnavailable,
			"push updates are not available on this server; poll /agent/v1/state instead")
		return
	}

	// Cap concurrent watchers so one large network cannot exhaust the
	// connection pool for every other network on this deployment. The cap fails
	// soft: an agent refused a slot falls back to polling.
	if max := s.cfg.MaxWatchers; max > 0 && s.cfg.Notifier.Subscribers(s.cfg.Agent.NetworkID) >= max {
		s.cfg.Metrics.PollFallback()
		w.Header().Set("Retry-After", "5")
		writeErr(w, http.StatusServiceUnavailable, "too many watchers; falling back to polling is expected")
		return
	}

	hold := DefaultWatchHold
	if v := r.URL.Query().Get("hold"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			hold = min(d, MaxWatchHold)
		}
	}

	knownConfig, _ := strconv.ParseInt(r.URL.Query().Get("config_epoch"), 10, 64)
	knownBlock, _ := strconv.ParseInt(r.URL.Query().Get("blocklist_epoch"), 10, 64)

	events, release := s.cfg.Notifier.Subscribe(s.cfg.Agent.NetworkID)
	defer release()

	// Paired with the deferred close so every early return below still
	// decrements. A gauge that only counts up is worse than no gauge.
	s.cfg.Metrics.WatcherOpened()
	defer s.cfg.Metrics.WatcherClosed()

	// Fast path: already behind, answer now.
	resp, err := s.enroll.State(r.Context(), id.HostID, knownConfig, knownBlock)
	if err != nil {
		s.log.Error("watch state failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if resp.Config != "" {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	timer := time.NewTimer(hold)
	defer timer.Stop()

	select {
	case <-events:
		// Re-read rather than trusting the event's epoch: another change may
		// have landed since, and the agent wants the newest generation, not the
		// one that happened to wake it.
		resp, err = s.enroll.State(r.Context(), id.HostID, knownConfig, knownBlock)
		if err != nil {
			s.log.Error("watch state failed after wake", "error", err)
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
	case <-timer.C:
		// Nothing changed. Returning current epochs with no payload lets the
		// agent reconnect immediately and keeps the steady-state response tiny.
	case <-r.Context().Done():
		return
	}

	writeJSON(w, http.StatusOK, resp)
}
