package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestSkewIsMeasuredFromTheDateHeader.
//
// The property that turns an invisible fault into a named one: nebula validates
// certificate windows against raw wall time with zero leeway, and Orbit
// backdates issuance by exactly one minute, so a host further behind than that
// rejects its own brand-new certificate. The apply fails, the loop rolls back
// and retries forever, and the failure is indistinguishable from a wrong key, a
// wrong CA, or a corrupted config.
//
// See docs/adr/0031-clock-skew-is-measured-not-inferred.md.
func TestSkewIsMeasuredFromTheDateHeader(t *testing.T) {
	// The server claims a time 90 minutes in the past, so this host reads as 90
	// minutes AHEAD. The sign matters: it decides which half of the advice the
	// operator is given.
	served := time.Now().Add(-90 * time.Minute).UTC()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", served.Format(http.TimeFormat))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"config_epoch":1,"blocklist_epoch":1}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	if _, ok := c.Skew(); ok {
		t.Fatal("a client that has sent nothing reported a measurement")
	}

	if _, err := c.State(context.Background(), 0, 0); err != nil {
		t.Fatalf("state: %v", err)
	}

	skew, ok := c.Skew()
	if !ok {
		t.Fatal("no skew recorded from a response carrying a Date header")
	}
	if skew < 80*time.Minute || skew > 100*time.Minute {
		t.Errorf("skew = %s, want about +90m", skew)
	}
	if skew <= MaxSkew {
		t.Errorf("90 minutes did not exceed MaxSkew (%s), so nothing would warn", MaxSkew)
	}
}

// TestNoDateHeaderLeavesTheLastMeasurementAlone.
//
// "No reading" and "no skew" must not look the same. A proxy that strips Date
// would otherwise erase a real warning by reporting zero, which is the failure
// mode that makes a measurement worse than none.
func TestNoDateHeaderLeavesTheLastMeasurementAlone(t *testing.T) {
	c := NewClient("http://example.invalid")
	c.skew, c.skewAt = 42*time.Minute, time.Now()

	c.observeDate(&http.Response{Header: http.Header{}}, time.Now())

	if got, _ := c.Skew(); got != 42*time.Minute {
		t.Errorf("a response with no Date header overwrote the measurement: %s", got)
	}
}

// TestAGoodClockReadsAsNoSkew guards the other direction: the midpoint
// correction must keep an ordinary round trip from registering as drift, or
// every healthy fleet warns.
func TestAGoodClockReadsAsNoSkew(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"config_epoch":1,"blocklist_epoch":1}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL)
	if _, err := c.State(context.Background(), 0, 0); err != nil {
		t.Fatalf("state: %v", err)
	}
	skew, ok := c.Skew()
	if !ok {
		t.Fatal("no measurement taken")
	}
	// Date has one-second resolution, so a correct clock lands within a couple
	// of seconds either way — well inside the one-minute tolerance.
	if skew > MaxSkew || skew < -MaxSkew {
		t.Errorf("a correct clock measured as %s of skew, which would warn on every healthy host", skew)
	}
}
