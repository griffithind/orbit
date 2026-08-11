package api

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// The enrollment limiter had no tests. It is the only public, unauthenticated,
// cryptographically expensive surface this server exposes, and the thing it
// exists to prevent is a denial of service — so the failure mode worth checking
// is not "does it refuse too much" but "can one caller make it refuse everyone
// else".

// TestOneSourceCannotDenyEveryOther.
//
// The bug this pins: the global ceiling was checked FIRST, and
// rate.Limiter.Allow spends a token whether or not the request is served. A
// source already over its own per-key limit therefore kept draining the global
// budget with requests that were about to be refused anyway. At the defaults
// that is 600 refusals a minute from one address, after which every other
// client gets 429 without having sent a single request.
//
// The attacker did not need to defeat their own limit. The rejections were the
// attack.
func TestOneSourceCannotDenyEveryOther(t *testing.T) {
	l := NewLimiter(LimiterConfig{
		PerMinute: 60, Burst: 2,
		GlobalPerMinute: 60, GlobalBurst: 10,
		TTL: time.Minute,
	})

	noisy := 0
	for range 50 {
		if l.Allow("10.0.0.1") {
			noisy++
		}
	}
	if noisy > 3 {
		t.Fatalf("the noisy source got %d requests through its burst of 2", noisy)
	}

	victim := 0
	for range 2 {
		if l.Allow("10.0.0.2") {
			victim++
		}
	}
	if victim == 0 {
		t.Errorf("a source that had sent nothing was refused entirely: %d rejected "+
			"requests from another key had spent the global budget", 50-noisy)
	}
}

// TestGlobalCeilingStillBounds. The reordering must not cost the property the
// global ceiling exists for: many distinct sources, each within its own limit,
// are still bounded in total. This is the distributed case a per-key limit
// cannot see.
func TestGlobalCeilingStillBounds(t *testing.T) {
	l := NewLimiter(LimiterConfig{
		PerMinute: 600, Burst: 5,
		GlobalPerMinute: 60, GlobalBurst: 10,
		TTL: time.Minute,
	})

	allowed := 0
	for i := range 200 {
		if l.Allow(fmt.Sprintf("10.0.%d.%d", i/256, i%256)) {
			allowed++
		}
	}
	if allowed > 12 {
		t.Errorf("200 distinct sources got %d requests through a global burst of 10", allowed)
	}
	if allowed == 0 {
		t.Error("the global ceiling refused everything, which is not a ceiling")
	}
}

// TestTheKeyTableIsBounded.
//
// Checking per-key first means a request reaches the map before the global
// ceiling can refuse it, so the map no longer grows only as fast as the global
// rate. Without an explicit cap that is an unbounded allocation driven by
// attacker-chosen keys — which is the memory exhaustion the TTL was there to
// prevent, arriving by a different door.
func TestTheKeyTableIsBounded(t *testing.T) {
	l := NewLimiter(LimiterConfig{
		PerMinute: 600, Burst: 5,
		GlobalPerMinute: 6_000_000, GlobalBurst: 1_000_000,
		TTL: time.Hour, // nothing is idle, so eviction cannot save us
	})

	for i := range maxKeys * 3 {
		l.Allow(fmt.Sprintf("key-%d", i))
	}

	l.mu.Lock()
	n := len(l.keys)
	l.mu.Unlock()
	if n > maxKeys {
		t.Errorf("tracking %d keys with a cap of %d", n, maxKeys)
	}
}

// TestIdleSourcesAreEvicted. The cap must not become permanent: a table full of
// sources that have all gone away has to make room, or the first busy minute
// after startup decides who can ever be limited again.
func TestIdleSourcesAreEvicted(t *testing.T) {
	l := NewLimiter(LimiterConfig{
		PerMinute: 600, Burst: 5,
		GlobalPerMinute: 6_000_000, GlobalBurst: 1_000_000,
		TTL: time.Nanosecond, // everything is idle by the next call
	})

	for i := range maxKeys + 10 {
		l.Allow(fmt.Sprintf("key-%d", i))
		if i%1000 == 0 {
			time.Sleep(time.Microsecond)
		}
	}

	l.mu.Lock()
	n := len(l.keys)
	l.mu.Unlock()
	if n >= maxKeys {
		t.Errorf("table sat at %d with every entry idle; eviction did not run", n)
	}
}

// TestIPv6IsBucketedByPrefix. A single client routinely holds a whole /64 and
// can source from any address in it, so a per-address limit there is one an
// attacker steps around without trying while it looks like it is working.
func TestIPv6IsBucketedByPrefix(t *testing.T) {
	a := limiterKey(netip.MustParseAddr("2001:db8::1"))
	b := limiterKey(netip.MustParseAddr("2001:db8::dead:beef"))
	if a != b {
		t.Errorf("two addresses in one /64 got separate buckets: %s and %s", a, b)
	}

	c := limiterKey(netip.MustParseAddr("2001:db8:0:1::1"))
	if a == c {
		t.Errorf("two different /64s share a bucket: %s", a)
	}

	// v4 stays exact: a /64 has no meaning there and bucketing wider would
	// group unrelated clients behind one limit.
	if got := limiterKey(netip.MustParseAddr("192.0.2.7")); got != "192.0.2.7" {
		t.Errorf("v4 key = %q, want the address itself", got)
	}
}
