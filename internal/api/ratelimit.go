package api

import (
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Rate limiting for the enrollment endpoint.
//
// Enrollment is the one surface that is public, unauthenticated, and
// cryptographically expensive: every request costs an Argon2-class hash lookup
// and, on success, a KMS signing operation. Leaving it unbounded means a single
// client can exhaust a signing quota (which is billable and rate-limited by the
// backend) or simply keep the CPU busy.
//
// docs/enrollment.md §2 has listed this as an invariant since the design was
// written. It was not implemented until now; the doc described behaviour the
// code did not have.
//
// The limit is per source address, with a global ceiling for the distributed
// case a per-address limit cannot see. Nothing finer is available: the request
// is unauthenticated, and the host it claims to be is unknown until a credential
// is successfully redeemed — which is the work the limit exists to protect.

// Limiter bounds request rate per key, with a shared global ceiling.
type Limiter struct {
	perKeyRate  rate.Limit
	perKeyBurst int
	ttl         time.Duration

	global *rate.Limiter

	mu   sync.Mutex
	keys map[string]*keyLimiter
}

type keyLimiter struct {
	lim  *rate.Limiter
	seen time.Time
}

// LimiterConfig tunes the enrollment limiter.
type LimiterConfig struct {
	// PerMinute is the sustained rate allowed from one source address.
	//
	// Enrollment is a once-per-host event, so a legitimate client needs one
	// request. The allowance exists for retries and for many hosts sharing one
	// NAT egress address, which is why it is not 1.
	PerMinute float64

	// Burst absorbs a fleet enrolling at once from behind one address.
	Burst int

	// GlobalPerMinute caps the whole endpoint regardless of source, covering
	// the distributed case a per-address limit cannot.
	GlobalPerMinute float64
	GlobalBurst     int

	// TTL is how long an idle source's limiter is retained. Without eviction
	// the map is an unbounded allocation driven by attacker-chosen keys, which
	// turns a rate limiter into a memory exhaustion vector.
	TTL time.Duration
}

func DefaultLimiterConfig() LimiterConfig {
	return LimiterConfig{
		PerMinute:       10,
		Burst:           20,
		GlobalPerMinute: 600,
		GlobalBurst:     200,
		TTL:             10 * time.Minute,
	}
}

func NewLimiter(cfg LimiterConfig) *Limiter {
	d := DefaultLimiterConfig()
	if cfg.PerMinute <= 0 {
		cfg.PerMinute = d.PerMinute
	}
	if cfg.Burst <= 0 {
		cfg.Burst = d.Burst
	}
	if cfg.GlobalPerMinute <= 0 {
		cfg.GlobalPerMinute = d.GlobalPerMinute
	}
	if cfg.GlobalBurst <= 0 {
		cfg.GlobalBurst = d.GlobalBurst
	}
	if cfg.TTL <= 0 {
		cfg.TTL = d.TTL
	}

	return &Limiter{
		perKeyRate:  rate.Limit(cfg.PerMinute / 60),
		perKeyBurst: cfg.Burst,
		ttl:         cfg.TTL,
		global:      rate.NewLimiter(rate.Limit(cfg.GlobalPerMinute/60), cfg.GlobalBurst),
		keys:        map[string]*keyLimiter{},
	}
}

// Allow reports whether a request from key may proceed.
func (l *Limiter) Allow(key string) bool {
	// Global first: a distributed attempt spread across many addresses passes
	// every per-key check and would otherwise be unbounded.
	if !l.global.Allow() {
		return false
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	k, ok := l.keys[key]
	if !ok {
		k = &keyLimiter{lim: rate.NewLimiter(l.perKeyRate, l.perKeyBurst)}
		l.keys[key] = k
	}
	k.seen = now

	// Evict opportunistically rather than on a timer. The work is proportional
	// to map size and only happens once the map is large enough to matter, so
	// there is no goroutine to leak and no ticker to coordinate.
	if len(l.keys) > 1024 {
		for key, v := range l.keys {
			if now.Sub(v.seen) > l.ttl {
				delete(l.keys, key)
			}
		}
	}

	return k.lim.Allow()
}

// limitEnroll wraps the enrollment handler.
//
// A limited request gets 429 with Retry-After. That is deliberately
// distinguishable from the 401 an invalid credential gets: an honest client
// behind a busy NAT needs to know to back off, and telling it apart from a
// rejected credential leaks nothing, since the caller already knows which
// request it sent.
func (s *Server) limitEnroll(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.limiter == nil {
			h(w, r)
			return
		}

		key := "unknown"
		if addr := s.clientAddr(r); addr.IsValid() {
			key = limiterKey(addr)
		}

		if !s.limiter.Allow(key) {
			s.log.Warn("enrollment rate limited", "from", key)
			w.Header().Set("Retry-After", strconv.Itoa(30))
			writeErr(w, http.StatusTooManyRequests, "too many enrollment attempts; retry shortly")
			return
		}
		h(w, r)
	}
}

// limiterKey groups an address into the unit worth limiting.
//
// IPv6 is bucketed by /64 rather than by exact address. A single client
// routinely holds a whole /64 and can source from any address in it, so
// limiting per-address would be trivially bypassed while looking like it was
// working.
func limiterKey(addr netip.Addr) string {
	if addr.Is6() && !addr.Is4In6() {
		if p, err := addr.Prefix(64); err == nil {
			return p.String()
		}
	}
	return addr.String()
}
