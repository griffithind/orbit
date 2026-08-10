// Package notify fans epoch changes out to waiting agents.
//
// The transport is Postgres LISTEN/NOTIFY. The transaction that advances a
// network's epoch also issues the NOTIFY (store.Tx.BumpEpoch), and Postgres
// delivers it on commit — so a rolled back change cannot wake agents for an
// update that never happened, and a committed one cannot fail to.
//
// Using the database we already have, rather than a message broker, is a
// deliberate scope choice: it is sufficient into the five figures of hosts and
// removes an entire component from day-one operations. The limit to watch is
// connection count, not throughput; revisit when a single Postgres cannot hold
// the watchers.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Channel is the Postgres notification channel BumpEpoch publishes on.
const Channel = "orbit_epoch"

// Event is one epoch advance.
type Event struct {
	NetworkID uuid.UUID `json:"network_id"`
	Kind      string    `json:"kind"`
	Epoch     int64     `json:"epoch"`
}

// Observer receives listener state changes. *metrics.Metrics satisfies it.
//
// An interface rather than a direct dependency on the metrics package: this
// package is the one thing that must keep working when everything else is
// broken, and it should not gain an import to be observable.
type Observer interface {
	ListenerUp(up bool)
	EpochNotified(kind string)
}

// Notifier listens for epoch changes and wakes per-network subscribers.
type Notifier struct {
	pool *pgxpool.Pool
	log  *slog.Logger
	obs  Observer

	mu   sync.Mutex
	subs map[uuid.UUID]map[int]chan Event
	next int

	// live is the current LISTEN state, read by Up. Not guarded by mu: the
	// readers are request handlers answering a health probe or rendering a
	// status badge, and taking the same lock the dispatch hot path holds to read
	// a boolean would put them behind every fan-out.
	live atomic.Bool

	// ready is closed once LISTEN is established, so a caller can avoid the
	// race where it publishes before the listener is actually listening.
	ready     chan struct{}
	readyOnce sync.Once
}

func New(pool *pgxpool.Pool, log *slog.Logger) *Notifier {
	return &Notifier{
		pool:  pool,
		log:   log,
		subs:  map[uuid.UUID]map[int]chan Event{},
		ready: make(chan struct{}),
	}
}

// Observe attaches an observer. Safe to skip; nil means no reporting.
func (n *Notifier) Observe(o Observer) *Notifier {
	n.obs = o
	return n
}

func (n *Notifier) up(state bool) {
	n.live.Store(state)
	if n.obs != nil {
		n.obs.ListenerUp(state)
	}
}

// Up reports whether the LISTEN connection is established right now.
//
// Distinct from Ready, and the distinction is the entire point: Ready means
// "established at least once" and stays satisfied across a drop and a
// reconnect, because its job is to let a publisher avoid racing startup. This
// reports the live state, which is what a health probe and a status badge need
// — a listener that dropped is a fleet that has silently fallen back to
// poll-interval latency, and reporting it as up would hide exactly the failure
// worth surfacing.
//
// False before Run is ever called, and false after it returns. Both readings
// are correct: in either case nothing is being pushed.
func (n *Notifier) Up() bool {
	return n.live.Load()
}

// Ready blocks until the listener is established or ctx is done.
func (n *Notifier) Ready(ctx context.Context) error {
	select {
	case <-n.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run holds a dedicated connection and dispatches notifications until ctx ends.
//
// It reconnects on failure rather than returning: losing the listener silently
// downgrades every agent to poll-interval latency, which is exactly the
// regression this package exists to prevent. A caller that sees Run return has
// a cancelled context, not a transient error.
func (n *Notifier) Run(ctx context.Context) error {
	backoff := 100 * time.Millisecond
	const maxBackoff = 10 * time.Second

	for ctx.Err() == nil {
		err := n.listen(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			n.log.Warn("epoch listener dropped, reconnecting",
				"error", err, "retryIn", backoff)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
	return ctx.Err()
}

func (n *Notifier) listen(ctx context.Context) error {
	// The down transition is paired with the up transition here rather than in
	// Run, so that no exit from this function can leave the reported state
	// stale. Run is the wrong owner for it: Run returns early on a cancelled
	// context, and a report left behind by that path would have Up saying yes
	// for a notifier that had stopped.
	defer n.up(false)

	conn, err := n.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN "+Channel); err != nil {
		return err
	}
	n.readyOnce.Do(func() { close(n.ready) })
	n.up(true)
	n.log.Debug("listening for epoch changes", "channel", Channel)

	for {
		raw, err := conn.Conn().WaitForNotification(ctx)
		if err != nil {
			return err
		}

		var ev Event
		if err := json.Unmarshal([]byte(raw.Payload), &ev); err != nil {
			// A malformed payload is a bug on the publishing side. Log it and
			// keep listening; dropping the connection would punish every
			// waiter for one bad message.
			n.log.Error("unparseable epoch notification",
				"payload", raw.Payload, "error", err)
			continue
		}
		if n.obs != nil {
			n.obs.EpochNotified(ev.Kind)
		}
		n.dispatch(ev)
	}
}

func (n *Notifier) dispatch(ev Event) {
	n.mu.Lock()
	defer n.mu.Unlock()

	for _, ch := range n.subs[ev.NetworkID] {
		select {
		case ch <- ev:
		default:
			// The subscriber has an unread event already. Dropping this one is
			// correct: every waiter re-reads current state on wake, so one
			// wakeup conveys everything a hundred would. The channel is a
			// signal, not a queue.
		}
	}
}

// Subscribe returns a channel that receives epoch changes for a network, and a
// function that must be called to release it.
//
// The channel is buffered by one and coalescing. Callers must treat a receive
// as "something changed, go look", never as a complete change log.
func (n *Notifier) Subscribe(networkID uuid.UUID) (<-chan Event, func()) {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := n.next
	n.next++
	ch := make(chan Event, 1)

	if n.subs[networkID] == nil {
		n.subs[networkID] = map[int]chan Event{}
	}
	n.subs[networkID][id] = ch

	return ch, func() {
		n.mu.Lock()
		defer n.mu.Unlock()
		if m := n.subs[networkID]; m != nil {
			delete(m, id)
			if len(m) == 0 {
				delete(n.subs, networkID)
			}
		}
	}
}

// Subscribers reports how many waiters a network currently has. Exposed for
// the per-network connection cap and for metrics; a runaway here is the first
// sign of pool exhaustion.
func (n *Notifier) Subscribers(networkID uuid.UUID) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.subs[networkID])
}

// ErrClosed is returned by Wait when the notifier stops.
var ErrClosed = errors.New("notifier closed")
