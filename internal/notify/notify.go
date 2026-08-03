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

// Notifier listens for epoch changes and wakes per-network subscribers.
type Notifier struct {
	pool *pgxpool.Pool
	log  *slog.Logger

	mu   sync.Mutex
	subs map[uuid.UUID]map[int]chan Event
	next int

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
	conn, err := n.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "LISTEN "+Channel); err != nil {
		return err
	}
	n.readyOnce.Do(func() { close(n.ready) })
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

// Total reports every waiter across all networks.
func (n *Notifier) Total() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	total := 0
	for _, m := range n.subs {
		total += len(m)
	}
	return total
}

// ErrClosed is returned by Wait when the notifier stops.
var ErrClosed = errors.New("notifier closed")

// Wait blocks until a change arrives for networkID, the timeout elapses, or ctx
// ends. It reports whether an event actually arrived, so a caller can
// distinguish "something changed" from "nothing happened, poll again".
func (n *Notifier) Wait(ctx context.Context, networkID uuid.UUID, timeout time.Duration) bool {
	ch, cancel := n.Subscribe(networkID)
	defer cancel()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ch:
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}
