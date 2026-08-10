package agent

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// TestLastPollIsSafeAcrossGoroutines.
//
// The loop writes the poll outcome from the tick goroutine; the status socket
// reads it from its own. This used to live in cmd/orbit as two unguarded fields
// on networkLoop, which is a data race the daemon avoided only because the
// socket happened not to be exercised under load. The assertion is the race
// detector — CI must run this package with -race for it to mean anything.
func TestLastPollIsSafeAcrossGoroutines(t *testing.T) {
	l := &Loop{now: func() time.Time { return time.Unix(0, 0) }}
	boom := errors.New("control plane unreachable")

	stop := make(chan struct{})
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = l.recordPoll(boom)
			_ = l.recordPoll(nil)
		}
	}()

	for i := 0; i < 2000; i++ {
		_, _ = l.LastPoll()
	}
	close(stop)
	wg.Wait()
}

// TestRecordPollReturnsItsArgument. recordPoll sits in the return path of Tick,
// so swallowing the error would silently turn every failed poll into a success.
func TestRecordPollReturnsItsArgument(t *testing.T) {
	l := &Loop{now: func() time.Time { return time.Unix(0, 0) }}
	boom := errors.New("nope")

	if got := l.recordPoll(boom); !errors.Is(got, boom) {
		t.Fatalf("recordPoll returned %v, want %v", got, boom)
	}
	at, err := l.LastPoll()
	if !errors.Is(err, boom) {
		t.Errorf("LastPoll error = %v, want %v", err, boom)
	}
	if at.IsZero() {
		t.Error("LastPoll time is zero; a recorded poll must carry when it happened")
	}

	if got := l.recordPoll(nil); got != nil {
		t.Fatalf("recordPoll(nil) returned %v, want nil", got)
	}
	if _, err := l.LastPoll(); err != nil {
		t.Errorf("a successful poll must clear the previous error, got %v", err)
	}
}
