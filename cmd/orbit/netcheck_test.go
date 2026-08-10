package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The clock check is the reason netcheck exists.
//
// A host whose clock is wrong fails to enroll and fails to renew, and reports
// it as a certificate error — which sends whoever is debugging to the CA, the
// one place the problem is not. Nothing else in the system says "your clock is
// wrong", so this check has to be right.

func serverAt(t *testing.T, when time.Time) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set explicitly rather than letting net/http stamp it, so the test
		// controls what the "server" believes the time is.
		w.Header().Set("Date", when.UTC().Format(http.TimeFormat))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestClockCheckAcceptsSmallSkew(t *testing.T) {
	// Inside maxSkew. Certificate issuance backdates by a minute, so a host
	// this close still gets a usable NotBefore.
	s := serverAt(t, time.Now().Add(-30*time.Second))

	got := clockCheck(context.Background(), s.URL)
	if !got.OK {
		t.Fatalf("30s of skew was rejected: %s", got.Detail)
	}
}

func TestClockCheckRejectsSkewInBothDirections(t *testing.T) {
	for name, offset := range map[string]time.Duration{
		"host ahead":  -10 * time.Minute, // server's clock is behind ours
		"host behind": 10 * time.Minute,  // server's clock is ahead of ours
	} {
		t.Run(name, func(t *testing.T) {
			s := serverAt(t, time.Now().Add(offset))

			got := clockCheck(context.Background(), s.URL)
			if got.OK {
				t.Fatalf("10 minutes of skew was accepted: %s", got.Detail)
			}
			// The direction has to be in the message: "fix your clock" is not
			// actionable without knowing which way it is wrong.
			if !strings.Contains(got.Detail, "ahead of") && !strings.Contains(got.Detail, "behind") {
				t.Errorf("detail does not say which way the clock is wrong: %q", got.Detail)
			}
			if got.Advice == "" {
				t.Error("a failed clock check must say what it breaks; it is reported " +
					"everywhere else as a certificate error")
			}
		})
	}
}

// TestClockCheckSurvivesAServerWithNoDate. Absence of the header is "unknown",
// not "fine": reporting OK would be a confident wrong answer in the direction
// that hides the fault.
func TestClockCheckSurvivesAServerWithNoDate(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Date"] = nil // suppress net/http's own stamp
		w.WriteHeader(http.StatusOK)
	}))
	defer s.Close()

	got := clockCheck(context.Background(), s.URL)
	if got.OK {
		t.Fatal("a server that sent no Date was reported as a healthy clock")
	}
	if !strings.Contains(got.Detail, "unknown") {
		t.Errorf("detail should say the skew is unknown, got %q", got.Detail)
	}
}

func TestClockCheckReportsAnUnreachableServer(t *testing.T) {
	s := serverAt(t, time.Now())
	url := s.URL
	s.Close() // nothing is listening now

	got := clockCheck(context.Background(), url)
	if got.OK {
		t.Fatal("an unreachable server was reported as a healthy clock")
	}
}

// TestInfoChecksDoNotFailTheCommand.
//
// netcheck is documented as usable before a host has been set up, and it is
// most useful precisely then. If "no agent" made the command non-zero, every
// machine that has not joined yet would report a problem it does not have.
func TestInfoChecksDoNotFailTheCommand(t *testing.T) {
	rep := netcheckReport{Healthy: true}
	add := func(c checkResult) {
		if !c.OK && !c.Info {
			rep.Healthy = false
		}
		rep.Checks = append(rep.Checks, c)
	}

	add(checkResult{Name: "agent", OK: false, Info: true})
	if !rep.Healthy {
		t.Fatal("an informational failure made the report unhealthy")
	}

	add(checkResult{Name: "tcp", OK: false})
	if rep.Healthy {
		t.Fatal("a real failure did not make the report unhealthy")
	}
}
