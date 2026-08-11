package web

import (
	"bytes"
	"log/slog"
	"testing"
)

// TestReplicasSharingAKeyProduceTheSameFormToken.
//
// The form token is an HMAC under csrfKey over the session cookie. When that key
// was generated per process, a form rendered by one replica was refused by
// another on submit — every time, not merely after a restart, which is the only
// case the original tradeoff comment considered. docs/design.md told operators
// to run N replicas behind a load balancer, and the console was the one surface
// that could not.
func TestReplicasSharingAKeyProduceTheSameFormToken(t *testing.T) {
	shared := bytes.Repeat([]byte{7}, 32)
	log := slog.New(slog.DiscardHandler)

	a, err := New(nil, nil, nil, Config{CSRFKey: shared}, log)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(nil, nil, nil, Config{CSRFKey: shared}, log)
	if err != nil {
		t.Fatal(err)
	}

	const cookie = "a-session-cookie-value"
	if a.csrfToken(cookie) != b.csrfToken(cookie) {
		t.Error("two replicas given the same key disagree on the form token; " +
			"a form rendered by one would be refused by the other")
	}

	// And the key still matters: without it they must not agree, or the token
	// is computable by anyone who learns the cookie.
	c, err := New(nil, nil, nil, Config{}, log)
	if err != nil {
		t.Fatal(err)
	}
	d, err := New(nil, nil, nil, Config{}, log)
	if err != nil {
		t.Fatal(err)
	}
	if c.csrfToken(cookie) == d.csrfToken(cookie) {
		t.Error("two processes with no configured key produced the same token, " +
			"so the token does not depend on the key at all")
	}
}
