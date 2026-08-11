package web

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func noticeServer(t *testing.T) *Server {
	t.Helper()
	s, err := New(nil, nil, nil, Config{CSRFKey: []byte("a-deployment-wide-key-32-bytes!!")},
		slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestABannerAnyoneCanWriteIsNotShown.
//
// The page-wide banner was populated from ?notice= on every render, and the
// login page's note from ?note=. Both are server-authored at every call site,
// and nothing enforced that — so a link to the real origin, with real TLS and
// the real sign-in form, could say whatever the sender chose. On /ui/login that
// is the page where a 256-bit admin token is typed and where the read-only
// default can be talked out of.
//
// Not XSS: the value reaches a text node through html/template and the CSP has
// no unsafe-inline. Content spoofing on the one page that matters is enough.
func TestABannerAnyoneCanWriteIsNotShown(t *testing.T) {
	s := noticeServer(t)

	forged := httptest.NewRequest(http.MethodGet, "/ui/memberships?notice="+
		"Session+ended+during+CA+rotation.+Sign+in+with+a+full-access+token.", nil)
	if got := s.verifiedNotice(forged); got != "" {
		t.Errorf("an unsigned banner was accepted: %q", got)
	}

	// A signature from a different deployment is no better than none.
	other := noticeServer(t)
	other.csrfKey = []byte("a-different-deployments-key-32b!")
	msg := "web-03 is blocked."
	wrong := httptest.NewRequest(http.MethodGet,
		"/ui/memberships?"+other.signNotice(msg).Encode(), nil)
	if got := s.verifiedNotice(wrong); got != "" {
		t.Errorf("a banner signed with another key was accepted: %q", got)
	}
}

// TestTheServersOwnBannersStillShow. The fix must not silence the real ones,
// which carry runtime data — which host, which epoch — and so cannot be an
// allowlist of fixed strings.
func TestTheServersOwnBannersStillShow(t *testing.T) {
	s := noticeServer(t)

	for _, msg := range []string{
		"web-03 is blocked. Blocklist epoch 42 — watch convergence to see it reach the fleet.",
		"You are signed out.",
	} {
		r := httptest.NewRequest(http.MethodGet, "/ui/x?"+s.signNotice(msg).Encode(), nil)
		if got := s.verifiedNotice(r); got != msg {
			t.Errorf("a banner this server wrote was dropped: %q", got)
		}
	}

	// And a replica sharing the deployment key agrees, which is what makes this
	// usable behind a load balancer at all.
	peer := noticeServer(t)
	msg := "Unblocked. Blocklist epoch 7."
	r := httptest.NewRequest(http.MethodGet, "/ui/x?"+s.signNotice(msg).Encode(), nil)
	if got := peer.verifiedNotice(r); got != msg {
		t.Errorf("another replica rejected a banner from this one: %q", got)
	}
}
