package api

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestAgentIdentityIgnoresTheForwardingHeader.
//
// The agent surface authenticates by source address alone, and it listens on
// the overlay — nothing proxies it, so an X-Forwarded-For arriving there is a
// value the caller chose. It was resolved through clientAddr, which honours the
// header when TrustForwardedFor is set.
//
// That flag is for the PUBLIC listener behind a reverse proxy, which is an
// ordinary way to deploy this. cmd/orbitd builds the overlay listener's config
// by copying the public one (`nodeCfg := apiCfg`), so switching it on for the
// proxy switched it on for a socket with no proxy in front.
//
// What that bought an attacker was not a disclosure. POST /agent/v1/renew takes
// its identity from this address and issues a certificate for a public key the
// request supplies, so any enrolled host could mint a valid certificate for any
// other member by setting one header.
func TestAgentIdentityIgnoresTheForwardingHeader(t *testing.T) {
	s := &Server{cfg: Config{TrustForwardedFor: true}}

	r := httptest.NewRequest(http.MethodGet, "/agent/v1/state", nil)
	r.RemoteAddr = "100.64.0.7:51820"
	r.Header.Set("X-Forwarded-For", "100.64.0.99")

	if got := s.peerAddr(r).String(); got != "100.64.0.7" {
		t.Errorf("peerAddr = %s; the caller's header decided who it is", got)
	}

	// The same request through the surface where a proxy is real still honours
	// the header — this must not be fixed by disabling the feature.
	if got := s.clientAddr(r).String(); got != "100.64.0.99" {
		t.Errorf("clientAddr = %s, want the forwarded address", got)
	}

	// And with the flag off, the two agree.
	off := &Server{cfg: Config{TrustForwardedFor: false}}
	if got := off.clientAddr(r).String(); got != "100.64.0.7" {
		t.Errorf("clientAddr with the flag off = %s, want the peer", got)
	}
}

// TestOnlyIdentityFreeCallersReadTheForwardingHeader.
//
// The test above pins what peerAddr does; this one pins that the identity path
// is the caller of it. They are different failures: the first catches peerAddr
// being changed, the second catches agentIdentity being changed back, and the
// second is the one that actually happened.
//
// Static because agentIdentity needs a store and a resolvable membership to run,
// and a rule about which helper a function calls should not need a database to
// check. Same approach as cmd/orbit/tree_test.go.
func TestOnlyIdentityFreeCallersReadTheForwardingHeader(t *testing.T) {
	fset := token.NewFileSet()
	pkg, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}

	// clientAddr honours X-Forwarded-For. Anything resolving WHO the caller is
	// must not be in this list.
	allowed := map[string]string{
		"limitEnroll":  "rate limiting, where a proxy in front is real",
		"handleEnroll": "records the source of an enrolment",
		"handleJoin":   "records the source of a join",
		"handleClaim":  "records the source of a claim",

		// The two that read the header itself.
		"clientAddr":    "the public-listener wrapper; identity never calls it",
		"agentPeerAddr": "the test-only seam on AgentListener, off in cmd/orbitd",
	}

	found, checked := map[string]bool{}, 0
	for _, p := range pkg {
		for _, f := range p.Files {
			ast.Inspect(f, func(n ast.Node) bool {
				fn, ok := n.(*ast.FuncDecl)
				if !ok {
					return true
				}
				checked++
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "clientAddr" {
						found[fn.Name.Name] = true
					}
					if id, ok := n.(*ast.Ident); ok && id.Name == "forwardedFor" {
						found[fn.Name.Name] = true
					}
					return true
				})
				return true
			})
		}
	}
	if checked < 50 {
		t.Fatalf("walked only %d functions; the parse is not seeing the package", checked)
	}
	for name := range allowed {
		if !found[name] {
			t.Errorf("%s is allowed to read the header but does not call clientAddr; "+
				"an allowance nothing uses is how the next one gets waved through", name)
		}
	}
	for name := range found {
		if _, ok := allowed[name]; !ok {
			t.Errorf("%s reads X-Forwarded-For via clientAddr. If it resolves identity, "+
				"use peerAddr — the header is caller-chosen on the overlay listener.", name)
		}
	}
}

// TestProductionNeverTrustsTheHeaderForIdentity.
//
// AgentListener.TrustForwardedForIdentity exists so e2e can assert an overlay
// source address without booting two nebula nodes. Anything that sets it makes
// every member of that network impersonatable, so the binary must not.
//
// Checked against the source rather than the type, because the failure would be
// someone wiring the orbitd flag to it — which is exactly how the field this
// replaces came to govern the agent surface.
func TestProductionNeverTrustsTheHeaderForIdentity(t *testing.T) {
	for _, dir := range []string{"../../cmd/orbitd", "../../cmd/orbit", "../../internal/web"} {
		files, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		seen := false
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".go") {
				continue
			}
			seen = true
			b, err := os.ReadFile(dir + "/" + f.Name())
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "TrustForwardedForIdentity") {
				t.Errorf("%s/%s sets TrustForwardedForIdentity; that makes every host "+
					"on the network impersonatable by any other", dir, f.Name())
			}
		}
		if !seen {
			t.Fatalf("%s held no Go files; this test is looking in the wrong place", dir)
		}
	}
}
