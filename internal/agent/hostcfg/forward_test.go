package hostcfg

import (
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// A fake upstream, so these assertions are about the forwarder rather than
// about whatever the machine running the tests resolves with.
func upstream(t *testing.T, h dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: h}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

func answerA(w dns.ResponseWriter, req *dns.Msg, ip string) {
	m := new(dns.Msg).SetReply(req)
	rr, _ := dns.NewRR(req.Question[0].Name + " 60 IN A " + ip)
	m.Answer = append(m.Answer, rr)
	_ = w.WriteMsg(m)
}

func query(t *testing.T, r *Resolver) *dns.Msg {
	t.Helper()
	req := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	rec := &capture{}
	r.forward(rec, req)
	if rec.msg == nil {
		t.Fatal("the forwarder wrote nothing; a client would wait out its own timeout")
	}
	return rec.msg
}

type capture struct {
	dns.ResponseWriter
	msg *dns.Msg
}

func (c *capture) WriteMsg(m *dns.Msg) error { c.msg = m; return nil }
func (c *capture) RemoteAddr() net.Addr      { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// TestASoftRefusalDoesNotEndTheQuery.
//
// The forwarder used to accept on `err == nil && resp != nil` regardless of
// rcode, so a SERVFAIL from the first upstream was relayed to the client and
// the second was never consulted. An upstream that will not answer is not the
// same as an answer.
func TestASoftRefusalDoesNotEndTheQuery(t *testing.T) {
	refuses := upstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})
	answers := upstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		answerA(w, req, "203.0.113.7")
	})

	r := &Resolver{log: discardLog{}, upstream: []string{refuses, answers}}
	got := query(t, r)

	if got.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode = %s, want NOERROR: a SERVFAIL from the first upstream "+
			"ended the query and the second was never asked", dns.RcodeToString[got.Rcode])
	}
	if len(got.Answer) != 1 {
		t.Errorf("answer count = %d, want 1", len(got.Answer))
	}
}

// TestEveryUpstreamRefusingStillAnswers. Soft errors are a reason to keep
// asking, not a reason to say nothing: a client with no reply at all waits out
// its own timeout on every lookup, which reads as a slow network.
func TestEveryUpstreamRefusingStillAnswers(t *testing.T) {
	refuse := func(w dns.ResponseWriter, req *dns.Msg) {
		_ = w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeRefused))
	}
	r := &Resolver{log: discardLog{}, upstream: []string{
		upstream(t, refuse), upstream(t, refuse),
	}}
	if got := query(t, r).Rcode; got == dns.RcodeSuccess {
		t.Errorf("rcode = NOERROR from two refusing upstreams")
	}
}

// TestADeadUpstreamDoesNotCostTheWholeTimeout. Three dead resolvers used to
// cost twelve seconds of client wall time, because they were tried one at a
// time with a four-second timeout each.
func TestADeadUpstreamDoesNotCostTheWholeTimeout(t *testing.T) {
	// A closed port: the OS answers ICMP port-unreachable at once.
	dead1, dead2 := deadAddr(t), deadAddr(t)
	live := upstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		answerA(w, req, "203.0.113.7")
	})

	r := &Resolver{log: discardLog{}, upstream: []string{dead1, dead2, live}}
	start := time.Now()
	got := query(t, r)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %s to get past two dead upstreams; they are being tried "+
			"one at a time", elapsed.Round(time.Millisecond))
	}
	if got.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %s, want NOERROR", dns.RcodeToString[got.Rcode])
	}
}

// TestNoUpstreamsAnswersRatherThanHanging. A host whose resolver list could not
// be read must still return something.
func TestNoUpstreamsAnswersRatherThanHanging(t *testing.T) {
	r := &Resolver{log: discardLog{}}
	if got := query(t, r).Rcode; got != dns.RcodeServerFailure {
		t.Errorf("rcode = %s, want SERVFAIL", dns.RcodeToString[got])
	}
}

func deadAddr(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	_ = pc.Close()
	return addr
}

type discardLog struct{}

func (discardLog) Info(string, ...any)  {}
func (discardLog) Warn(string, ...any)  {}
func (discardLog) Error(string, ...any) {}
func (discardLog) Debug(string, ...any) {}

// TestAMissInsideTheMeshDomainIsNXDOMAIN.
//
// A miss under `<slug>.internal` used to be forwarded to whatever the machine
// resolves with — the operator's ISP or corporate resolver — which leaks the
// network's own topology and host inventory one typo at a time. There is also
// nothing out there to find: nobody else is authoritative for our suffix.
func TestAMissInsideTheMeshDomainIsNXDOMAIN(t *testing.T) {
	// atomic, because the handler runs on the dns server's goroutine and the
	// assertion reads from the test's. A plain bool here is a data race that
	// happens to pass — which the race detector caught on the sibling test
	// below, where the write actually occurs.
	var leaked atomic.Bool
	up := upstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		leaked.Store(true)
		answerA(w, req, "203.0.113.7")
	})

	r := &Resolver{log: discardLog{}, upstream: []string{up}}
	r.state = DNSState{Domain: "lab.internal", Hosts: map[string][]netip.Addr{
		"db.lab.internal.": {netip.MustParseAddr("10.42.0.9")},
	}}

	rec := &capture{}
	r.ServeDNS(rec, new(dns.Msg).SetQuestion("typo.lab.internal.", dns.TypeA))

	if leaked.Load() {
		t.Error("an internal hostname was sent to the machine's upstream resolver")
	}
	if rec.msg == nil || rec.msg.Rcode != dns.RcodeNameError {
		t.Errorf("rcode = %v, want NXDOMAIN", rec.msg)
	}
	if rec.msg != nil && !rec.msg.Authoritative {
		t.Error("the answer was not marked authoritative, so a caching resolver will re-ask")
	}
}

// TestANameOutsideTheMeshDomainStillForwards. Authority is for our suffix and
// nothing else — this resolver is the only one many hosts have.
func TestANameOutsideTheMeshDomainStillForwards(t *testing.T) {
	var forwarded atomic.Bool
	up := upstream(t, func(w dns.ResponseWriter, req *dns.Msg) {
		forwarded.Store(true)
		answerA(w, req, "203.0.113.7")
	})
	r := &Resolver{log: discardLog{}, upstream: []string{up}}
	r.state = DNSState{Domain: "lab.internal"}

	rec := &capture{}
	r.ServeDNS(rec, new(dns.Msg).SetQuestion("example.com.", dns.TypeA))

	if !forwarded.Load() {
		t.Error("a public name was not forwarded; this resolver is the only one many hosts have")
	}
	if rec.msg == nil || rec.msg.Rcode != dns.RcodeSuccess {
		t.Errorf("rcode = %v, want NOERROR", rec.msg)
	}
}

// TestAKnownNameWithNoAddressOfThatFamilyIsNODATA guards behaviour that is
// already right: NXDOMAIN there would make a v4-only host invisible to anything
// that asked for AAAA first, and most resolvers ask for both.
func TestAKnownNameWithNoAddressOfThatFamilyIsNODATA(t *testing.T) {
	r := &Resolver{log: discardLog{}}
	r.state = DNSState{Domain: "lab.internal", Hosts: map[string][]netip.Addr{
		"db.lab.internal.": {netip.MustParseAddr("10.42.0.9")},
	}}

	rec := &capture{}
	r.ServeDNS(rec, new(dns.Msg).SetQuestion("db.lab.internal.", dns.TypeAAAA))

	if rec.msg == nil || rec.msg.Rcode != dns.RcodeSuccess || len(rec.msg.Answer) != 0 {
		t.Errorf("want NOERROR with no answers, got %v", rec.msg)
	}
}
