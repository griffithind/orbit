package agent

import (
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

const dnsCfg = `
tun:
  dev: orbit0
orbit:
  dns:
    domain: lab.internal
    listen: 10.42.0.5:53
    hosts:
      - name: laptop
        addrs: [10.42.0.5]
      - name: lab-pi
        addrs: [10.42.0.9, fd42::9]
`

func TestDNSStateFromConfig(t *testing.T) {
	d, err := DNSStateFromConfig(dnsCfg)
	if err != nil {
		t.Fatal(err)
	}
	if d.Empty() {
		t.Fatal("a config with names should not be empty")
	}
	if got, want := d.Listen, netip.MustParseAddrPort("10.42.0.5:53"); got != want {
		t.Errorf("listen = %v, want %v", got, want)
	}
	// Both spellings, so a bare name works whatever the OS search list says.
	for _, name := range []string{"laptop.", "laptop.lab.internal.", "lab-pi.", "lab-pi.lab.internal."} {
		if _, ok := d.Hosts[name]; !ok {
			t.Errorf("no answer for %q", name)
		}
	}
	if n := len(d.Hosts["lab-pi."]); n != 2 {
		t.Errorf("dual-stack host has %d addresses, want 2", n)
	}
}

// TestDNSStateEmptyWithoutASection is the withdrawal path: a network that stops serving
// names must make the agent tear the resolver down, not skip and leave it answering.
func TestDNSStateEmptyWithoutASection(t *testing.T) {
	d, err := DNSStateFromConfig("tun:\n  dev: orbit0\n")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Empty() {
		t.Error("a config with no name table should be empty")
	}
}

// TestResolverAnswersAndForwards runs the real thing: a resolver on loopback with a
// stub upstream, checking that a mesh name is answered locally and anything else is
// passed on rather than refused.
func TestResolverAnswersAndForwards(t *testing.T) {
	upstream, upAddr := stubUpstream(t)
	defer upstream.Shutdown()

	r := NewResolver(quietLogger{})
	// Serve, but do not touch this machine's own resolver configuration.
	r.apply = func(_, _, _ string, _ bool) error { return nil }
	r.remove = func(_, _ string) error { return nil }
	r.upstream = []string{upAddr}
	d, err := DNSStateFromConfig(dnsCfg)
	if err != nil {
		t.Fatal(err)
	}
	d.Listen = netip.MustParseAddrPort("127.0.0.1:0")
	// Port 0 cannot be asked back for, so bind an explicit free one.
	d.Listen = netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), freePort(t))
	if err := r.Apply(d); err != nil {
		t.Fatal(err)
	}
	defer r.Stop()

	ask := func(name string, qtype uint16) *dns.Msg {
		t.Helper()
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		resp, _, err := (&dns.Client{}).Exchange(m, d.Listen.String())
		if err != nil {
			t.Fatalf("query %s: %v", name, err)
		}
		return resp
	}

	got := ask("lab-pi.lab.internal.", dns.TypeA)
	if len(got.Answer) != 1 {
		t.Fatalf("mesh name got %d answers, want 1: %v", len(got.Answer), got.Answer)
	}
	if a, ok := got.Answer[0].(*dns.A); !ok || a.A.String() != "10.42.0.9" {
		t.Errorf("mesh name answered %v, want 10.42.0.9", got.Answer[0])
	}

	// A known name with no address of the asked family is NOERROR and no
	// answers, never NXDOMAIN: saying it does not exist would hide a v4-only
	// host from anything that asks AAAA first, which is most things.
	if got := ask("laptop.lab.internal.", dns.TypeAAAA); got.Rcode != dns.RcodeSuccess || len(got.Answer) != 0 {
		t.Errorf("v4-only host over AAAA: rcode=%v answers=%d, want NOERROR/0", got.Rcode, len(got.Answer))
	}

	if got := ask("example.com.", dns.TypeA); len(got.Answer) != 1 {
		t.Errorf("public name was not forwarded: rcode=%v answers=%d", got.Rcode, len(got.Answer))
	}
}

func stubUpstream(t *testing.T) (*dns.Server, string) {
	t.Helper()
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), freePort(t)).String()
	s := &dns.Server{Addr: addr, Net: "udp"}
	s.Handler = dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		rr, _ := dns.NewRR(req.Question[0].Name + " 60 IN A 93.184.216.34")
		m.Answer = append(m.Answer, rr)
		_ = w.WriteMsg(m)
	})
	started := make(chan struct{})
	s.NotifyStartedFunc = func() { close(started) }
	go s.ListenAndServe()
	<-started
	return s, addr
}

type quietLogger struct{}

func (quietLogger) Info(string, ...any) {}
func (quietLogger) Warn(string, ...any) {}

// freePort reserves a UDP port and hands back the number.
//
// Bound and closed rather than picked at random: two tests racing for the same number is
// a failure that reproduces once a fortnight and never on the machine looking at it.
func freePort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}
