package agent

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.yaml.in/yaml/v3"
)

// The agent's resolver: mesh names answered locally, everything else forwarded.
//
// The name table arrives in the signed configuration, so answering needs no lookup, no
// lighthouse and no round trip — see nebulacfg's dnsSection for why that channel was
// preferred to the DNS server nebula can already run. What is left for the agent is to
// serve the table and to forward what is not in it.
//
// FORWARDING IS THE PART THAT NEEDS CARE. Once the OS points at this resolver, asking the
// OS to resolve anything comes back here, and a resolver that forwards to itself is a
// loop that ends in a stack overflow or a timeout, depending on the platform. So the
// upstream servers are captured BEFORE the OS is changed and dialled explicitly, never
// through net.Resolver's default path.

// DNSState is the resolver's desired state, read from the verified configuration.
type DNSState struct {
	// Domain is the search suffix: <slug>.internal. A host answers both its bare
	// name and its qualified one, because "ssh laptop" is the point and
	// "laptop.lab.internal" is what it means.
	Domain string

	// Listen is this host's own overlay address, port 53.
	Listen netip.AddrPort

	// TunDev is the link systemd-resolved hangs this machine's DNS settings
	// off, so `resolvectl revert <dev>` can take all of them away by name.
	TunDev string

	// Global is true when every lookup must come here, not just the mesh
	// domain. It follows the exit node, because that is the case where leaving
	// the machine's resolver pointed at the local network tells that network
	// every name this machine looks up.
	Global bool

	// Hosts maps a lowercased fully-qualified name to every address it has.
	//
	// EVERY address: a dual-stack machine has two and an answer carrying one of
	// them works until the day the other is the reachable one.
	Hosts map[string][]netip.Addr
}

// Empty reports whether there is nothing to serve, and so nothing to run.
func (d DNSState) Empty() bool { return len(d.Hosts) == 0 || !d.Listen.IsValid() }

// String is a stable description, used to decide whether anything changed. Sorted by
// construction because the configuration it came from is ordered, and the configuration
// is ordered because it is signed.
func (d DNSState) String() string {
	if d.Empty() {
		return "dns=off"
	}
	return fmt.Sprintf("dns=%s domain=%s dev=%s global=%v names=%d",
		d.Listen, d.Domain, d.TunDev, d.Global, len(d.Hosts))
}

// DNSStateFromConfig reads the name table out of a VERIFIED configuration.
//
// From the verified bytes, never from the file on disk, for the same reason host state is:
// a name table decides where this machine's traffic goes, so it must carry the same proof
// as the certificate paths beside it. A resolver an attacker can edit is a machine that
// can be pointed anywhere.
func DNSStateFromConfig(yamlCfg string) (DNSState, error) {
	var doc struct {
		Tun struct {
			Dev string `yaml:"dev"`
		} `yaml:"tun"`
		Orbit *struct {
			ExitNode bool `yaml:"exit_node"`
			DNS      *struct {
				Domain string `yaml:"domain"`
				Listen string `yaml:"listen"`
				Hosts  []struct {
					Name  string   `yaml:"name"`
					Addrs []string `yaml:"addrs"`
				} `yaml:"hosts"`
			} `yaml:"dns"`
		} `yaml:"orbit"`
	}
	if err := yaml.Unmarshal([]byte(yamlCfg), &doc); err != nil {
		return DNSState{}, fmt.Errorf("read the name table from the configuration: %w", err)
	}
	if doc.Orbit == nil || doc.Orbit.DNS == nil {
		// No names in this network. The zero value is Empty(), which makes the
		// agent tear its resolver down rather than skip — a machine whose
		// network stopped serving names must stop answering for them.
		return DNSState{}, nil
	}

	src := doc.Orbit.DNS
	listen, err := netip.ParseAddrPort(src.Listen)
	if err != nil {
		return DNSState{}, fmt.Errorf("dns listen address %q: %w", src.Listen, err)
	}

	d := DNSState{
		Domain: strings.ToLower(strings.Trim(src.Domain, ".")),
		Listen: listen,
		TunDev: doc.Tun.Dev,
		Global: doc.Orbit.ExitNode,
		Hosts:  make(map[string][]netip.Addr, len(src.Hosts)*2),
	}
	for _, h := range src.Hosts {
		if h.Name == "" {
			continue
		}
		var addrs []netip.Addr
		for _, raw := range h.Addrs {
			a, err := netip.ParseAddr(raw)
			if err != nil {
				return DNSState{}, fmt.Errorf("address %q for %q: %w", raw, h.Name, err)
			}
			addrs = append(addrs, a)
		}
		if len(addrs) == 0 {
			continue
		}
		name := strings.ToLower(h.Name)
		// Both spellings, so a bare name works without depending on the search
		// list the OS was configured with. Search lists are the part of DNS
		// configuration most likely to be overwritten by something else on the
		// machine, and a name that resolves only through one is a name that
		// stops working for reasons nobody can see.
		d.Hosts[name+"."] = addrs
		if d.Domain != "" {
			d.Hosts[name+"."+d.Domain+"."] = addrs
		}
	}
	return d, nil
}

// Resolver serves DNSState and forwards what it cannot answer.
type Resolver struct {
	log logger

	mu       sync.RWMutex
	state    DNSState
	upstream []string

	servers []*dns.Server
	current string // the applied state's String(), to skip no-op reconciles

	// apply and remove point the machine at this resolver. Fields rather than
	// direct calls so a unit test cannot rewrite the DNS configuration of the
	// machine it happens to be running on.
	apply  func(dev, domain, addr string, global bool) error
	remove func(dev, domain string) error
}

// NewResolver returns a resolver that is not yet listening.
func NewResolver(log logger) *Resolver {
	return &Resolver{log: log, apply: applyDNS, remove: removeDNS}
}

// Apply makes the state true, restarting the listener if the address changed.
//
// Safe to call every cycle with the same state: the common case compares two strings and
// returns. That matters because this runs in the reconcile loop, and a resolver that
// rebound its socket every poll would drop every query in flight, forever.
func (r *Resolver) Apply(d DNSState) error {
	if d.String() == r.current && r.current != "" {
		// Same listener, same names — but the table is swapped anyway in case
		// an address changed under an unchanged name count.
		r.mu.Lock()
		r.state = d
		r.mu.Unlock()
		return nil
	}
	if d.Empty() {
		// The OS first: a machine pointed at a resolver that is about to stop
		// answering resolves nothing, and the window is however long teardown
		// takes.
		if err := r.remove(r.state.TunDev, r.state.Domain); err != nil {
			r.log.Warn("could not restore this machine's resolver", "error", err)
		}
		r.Stop()
		r.current = ""
		return nil
	}

	// Captured BEFORE the OS is pointed here, and kept across restarts: once
	// this resolver is the system resolver, asking the system where to forward
	// returns this resolver.
	// Registered before the upstreams are read, so a re-read that happens after
	// the OS was pointed here cannot pick this address up as an upstream.
	ownResolvers.Store(d.Listen.Addr().String(), struct{}{})

	r.mu.Lock()
	if len(r.upstream) == 0 {
		r.upstream = systemResolvers()
	}
	r.state = d
	up := len(r.upstream)
	r.mu.Unlock()

	r.Stop()
	if err := r.listen(d.Listen); err != nil {
		return err
	}
	// Only once it is answering. Pointing the OS at a socket that is not
	// listening yet is a machine that cannot resolve its own control plane.
	//
	// A failure here does NOT take the listener down. The resolver still answers
	// anything that asks it, which is worth having, and the reconcile loop
	// retries every cycle — whereas tearing down on a transient permission
	// error would turn one bad moment into a machine that resolves nothing.
	// current stays empty so the next cycle tries again rather than deciding
	// nothing changed.
	if err := r.apply(d.TunDev, d.Domain, d.Listen.String(), d.Global); err != nil {
		return fmt.Errorf("point this machine at the mesh resolver: %w", err)
	}

	r.current = d.String()
	r.log.Info("resolver serving the mesh name table",
		"listen", d.Listen, "domain", d.Domain, "names", len(d.Hosts), "upstream", up)
	return nil
}

func (r *Resolver) listen(at netip.AddrPort) error {
	// UDP and TCP both: a response larger than the client's buffer sets the
	// truncated bit and a well-behaved resolver retries over TCP. Serving only
	// UDP works until an answer grows, which is exactly when somebody has added
	// enough machines to stop noticing.
	for _, net_ := range []string{"udp", "tcp"} {
		s := &dns.Server{
			Addr:    at.String(),
			Net:     net_,
			Handler: r,
		}
		started := make(chan error, 1)
		s.NotifyStartedFunc = func() { started <- nil }
		go func() {
			if err := s.ListenAndServe(); err != nil {
				select {
				case started <- err:
				default:
				}
			}
		}()
		select {
		case err := <-started:
			if err != nil {
				r.Stop()
				return fmt.Errorf("serve dns on %s/%s: %w", at, net_, err)
			}
		case <-time.After(5 * time.Second):
			r.Stop()
			return fmt.Errorf("serve dns on %s/%s: timed out binding", at, net_)
		}
		r.servers = append(r.servers, s)
	}
	return nil
}

// Stop takes the listeners down. Idempotent, and it deliberately keeps the captured
// upstream: a restart must not re-read the system resolvers, because by then they are us.
func (r *Resolver) Stop() {
	for _, s := range r.servers {
		_ = s.Shutdown()
	}
	r.servers = nil
}

// ServeDNS answers from the table, or forwards.
func (r *Resolver) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) != 1 {
		// Multi-question queries are not a thing any resolver in use actually
		// sends, and guessing at one would mean answering half a question.
		r.forward(w, req)
		return
	}
	q := req.Question[0]
	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		r.forward(w, req)
		return
	}

	r.mu.RLock()
	addrs, ok := r.state.Hosts[strings.ToLower(q.Name)]
	r.mu.RUnlock()
	if !ok {
		r.forward(w, req)
		return
	}

	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true
	for _, a := range addrs {
		if a.Is4() != (q.Qtype == dns.TypeA) {
			continue
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN %s %s",
			q.Name, dns.TypeToString[q.Qtype], a))
		if err != nil {
			continue
		}
		m.Answer = append(m.Answer, rr)
	}
	// A known name with no address of the asked family is NOERROR with no
	// answers, not NXDOMAIN. Saying the name does not exist would make a
	// v4-only host invisible to anything that asked for AAAA first, and most
	// resolvers ask for both.
	_ = w.WriteMsg(m)
}

// forward passes a query to the resolvers this machine had before we changed them.
func (r *Resolver) forward(w dns.ResponseWriter, req *dns.Msg) {
	r.mu.RLock()
	up := r.upstream
	r.mu.RUnlock()

	c := &dns.Client{Timeout: 4 * time.Second}
	for _, server := range up {
		resp, _, err := c.Exchange(req, server)
		if err == nil && resp != nil {
			_ = w.WriteMsg(resp)
			return
		}
	}

	// Every upstream failed, or there were none. SERVFAIL rather than silence:
	// a client that gets no answer waits out its own timeout on every lookup,
	// which reads as "the network is slow" rather than "DNS is broken".
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	_ = w.WriteMsg(m)
}

// isOwnResolver reports whether an address is a resolver Orbit is running.
//
// The guard against the only way this design can fail catastrophically. Once the OS is
// pointed at this resolver, the system's list of resolvers contains this resolver, and a
// restart that re-read it would forward every query to itself.
//
// Package-level rather than a method because the platform readers call it while the
// resolver's lock is held by Apply.
var ownResolvers sync.Map // string -> struct{}

func isOwnResolver(host string) bool {
	_, ok := ownResolvers.Load(strings.TrimSpace(host))
	return ok
}

// hostPort53 normalises a bare address into something dns.Client can dial.
func hostPort53(s string) string {
	if _, _, err := net.SplitHostPort(s); err == nil {
		return s
	}
	return net.JoinHostPort(s, "53")
}
