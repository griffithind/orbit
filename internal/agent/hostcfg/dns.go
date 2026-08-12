package hostcfg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"go.yaml.in/yaml/v3"
)

// Every platform records the address it is serving on, and the device it hung
// its settings from, because Apply is shared; only the platforms with a resolver
// reader consult them. See isOwnResolver and isOwnDevice in dns_unix.go.
//
// The var declarations live HERE and the readers live there, which is the split
// ADR-0017 exists about: a helper in a file every platform compiles, called only
// from two of them, is an orphan the gates could not see until they ran per-GOOS.
var (
	ownResolvers sync.Map // string -> struct{}
	ownDevices   sync.Map // string -> struct{}
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

// ErrDNSUnsupported means this machine has no mechanism Orbit is willing to use to change
// its resolver.
//
// Distinct from an ordinary failure because the two deserve opposite handling. A
// permission error or a busy resolved is transient, so the reconcile loop should keep
// trying; a machine with no systemd-resolved will still have none next cycle, and
// retrying forever would log the same line every poll for the life of the host. Said once
// and then left alone.
var ErrDNSUnsupported = errors.New("this machine has no supported way to point itself at the mesh resolver")

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

	// upstreamAt is when the list was last read, and it is what makes roaming
	// work. The list used to be captured once per process and kept forever —
	// deliberately, as the defence against forwarding to ourselves — so a laptop
	// that captured 192.168.1.1 at home forwarded there in the café until the
	// agent restarted, which under Restart=always it does not.
	//
	// Re-reading is safe now because the guard tests what an upstream IS rather
	// than whose address it is: resolved's own per-link list, loopback refused,
	// our own addresses refused. See ADR-0013 and ADR-0030.
	upstreamAt time.Time

	servers []*dns.Server
	current string // the applied state's String(), to skip no-op reconciles

	// apply and remove point the machine at this resolver. Fields rather than
	// direct calls so a unit test cannot rewrite the DNS configuration of the
	// machine it happens to be running on.
	apply  func(dev, domain, addr string, global bool) error
	remove func(dev, domain string) error
}

// upstreamTTL is how long a captured resolver list is trusted.
//
// Long enough that this is not a per-query cost and short enough that moving
// networks is a coffee-length inconvenience rather than a reboot. The read is
// one exec of resolvectl or scutil.
const upstreamTTL = 5 * time.Minute

// forwardTimeout bounds one upstream exchange, and forwardStagger is how long
// the second upstream waits before joining in.
//
// The stagger keeps the common case — the first resolver answers — from
// multiplying every query on the machine by the number of resolvers it has,
// while a dead first upstream costs 150ms rather than the whole timeout.
const (
	forwardTimeout = 4 * time.Second
	forwardStagger = 150 * time.Millisecond
)

// NewResolver returns a resolver that is not yet listening.
func NewResolver(log logger) *Resolver {
	return &Resolver{log: log, apply: applyDNS, remove: removeDNS}
}

// refreshUpstreams re-reads the machine's resolvers when the list has aged out.
//
// Called from the reconcile path, not from the query path: a lookup must never
// block on an exec, and a list that is five minutes stale answers correctly for
// every host that has not moved — which is all of them, nearly all the time.
func (r *Resolver) refreshUpstreams() {
	r.mu.RLock()
	fresh := time.Since(r.upstreamAt) < upstreamTTL && len(r.upstream) > 0
	r.mu.RUnlock()
	if fresh {
		return
	}
	found := systemResolvers()
	if len(found) == 0 {
		// Keep what we had. An empty read is "could not tell" — a resolvectl
		// that failed, a scutil that returned nothing — and adopting it would
		// turn a transient hiccup into a host that forwards nowhere.
		return
	}
	r.mu.Lock()
	r.upstream, r.upstreamAt = found, time.Now()
	r.mu.Unlock()
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

		// AND THE OS IS RE-ASSERTED, which this branch used to skip.
		//
		// resolved keeps DNS settings per LINK, so everything Orbit sets hangs
		// off the tun device — and when nebula restarts, the device is destroyed
		// and recreated and every setting goes with it. The config string is
		// unchanged, so this branch returned, and the machine silently stopped
		// being pointed at its resolver until the config epoch happened to move.
		//
		// It contradicted the principle stated two files over: configcheck.go,
		// "repair and confirm are the same operation", and loop.go, host rules
		// "have to be re-asserted rather than assumed". Host state re-applies
		// wholesale every cycle; DNS had opted out.
		// See docs/adr/0030-the-forwarder-is-a-real-forwarder.md.
		if err := r.apply(d.TunDev, d.Domain, d.Listen.String(), d.Global); err != nil &&
			!errors.Is(err, ErrDNSUnsupported) {
			r.log.Warn("could not re-assert this machine's resolver settings", "error", err)
		}
		r.refreshUpstreams()
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
	if d.TunDev != "" {
		ownDevices.Store(d.TunDev, struct{}{})
	}

	r.mu.Lock()
	if len(r.upstream) == 0 {
		r.upstream = systemResolvers()
		r.upstreamAt = time.Now()
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
		if !errors.Is(err, ErrDNSUnsupported) {
			return fmt.Errorf("point this machine at the mesh resolver: %w", err)
		}
		// Nothing to retry. Recorded as applied so the next cycle is a string
		// compare rather than the same complaint again, and said once at a
		// level that will actually be read.
		r.current = d.String()
		r.log.Warn("serving mesh names, but this machine must be pointed at the resolver by hand",
			"resolver", d.Listen, "domain", d.Domain, "reason", err)
		return nil
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
	name := strings.ToLower(q.Name)

	r.mu.RLock()
	addrs, ok := r.state.Hosts[name]
	domain := r.state.Domain
	r.mu.RUnlock()

	if q.Qtype != dns.TypeA && q.Qtype != dns.TypeAAAA {
		// Not an address question. Still ours to answer if it names our own
		// suffix — see below — but there is nothing to answer WITH, so it is
		// NODATA rather than a forward.
		if ownsName(name, domain) {
			r.nodata(w, req)
			return
		}
		r.forward(w, req)
		return
	}

	if !ok {
		// AUTHORITY. A miss inside `<slug>.internal` is NXDOMAIN, not a forward.
		//
		// Forwarding it sent every typo, every search-list permutation
		// (`laptop.lab.internal.lab.internal.`) and every stale internal
		// hostname to the machine's upstream — the operator's ISP or corporate
		// resolver — which is the network's own topology and host inventory,
		// leaked one lookup at a time. There is also nothing out there to find:
		// nobody else is authoritative for our suffix.
		// See docs/adr/0029-the-resolver-is-authoritative-for-its-own-domain.md.
		if ownsName(name, domain) {
			r.nxdomain(w, req)
			return
		}
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
// forward asks the machine's real resolvers, concurrently, and escalates.
//
// The previous version was a sequential loop that accepted on `err == nil &&
// resp != nil` — regardless of rcode. Three properties fell out of that, and
// each is a way for a name to fail to resolve on a machine whose DNS Orbit has
// taken over:
//
//   - A SERVFAIL or REFUSED from the first upstream was relayed to the client
//     and the second was never consulted.
//   - Three dead upstreams cost twelve seconds of client wall time.
//   - It was UDP only, with no escape: dns.Client with Net unset defaults to
//     udp and miekg documents that Exchange "does not retry a failed query, nor
//     will it fall back to TCP in case of truncation". Orbit's own TCP listener
//     forwarded over UDP too, so a client that saw TC and escalated got the same
//     truncated answer with nowhere left to go.
//
// See docs/adr/0030-the-forwarder-is-a-real-forwarder.md.
func (r *Resolver) forward(w dns.ResponseWriter, req *dns.Msg) {
	r.mu.RLock()
	up := r.upstream
	r.mu.RUnlock()

	if len(up) == 0 {
		r.refuse(w, req)
		return
	}

	type answer struct {
		msg *dns.Msg
		err error
	}
	// Buffered for every upstream, so a late responder never blocks on a send
	// nobody is reading — this function returns as soon as it has an answer.
	results := make(chan answer, len(up))

	ctx, cancel := context.WithTimeout(context.Background(), forwardTimeout)
	defer cancel()

	for i, server := range up {
		go func(i int, server string) {
			// Staggered rather than simultaneous. The first upstream is almost
			// always the right one, and firing all of them at once would
			// multiply every query on the machine's real resolvers by the number
			// of them it has.
			if d := time.Duration(i) * forwardStagger; d > 0 {
				select {
				case <-time.After(d):
				case <-ctx.Done():
					return
				}
			}
			msg, err := exchange(ctx, req, server)
			select {
			case results <- answer{msg, err}:
			case <-ctx.Done():
			}
		}(i, server)
	}

	var soft *dns.Msg // best refusal seen, in case nothing better arrives
	for range up {
		select {
		case a := <-results:
			if a.err != nil || a.msg == nil {
				continue
			}
			// SERVFAIL and REFUSED are SOFT: an upstream that will not answer is
			// not the same as an answer, and a slower resolver may still know.
			// Kept as a fallback so a client still gets a real rcode if every
			// upstream refuses.
			if rc := a.msg.Rcode; rc == dns.RcodeServerFailure || rc == dns.RcodeRefused {
				if soft == nil {
					soft = a.msg
				}
				continue
			}
			_ = w.WriteMsg(a.msg)
			return
		case <-ctx.Done():
			goto done
		}
	}
done:
	if soft != nil {
		_ = w.WriteMsg(soft)
		return
	}
	r.refuse(w, req)
}

// refuse answers SERVFAIL rather than nothing.
//
// A client that gets no answer waits out its own timeout on every lookup, which
// reads as "the network is slow" rather than "DNS is broken".
func (r *Resolver) refuse(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetRcode(req, dns.RcodeServerFailure)
	_ = w.WriteMsg(m)
}

// exchange asks one upstream, over UDP, and retries over TCP if the answer came
// back truncated.
//
// The escalation is the point. Without it Orbit's TCP listener was decoration:
// a client that received TC and reconnected over TCP got the same truncated
// answer, because this side forwarded over UDP either way.
func exchange(ctx context.Context, req *dns.Msg, server string) (*dns.Msg, error) {
	udp := &dns.Client{Net: "udp", Timeout: forwardTimeout}
	msg, _, err := udp.ExchangeContext(ctx, req, server)
	if err != nil {
		return nil, err
	}
	if msg == nil || !msg.Truncated {
		return msg, nil
	}
	tcp := &dns.Client{Net: "tcp", Timeout: forwardTimeout}
	full, _, terr := tcp.ExchangeContext(ctx, req, server)
	if terr != nil || full == nil {
		return msg, nil // the truncated answer beats no answer
	}
	return full, nil
}

// ownsName reports whether a query falls inside the suffix this resolver is
// authoritative for.
//
// The bare `<name>.` keys are deliberately NOT covered: they sit in the DNS
// root, which Orbit does not own, so a miss there has to go upstream. Removing
// those keys is ADR-0029's other half and needs a working search domain on
// every platform first — macOS writes /etc/resolver/<domain>, which is
// per-domain resolution rather than a search suffix.
func ownsName(name, domain string) bool {
	if domain == "" {
		return false
	}
	suffix := strings.ToLower(strings.TrimSuffix(domain, ".")) + "."
	return strings.HasSuffix(name, "."+suffix) || name == suffix
}

// nxdomain says the name does not exist, authoritatively.
func (r *Resolver) nxdomain(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg).SetRcode(req, dns.RcodeNameError)
	m.Authoritative = true
	_ = w.WriteMsg(m)
}

// nodata says the name exists but has nothing of the type asked for.
func (r *Resolver) nodata(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg).SetReply(req)
	m.Authoritative = true
	_ = w.WriteMsg(m)
}
