// Package mesh makes the control plane a member of the overlay it manages.
//
// This is what lets the agent API derive identity from a request's source
// address instead of from a bearer token. Nebula's firewall verifies on every
// packet that a peer's certificate actually contains its source address
// (firewall.go Drop), so an overlay-bound listener gets mTLS-grade
// authentication with no credential on any host to steal.
//
// Nebula runs here on a userspace device (overlay.NewUserDeviceFromConfig), the
// same mechanism the upstream service package exists for. That means the
// control plane needs no tun device, no root, and no changes to host
// networking; it gets a private network stack and serves HTTP on it.
//
// One node per network, not one per deployment. Two networks may legitimately
// use the same prefix, so a source address is only unambiguous within a network;
// the listener a request arrived on is what identifies which.
package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/overlay"
	"github.com/slackhq/nebula/service"
	"go.yaml.in/yaml/v3"

	"github.com/griffithind/orbit/internal/enroll"
)

// Config describes one network the control plane should join.
type Config struct {
	NetworkID uuid.UUID

	// Addr is this instance's overlay address on the network. Each replica
	// needs its own; the host_address uniqueness constraint enforces that
	// rather than letting two silently collide.
	Addr netip.Addr

	// Name is the host record's name. Defaults to "orbit-control-<addr>".
	Name string

	// ListenPort is the UDP port nebula binds for this node. Zero lets the
	// kernel choose, which is usually right: the control plane dials out to
	// lighthouses and does not need a predictable port.
	ListenPort int

	// AgentPort is the TCP port the agent API listens on over the overlay. It
	// is the only inbound OVERLAY port the control plane accepts.
	AgentPort int

	// LighthouseAddrs are this node's public "host:port" entries. Supplying
	// them makes the control plane a lighthouse for its network.
	//
	// Opt-in by supplying the address rather than a separate boolean, because a
	// lighthouse nobody can reach is worse than none: every host would keep
	// trying it. If you cannot say where to reach it, it is not a lighthouse.
	//
	// Sensible on a single-VM deployment, where the control plane already needs
	// a public address for enrollment and a lighthouse needs one too. It does
	// couple the two: restarting orbitd briefly interrupts discovery and hole
	// punching for hosts without an established tunnel. Existing tunnels are
	// unaffected.
	LighthouseAddrs []string

	// Relay makes the control plane relay traffic for hosts that cannot punch.
	//
	// Off by default, and a real trade-off rather than an oversight. A relay is
	// in the data path: it spends bandwidth and CPU forwarding other hosts'
	// traffic, on the machine holding the mesh's root CA key, and restarting it
	// drops live traffic rather than just delaying a handshake. Prefer a
	// separate relay host.
	Relay bool

	// Heartbeat is how often this replica refreshes its registration. Agents
	// only see replicas that have heartbeated recently, so this bounds how long
	// a dead replica keeps being handed out.
	Heartbeat time.Duration
}

// Node is the control plane's membership of one network.
type Node struct {
	cfg    Config
	ctrl   *nebula.Control
	svc    *service.Service
	log    *slog.Logger
	hostID uuid.UUID
	// seeded records whether this start created the host record, and therefore
	// whether the seed flags took effect.
	seeded bool

	// c is retained so the node can reload itself. The control plane is a mesh
	// member and needs the same updates every other host gets; rendering its
	// config once at startup leaves it rejecting hosts that renewed onto a
	// rotated CA and trusting ones that have been blocked.
	c  *config.C
	es *enroll.Service

	// mu guards the certificate material across a refresh, which reads it, and
	// a renewal, which replaces it.
	mu      sync.Mutex
	certPEM string
	keyPEM  string

	NotAfter time.Time
}

// DefaultHeartbeat is deliberately much shorter than the staleness window the
// maintenance sweep prunes on, so a brief pause (GC, a slow database) never
// makes a healthy replica disappear from the list agents are given.
const DefaultHeartbeat = 30 * time.Second

// Join issues the control plane a certificate and brings up its nebula stack.
func Join(ctx context.Context, es *enroll.Service, cfg Config, log *slog.Logger) (*Node, error) {
	if !cfg.Addr.IsValid() {
		return nil, fmt.Errorf("mesh: no overlay address for network %s", cfg.NetworkID)
	}
	if cfg.Name == "" {
		cfg.Name = "orbit-control-" + cfg.Addr.String()
	}

	issued, err := es.SelfIssue(ctx, cfg.NetworkID, cfg.Addr, cfg.Name, enroll.SelfIssueRoles{
		IsLighthouse: len(cfg.LighthouseAddrs) > 0,
		IsRelay:      cfg.Relay,
		StaticAddrs:  cfg.LighthouseAddrs,
	})
	if err != nil {
		return nil, fmt.Errorf("mesh: self-issue for network %s: %w", cfg.NetworkID, err)
	}

	// Inline the certificate material rather than writing files. Nebula accepts
	// either a path or PEM for pki.ca, pki.cert, and pki.key, so the control
	// plane's private key can live only in memory: a restart rotates it, and a
	// stolen disk yields nothing.
	cfgYAML, err := inlineInto(issued.Config, issued.CABundle, issued.Certificate, issued.PrivateKey, cfg)
	if err != nil {
		return nil, fmt.Errorf("mesh: build config: %w", err)
	}

	c := config.NewC(log.With("component", "nebula"))
	if err := c.LoadString(cfgYAML); err != nil {
		return nil, fmt.Errorf("mesh: load config: %w", err)
	}

	ctrl, err := nebula.Main(c, false, "orbit-control-plane", log.With("component", "nebula"), overlay.NewUserDeviceFromConfig)
	if err != nil {
		return nil, fmt.Errorf("mesh: start nebula on network %s: %w", cfg.NetworkID, err)
	}

	svc, err := service.New(ctrl)
	if err != nil {
		return nil, fmt.Errorf("mesh: start userspace stack: %w", err)
	}

	log.Info("control plane joined the overlay",
		"network", cfg.NetworkID, "addr", cfg.Addr,
		"host", issued.HostID, "certNotAfter", issued.NotAfter)

	return &Node{
		cfg: cfg, ctrl: ctrl, svc: svc, log: log, c: c, es: es,
		hostID:   issued.HostID,
		seeded:   issued.Created,
		certPEM:  issued.Certificate,
		keyPEM:   issued.PrivateKey,
		NotAfter: issued.NotAfter,
	}, nil
}

// Refresh re-renders this node's configuration and reloads nebula.
//
// Keeps the current certificate: reloading with the same certificate is a
// no-op as far as nebula's PKI is concerned (pki.go reloadCerts compares
// networks and curve), while the trust bundle, blocklist, and static host map
// are all replaced.
func (n *Node) Refresh(ctx context.Context) error {
	cfgYAML, caBundle, err := n.es.ControlPlaneMaterial(ctx, n.hostID)
	if err != nil {
		return fmt.Errorf("render control plane config: %w", err)
	}

	n.mu.Lock()
	yaml, err := inlineInto(cfgYAML, caBundle, n.certPEM, n.keyPEM, n.cfg)
	n.mu.Unlock()
	if err != nil {
		return err
	}

	if err := n.c.ReloadConfigString(yaml); err != nil {
		return fmt.Errorf("reload control plane config: %w", err)
	}
	return nil
}

// renewIfDue replaces the control plane's own certificate before it expires.
//
// Without this the control plane silently drops off the overlay one certificate
// lifetime after it started, taking the agent API with it — the same failure
// the agent's renewal loop exists to prevent on every other host, and easy to
// forget because this host is not managed by an agent.
func (n *Node) renewIfDue(ctx context.Context) error {
	notBefore, notAfter, err := n.es.ControlPlaneCertificate(ctx, n.hostID)
	if err != nil {
		return err
	}
	// Halfway through, the same rule agents use: it leaves the remaining half
	// of the lifetime to recover from a failure.
	if time.Now().Before(notBefore.Add(notAfter.Sub(notBefore) / 2)) {
		return nil
	}

	issued, err := n.es.SelfIssue(ctx, n.cfg.NetworkID, n.cfg.Addr, n.cfg.Name, enroll.SelfIssueRoles{
		IsLighthouse: len(n.cfg.LighthouseAddrs) > 0,
		IsRelay:      n.cfg.Relay,
		StaticAddrs:  n.cfg.LighthouseAddrs,
	})
	if err != nil {
		return fmt.Errorf("renew control plane certificate: %w", err)
	}

	n.mu.Lock()
	n.certPEM, n.keyPEM = issued.Certificate, issued.PrivateKey
	n.NotAfter = issued.NotAfter
	yaml, err := inlineInto(issued.Config, issued.CABundle, n.certPEM, n.keyPEM, n.cfg)
	n.mu.Unlock()
	if err != nil {
		return err
	}

	if err := n.c.ReloadConfigString(yaml); err != nil {
		return fmt.Errorf("reload after renewal: %w", err)
	}
	n.log.Info("control plane certificate renewed", "notAfter", issued.NotAfter)
	return nil
}

// Maintain keeps this node current until ctx ends.
//
// changes fires when the network's epoch advances; nil falls back to the timer
// alone, which is correct but converges at the tick interval rather than
// immediately.
func (n *Node) Maintain(ctx context.Context, changes <-chan struct{}, tick time.Duration) {
	if tick <= 0 {
		tick = time.Minute
	}
	t := time.NewTicker(tick)
	defer t.Stop()

	refresh := func(reason string) {
		if err := n.Refresh(ctx); err != nil {
			// Not fatal. The control plane keeps running on its current
			// configuration, which is stale but working; failing hard here
			// would turn a stale trust bundle into an outage.
			n.log.Warn("control plane refresh failed", "reason", reason, "error", err)
			return
		}
		n.log.Debug("control plane configuration refreshed", "reason", reason)
	}

	for {
		select {
		case <-ctx.Done():
			return

		case <-changes:
			refresh("epoch changed")

		case <-t.C:
			// The timer covers what the notification cannot: a missed or
			// dropped notification, and the certificate's own expiry, which no
			// epoch change announces.
			refresh("periodic")
			if err := n.renewIfDue(ctx); err != nil {
				n.log.Error("control plane certificate renewal failed",
					"error", err, "notAfter", n.NotAfter)
			}
		}
	}
}

// HostID is the host record this replica self-issued against.
// Roles reports the data-plane roles actually in force, read from the host
// record rather than from this process's flags. Once someone has changed a role
// through the API those are no longer the same thing, and reporting the flags
// would be a lie.
type Roles struct {
	IsLighthouse bool
	IsRelay      bool
	// SeededThisStart is true when this start created the host record, and the
	// seed flags therefore took effect.
	SeededThisStart bool
}

func (n *Node) Roles(ctx context.Context) (Roles, error) {
	h, err := n.es.HostRoles(ctx, n.hostID)
	if err != nil {
		return Roles{}, err
	}
	return Roles{IsLighthouse: h.IsLighthouse, IsRelay: h.IsRelay, SeededThisStart: n.seeded}, nil
}

func (n *Node) HostID() uuid.UUID { return n.hostID }

// Announce registers this replica and keeps the registration fresh until ctx
// ends.
//
// The first registration is synchronous so that a replica is discoverable
// before it starts serving; an agent handed an endpoint that is not yet
// listening would fail over for no reason.
func (n *Node) Announce(ctx context.Context, reg Registrar) error {
	hb := n.cfg.Heartbeat
	if hb <= 0 {
		hb = DefaultHeartbeat
	}

	if err := reg.Register(ctx, n.cfg.NetworkID, n.hostID, n.cfg.Addr, n.cfg.AgentPort); err != nil {
		return fmt.Errorf("mesh: announce on network %s: %w", n.cfg.NetworkID, err)
	}

	go func() {
		t := time.NewTicker(hb)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// A failed heartbeat is not fatal. The replica keeps serving;
				// it just stops being advertised if the failure persists, which
				// is the correct outcome for a replica that cannot reach the
				// database anyway.
				if err := reg.Register(ctx, n.cfg.NetworkID, n.hostID, n.cfg.Addr, n.cfg.AgentPort); err != nil {
					n.log.Warn("control plane heartbeat failed", "error", err)
				}
			}
		}
	}()
	return nil
}

// Registrar records a replica's agent endpoint. Satisfied by the store; an
// interface so mesh does not depend on it directly.
type Registrar interface {
	Register(ctx context.Context, networkID, hostID uuid.UUID, addr netip.Addr, agentPort int) error
}

// NetworkID reports which network this node serves. The agent API needs it to
// resolve a source address unambiguously.
func (n *Node) NetworkID() uuid.UUID { return n.cfg.NetworkID }

// Addr reports the control plane's overlay address on this network.
func (n *Node) Addr() netip.Addr { return n.cfg.Addr }

// Listen returns a listener bound to the overlay only.
//
// Reachable exclusively by peers with a valid certificate for this network.
// There is no path from the public internet to it, which is the point: the
// management API is not merely authenticated, it is unroutable from outside.
func (n *Node) Listen(port int) (net.Listener, error) {
	ln, err := n.svc.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, fmt.Errorf("mesh: listen on overlay %s:%d: %w", n.cfg.Addr, port, err)
	}
	return ln, nil
}

// AgentEndpoint is the URL agents on this network should use.
func (n *Node) AgentEndpoint(port int) string {
	return fmt.Sprintf("http://%s:%d", n.cfg.Addr, port)
}

// ShutdownGrace bounds how long Close waits for nebula's goroutines to finish
// after it has been told to stop.
//
// Bounded because Wait is a wait on somebody else's shutdown completing. It
// blocks until every reader goroutine has exited AND the interface has released
// its construction token, and if any one of them does not come back — a
// blocking device read that never returns, a tunnel close that stalls — Wait
// never returns either. An unbounded wait there makes a control plane that
// cannot finish shutting down, which turns a restart into a SIGKILL and a clean
// stop into an operational surprise.
//
// Ten seconds is past any legitimate teardown: closing tunnels is the slow part
// and is proportional to hostmap size, which on a control plane is small. Past
// that the process is exiting anyway, and leaked goroutines in a dying process
// cost nothing.
const ShutdownGrace = 10 * time.Second

// Close stops nebula and waits, briefly, for it to finish.
//
// The error is Close's, not Wait's: failing to stop is worth reporting, while
// taking too long to finish stopping is worth logging and moving past.
func (n *Node) Close() error {
	err := n.svc.Close()

	done := make(chan struct{})
	go func() {
		_ = n.svc.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(ShutdownGrace):
		n.log.Warn("nebula did not finish shutting down; continuing anyway",
			"waited", ShutdownGrace, "network", n.cfg.NetworkID)
	}
	return err
}

// inlineInto turns a rendered host fragment into the control plane's own
// configuration, carrying certificate material inline.
//
// Done by parsing and re-emitting rather than by string substitution: a PEM
// blob is multi-line, and only a real YAML encoder gets the quoting right.
func inlineInto(rendered, caBundle, certPEM, keyPEM string, cfg Config) (string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(rendered), &doc); err != nil {
		return "", fmt.Errorf("parse rendered config: %w", err)
	}

	pki, ok := doc["pki"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("rendered config has no pki section")
	}
	pki["ca"] = caBundle
	pki["cert"] = certPEM
	pki["key"] = keyPEM

	listen, ok := doc["listen"].(map[string]any)
	if !ok {
		listen = map[string]any{}
		doc["listen"] = listen
	}
	listen["port"] = cfg.ListenPort

	// A lighthouse on an ephemeral port is one nothing can find, and nebula
	// refuses the config rather than starting into that state — with a message
	// about "lighthouse.am_lighthouse enabled on node but no port number is
	// set", which names nebula's field and not the reason Orbit produced it.
	//
	// Caught here so the error names the actual cause. Port 0 is right for a
	// control plane that only dials out; it is a contradiction the moment the
	// host record says this node is also a lighthouse, and the two facts are
	// decided in different places — the port by a flag, the role by a database
	// row — so nothing else compares them.
	if lh, ok := doc["lighthouse"].(map[string]any); ok {
		if am, _ := lh["am_lighthouse"].(bool); am && cfg.ListenPort == 0 {
			return "", fmt.Errorf(
				"this control plane is a lighthouse but has no fixed nebula port: "+
					"hosts are told to reach it at %v while it would listen on a random one. "+
					"Set -nebula-port (default 4242), or clear the lighthouse role on its host record",
				cfg.LighthouseAddrs)
		}
	}

	// The control plane accepts exactly one inbound port: the agent API.
	//
	// This is set here rather than left to the host's role, and it REPLACES
	// whatever the role produced. The control plane's exposure to every managed
	// host in the mesh must not depend on an operator editing a role correctly;
	// a role that opened SSH would turn the control plane into a lateral
	// movement target reachable from every enrolled machine.
	//
	// Getting this wrong is silent. Nebula's default posture is deny-inbound,
	// so a control plane with no rule simply drops every agent connection and
	// looks like a network problem.
	fw, ok := doc["firewall"].(map[string]any)
	if !ok {
		fw = map[string]any{}
		doc["firewall"] = fw
	}
	fw["inbound"] = []map[string]any{{
		"port":  fmt.Sprintf("%d", cfg.AgentPort),
		"proto": "tcp",
		"host":  "any",
	}}

	// Roles are NOT overridden here. am_lighthouse, am_relay, and the lighthouse
	// list all come from the host record, rendered by the same code that renders
	// every other host — so changing the control plane's role is an ordinary API
	// call that takes effect on the next refresh, with no restart and no flag.
	//
	// An earlier version forced them from flags, on the theory that a stray edit
	// to the record should not be able to put the machine holding the CA key
	// into the data path. That reasoning does not survive contact: editing a
	// host record already requires an admin token, and someone holding one can
	// do considerably worse than make this node relay encrypted traffic it
	// cannot read.
	//
	// One override remains, and it is load-bearing. renderFor disables the tun
	// device for a lighthouse that is not also a relay, which is right for an
	// ordinary tun-less lighthouse and wrong here: the control plane serves the
	// agent API on its userspace device, so disabling it would take the agent
	// API down the moment the control plane became a lighthouse.
	if tun, ok := doc["tun"].(map[string]any); ok {
		tun["disabled"] = false
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("re-marshal config: %w", err)
	}
	return string(out), nil
}
