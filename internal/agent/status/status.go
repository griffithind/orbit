package status

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"

	"go.yaml.in/yaml/v3"

	"github.com/griffithind/orbit/internal/agent/hostcfg"
)

// The agent's local status socket.
//
// One socket for the whole process, at <root>/agent.sock, because one process
// serves every joined network — the same reason there is one service unit. The
// network is a field in the answer, not a socket of its own.
//
// HTTP over a unix socket rather than a bespoke protocol: net/http is already
// linked, the paths carry a version, and `curl --unix-socket` works on it
// without any tooling of ours.
//
// Read-only. nebula's Control also offers CloseTunnel, SetRemoteForTunnel and
// CloseAllTunnels, and none of them are reachable here. Keeping the surface
// read-only means the blast radius of a permissions mistake is disclosure
// rather than control of the data plane.

// SocketName is the socket's name inside the agent root.
const SocketName = "agent.sock"

// SocketPath is where the agent listens for status requests.
func SocketPath(root string) string { return filepath.Join(root, SocketName) }

// SocketMode is 0600: root only.
//
// The report names every network this host has joined, its control plane, and
// its certificate. On a shared machine that is a map of the estate, and root is
// already required to run the agent at all — so restricting it costs nothing
// today. Widening it to a group is a deliberate flag, not a default.
const SocketMode os.FileMode = 0o600

// Report is the whole of GET /v1/status.
type Report struct {
	Version  string          `json:"version"`
	Root     string          `json:"root"`
	PID      int             `json:"pid"`
	Started  time.Time       `json:"started"`
	Networks []NetworkStatus `json:"networks"`
}

// NetworkStatus is one joined network.
type NetworkStatus struct {
	Network string `json:"network"`
	Dir     string `json:"dir"`

	// Ready is false when this network could not be set up at all — an
	// unreadable state file, a directory half-written by a concurrent install.
	// Such a network is retried forever in the background, so reporting it as
	// absent would hide the single most useful fact about a broken host.
	Ready bool   `json:"ready"`
	Error string `json:"error,omitempty"`

	MembershipID string `json:"membership_id,omitempty"`
	ControlURL   string `json:"control_url,omitempty"`
	Replicas     int    `json:"replicas,omitempty"`

	Nebula      NebulaStatus `json:"nebula"`
	Certificate *CertStatus  `json:"certificate,omitempty"`

	ConfigEpoch    int64 `json:"config_epoch"`
	BlocklistEpoch int64 `json:"blocklist_epoch"`

	// LastPoll is when the agent last completed a tick, and LastPollError what
	// it failed with. Together they separate "the control plane is unreachable"
	// from "the control plane has nothing new", which look identical from the
	// epochs alone.
	LastPoll      time.Time `json:"last_poll,omitempty"`
	LastPollError string    `json:"last_poll_error,omitempty"`

	// The three states a host can be stuck in, each carried explicitly rather
	// than left to be inferred from the epochs.
	DataPlaneDownSince time.Time `json:"data_plane_down_since,omitempty"`
	UnconfirmedSince   time.Time `json:"unconfirmed_since,omitempty"`
	QuarantinedEpoch   int64     `json:"quarantined_config_epoch,omitempty"`

	// Host is what the control plane told this machine to do to itself:
	// routes, forwarding, NAT and DNS. Nil when it was told nothing, so an
	// ordinary member's status is what it always was.
	Host *HostStatus `json:"host,omitempty"`
}

// NebulaStatus is the embedded data plane.
type NebulaStatus struct {
	// Known is false when the supervisor cannot observe the process. It is not
	// the same as "not running", and reporting it as such would call every
	// unobservable host down.
	Known    bool   `json:"known"`
	Running  bool   `json:"running"`
	Instance string `json:"instance,omitempty"`

	// Detail is why it stopped, when it stopped on its own — a bound port, a
	// missing device, a configuration nebula refused.
	Detail string `json:"detail,omitempty"`
}

// PeerReport is GET /v1/networks/{slug}/peers.
type PeerReport struct {
	Network string `json:"network"`

	// Running is nebula's state. When false the lists below are empty because
	// there is nothing to ask, NOT because this host has no peers — and those
	// are different diagnoses with different remedies.
	Running bool   `json:"running"`
	Detail  string `json:"detail,omitempty"`

	// Established are peers with a tunnel; Pending are peers mid-handshake.
	// Separate lists, because "we are trying" and "we are connected" answer the
	// question differently.
	Established []Peer `json:"established"`
	Pending     []Peer `json:"pending,omitempty"`
}

// Peer is one entry of nebula's hostmap.
type Peer struct {
	// Name and Groups come from the peer's certificate, the only identity in
	// the handshake. Empty when the tunnel has not got far enough to have
	// verified one, which is the normal state for a pending entry.
	Name   string   `json:"name,omitempty"`
	Groups []string `json:"groups,omitempty"`

	VpnAddrs []string `json:"vpn_addrs"`

	// CurrentRemote is the underlay address packets are going to right now.
	CurrentRemote string `json:"current_remote,omitempty"`

	// KnownRemotes are the underlay addresses this host has learned for the
	// peer, whether or not any of them answered.
	//
	// The distinction it exists to draw: "we know four addresses for this peer
	// and none of them worked" and "we have never heard of this peer" used to
	// print identically, and they have opposite causes and opposite fixes.
	KnownRemotes []string `json:"known_remotes,omitempty"`

	// RelaysToMe are the peers available to relay this one's traffic to us, and
	// RelaysThroughMe the peers whose traffic we relay for it.
	//
	// AVAILABLE, not in use. Nebula never removes a relay from relayState once
	// hole punching succeeds, so a non-empty RelaysToMe on a working direct
	// tunnel is the normal state — which is why it is not the relay predicate.
	// See Relayed.
	RelaysToMe      []string `json:"relays_to_me,omitempty"`
	RelaysThroughMe []string `json:"relays_through_me,omitempty"`

	// Messages is nebula's counter for the tunnel. Zero on an established
	// tunnel means it came up and has carried nothing, which is worth seeing.
	Messages uint64 `json:"messages"`

	CertNotAfter time.Time `json:"cert_not_after,omitempty"`
}

// Relayed reports whether traffic from this peer reaches us through somebody
// else.
//
// Mirrors nebula's own decision, third_party/nebula/inside.go:347:
//
//	useRelay := !remote.IsValid() && !hostinfo.GetRemote().IsValid()
//
// — a peer is relayed when there is no usable direct remote, full stop. This
// used to be len(RelaysToMe) > 0, which reports the HISTORY of a connection as
// if it were its state: nebula never drops a relay after a successful punch, so
// a tunnel that punched through perfectly still printed `relay`. It reported a
// working mesh as broken.
//
// If nebula's predicate changes, this one has to be re-read. That cost is the
// point — the old one drifted precisely because nothing tied it to anything.
func (p Peer) Relayed() bool { return p.CurrentRemote == "" }

// PeersFrom maps nebula's hostmap entries.
//
// Deliberately lossy. LocalIndex and RemoteIndex identify a tunnel inside
// nebula and mean nothing to an operator; carrying them would be two more
// columns nobody can act on.
func PeersFrom(hosts []nebula.ControlHostInfo) []Peer {
	out := make([]Peer, 0, len(hosts))
	for _, h := range hosts {
		p := Peer{
			VpnAddrs:        addrStrings(h.VpnAddrs),
			Messages:        h.MessageCounter,
			KnownRemotes:    addrPortStrings(h.RemoteAddrs),
			RelaysToMe:      addrStrings(h.CurrentRelaysToMe),
			RelaysThroughMe: addrStrings(h.CurrentRelaysThroughMe),
		}
		if h.CurrentRemote.IsValid() {
			p.CurrentRemote = h.CurrentRemote.String()
		}
		if h.Cert != nil {
			p.Name = h.Cert.Name()
			p.Groups = h.Cert.Groups()
			p.CertNotAfter = h.Cert.NotAfter()
		}
		out = append(out, p)
	}
	// Sorted, because the hostmap iterates a Go map. Without this, two runs
	// against an unchanged mesh print different orders and an operator
	// comparing them is reading a shuffle.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return strings.Join(out[i].VpnAddrs, ",") < strings.Join(out[j].VpnAddrs, ",")
	})
	return out
}

// addrPortStrings is addrStrings for the candidate remote list, which carries
// ports because an underlay address without one is not dialable.
func addrPortStrings(addrs []netip.AddrPort) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

func addrStrings(addrs []netip.Addr) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

// CertStatus is the certificate as currently on disk.
type CertStatus struct {
	Name     string   `json:"name"`
	Groups   []string `json:"groups,omitempty"`
	Networks []string `json:"networks,omitempty"`

	// UnsafeNetworks are the subnets this host routes into the overlay.
	//
	// Load-bearing rather than informational: their PRESENCE changes what an
	// omitted local_cidr means to nebula's firewall, from "any address" to "only
	// this host's own". A diagnostic that cannot see them cannot model the
	// gateway case, which is the case that is hardest to reason about by hand.
	UnsafeNetworks []string `json:"unsafe_networks,omitempty"`

	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}

// ReadCertStatus loads the certificate a network is running.
//
// Read from disk on every request rather than cached from the last renewal: the
// point of the command is to diagnose a host whose in-memory view may be the
// thing that is wrong.
func ReadCertStatus(path string) (*CertStatus, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, _, err := cert.UnmarshalCertificateFromPEM(b)
	if err != nil {
		return nil, err
	}
	cs := &CertStatus{
		Name:      c.Name(),
		Groups:    c.Groups(),
		NotBefore: c.NotBefore(),
		NotAfter:  c.NotAfter(),
	}
	for _, n := range c.Networks() {
		cs.Networks = append(cs.Networks, n.String())
	}
	for _, n := range c.UnsafeNetworks() {
		cs.UnsafeNetworks = append(cs.UnsafeNetworks, n.String())
	}
	if fp, err := c.Fingerprint(); err == nil {
		cs.Fingerprint = fp
	}
	return cs, nil
}

// Expired reports whether the certificate is outside its validity window.
func (c CertStatus) Expired(now time.Time) bool {
	return now.Before(c.NotBefore) || now.After(c.NotAfter)
}

// Server serves the socket.
type Server struct {
	// Path is the socket. Empty disables the server entirely.
	Path string
	Log  *slog.Logger

	// Report produces the current answer. Called per request so the report is
	// never staler than the request that asked for it.
	Report func(context.Context) Report

	// Peers answers for one network. ErrUnknownNetwork becomes a 404; anything
	// else is a 500.
	Peers func(ctx context.Context, network string) (PeerReport, error)

	// Explain answers whether traffic to a peer would pass.
	Explain func(ctx context.Context, network string, req ExplainRequest) (Explanation, error)
}

// ErrUnknownNetwork is a slug this host has not joined.
var ErrUnknownNetwork = errors.New("no such network on this host")

// Serve listens until ctx is cancelled.
//
// A failure here must never stop the agent: diagnostics going missing is worse
// than not having them, but it is not worth taking a host's overlays down for.
// Callers log the error and carry on — see cmd/orbit/agent.go.
func (s *Server) Serve(ctx context.Context) error {
	if s.Path == "" {
		return nil
	}

	ln, err := listenUnix(s.Path)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(s.Path) }()

	// After Listen, not before: the socket does not exist until then, and a
	// umask of 0022 would otherwise leave it group- and world-readable.
	if err := os.Chmod(s.Path, SocketMode); err != nil {
		_ = ln.Close()
		return fmt.Errorf("chmod %s: %w", s.Path, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, s.Report(r.Context()))
	})
	mux.HandleFunc("GET /v1/networks/{slug}/peers", func(w http.ResponseWriter, r *http.Request) {
		if s.Peers == nil {
			http.Error(w, "peers are not served here", http.StatusNotFound)
			return
		}
		rep, err := s.Peers(r.Context(), r.PathValue("slug"))
		switch {
		case errors.Is(err, ErrUnknownNetwork):
			http.Error(w, err.Error(), http.StatusNotFound)
		case err != nil:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		default:
			writeStatusJSON(w, rep)
		}
	})
	mux.HandleFunc("GET /v1/networks/{slug}/explain", func(w http.ResponseWriter, r *http.Request) {
		if s.Explain == nil {
			http.Error(w, "explain is not served here", http.StatusNotFound)
			return
		}
		q := r.URL.Query()
		ex, err := s.Explain(r.Context(), r.PathValue("slug"), ExplainRequest{
			Peer:  q.Get("peer"),
			Proto: q.Get("proto"),
			Port:  q.Get("port"),
		})
		switch {
		case errors.Is(err, ErrUnknownNetwork):
			http.Error(w, err.Error(), http.StatusNotFound)
		case err != nil:
			// A bad protocol, an unresolvable peer: the caller's question was
			// malformed, not the agent's state. 400 so the CLI can map it to a
			// usage exit rather than telling somebody their agent is broken.
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			writeStatusJSON(w, ex)
		}
	})

	srv := &http.Server{
		Handler: mux,
		// A local reader that stops reading must not pin a goroutine forever.
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	err = srv.Serve(ln)
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// listenUnix binds the socket, clearing a stale one but never a live one.
//
// The dance matters. Unlinking unconditionally would let a second agent steal
// the socket from a running first one: the bind succeeds, both processes look
// healthy, and every status request goes to whichever won — while the other
// keeps serving networks nobody can see. So connect first: a successful connect
// means somebody is listening and this is a genuine conflict, and only a
// refused connection proves the path is a leftover.
func listenUnix(path string) (net.Listener, error) {
	if _, err := os.Stat(path); err == nil {
		c, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("another agent is already listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	return ln, nil
}

func writeStatusJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// ErrNoAgent is returned when nothing is listening on the socket.
//
// A distinct error because it is the answer to the most common question this
// command is asked — "why is nothing working" — and the caller should say "the
// agent is not running" rather than surface a dial error about a path.
var ErrNoAgent = errors.New("the orbit agent is not running")

// Fetch reads the whole report from a running agent.
func Fetch(ctx context.Context, path string) (Report, error) {
	var rep Report
	err := fetch(ctx, path, "/v1/status", &rep)
	return rep, err
}

// FetchPeers reads one network's hostmap from a running agent.
func FetchPeers(ctx context.Context, path, network string) (PeerReport, error) {
	var rep PeerReport
	err := fetch(ctx, path, "/v1/networks/"+url.PathEscape(network)+"/peers", &rep)
	return rep, err
}

// FetchExplain asks a running agent whether traffic to a peer would pass.
func FetchExplain(ctx context.Context, path, network string, req ExplainRequest) (Explanation, error) {
	q := url.Values{}
	q.Set("peer", req.Peer)
	if req.Proto != "" {
		q.Set("proto", req.Proto)
	}
	if req.Port != "" {
		q.Set("port", req.Port)
	}
	var ex Explanation
	err := fetch(ctx, path,
		"/v1/networks/"+url.PathEscape(network)+"/explain?"+q.Encode(), &ex)
	return ex, err
}

// ErrBadQuestion is a request the agent could not make sense of — an unknown
// protocol, a peer that resolves to nothing. Distinct from a broken agent
// because the remedy is to retype the command.
var ErrBadQuestion = errors.New("the question could not be answered as asked")

// fetch is the only client of the socket, so the wire format has exactly one
// implementation on each side and no caller hand-rolls a unix transport.
func fetch(ctx context.Context, path, route string, into any) error {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
		Timeout: 10 * time.Second,
	}

	// The host in the URL is ignored by the dialer above but must be present
	// and valid for net/http to accept the request at all.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent"+route, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		// Nothing there, or something there that will not talk: both mean no
		// agent from the caller's point of view. Permission is different — the
		// agent may be running perfectly well and the caller simply is not
		// root — so that one keeps its own error.
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return ErrNoAgent
		}
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("cannot read %s: %w (run as root)", path, os.ErrPermission)
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		// The body carries which network was asked for, and losing it here
		// would leave the caller printing "404" at somebody who mistyped a slug.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%w: %s", ErrUnknownNetwork, strings.TrimSpace(string(body)))
	}
	if resp.StatusCode == http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("%w: %s", ErrBadQuestion, strings.TrimSpace(string(body)))
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent returned %s", resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(into); err != nil {
		return fmt.Errorf("parse agent response: %w", err)
	}
	return nil
}

// HostStatus is what this machine was told to do to itself, and to resolve with.
//
// READ FROM THE SAME VERIFIED CONFIGURATION the reconcilers act on, not from the kernel
// and not from a cache. Status that reads the machine would answer "what is true", which
// sounds better but is the wrong question here: an operator looking at `orbit status`
// after adding a route needs to know whether the instruction ARRIVED. If it arrived and
// did not take, the reconcile error says so on the next line, and the two together name
// the failure. A status that only inspected the kernel could not tell "the control plane
// never sent it" from "it was sent and failed".
type HostStatus struct {
	// Routes are the external prefixes this host reaches through the mesh.
	Routes []string `json:"routes,omitempty"`

	// ExitNode is true when one of those is a default route.
	ExitNode bool `json:"exit_node,omitempty"`

	// Forwarding and Masquerade are the gateway side: what this host carries
	// for others.
	Forwarding bool     `json:"forwarding,omitempty"`
	Masquerade []string `json:"masquerade,omitempty"`

	// Resolver, Domain and Names describe the DNS this host serves itself.
	Resolver string `json:"resolver,omitempty"`
	Domain   string `json:"dns_domain,omitempty"`
	Names    int    `json:"dns_names,omitempty"`
}

// Empty reports whether this host was told nothing beyond plain membership, so status can
// leave the whole section out rather than print a row of zeroes.
func (h HostStatus) Empty() bool {
	return len(h.Routes) == 0 && !h.Forwarding && len(h.Masquerade) == 0 && h.Resolver == ""
}

// HostStatusFromConfig reads all of it out of one verified configuration.
func HostStatusFromConfig(yamlCfg string) (HostStatus, error) {
	var out HostStatus

	hs, err := hostcfg.HostStateFromConfig(yamlCfg)
	if err != nil {
		return out, err
	}
	out.Forwarding = hs.Forward
	out.ExitNode = hs.ExitNode
	for _, p := range hs.Masquerade {
		out.Masquerade = append(out.Masquerade, p.String())
	}

	if d, err := hostcfg.DNSStateFromConfig(yamlCfg); err == nil && !d.Empty() {
		out.Resolver = d.Listen.String()
		out.Domain = d.Domain
		// Halved: every machine is stored under both its bare and its qualified
		// name, and reporting the map size would tell an operator there are
		// twice as many hosts as they have.
		out.Names = len(d.Hosts) / 2
		if d.Domain == "" {
			out.Names = len(d.Hosts)
		}
	}

	var doc struct {
		Tun struct {
			UnsafeRoutes []struct {
				Route string `yaml:"route"`
			} `yaml:"unsafe_routes"`
		} `yaml:"tun"`
	}
	if err := yaml.Unmarshal([]byte(yamlCfg), &doc); err != nil {
		return out, fmt.Errorf("read routes from the configuration: %w", err)
	}
	for _, r := range doc.Tun.UnsafeRoutes {
		out.Routes = append(out.Routes, r.Route)
	}
	return out, nil
}
