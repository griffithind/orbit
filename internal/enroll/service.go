package enroll

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

var (
	ErrInvalidCredential = errors.New("invalid or expired enrollment credential")
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrCurveMismatch     = errors.New("public key curve does not match the network")
	ErrHostBlocked       = errors.New("host is blocked")
	ErrNoHost            = errors.New("credential is not bound to a host")
)

// DefaultCodeTTL is short on purpose. A long-lived join token sitting in a
// configuration management repository is the usual way a fleet's trust
// boundary is lost; fifteen minutes is enough to run an installer and not much
// else.
const DefaultCodeTTL = 15 * time.Minute

// Config parameterizes the service.
type Config struct {
	// Paths is where the agent will place files on the managed host.
	Paths nebulacfg.Paths
	// ListenPort is the nebula UDP port written into rendered configs.
	ListenPort int
	// EnrollURL is returned alongside a new code so an installer needs only one
	// value.
	EnrollURL string
	// Log receives operational detail about rejected enrollments alongside the
	// audit record. Nil discards it.
	Log *slog.Logger

	// ControlPlaneStaleAfter is how long a replica may go without heartbeating
	// before it stops being advertised to agents. Zero uses the default.
	ControlPlaneStaleAfter time.Duration

	// RecoveryGrace is how long past expiry a host may still recover. Zero uses
	// DefaultRecoveryGrace.
	RecoveryGrace time.Duration
}

// Service performs enrollment and renewal.
type Service struct {
	store    *store.Store
	registry *ca.Registry
	hasher   *Hasher
	cfg      Config
	log      *slog.Logger

	// now is injectable for tests.
	now func() time.Time
}

func NewService(st *store.Store, reg *ca.Registry, h *Hasher, cfg Config) *Service {
	if cfg.Paths.CA == "" {
		cfg.Paths = nebulacfg.DefaultPaths()
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 4242
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Service{store: st, registry: reg, hasher: h, cfg: cfg, log: log, now: time.Now}
}

func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// CreateCode mints an enrollment credential for an existing host.
//
// Returns the plaintext, which the caller must relay to exactly one place and
// never store. Only its keyed hash is persisted.
func (s *Service) CreateCode(ctx context.Context, hostID uuid.UUID, ttl time.Duration, createdBy string) (*wire.EnrollmentCodeResponse, error) {
	if ttl <= 0 {
		ttl = DefaultCodeTTL
	}

	plaintext, stored, err := s.hasher.NewCredential()
	if err != nil {
		return nil, err
	}
	expiresAt := s.clock().Add(ttl)

	err = s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		// A blocked host must not be re-enrollable; that would turn blocking
		// into a temporary inconvenience.
		if host.State == store.HostSuspended {
			return ErrHostBlocked
		}

		cred := store.EnrollmentCredential{
			NetworkID: host.NetworkID,
			HostID:    &host.ID,
			Method:    store.MethodCode,
			ExpiresAt: expiresAt,
			CreatedBy: createdBy,
		}
		if err := tx.CreateEnrollmentCredential(ctx, &cred, stored); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "user", ActorID: createdBy,
			Action:     store.ActionEnrollCodeCreated,
			TargetType: "host", TargetID: host.ID.String(),
		})
	})
	if err != nil {
		return nil, err
	}

	return &wire.EnrollmentCodeResponse{
		Code:      plaintext,
		ExpiresAt: expiresAt,
		EnrollURL: s.cfg.EnrollURL,
	}, nil
}

// Enroll redeems a credential and issues the host's first certificate.
func (s *Service) Enroll(ctx context.Context, req wire.EnrollRequest, from netip.Addr) (*wire.EnrollResponse, error) {
	if err := Validate(req.Credential); err != nil {
		return nil, ErrInvalidCredential
	}

	// Redemption first, and atomically. Everything after this point is work we
	// only do for the one caller that actually consumed the credential; doing
	// any of it beforehand would let an attacker with an already-used code
	// still cost us a certificate issuance.
	redeemed, err := s.store.RedeemEnrollmentCredential(ctx, s.hasher.Hash(req.Credential), from)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Audited with no target: the credential did not resolve, so there
			// is no host to attribute the attempt to, but the attempt itself is
			// exactly what someone reviewing an incident wants to see. A burst
			// of these from one address is the signature of a replayed or
			// guessed code.
			s.log.Warn("enrollment rejected: unknown, spent, or expired credential", "from", from)
			s.auditUnknownCredential(ctx, from)
			return nil, ErrInvalidCredential
		}
		return nil, err
	}
	if redeemed.HostID == nil {
		// Only cloud_iid creates its host on redemption, and that path is not
		// implemented yet. Fail loudly rather than inventing a host.
		return nil, ErrNoHost
	}

	var resp *wire.EnrollResponse
	err = s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, *redeemed.HostID)
		if err != nil {
			return err
		}
		if host.State == store.HostSuspended {
			return ErrHostBlocked
		}

		out, err := s.issueAndRender(ctx, tx, host, req.PublicKey, req.Curve)
		if err != nil {
			return err
		}

		if err := tx.SetHostState(ctx, host.ID, store.HostEnrolled); err != nil {
			return err
		}
		if err := tx.RecordAgentReport(ctx, host.ID, store.AgentReport{
			NebulaVersion: req.NebulaVersion,
			AgentVersion:  req.AgentVersion,
		}); err != nil {
			return err
		}

		var ip *netip.Addr
		if from.IsValid() {
			ip = &from
		}
		if err := tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "agent", ActorID: host.ID.String(),
			Action:     store.ActionEnrolled,
			TargetType: "host", TargetID: host.ID.String(),
			SourceIP: ip,
		}); err != nil {
			return err
		}

		out.AgentEndpoints = s.agentEndpoints(ctx, tx, host.NetworkID)
		resp = out
		return nil
	})
	if err != nil {
		// Past redemption the host IS known, so this failure names a target: a
		// spent credential combined with a rejected enrollment is the shape of
		// an attacker replaying a code they intercepted.
		//
		// A separate transaction, because the one above rolled back — an audit
		// record written inside it would have rolled back with it.
		s.auditEnrollFailure(ctx, redeemed, from, err)
		return nil, err
	}
	return resp, nil
}

// auditUnknownCredential records an attempt that resolved to nothing.
//
// Best effort, and never allowed to change what the caller sees: the request has
// already failed, and a logging problem must not turn a rejected credential into
// a server error.
func (s *Service) auditUnknownCredential(ctx context.Context, from netip.Addr) {
	var ip *netip.Addr
	if from.IsValid() {
		ip = &from
	}
	err := s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "agent",
			Action:    store.ActionEnrollFailed,
			Meta:      []byte(`{"reason":"unknown, spent, or expired credential"}`),
			SourceIP:  ip,
		})
	})
	if err != nil {
		s.log.Error("could not audit a rejected enrollment", "error", err)
	}
}

// auditEnrollFailure records an enrollment failure against a known host.
//
// Best effort: the request has already failed, and failing to log why must not
// change what the caller sees.
func (s *Service) auditEnrollFailure(ctx context.Context, redeemed *store.RedeemedCredential, from netip.Addr, cause error) {
	var ip *netip.Addr
	if from.IsValid() {
		ip = &from
	}
	target := ""
	if redeemed.HostID != nil {
		target = redeemed.HostID.String()
	}

	err := s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "agent", ActorID: target,
			Action:     store.ActionEnrollFailed,
			TargetType: "host", TargetID: target,
			Meta:     []byte(fmt.Sprintf(`{"reason":%q}`, cause.Error())),
			SourceIP: ip,
		})
	})
	if err != nil {
		s.log.Error("could not audit a failed enrollment", "error", err)
	}
}

// DefaultControlPlaneStaleAfter is several heartbeats' worth of slack, so a
// replica pausing briefly is not dropped from the list agents are handed.
const DefaultControlPlaneStaleAfter = 3 * time.Minute

// agentEndpoints lists the overlay URLs agents on a network may use.
//
// Read live from the registry rather than from configuration, so a replica that
// joined a minute ago is handed out and one that died stops being handed out,
// with no restart or reconfiguration anywhere.
//
// An empty result is not an error: it means no replica has joined this network,
// and the agent keeps talking to whatever endpoint it enrolled against.
func (s *Service) agentEndpoints(ctx context.Context, tx *store.Tx, networkID uuid.UUID) []string {
	stale := s.cfg.ControlPlaneStaleAfter
	if stale <= 0 {
		stale = DefaultControlPlaneStaleAfter
	}

	live, err := tx.LiveControlPlanes(ctx, networkID, s.clock().Add(-stale))
	if err != nil {
		// Not fatal. Failing enrollment because the endpoint list could not be
		// built would be worse than handing back none: the host still gets a
		// working certificate and can reach the public endpoint.
		s.log.Warn("could not list control planes", "network", networkID, "error", err)
		return nil
	}

	out := make([]string, 0, len(live))
	for _, cp := range live {
		out = append(out, fmt.Sprintf("http://%s:%d", cp.Addr, cp.AgentPort))
	}
	return out
}

// Renew issues a fresh certificate for an already-enrolled host.
//
// Identity comes from the caller, which on the overlay-bound agent API is the
// verified source address rather than anything in the request body.
func (s *Service) Renew(ctx context.Context, hostID uuid.UUID, req wire.RenewRequest) (*wire.EnrollResponse, error) {
	var resp *wire.EnrollResponse
	err := s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		if host.State == store.HostSuspended {
			return ErrHostBlocked
		}

		out, err := s.issueAndRender(ctx, tx, host, req.PublicKey, req.Curve)
		if err != nil {
			return err
		}
		if err := tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "agent", ActorID: host.ID.String(),
			Action:     store.ActionCertificateIssued,
			TargetType: "host", TargetID: host.ID.String(),
		}); err != nil {
			return err
		}
		out.AgentEndpoints = s.agentEndpoints(ctx, tx, host.NetworkID)
		resp = out
		return nil
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// State answers an agent poll. Config and certificate material are included
// only when the agent is behind, so a steady-state poll stays small.
func (s *Service) State(ctx context.Context, hostID uuid.UUID, knownConfig, knownBlock int64) (*wire.StateResponse, error) {
	var resp wire.StateResponse
	err := s.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		net, err := tx.GetNetwork(ctx, host.NetworkID)
		if err != nil {
			return err
		}

		resp.ConfigEpoch = net.ConfigEpoch
		resp.BlocklistEpoch = net.BlocklistEpoch

		certs, err := tx.ActiveCertificates(ctx, host.ID)
		if err != nil {
			return err
		}
		if len(certs) > 0 {
			// The highest version is the one the host leads with.
			c := certs[len(certs)-1]
			resp.RenewAfter = c.RenewAt()
			resp.NotAfter = c.NotAfter
		}

		if knownConfig >= net.ConfigEpoch && knownBlock >= net.BlocklistEpoch {
			return nil
		}

		fragment, bundle, err := s.renderFor(ctx, tx, host, net)
		if err != nil {
			return err
		}
		resp.Config = string(fragment)
		resp.CABundle = bundle
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// issueAndRender mints a certificate and renders the matching configuration.
func (s *Service) issueAndRender(ctx context.Context, tx *store.Tx, host *store.Host, pubKeyB64, curveName string) (*wire.EnrollResponse, error) {
	net, err := tx.GetNetwork(ctx, host.NetworkID)
	if err != nil {
		return nil, err
	}

	pub, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil || len(pub) == 0 {
		return nil, ErrInvalidPublicKey
	}
	curve, err := parseCurve(curveName)
	if err != nil {
		return nil, err
	}
	if curve.String() != net.Curve {
		return nil, fmt.Errorf("%w: host offered %s, network is %s", ErrCurveMismatch, curve, net.Curve)
	}
	if err := validatePublicKey(curve, pub); err != nil {
		return nil, err
	}

	caRow, err := tx.GetActiveCA(ctx, net.ID)
	if err != nil {
		return nil, err
	}
	issuer, err := s.registry.Issuer(ctx, caRow.Fingerprint, caRow.CertPEM, caRow.SignerRef)
	if err != nil {
		return nil, err
	}

	networks, err := certNetworks(host.Addrs, net.CIDRs)
	if err != nil {
		return nil, err
	}

	var groups []string
	if host.RoleID != nil {
		role, err := tx.GetRole(ctx, *host.RoleID)
		if err != nil {
			return nil, err
		}
		groups = role.Groups
	}

	// ValidityFor clamps to the CA's window. Without it a CA created moments
	// ago would reject a certificate backdated for clock skew.
	notBefore, notAfter, err := issuer.ValidityFor(net.CertTTL, time.Minute)
	if err != nil {
		return nil, err
	}

	hostCert, err := issuer.IssueHost(ctx, ca.HostParams{
		Name:      host.Name,
		Version:   cert.Version(net.CertVer),
		Networks:  networks,
		Groups:    groups,
		PublicKey: pub,
		NotBefore: notBefore,
		NotAfter:  notAfter,
	})
	if err != nil {
		return nil, fmt.Errorf("issue certificate: %w", err)
	}

	pem, err := hostCert.MarshalPEM()
	if err != nil {
		return nil, err
	}
	fingerprint, err := hostCert.Fingerprint()
	if err != nil {
		return nil, err
	}

	rec := store.Certificate{
		HostID: host.ID, CAID: caRow.ID, Fingerprint: fingerprint, PEM: string(pem),
		CertVer: net.CertVer, NotBefore: notBefore, NotAfter: notAfter,
	}
	if err := tx.InsertCertificate(ctx, &rec); err != nil {
		return nil, err
	}

	fragment, bundle, err := s.renderFor(ctx, tx, host, net)
	if err != nil {
		return nil, err
	}

	return &wire.EnrollResponse{
		HostID:         host.ID.String(),
		HostName:       host.Name,
		Certificate:    string(pem),
		CABundle:       bundle,
		Config:         string(fragment),
		ConfigEpoch:    net.ConfigEpoch,
		BlocklistEpoch: net.BlocklistEpoch,
		RenewAfter:     rec.RenewAt(),
		NotAfter:       notAfter,
	}, nil
}

// renderFor assembles a host's configuration fragment and trust bundle.
func (s *Service) renderFor(ctx context.Context, tx *store.Tx, host *store.Host, net *store.Network) ([]byte, string, error) {
	topology, err := tx.NetworkTopology(ctx, net.ID)
	if err != nil {
		return nil, "", err
	}

	var lighthouses []nebulacfg.Lighthouse
	var relays []netip.Addr
	for _, th := range topology {
		if th.ID == host.ID {
			continue // never point a host at itself
		}
		if len(th.Addrs) == 0 {
			continue
		}
		if th.IsLighthouse {
			lighthouses = append(lighthouses, nebulacfg.Lighthouse{
				VpnAddr: th.Addrs[0], StaticAddrs: th.StaticAddrs,
			})
		}
		if th.IsRelay {
			relays = append(relays, th.Addrs[0])
		}
	}

	blocklist, err := tx.LiveBlocklist(ctx, net.ID, s.clock())
	if err != nil {
		return nil, "", err
	}
	bundle, err := tx.TrustBundlePEM(ctx, net.ID)
	if err != nil {
		return nil, "", err
	}

	fw := nebulacfg.DefaultFirewall()
	if host.RoleID != nil {
		role, err := tx.GetRole(ctx, *host.RoleID)
		if err != nil {
			return nil, "", err
		}
		if fw, err = nebulacfg.ParseFirewall(role.FirewallRules); err != nil {
			return nil, "", err
		}
	}

	fragment, err := nebulacfg.Render(nebulacfg.Input{
		Paths:        s.cfg.Paths,
		AmLighthouse: host.IsLighthouse,
		AmRelay:      host.IsRelay,
		Lighthouses:  lighthouses,
		Relays:       relays,
		Blocklist:    blocklist,
		Firewall:     fw,
		ListenPort:   s.cfg.ListenPort,
		// A lighthouse with no tun device needs no root. Only safe when it is
		// not also a relay, since relaying is a data-plane role.
		TunDisabled: host.IsLighthouse && !host.IsRelay,
	})
	if err != nil {
		return nil, "", err
	}
	return fragment, bundle, nil
}

// certNetworks pairs each of a host's addresses with the prefix length of the
// network CIDR that contains it.
//
// Nebula derives the host's address from Addr() and the routable network from
// the prefix length, so 10.42.0.7/16 and 10.42.0.7/32 mean materially different
// things: the first can reach the whole overlay directly, the second treats
// every peer as off-net. Getting this wrong produces a host that enrolls
// successfully and then cannot route.
func certNetworks(addrs []netip.Addr, cidrs []netip.Prefix) ([]netip.Prefix, error) {
	if len(addrs) == 0 {
		return nil, errors.New("host has no overlay address")
	}
	out := make([]netip.Prefix, 0, len(addrs))
	for _, a := range addrs {
		matched := false
		for _, c := range cidrs {
			if c.Contains(a) {
				out = append(out, netip.PrefixFrom(a, c.Bits()))
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("address %s is not within any network prefix %v", a, cidrs)
		}
	}
	return out, nil
}

func parseCurve(name string) (cert.Curve, error) {
	switch name {
	case "CURVE25519", "25519", "":
		return cert.Curve_CURVE25519, nil
	case "P256":
		return cert.Curve_P256, nil
	default:
		return 0, fmt.Errorf("unknown curve %q", name)
	}
}

// validatePublicKey rejects keys that are structurally wrong for the curve.
//
// An all-zero X25519 key, and the other low-order points, are not a practical
// attack on the handshake here, but they do indicate a broken client, and
// accepting one mints a certificate that can never complete a handshake. Better
// to fail at enrollment with a clear reason.
func validatePublicKey(curve cert.Curve, pub []byte) error {
	switch curve {
	case cert.Curve_CURVE25519:
		if len(pub) != 32 {
			return fmt.Errorf("%w: x25519 key must be 32 bytes, got %d", ErrInvalidPublicKey, len(pub))
		}
	case cert.Curve_P256:
		if len(pub) != 65 || pub[0] != 0x04 {
			return fmt.Errorf("%w: p256 key must be a 65 byte uncompressed point", ErrInvalidPublicKey)
		}
	}

	allZero := true
	for _, b := range pub {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return fmt.Errorf("%w: key is all zero", ErrInvalidPublicKey)
	}
	return nil
}

// SelfIssued is a generation for the control plane's own mesh membership.
type SelfIssued struct {
	HostID      uuid.UUID
	Config      string
	Certificate string
	CABundle    string
	PrivateKey  string
	NotAfter    time.Time
	// Created is true when this call created the host record, meaning the
	// seeded roles took effect rather than being ignored.
	Created bool
}

// SelfIssue mints the control plane its own identity on a network.
//
// Orbit has to be a nebula host to serve the agent API over the overlay, and it
// already holds the CA, so it issues its own certificate directly rather than
// enrolling. That is not a privilege escalation: anything Orbit could grant
// itself here it could already grant to any host.
//
// The keypair is generated per call and never persisted. The control plane's
// private key living only in memory means a restart rotates it, a stolen disk
// yields nothing, and there is no key file to manage. The cost is a fresh
// certificate on every restart, which at these volumes is free.
//
// The host record is created once and reused, so the overlay address stays
// stable across restarts and the address-uniqueness constraint does the work of
// stopping two replicas from claiming the same one.
// SelfIssueRoles seeds the control plane's data-plane roles when its host
// record is first created.
//
// A seed, not an override. After the record exists it is the source of truth,
// exactly as it is for every other host, so changing the control plane's role
// is an ordinary API call rather than a flag edit and a restart. Anything else
// would make this one host special for no reason a reader could reconstruct.
//
// Public addresses have to be seeded from somewhere: a node behind NAT cannot
// discover its own, so the operator states it once.
type SelfIssueRoles struct {
	IsLighthouse bool
	IsRelay      bool
	// StaticAddrs are the public "host:port" entries other hosts dial. A
	// lighthouse without them is unreachable and is skipped when rendering.
	StaticAddrs []string
}

func (s *Service) SelfIssue(ctx context.Context, networkID uuid.UUID, addr netip.Addr, name string, roles SelfIssueRoles) (*SelfIssued, error) {
	var out *SelfIssued

	var created bool
	err := s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		net, err := tx.GetNetwork(ctx, networkID)
		if err != nil {
			return err
		}
		if !net.ContainsAddr(addr) {
			return fmt.Errorf("%s is not within network %s (%v)", addr, net.Name, net.CIDRs)
		}

		host, err := tx.FindHostByAddr(ctx, networkID, addr)
		switch {
		case errors.Is(err, store.ErrNotFound):
			host = &store.Host{
				NetworkID:    networkID,
				Name:         name,
				Addrs:        []netip.Addr{addr},
				State:        store.HostActive,
				Tags:         []string{"orbit-control-plane"},
				IsLighthouse: roles.IsLighthouse,
				IsRelay:      roles.IsRelay,
				StaticAddrs:  roles.StaticAddrs,
			}
			if err := tx.CreateHost(ctx, host); err != nil {
				return fmt.Errorf("create control plane host: %w", err)
			}
			created = true
		case err != nil:
			return err
		default:
			// Reuse the existing record. A different name at the same address
			// means an operator pointed two things at one address; refuse
			// rather than quietly take it over.
			if host.Name != name {
				return fmt.Errorf("overlay address %s is already held by host %q", addr, host.Name)
			}
			// The record already exists, so it wins. Seeding again on every
			// start would mean a role changed through the API silently
			// reverting on the next restart, which is the kind of bug that
			// takes a long evening to find.
		}

		curve, err := parseCurve(net.Curve)
		if err != nil {
			return err
		}
		pub, priv, err := ca.GenerateHostKey(curve)
		if err != nil {
			return fmt.Errorf("generate control plane keypair: %w", err)
		}

		resp, err := s.issueAndRender(ctx, tx, host, base64.StdEncoding.EncodeToString(pub), net.Curve)
		if err != nil {
			return err
		}

		out = &SelfIssued{
			HostID:      host.ID,
			Config:      resp.Config,
			Certificate: resp.Certificate,
			CABundle:    resp.CABundle,
			PrivateKey:  string(cert.MarshalPrivateKeyToPEM(curve, priv)),
			NotAfter:    resp.NotAfter,
			Created:     created,
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ControlPlaneMaterial re-renders a control plane's configuration without
// issuing a certificate.
//
// The control plane is a mesh member, so it needs the same updates every other
// host gets: a rotated CA in its trust bundle, a new lighthouse in its
// static_host_map, a revoked fingerprint in its blocklist. Without them it
// rejects hosts that renewed onto a new CA and keeps trusting blocked ones.
//
// Separate from SelfIssue because those updates arrive far more often than a
// certificate needs replacing, and minting one per blocklist change would churn
// the database and rotate the control plane's key for no reason.
func (s *Service) ControlPlaneMaterial(ctx context.Context, hostID uuid.UUID) (config, caBundle string, err error) {
	err = s.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		net, err := tx.GetNetwork(ctx, host.NetworkID)
		if err != nil {
			return err
		}
		fragment, bundle, err := s.renderFor(ctx, tx, host, net)
		if err != nil {
			return err
		}
		config, caBundle = string(fragment), bundle
		return nil
	})
	return config, caBundle, err
}

// ControlPlaneCertificate returns the control plane's current certificate
// window, so it can renew before it expires.
func (s *Service) ControlPlaneCertificate(ctx context.Context, hostID uuid.UUID) (notBefore, notAfter time.Time, err error) {
	err = s.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		certs, err := tx.ActiveCertificates(ctx, hostID)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			return fmt.Errorf("control plane host %s has no active certificate", hostID)
		}
		c := certs[len(certs)-1]
		notBefore, notAfter = c.NotBefore, c.NotAfter
		return nil
	})
	return notBefore, notAfter, err
}

// HostRoles reads a host's current data-plane roles.
func (s *Service) HostRoles(ctx context.Context, hostID uuid.UUID) (*store.Host, error) {
	var h *store.Host
	err := s.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		h, err = tx.GetHost(ctx, hostID)
		return err
	})
	return h, err
}
