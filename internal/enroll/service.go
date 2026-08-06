package enroll

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/policy"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/version"
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

	// NetworkIdentity resolves a network's identity signer ref into the private
	// key that signs join proofs.
	//
	// A function rather than a *vault.Vault, for the reason PolicySource is one:
	// internal/enroll would otherwise import the vault, the vault imports the
	// store, and a test that wanted to check a join proof would need a database
	// and a passphrase. Nil falls back to reading a file:// ref directly, which
	// is what a deployment with no vault does anyway.
	NetworkIdentity func(ctx context.Context, ref string) (ed25519.PrivateKey, error)

	// ControlPlaneStaleAfter is how long a replica may go without heartbeating
	// before it stops being advertised to agents. Zero uses the default.
	ControlPlaneStaleAfter time.Duration

	// Policy supplies a network's compiled-policy inputs.
	//
	// NIL MEANS THE DEFAULT, store.NetworkPolicy — not "disabled". NewService
	// fills it in, and that default is what makes the feature safe to leave
	// unmentioned: store.NetworkPolicy returns nil for any network whose
	// firewall_source is not 'policy', so a deployment that has never heard of
	// policy renders exactly the per-role rules it always did, byte for byte.
	//
	// It defaults rather than requiring each caller to pass it because this
	// struct is built from a literal in ten places — cmd/orbitd and nine test
	// harnesses — and a field omitted from a literal is silent. Omitting this
	// one produced a state where a policy could be stored, switched on, and
	// reported in force by every endpoint while nothing rendered it: an operator
	// believing a firewall was enforced when no host had ever seen it.
	//
	// Set DisablePolicy to opt out deliberately.
	Policy PolicySource

	// DisablePolicy turns the policy path off entirely, for a caller that wants
	// to prove the per-role path in isolation. Explicit, because "I forgot" and
	// "I meant to" must not look the same.
	DisablePolicy bool
}

// PolicySource returns a network's policy document and the fleet its selectors
// resolve against.
//
// A function rather than a method on the store, for two reasons. It keeps
// internal/policy a pure function of its inputs — the compiler never learns
// what a database is — and it lets the wiring decide whether a deployment has
// policy at all, which is what makes the feature opt-in rather than a column
// everything has to interpret.
//
// doc is nil for a network with no policy, which is the common case and is not
// an error. The transaction is threaded through so the document and the fleet
// are read at the same instant as the rest of the render: a fleet from one
// snapshot compiled against a document from another would produce rules for a
// network that never existed.
type PolicySource func(ctx context.Context, tx *store.Tx, networkID uuid.UUID) (doc []byte, fleet []policy.Membership, err error)

// The store's implementation has to keep fitting. An assertion here rather than
// at the wiring site because the wiring site is a struct literal, where a
// signature drift shows up as "cannot use ... as PolicySource" pointing at
// main.go and explaining nothing.
var _ PolicySource = store.NetworkPolicy

// Service performs enrollment and renewal.
type Service struct {
	store    *store.Store
	registry *ca.Registry
	cfg      Config
	log      *slog.Logger

	// now is injectable for tests.
	now func() time.Time

	// identityKeys caches each network's identity private key, which every join
	// needs to sign its proof. Cached because the alternative is reading and
	// Argon2-decrypting a file on a public, unauthenticated endpoint.
	identityMu   sync.Mutex
	identityKeys map[uuid.UUID]ed25519.PrivateKey
}

func NewService(st *store.Store, reg *ca.Registry, cfg Config) *Service {
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
	// The safe default, applied here rather than trusted to every call site.
	if cfg.Policy == nil && !cfg.DisablePolicy {
		cfg.Policy = store.NetworkPolicy
	}
	return &Service{store: st, registry: reg, cfg: cfg, log: log, now: time.Now}
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
//
// actor is threaded through rather than a bare id string: this previously took
// one and recorded it as actor_type "user" while every caller passed a token
// uuid, which is precisely the mislabel an audit trail must not have.
func (s *Service) CreateCode(ctx context.Context, membershipID uuid.UUID, ttl time.Duration, actor store.Identity) (*wire.EnrollmentCodeResponse, error) {
	if ttl <= 0 {
		ttl = DefaultCodeTTL
	}

	plaintext, stored, err := NewCredential()
	if err != nil {
		return nil, err
	}
	expiresAt := s.clock().Add(ttl)

	err = s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, membershipID)
		if err != nil {
			return err
		}
		// A blocked host must not be re-enrollable; that would turn blocking
		// into a temporary inconvenience.
		if host.State == store.MembershipSuspended {
			return ErrHostBlocked
		}

		cred := store.EnrollmentCredential{
			NetworkID:    host.NetworkID,
			MembershipID: &host.ID,
			Method:       store.MethodCode,
			ExpiresAt:    expiresAt,
			CreatedBy:    actor.Subject,
		}
		if err := tx.CreateEnrollmentCredential(ctx, &cred, stored); err != nil {
			return err
		}
		return tx.AppendAudit(ctx,
			actor.Audit(store.ActionEnrollCodeCreated, "host", host.ID.String()))
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
	redeemed, err := s.store.RedeemEnrollmentCredential(ctx, Hash(req.Credential), from)
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
	if redeemed.MembershipID == nil {
		// Unreachable: membership_id is NOT NULL as of migration 0003. Kept as an
		// assertion because the alternative to failing here is inventing a
		// host, and a control plane that mints an identity out of a NULL is a
		// worse outcome than an error nobody ever sees.
		return nil, ErrNoHost
	}

	var resp *wire.EnrollResponse
	err = s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, *redeemed.MembershipID)
		if err != nil {
			return err
		}
		if host.State == store.MembershipSuspended {
			return ErrHostBlocked
		}

		out, err := s.issueAndRender(ctx, tx, host, req.PublicKey, req.Curve)
		if err != nil {
			return err
		}

		if err := tx.SetHostState(ctx, host.ID, store.MembershipEnrolled); err != nil {
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
			ActorType: store.ActorAgent, ActorID: host.ID.String(), ActorDisplay: host.Name,
			Action:     store.ActionEnrolled,
			TargetType: "host", TargetID: host.ID.String(),
			SourceIP: ip,
		}); err != nil {
			return err
		}

		if out.AgentEndpoints, err = s.agentEndpoints(ctx, tx, host.NetworkID); err != nil {
			return err
		}
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
			ActorType: store.ActorAgent,
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
	if redeemed.MembershipID != nil {
		target = redeemed.MembershipID.String()
	}

	err := s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: store.ActorAgent, ActorID: target,
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
//
// THE QUERY ERROR IS RETURNED, not swallowed — and that is the point, because
// of the line above. A failure used to be logged and turned into an empty
// slice, on the reasoning that failing an enrollment because a secondary field
// could not be built is worse than handing back none.
//
// The reasoning has a hole: an empty list is not "no answer" here, it is an
// ANSWER. The agent records it and stops looking for replicas over the overlay.
// Turning a database failure into that claim tells the machine something false
// and leaves nothing behind to attribute it to — an agent pinned to the public
// URL with no failover, and the cause three days earlier in a log nobody kept.
//
// It is also not really secondary. This runs inside the same transaction as the
// certificate insert, so a query failing here means that transaction is in
// trouble anyway. Failing the whole enrollment is the honest outcome: atomic,
// retried, and it says what went wrong.
func (s *Service) agentEndpoints(ctx context.Context, tx *store.Tx, networkID uuid.UUID) ([]string, error) {
	stale := s.cfg.ControlPlaneStaleAfter
	if stale <= 0 {
		stale = DefaultControlPlaneStaleAfter
	}

	live, err := tx.LiveControlPlanes(ctx, networkID, stale)
	if err != nil {
		return nil, fmt.Errorf("list control planes for network %s: %w", networkID, err)
	}

	out := make([]string, 0, len(live))
	for _, cp := range live {
		out = append(out, fmt.Sprintf("http://%s:%d", cp.Addr, cp.AgentPort))
	}
	return out, nil
}

// Renew issues a fresh certificate for an already-enrolled host.
//
// Identity comes from the caller, which on the overlay-bound agent API is the
// verified source address rather than anything in the request body.
func (s *Service) Renew(ctx context.Context, membershipID uuid.UUID, req wire.RenewRequest) (*wire.EnrollResponse, error) {
	var resp *wire.EnrollResponse
	err := s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, membershipID)
		if err != nil {
			return err
		}
		if host.State == store.MembershipSuspended {
			return ErrHostBlocked
		}

		out, err := s.issueAndRender(ctx, tx, host, req.PublicKey, req.Curve)
		if err != nil {
			return err
		}
		if err := tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: store.ActorAgent, ActorID: host.ID.String(), ActorDisplay: host.Name,
			Action:     store.ActionCertificateIssued,
			TargetType: "host", TargetID: host.ID.String(),
		}); err != nil {
			return err
		}
		if out.AgentEndpoints, err = s.agentEndpoints(ctx, tx, host.NetworkID); err != nil {
			return err
		}
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
func (s *Service) State(ctx context.Context, membershipID uuid.UUID, knownConfig, knownBlock int64) (*wire.StateResponse, error) {
	var resp wire.StateResponse
	err := s.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, membershipID)
		if err != nil {
			return err
		}
		net, err := tx.GetNetwork(ctx, host.NetworkID)
		if err != nil {
			return err
		}

		resp.ConfigEpoch = net.ConfigEpoch
		resp.BlocklistEpoch = net.BlocklistEpoch

		// The one generation an agent must not merely reload.
		//
		// Sent on every poll rather than only while the agent is behind, for the
		// same reason the certificate window is: a steady-state poll returns no
		// config, and an agent that missed the one response carrying this would
		// never learn it needs to restart. It is a small integer and it is
		// idempotent — the agent compares it against the generation it last
		// restarted for — so repeating it costs nothing and losing it costs a
		// host that quietly runs the wrong certificate forever.
		resp.RestartRequiredEpoch = host.RestartRequiredEpoch
		resp.NetworkSlug = net.Slug

		certs, err := tx.ActiveCertificates(ctx, host.ID)
		if err != nil {
			return err
		}
		if len(certs) > 0 {
			// The highest version is the one the host leads with.
			c := certs[len(certs)-1]
			resp.RenewAfter = c.RenewAt()
			resp.NotAfter = c.NotAfter

			// Pull renewal forward when this host's certificate predates its
			// role's last groups change.
			//
			// Groups are inside the signed certificate, so a role edit does not
			// reach a host until it renews — at its own midpoint, hours away.
			// For an access-control change that is not latency, it is a window
			// in which the policy an operator has been told is live is not.
			//
			// Sending "now" does not stampede: the agent spreads a pulled-forward
			// hint across PullForwardSpread using its own deterministic per-host
			// offset (internal/agent/renew.go, RenewAtWithHint), and clamps it
			// into the certificate's validity window. It also ignores a hint that
			// merely restates the midpoint, which is why this must be the only
			// place that sends anything else — the unconditional midpoint above
			// is precisely the value the agent is documented to disregard.
			//
			// Cost of being wrong is one early signature. Cost of not doing it is
			// a policy change that silently takes half a certificate lifetime.
			if host.RoleID != nil {
				changed, err := tx.RoleGroupsChangedAt(ctx, *host.RoleID)
				if err != nil {
					return err
				}
				if changed != nil && c.IssuedAt.Before(*changed) {
					resp.RenewAfter = s.clock()
				}
			}

			// The same mechanism for an address change, and a stronger reason
			// for it.
			//
			// Stale groups are a policy that has not taken effect yet. A stale
			// ADDRESS is a certificate that no longer authorises the packets the
			// host is sending: nebula's firewall verifies on every packet that a
			// peer's source address appears in its certificate, so once the
			// address moves the host is not merely behind, it is off the mesh
			// until it reissues. Waiting out half a certificate lifetime for
			// that is downtime, not latency.
			// ROUTES for the same reason, and it is the same failure. Nebula
			// reads routing authority from the certificate, so a gateway whose
			// routes changed after its certificate was issued is not merely
			// behind — it will refuse to carry the prefix the control plane has
			// already told every other machine to reach through it. Without
			// this, `orbit route add` succeeded and did nothing until the
			// ordinary renewal, half a certificate lifetime later.
			if certStale(c.IssuedAt, host.AddrChangedAt, host.RoutesChangedAt) {
				resp.RenewAfter = s.clock()
			}
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
		resp.ConfigSig, err = s.signMaterial(ctx, net, host.ID.String(), resp.Config, resp.CABundle)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// signMaterial produces the proof that this control plane rendered a
// generation.
//
// Called wherever material is put on the wire, and the call is not optional: an
// agent that accepts unsigned material has none of the property this exists for,
// so a rendering path that forgot to sign would silently opt its hosts out. Both
// producers — issueAndRender and State — go through here for that reason.
func (s *Service) signMaterial(ctx context.Context, net *store.Network,
	membershipID, config, bundle string) (*wire.ConfigSignature, error) {

	priv, err := s.networkIdentity(ctx, net)
	if err != nil {
		return nil, err
	}
	e := ca.NewConfigEnvelope(net.NetworkID, membershipID,
		net.ConfigEpoch, net.BlocklistEpoch, config, bundle)
	sig, err := ca.SignConfig(priv, e)
	if err != nil {
		return nil, err
	}
	return &wire.ConfigSignature{
		NetworkID:      e.NetworkID,
		MembershipID:   e.MembershipID,
		ConfigEpoch:    e.ConfigEpoch,
		BlocklistEpoch: e.BlocklistEpoch,
		ConfigSHA256:   e.ConfigSHA256,
		CABundleSHA256: e.CABundleSHA256,
		Signature:      base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// issueAndRender mints a certificate and renders the matching configuration.
func (s *Service) issueAndRender(ctx context.Context, tx *store.Tx, host *store.Membership, pubKeyB64, curveName string) (*wire.EnrollResponse, error) {
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

	// The prefixes this machine is allowed to route, INTO THE CERTIFICATE.
	//
	// This is what makes a route real. The route table is intent; nebula
	// requires the gateway's certificate to carry the prefix, and the issuer
	// refuses anything the CA does not permit — so a route the CA was never
	// widened for fails here, loudly, rather than rendering into a config that
	// silently reaches nobody.
	routes, err := tx.MembershipRoutes(ctx, host.ID)
	if err != nil {
		return nil, err
	}

	membershipCert, err := issuer.IssueHost(ctx, ca.HostParams{
		Name:           host.Name,
		Version:        cert.Version(net.CertVer),
		Networks:       networks,
		UnsafeNetworks: store.RoutePrefixes(routes),
		Groups:         groups,
		PublicKey:      pub,
		NotBefore:      notBefore,
		NotAfter:       notAfter,
	})
	if err != nil {
		return nil, fmt.Errorf("issue certificate: %w", err)
	}

	pem, err := membershipCert.MarshalPEM()
	if err != nil {
		return nil, err
	}
	fingerprint, err := membershipCert.Fingerprint()
	if err != nil {
		return nil, err
	}

	rec := store.Certificate{
		MembershipID: host.ID, CAID: caRow.ID, Fingerprint: fingerprint, PEM: string(pem),
		CertVer: net.CertVer, NotBefore: notBefore, NotAfter: notAfter,
	}
	if err := tx.InsertCertificate(ctx, &rec); err != nil {
		return nil, err
	}

	fragment, bundle, err := s.renderFor(ctx, tx, host, net)
	if err != nil {
		return nil, err
	}

	sig, err := s.signMaterial(ctx, net, host.ID.String(), string(fragment), bundle)
	if err != nil {
		return nil, err
	}

	return &wire.EnrollResponse{
		MembershipID:   host.ID.String(),
		ConfigSig:      sig,
		NetworkKey:     base64.StdEncoding.EncodeToString(net.IdentityPublicKey),
		MembershipName: host.Name,
		Certificate:    string(pem),
		CABundle:       bundle,
		Config:         string(fragment),
		ConfigEpoch:    net.ConfigEpoch,
		BlocklistEpoch: net.BlocklistEpoch,
		RenewAfter:     rec.RenewAt(),
		NotAfter:       notAfter,

		// Where this configuration goes, and what shape it is. The agent's very
		// first write happens here, before any state poll, so an agent that had
		// to guess would create one layout now and discover the other later —
		// leaving both on disk with nebula reading whichever the unit file
		// happens to name.
		NetworkSlug: net.Slug,
	}, nil
}

// instance resolves the per-(host, network) settings a rendered configuration
// needs.
//
// Three levels with one rule: the host's value, then the network's, then the
// control plane's. A deployment that has set none behaves exactly as it did
// before any of these columns existed, which is what keeps this from re-porting
// a running fleet on the next poll.
type instance struct {
	paths      nebulacfg.Paths
	listenPort int
	tunDev     string
	overrides  map[string]any
}

func (s *Service) instanceFor(host *store.Membership, net *store.Network) (instance, error) {
	// A directory per network, which is what lets one machine run two nebulas
	// without their config directories overlapping.
	in := instance{paths: nebulacfg.PathsFor(net.Slug)}

	switch {
	case host.ListenPort != nil:
		in.listenPort = *host.ListenPort
	case net.ListenPort != nil:
		in.listenPort = *net.ListenPort
	default:
		in.listenPort = s.cfg.ListenPort
	}

	in.tunDev = host.TunDev
	if in.tunDev == "" {
		in.tunDev = nebulacfg.TunDevSuggestion(net.Slug)
	}

	netOv, err := nebulacfg.ParseOverrides(net.Overrides)
	if err != nil {
		return instance{}, err
	}
	hostOv, err := nebulacfg.ParseOverrides(host.Overrides)
	if err != nil {
		return instance{}, err
	}
	in.overrides = nebulacfg.MergeOverrides(netOv, hostOv)
	return in, nil
}

// renderFor assembles a host's configuration and trust bundle.
func (s *Service) renderFor(ctx context.Context, tx *store.Tx, host *store.Membership, net *store.Network) ([]byte, string, error) {
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
				VpnAddr: th.Addrs[0], StaticAddrs: th.StaticAddrs(s.cfg.ListenPort),
			})
		}
		if th.IsRelay {
			relays = append(relays, th.Addrs[0])
		}
	}

	// Routes this host may reach through somebody else. Its OWN routes are
	// excluded: a gateway reaches its prefix on a real interface, and pointing
	// it back through the overlay at itself is a loop.
	// The exit node this host CHOSE, if any. Not automatic: a default route
	// captures everything, so it is rendered only for a machine that asked.
	exit, err := tx.ExitRoute(ctx, host.ID)
	if err != nil {
		return nil, "", err
	}

	routes, err := s.routesFor(ctx, tx, host, net, exit)
	if err != nil {
		return nil, "", err
	}

	// What THIS host forwards for, which is the other half: routesFor excluded
	// its own prefixes because it reaches them on a real interface, but it still
	// has to be told to enable forwarding and NAT them.
	own, err := tx.MembershipRoutes(ctx, host.ID)
	if err != nil {
		return nil, "", err
	}
	serves := make([]nebulacfg.Served, 0, len(own))
	for _, r := range own {
		serves = append(serves, nebulacfg.Served{Prefix: r.Prefix, Masquerade: r.Masquerade})
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

	compiled, err := s.compilePolicy(ctx, tx, host, net)
	if err != nil {
		return nil, "", err
	}

	inst, err := s.instanceFor(host, net)
	if err != nil {
		return nil, "", err
	}

	tunDisabled := host.IsLighthouse && !host.IsRelay
	tunDev := inst.tunDev
	if tunDisabled {
		// Naming a device nebula will not create is noise at best and a
		// misleading answer to "which interface is this host on" at worst.
		tunDev = ""
	}

	names, err := namesFor(ctx, tx, net)
	if err != nil {
		return nil, "", err
	}

	fragment, err := nebulacfg.Render(nebulacfg.Input{
		DNSDomain:    dnsDomainFor(net),
		DNSListen:    firstAddr(host.Addrs),
		Names:        names,
		Paths:        inst.paths,
		AmLighthouse: host.IsLighthouse,
		AmRelay:      host.IsRelay,
		Lighthouses:  lighthouses,
		Relays:       relays,
		Blocklist:    blocklist,
		Firewall:     fw,
		Policy:       compiled,
		Routes:       routes,
		Serves:       serves,
		SoMark:       soMarkFor(exit),
		ListenPort:   inst.listenPort,
		TunDev:       tunDev,
		// A lighthouse with no tun device needs no root. Only safe when it is
		// not also a relay, since relaying is a data-plane role.
		TunDisabled: tunDisabled,
		Overrides:   inst.overrides,
	})
	if err != nil {
		return nil, "", err
	}
	return fragment, bundle, nil
}

// DefaultRouteSoMark is the packet mark nebula puts on its own traffic when
// this host has a default route.
//
// A constant rather than a setting: the mark only has to be unique among the
// things marking packets on one machine, and a knob would be a number two
// operators pick differently for no benefit. 0x4242 is chosen to be recognisable
// in `nft list ruleset` and outside the ranges systemd-networkd and Docker use.
const DefaultRouteSoMark = 0x4242

// soMarkFor returns the mark, or zero when this host has no default route.
//
// Zero omits so_mark entirely, which matters: the setting is Linux-only, and
// emitting it on a Mac's configuration would be a key nebula ignores there but
// that reads as though something is configured.
func soMarkFor(exit *store.Route) int {
	if exit == nil {
		return 0
	}
	return DefaultRouteSoMark
}

// routesFor groups a network's routes by prefix, ready to render.
//
// Grouping is the point: two memberships offering one prefix become one
// unsafe_routes entry with two `via` gateways, which is what makes nebula load
// balance and fail between them. One entry each would be accepted and treated
// as a single path, losing exactly the redundancy that motivated the second
// gateway.
//
// A host's own routes are excluded. It reaches those on its own interfaces, and
// an unsafe_route naming itself as the gateway is a loop nebula has no reason
// to detect.
func (s *Service) routesFor(ctx context.Context, tx *store.Tx,
	host *store.Membership, net *store.Network, exit *store.Route) ([]nebulacfg.Route, error) {

	rows, err := tx.NetworkRoutes(ctx, net.ID)
	if err != nil {
		return nil, err
	}

	// NetworkRoutes orders by prefix, so a linear pass groups them and the
	// output order is the query's — deterministic, which matters because the
	// rendered configuration is signed and a reordering would change its digest
	// and re-apply a configuration that had not changed.
	var out []nebulacfg.Route
	for _, r := range rows {
		if r.MembershipID == host.ID {
			continue
		}
		// A DEFAULT route reaches only the machine that asked for it. Rendering
		// every 0.0.0.0/0 in the network to everybody would move a whole
		// fleet's internet traffic through whichever gateway somebody added
		// most recently — a change nobody made, visible as a latency complaint
		// a week later.
		if r.Prefix.Bits() == 0 && (exit == nil || exit.ID != r.ID) {
			continue
		}
		mtu := 0
		if r.MTU != nil {
			mtu = *r.MTU
		}
		if n := len(out); n > 0 && out[n-1].Prefix == r.Prefix {
			out[n-1].Gateways = append(out[n-1].Gateways,
				nebulacfg.Gateway{Addr: r.GatewayAddr, Weight: r.Weight})
			continue
		}
		out = append(out, nebulacfg.Route{
			Prefix:   r.Prefix,
			MTU:      mtu,
			Install:  r.Install,
			Gateways: []nebulacfg.Gateway{{Addr: r.GatewayAddr, Weight: r.Weight}},
		})
	}
	return out, nil
}

// compilePolicy resolves the network's policy into this host's rules, or
// returns nil when the network has none.
//
// Nil is the answer for every network that has not opted in, and it is the
// answer that leaves the render byte-identical to what it was before this
// existed. Anything else here is a change to a running fleet's firewall.
func (s *Service) compilePolicy(ctx context.Context, tx *store.Tx, host *store.Membership, net *store.Network) (*policy.Ruleset, error) {
	if s.cfg.Policy == nil {
		return nil, nil
	}
	raw, fleet, err := s.cfg.Policy(ctx, tx, net.ID)
	if err != nil {
		return nil, fmt.Errorf("read policy for network %s: %w", net.Slug, err)
	}
	if len(raw) == 0 {
		return nil, nil
	}

	doc, err := policy.Parse(raw)
	if err != nil {
		// Refusing to render is the right failure. A stored document that no
		// longer compiles — because a host it named was deleted — must not
		// silently degrade to "no rules", which in authoritative mode is
		// "nothing may talk to this host".
		return nil, fmt.Errorf("network %s policy: %w", net.Slug, err)
	}

	mgmt, err := s.managementEndpoints(ctx, tx, net.ID)
	if err != nil {
		return nil, err
	}

	c := policy.Compiler{
		Fleet:      policy.Snapshot{Members: fleet, CIDRs: net.CIDRs},
		Management: mgmt,
	}
	rs, err := c.Membership(doc, host.ID.String())
	if err != nil {
		return nil, fmt.Errorf("compile policy for host %s: %w", host.Name, err)
	}
	return &rs, nil
}

// managementEndpoints is the control plane reachability the compiled policy may
// not remove.
//
// Read from the live registry, the same source agentEndpoints uses, so the
// floor names the replicas that actually exist rather than a configured guess.
//
// THE ERROR IS RETURNED, and here it matters more than anywhere else. This is
// the reachability the compiled policy may NOT remove — the rules that keep a
// host able to reach the control plane whatever else the policy says. Rendering
// no floor because a query failed hands the machine a configuration that can
// lock it away from the only thing able to fix it, and does so silently. That
// is the one failure mode with no way back over the network.
func (s *Service) managementEndpoints(ctx context.Context, tx *store.Tx, networkID uuid.UUID) ([]policy.Endpoint, error) {
	stale := s.cfg.ControlPlaneStaleAfter
	if stale <= 0 {
		stale = DefaultControlPlaneStaleAfter
	}
	live, err := tx.LiveControlPlanes(ctx, networkID, stale)
	if err != nil {
		return nil, fmt.Errorf("list control planes for the policy management floor "+
			"of network %s: %w", networkID, err)
	}
	out := make([]policy.Endpoint, 0, len(live))
	for _, cp := range live {
		out = append(out, policy.Endpoint{Addr: cp.Addr, Port: cp.AgentPort})
	}
	return out, nil
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

// parseCurve is ca.ParseCurve plus the wire's compatibility default: an agent
// that sends no curve at all is talking about CURVE25519, which is what every
// agent predating P-256 support meant.
func parseCurve(name string) (cert.Curve, error) {
	if name == "" {
		return cert.Curve_CURVE25519, nil
	}
	return ca.ParseCurve(name)
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
	MembershipID uuid.UUID
	Config       string
	Certificate  string
	CABundle     string
	PrivateKey   string
	NotAfter     time.Time
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
	// PublicAddrs are the public HOSTS other machines dial — no ports. The port
	// comes from this membership's listen port, because two networks on one
	// machine cannot share one; see migration 0019.
	//
	// A lighthouse without them is unreachable and is skipped when rendering.
	PublicAddrs []string

	// AdvertisePort overrides the bound port, for a control plane behind port
	// forwarding.
	AdvertisePort *int

	// ListenPort is the UDP port this node's nebula actually binds.
	//
	// It has to be recorded, not inferred. What other machines dial is derived
	// as (device public address) : (this membership's port), so a membership
	// with no listen_port falls through to the network's default and then the
	// control plane's — and a control plane started on a port that is neither
	// would advertise itself somewhere nothing is listening. That used to be
	// invisible because static_addrs stored the "host:port" string whole.
	ListenPort int
}

// listenPortOf returns the port to record, or nil when the caller did not say.
//
// Zero is not a port, and storing it would mean "bind port 0" to every reader.
func listenPortOf(roles SelfIssueRoles) *int {
	if roles.ListenPort <= 0 {
		return nil
	}
	p := roles.ListenPort
	return &p
}

// deviceKey is the control plane's own device public key, DER SPKI.
//
// The control plane is a machine on its own network, and under the device model
// a membership names one — there is no "system" exemption, and adding one would
// mean a nullable column and a nil branch on every read, for exactly one row.
//
// It is the SAME key for every network this instance joins, because it is one
// machine. That falls out of the model rather than being arranged: a device
// outlives every network it joins.
func (s *Service) SelfIssue(ctx context.Context, networkID uuid.UUID, addr netip.Addr, name string, deviceKey []byte, roles SelfIssueRoles) (*SelfIssued, error) {
	var out *SelfIssued

	var created bool
	err := s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		net, err := tx.GetNetwork(ctx, networkID)
		if err != nil {
			return err
		}
		if !net.ContainsAddr(addr) {
			// Named by slug rather than by name: the slug is what an operator
			// passes back on the command line, and it is the one that will still
			// be correct after someone edits the display name.
			return fmt.Errorf("%s is not within network %s (%v)", addr, net.Slug, net.CIDRs)
		}

		// Recorded on every start, not only on first creation: last_seen_at is
		// how an operator tells a running control plane from a stale row, and
		// the control plane is the one machine that never reports through the
		// agent API.
		self := store.Device{
			PublicKey: deviceKey,
			Hostname:  name,
		}
		if err := tx.SeeDevice(ctx, &self); err != nil {
			return fmt.Errorf("record the control plane device: %w", err)
		}
		if self.Blocked() {
			// Blocking the control plane's own device would otherwise be a
			// silent way to break every start after the next one. Refusing
			// loudly is better than a mesh node that never comes up.
			return fmt.Errorf("%w: this control plane's own device (%s)",
				store.ErrDeviceBlocked, self.KeyFingerprint)
		}

		host, err := tx.FindHostByAddr(ctx, networkID, addr)
		switch {
		case errors.Is(err, store.ErrNotFound):
			host = &store.Membership{
				NetworkID:    networkID,
				Name:         name,
				Addrs:        []netip.Addr{addr},
				State:        store.MembershipActive,
				Tags:         []string{"orbit-control-plane"},
				IsLighthouse: roles.IsLighthouse,
				IsRelay:      roles.IsRelay,
				DeviceID:     &self.ID,
				// Both ports, so this membership's advertised address can be
				// derived without reaching for a default that is not this
				// node's. Nil AdvertisePort is the common case and means "the
				// port we bind is the port that reaches us".
				ListenPort:    listenPortOf(roles),
				AdvertisePort: roles.AdvertisePort,
			}
			if err := tx.CreateHost(ctx, host); err != nil {
				return fmt.Errorf("create control plane host: %w", err)
			}
			// The addresses go on the DEVICE, because that is what they are:
			// this machine's public addresses, shared by every network it
			// lights. Seeded only at creation, like the roles above — after
			// that the record is the source of truth and `orbit device
			// set-addrs` is how it changes.
			if len(roles.PublicAddrs) > 0 {
				if err := tx.SetDevicePublicAddrs(ctx, self.ID, roles.PublicAddrs); err != nil {
					return fmt.Errorf("seed control plane public addresses: %w", err)
				}
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
			MembershipID: host.ID,
			Config:       resp.Config,
			Certificate:  resp.Certificate,
			CABundle:     resp.CABundle,
			PrivateKey:   string(cert.MarshalPrivateKeyToPEM(curve, priv)),
			NotAfter:     resp.NotAfter,
			Created:      created,
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
// ReportControlPlaneApplied records the generation the control plane is now
// running, against its own host record.
//
// The control plane is a mesh member and Convergence counts it like any other
// host. Without this its applied epoch stays at 0 forever, convergence can
// never read 100%, and CA activation — which refuses while any host is behind —
// becomes permanently impossible. The failure is silent until somebody needs to
// rotate a compromised CA.
//
// It reuses RecordAgentReport rather than writing the columns directly, so the
// control plane converges by exactly the rule every other host converges by:
// the same monotonicity, the same last_seen_at, the same audit behaviour.
// AgentVersion is Orbit's own build, because on this host the agent and the
// control plane are the same process.
func (s *Service) ReportControlPlaneApplied(ctx context.Context, membershipID uuid.UUID, configEpoch, blocklistEpoch int64) error {
	return s.store.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		return tx.RecordAgentReport(ctx, membershipID, store.AgentReport{
			ConfigEpoch:    configEpoch,
			BlocklistEpoch: blocklistEpoch,
			AgentVersion:   version.Version,
		})
	})
}

// ControlPlaneEpochs reports the network generation the control plane's host
// record belongs to, so a caller that has just applied a rendered config knows
// which generation it applied.
func (s *Service) ControlPlaneEpochs(ctx context.Context, membershipID uuid.UUID) (configEpoch, blocklistEpoch int64, err error) {
	err = s.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, membershipID)
		if err != nil {
			return err
		}
		net, err := tx.GetNetwork(ctx, host.NetworkID)
		if err != nil {
			return err
		}
		configEpoch, blocklistEpoch = net.ConfigEpoch, net.BlocklistEpoch
		return nil
	})
	return configEpoch, blocklistEpoch, err
}

func (s *Service) ControlPlaneMaterial(ctx context.Context, membershipID uuid.UUID) (config, caBundle string, err error) {
	err = s.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, membershipID)
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
func (s *Service) ControlPlaneCertificate(ctx context.Context, membershipID uuid.UUID) (notBefore, notAfter time.Time, err error) {
	err = s.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		certs, err := tx.ActiveCertificates(ctx, membershipID)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			return fmt.Errorf("control plane host %s has no active certificate", membershipID)
		}
		c := certs[len(certs)-1]
		notBefore, notAfter = c.NotBefore, c.NotAfter
		return nil
	})
	return notBefore, notAfter, err
}

// HostRoles reads a host's current data-plane roles.
func (s *Service) HostRoles(ctx context.Context, membershipID uuid.UUID) (*store.Membership, error) {
	var h *store.Membership
	err := s.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		var err error
		h, err = tx.GetHost(ctx, membershipID)
		return err
	})
	return h, err
}

// DNSSuffix is the parent domain every network's names sit under.
//
// .internal, because ICANN reserved it for exactly this in 2024 and it can
// therefore never be delegated to somebody else. A made-up TLD works until the
// day it does not, and the failure is a machine resolving an internal name to a
// stranger's server.
const DNSSuffix = "internal"

// dnsDomainFor is the search domain for a network.
//
// The SLUG, not the display name. UpdateNetworkName changes the label and
// nothing else, so a rename must not move every machine's fully-qualified name
// out from under whatever is using it.
func dnsDomainFor(net *store.Network) string {
	if net.Slug == "" {
		return ""
	}
	return net.Slug + "." + DNSSuffix
}

// namesFor is the name table this network's hosts resolve locally.
//
// Every reachable machine, not just the ones this host may talk to. Policy
// decides what a connection can do; hiding a name would only mean a failure
// surfaces as "no such host" rather than as the refusal it actually is, which
// is harder to diagnose and no more private — the address is in the
// certificate the moment a handshake is attempted.
func namesFor(ctx context.Context, tx *store.Tx, net *store.Network) ([]nebulacfg.Name, error) {
	rows, err := tx.NetworkNames(ctx, net.ID)
	if err != nil {
		return nil, err
	}
	out := make([]nebulacfg.Name, 0, len(rows))
	for _, r := range rows {
		out = append(out, nebulacfg.Name{Name: r.Name, Addr: r.Addr})
	}
	return out, nil
}

// firstAddr is where this host's resolver binds. Zero when the membership has
// no address yet, which renders no dns section at all rather than one that
// cannot be served.
func firstAddr(addrs []netip.Addr) netip.Addr {
	if len(addrs) == 0 {
		return netip.Addr{}
	}
	return addrs[0]
}

// certStale reports whether a certificate predates any change that belongs in it.
//
// Variadic over the timestamps rather than a chain of comparisons, so adding the
// next thing that lives in a certificate is one argument and not another branch
// somebody can forget to write.
func certStale(issuedAt time.Time, changes ...*time.Time) bool {
	for _, at := range changes {
		if at != nil && issuedAt.Before(*at) {
			return true
		}
	}
	return false
}
