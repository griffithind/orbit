package web

import (
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/store"
)

// View models, and the reason they exist.
//
// Templates receive these rather than store types directly. That costs a
// conversion per screen and buys two things worth more: every decision about
// what a state MEANS — is this host behind, is this certificate overdue, is this
// rotation finishable — happens in Go where a test can assert it, and no
// template ever has to reach three fields deep into a struct it cannot be
// type-checked against.

//------------------------------------------------------------------------------
// Status, which is never colour alone
//------------------------------------------------------------------------------

// badge is one status, rendered as a glyph AND a word AND a colour.
//
// All three, always. This gets read on a phone, outdoors, at night, by someone
// who may be colourblind and is certainly in a hurry — and the failure mode of
// colour-only status is not "slightly harder to read", it is an operator who
// sees green where the system said red. The glyph survives a greyscale
// screenshot pasted into a ticket; the word survives everything.
type badge struct {
	Glyph string
	Word  string
	// Tone selects the CSS class: ok, warn, bad, or muted. It is the *third*
	// signal, never the only one.
	Tone string
}

var (
	badgeOK      = func(w string) badge { return badge{Glyph: "✓", Word: w, Tone: "ok"} }
	badgeWarn    = func(w string) badge { return badge{Glyph: "▲", Word: w, Tone: "warn"} }
	badgeBad     = func(w string) badge { return badge{Glyph: "✕", Word: w, Tone: "bad"} }
	badgeMuted   = func(w string) badge { return badge{Glyph: "·", Word: w, Tone: "muted"} }
	badgeOverdue = badge{Glyph: "!", Word: "OVERDUE", Tone: "bad"}
)

// hostStateBadge renders a host's lifecycle state.
func hostStateBadge(state string) badge {
	switch state {
	case store.HostActive:
		return badgeOK("active")
	case store.HostEnrolled:
		return badgeOK("enrolled")
	case store.HostCreated:
		// Not a fault, but not a working host either: it holds no certificate and
		// cannot appear in convergence at all.
		return badgeMuted("awaiting enrollment")
	case store.HostSuspended:
		return badgeBad("blocked")
	case store.HostDeleted:
		return badgeMuted("deleted")
	default:
		return badgeMuted(state)
	}
}

func caStateBadge(state string) badge {
	switch state {
	case store.CAActive:
		return badgeOK("active — signing")
	case store.CAPending:
		return badgeWarn("pending — distributed, not signing")
	case store.CARetiring:
		return badgeWarn("retiring — trusted, not signing")
	case store.CARetired:
		return badgeMuted("retired — not distributed")
	default:
		return badgeMuted(state)
	}
}

//------------------------------------------------------------------------------
// Networks
//------------------------------------------------------------------------------

type networkView struct {
	ID             string
	Slug           string
	Name           string
	CIDRs          []string
	ConfigEpoch    int64
	BlocklistEpoch int64
	FirewallSource string
	ConfigMode     string
	CertTTL        string
}

func newNetworkView(n *store.Network) networkView {
	v := networkView{
		ID:             n.ID.String(),
		Slug:           n.Slug,
		Name:           n.Name,
		ConfigEpoch:    n.ConfigEpoch,
		BlocklistEpoch: n.BlocklistEpoch,
		FirewallSource: n.FirewallSource,
		ConfigMode:     n.ConfigMode,
		CertTTL:        n.CertTTL.String(),
	}
	for _, c := range n.CIDRs {
		v.CIDRs = append(v.CIDRs, c.String())
	}
	return v
}

//------------------------------------------------------------------------------
// Hosts
//------------------------------------------------------------------------------

type hostView struct {
	ID    string
	Name  string
	State string
	Badge badge

	OverlayAddrs []string
	RoleID       string
	RoleName     string
	Tags         []string

	IsLighthouse bool
	IsRelay      bool
	StaticAddrs  []string

	NebulaVersion string
	AgentVersion  string

	LastSeenAt *time.Time
	CreatedAt  time.Time

	AppliedConfigEpoch    int64
	AppliedBlocklistEpoch int64
	ConfigEpoch           int64
	BlocklistEpoch        int64

	// ConfigBadge and BlockBadge compare the applied epoch against the network's.
	// Computed here rather than in the template because "behind" has a definition
	// — and it is the same one HostFilter.Behind and Convergence use, which is the
	// only reason the number on this page can be trusted to agree with the number
	// on the overview.
	ConfigBadge badge
	BlockBadge  badge

	RestartRequiredEpoch int64
	RestartPending       bool

	ListenPort int
	// ListenPortLabel is what the page shows: the number, or a sentence when the
	// host inherits a default this process cannot see.
	ListenPortLabel string
	TunDev          string
	ConfigMode      string
}

func newHostView(h *store.Host, n *store.Network) hostView {
	v := hostView{
		ID:    h.ID.String(),
		Name:  h.Name,
		State: h.State,
		Badge: hostStateBadge(h.State),

		OverlayAddrs: addrStrings(h.Addrs),
		RoleName:     h.RoleName,
		Tags:         h.Tags,

		IsLighthouse: h.IsLighthouse,
		IsRelay:      h.IsRelay,
		StaticAddrs:  h.StaticAddrs,

		NebulaVersion: h.NebulaVersion,
		AgentVersion:  h.AgentVersion,
		LastSeenAt:    h.LastSeenAt,
		CreatedAt:     h.CreatedAt,

		AppliedConfigEpoch:    h.AppliedConfigEpoch,
		AppliedBlocklistEpoch: h.AppliedBlocklistEpoch,

		RestartRequiredEpoch: h.RestartRequiredEpoch,
		TunDev:               h.TunDev,
		ConfigMode:           h.ConfigMode,
	}
	if h.RoleID != nil {
		v.RoleID = h.RoleID.String()
	}
	if h.ListenPort != nil {
		v.ListenPort = *h.ListenPort
	}

	if n != nil {
		v.ConfigEpoch = n.ConfigEpoch
		v.BlocklistEpoch = n.BlocklistEpoch
		v.ConfigBadge = epochBadge(h.AppliedConfigEpoch, n.ConfigEpoch, h.State)
		v.BlockBadge = epochBadge(h.AppliedBlocklistEpoch, n.BlocklistEpoch, h.State)

		// A restart is outstanding when the host has applied the generation that
		// demanded one but nebula has not yet been restarted for it. The store
		// records only the epoch, so "pending" is the comparison — and it stays
		// true until a later generation supersedes it.
		v.RestartPending = h.RestartRequiredEpoch > 0 &&
			h.AppliedConfigEpoch < h.RestartRequiredEpoch

		// The same inheritance api.hostResponse resolves, and a short obvious
		// mirror of it rather than anything cleverer: reimplementing the
		// precedence differently is how a UI comes to report a value the rendered
		// configuration does not use.
		if v.ListenPort == 0 && n.ListenPort != nil {
			v.ListenPort = *n.ListenPort
		}
		if v.ConfigMode == "" {
			v.ConfigMode = n.ConfigMode
		}
		if v.TunDev == "" && v.ConfigMode != "" {
			v.TunDev = nebulacfg.TunDevSuggestion(n.Slug)
		}
	}

	// Zero means "whatever the control plane was started with", and this process
	// genuinely does not know that number — it is a flag on orbitd, not a stored
	// value. Rendering a literal 0 would be a port nobody listens on presented as
	// fact, so the page says what is actually true instead.
	v.ListenPortLabel = "the control plane's default"
	if v.ListenPort != 0 {
		v.ListenPortLabel = strconv.Itoa(v.ListenPort)
	}
	return v
}

// epochBadge compares an applied epoch against the network's current one.
//
// A host that has never enrolled is 'awaiting enrollment' rather than 'behind'.
// It has never held a certificate and can never report an epoch, so calling it
// behind would make the badge permanently red on a host that is not broken —
// the same reason HostFilter.Behind scopes itself to enrolled and active.
func epochBadge(applied, current int64, state string) badge {
	if state == store.HostCreated {
		return badgeMuted("not enrolled")
	}
	if applied >= current {
		return badgeOK(fmt.Sprintf("at %d", applied))
	}
	return badgeWarn(fmt.Sprintf("at %d, network is at %d", applied, current))
}

func addrStrings(addrs []netip.Addr) []string {
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

//------------------------------------------------------------------------------
// Certificates
//------------------------------------------------------------------------------

type certView struct {
	ID          string
	Fingerprint string
	// Short is the first 16 hex characters, which is what fits on a phone and
	// what an operator compares against a log line. The full value is still on
	// the page — truncating a fingerprint everywhere would make it impossible to
	// verify one.
	Short   string
	State   string
	Badge   badge
	CAID    string
	CAName  string
	CertVer int

	NotBefore time.Time
	NotAfter  time.Time
	RenewAt   time.Time
	IssuedAt  time.Time

	// Overdue means the renewal midpoint has passed and this certificate is
	// still the active one. THIS IS THE DIAGNOSIS. The agent renews at 50% of
	// lifetime precisely so the remaining half is recovery time; a certificate
	// past that point means renewal has been failing for a while and nobody has
	// noticed, and the host will drop off the mesh when the clock runs out.
	Overdue bool
	Expired bool
}

func newCertView(c store.CertificateRow, now time.Time) certView {
	v := certView{
		ID:          c.ID.String(),
		Fingerprint: c.Fingerprint,
		Short:       shortFingerprint(c.Fingerprint),
		State:       c.State,
		CAID:        c.CAID.String(),
		CAName:      c.CAName,
		CertVer:     int(c.CertVer),
		NotBefore:   c.NotBefore,
		NotAfter:    c.NotAfter,
		RenewAt:     c.RenewAt(),
		IssuedAt:    c.IssuedAt,
	}
	v.Expired = now.After(c.NotAfter)
	v.Overdue = c.State == store.CertActive && !v.Expired && now.After(v.RenewAt)

	switch {
	case c.State == store.CertRevoked:
		v.Badge = badgeBad("revoked")
	case v.Expired:
		v.Badge = badgeBad("expired")
	case c.State == store.CertSuperseded:
		v.Badge = badgeMuted("superseded")
	case c.State == store.CertPending:
		v.Badge = badgeMuted("pending")
	case v.Overdue:
		v.Badge = badgeOverdue
	default:
		v.Badge = badgeOK("active")
	}
	return v
}

func shortFingerprint(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16]
}

//------------------------------------------------------------------------------
// Diagnosis
//------------------------------------------------------------------------------

// finding is one observation about why a host is in the state it is in.
type finding struct {
	Badge   badge
	Summary string
	Detail  string
}

// diagnose answers the question the host detail page exists to answer: why is
// this host not renewing.
//
// It is a list rather than a single verdict on purpose. The real cases are
// compound — a host that is blocked AND was last seen an hour ago AND holds an
// overdue certificate signed by a CA that is retiring — and collapsing that to
// one line means the operator fixes the first thing and comes back.
//
// Ordered worst first, because the top of the list is what gets read.
func diagnose(h hostView, certs []certView, now time.Time, activeCAID string, hasActiveCA bool) []finding {
	var out []finding

	if h.State == store.HostSuspended {
		out = append(out, finding{
			Badge:   badgeBad("blocked"),
			Summary: "this host is blocked",
			Detail: "Its certificates are revoked and its fingerprints are in every " +
				"other host's blocklist. It cannot reach the overlay, so it cannot " +
				"renew, and it will keep appearing as behind for as long as it is blocked.",
		})
	}

	if !hasActiveCA {
		out = append(out, finding{
			Badge:   badgeBad("no active CA"),
			Summary: "this network has no certificate authority that can sign",
			Detail: "Renewal fails for every host in the network, not just this one, " +
				"and will keep failing until a CA is promoted. See the rotation page.",
		})
	}

	var active *certView
	for i := range certs {
		if certs[i].State == store.CertActive {
			active = &certs[i]
			break
		}
	}

	switch {
	case h.State == store.HostCreated:
		out = append(out, finding{
			Badge:   badgeMuted("never enrolled"),
			Summary: "this host has never enrolled",
			Detail: "It holds no certificate and has never contacted the control plane. " +
				"Hand it an enrollment code and run the agent on it.",
		})
	case active == nil:
		out = append(out, finding{
			Badge:   badgeBad("no active certificate"),
			Summary: "this host holds no active certificate",
			Detail: "It enrolled at some point but has nothing valid now. It cannot " +
				"reach the overlay, which means it cannot renew through the agent API — " +
				"recovery (proof of possession over the public listener) is the way back.",
		})
	case active.Expired:
		out = append(out, finding{
			Badge:   badgeBad("certificate expired"),
			Summary: "its certificate expired " + ago(active.NotAfter),
			Detail: "Nebula rejects an expired certificate before it consults anything " +
				"else, so this host is off the mesh and cannot renew over it.",
		})
	case active.Overdue:
		out = append(out, finding{
			Badge: badgeOverdue,
			Summary: "renewal was due " + ago(active.RenewAt) +
				" and has not happened; the certificate expires " + ago(active.NotAfter),
			Detail: "The agent renews at the midpoint of a certificate's lifetime so that " +
				"the remaining half is recovery time. Past that point, renewal has been " +
				"failing for a while — check when this host was last seen, and whether its " +
				"issuing CA is still able to sign.",
		})
	}

	if active != nil && activeCAID != "" && active.CAID != activeCAID {
		out = append(out, finding{
			Badge:   badgeWarn("signed by an older CA"),
			Summary: "its certificate was signed by " + active.CAName + ", which is no longer the signer",
			Detail: "That is normal during a rotation and resolves itself at the next " +
				"renewal. It becomes a problem if that CA is retired before this host " +
				"renews — retiring drops it from every trust bundle, and this host's " +
				"certificate stops verifying.",
		})
	}

	if h.State != store.HostCreated {
		switch {
		case h.LastSeenAt == nil:
			out = append(out, finding{
				Badge:   badgeBad("never reported"),
				Summary: "this host has never reported to the control plane",
				Detail: "It was issued a certificate but its agent has never checked in. " +
					"Either the agent is not running, or it cannot reach the agent API on " +
					"the overlay.",
			})
		case now.Sub(*h.LastSeenAt) > staleAfter:
			out = append(out, finding{
				Badge:   badgeWarn("silent"),
				Summary: "last seen " + ago(*h.LastSeenAt),
				Detail: "The agent polls far more often than this. A host this quiet is " +
					"powered off, has no route to the control plane, or is running an agent " +
					"that has stopped.",
			})
		}
	}

	if h.RestartPending {
		out = append(out, finding{
			Badge:   badgeWarn("restart required"),
			Summary: fmt.Sprintf("nebula must RESTART for generation %d, not reload", h.RestartRequiredEpoch),
			Detail: "This host's overlay addresses changed. Nebula refuses a certificate " +
				"reload whose networks differ, so it keeps running the old certificate " +
				"until the process restarts. Waiting does not help.",
		})
	}

	if len(out) == 0 {
		out = append(out, finding{
			Badge:   badgeOK("healthy"),
			Summary: "nothing is wrong with this host",
			Detail: "It is enrolled, converged, seen recently, and holds a current " +
				"certificate signed by the active CA.",
		})
	}
	return out
}

// staleAfter is how quiet a host has to be before the UI says so.
//
// Fifteen minutes is several agent poll intervals, not one: a host that missed a
// single poll is not interesting, and a diagnosis page that cries about it
// teaches an operator to skip the section that also carries the real findings.
const staleAfter = 15 * time.Minute

//------------------------------------------------------------------------------
// Convergence
//------------------------------------------------------------------------------

type convergenceView struct {
	ConfigEpoch    int64
	BlocklistEpoch int64
	HostsTotal     int
	ConfigApplied  int
	BlockApplied   int
	ConfigBadge    badge
	BlockBadge     badge
	Lagging        []laggingView
	// Truncated reports that the lagging list was capped, so a reader does not
	// take a list of 100 as the whole story.
	Truncated bool
}

type laggingView struct {
	HostID                string
	Name                  string
	AppliedConfigEpoch    int64
	AppliedBlocklistEpoch int64
	LastSeenAt            *time.Time
}

func newConvergenceView(c *store.Convergence, limit int) convergenceView {
	v := convergenceView{
		ConfigEpoch:    c.ConfigEpoch,
		BlocklistEpoch: c.BlocklistEpoch,
		HostsTotal:     c.HostsTotal,
		ConfigApplied:  c.ConfigApplied,
		BlockApplied:   c.BlockApplied,
		ConfigBadge:    convergedBadge(c.ConfigApplied, c.HostsTotal),
		BlockBadge:     convergedBadge(c.BlockApplied, c.HostsTotal),
		Truncated:      len(c.Lagging) >= limit,
	}
	for _, l := range c.Lagging {
		v.Lagging = append(v.Lagging, laggingView{
			HostID:                l.HostID.String(),
			Name:                  l.Name,
			AppliedConfigEpoch:    l.AppliedConfigEpoch,
			AppliedBlocklistEpoch: l.AppliedBlocklistEpoch,
			LastSeenAt:            l.LastSeenAt,
		})
	}
	return v
}

func convergedBadge(applied, total int) badge {
	switch {
	case total == 0:
		return badgeMuted("no hosts")
	case applied >= total:
		return badgeOK(fmt.Sprintf("%d of %d converged", applied, total))
	default:
		return badgeWarn(fmt.Sprintf("%d of %d converged", applied, total))
	}
}
