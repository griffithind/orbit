package web

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/store"
)

// The incident core.
//
// The overview answers, for one network and in one screen, the four questions
// asked at the start of every incident: has the fleet applied what it was told,
// who has not, whose certificates are about to run out, and is the control plane
// itself still whole. Nothing here is a chart. Prometheus already draws those,
// and a sparkline is a worse answer than a number and a name during the ten
// minutes this page exists for.

//------------------------------------------------------------------------------
// Navigation
//------------------------------------------------------------------------------

// navNetworkLimit is how many networks the header picker will list inline.
//
// It exists because the first version had no limit, and a deployment with a few
// hundred networks rendered every one of them as a link across the top of every
// page — pushing the actual content off the screen and making the header the
// largest thing in the product. Past the limit the picker collapses to a count
// and a link to the full list, which is the only shape that stays usable at both
// ends of the range.
//
// Eight rather than a rounder number: it is what fits on one line on a phone
// without wrapping into a block.
const navNetworkLimit = 8

// withNav fills in the network picker.
//
// One extra query per page, deliberately. A UI that cannot move between networks
// without going back to a menu is a UI that gets abandoned for the CLI on a
// deployment with more than one, and the query is a single scan of a table that
// has as many rows as the deployment has networks.
func (s *Server) withNav(ctx context.Context, p *pageData, current string) error {
	return s.store.Read(ctx, func(ctx context.Context, tx *store.Tx) error {
		nets, err := tx.ListNetworks(ctx)
		if err != nil {
			return err
		}
		p.NetworkCount = len(nets)
		p.CurrentNetwork = current

		if len(nets) > navNetworkLimit {
			// Still name the one being looked at, so the header says where you
			// are even when it cannot list the alternatives.
			for _, n := range nets {
				if n.ID.String() == current {
					p.Networks = []networkLink{{ID: n.ID.String(), Slug: n.Slug, Name: n.Name}}
					break
				}
			}
			return nil
		}

		for _, n := range nets {
			p.Networks = append(p.Networks, networkLink{
				ID: n.ID.String(), Slug: n.Slug, Name: n.Name,
			})
		}
		return nil
	})
}

// handleIndex is the front door.
//
// A deployment with exactly one network — which is most of them — should never
// see a list with one item on it, so it goes straight to that network's
// overview. The redirect is temporary rather than permanent: a second network
// created later must not be unreachable because a browser cached the hop.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) error {
	var nets []store.Network
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		nets, err = tx.ListNetworks(ctx)
		return err
	})
	if err != nil {
		return err
	}
	if len(nets) == 1 {
		http.Redirect(w, r, "/ui/networks/"+nets[0].ID.String(), http.StatusSeeOther)
		return nil
	}
	return s.renderNetworks(w, r, nets)
}

func (s *Server) handleNetworks(w http.ResponseWriter, r *http.Request) error {
	var nets []store.Network
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		nets, err = tx.ListNetworks(ctx)
		return err
	})
	if err != nil {
		return err
	}
	return s.renderNetworks(w, r, nets)
}

type networksView struct {
	Networks []networkView
}

func (s *Server) renderNetworks(w http.ResponseWriter, r *http.Request, nets []store.Network) error {
	p := s.newPage(r, "Networks")
	if err := s.withNav(r.Context(), p, ""); err != nil {
		return err
	}
	v := networksView{}
	for i := range nets {
		v.Networks = append(v.Networks, newNetworkView(&nets[i]))
	}
	p.Data = v
	return s.render(w, r, "networks.html", http.StatusOK, p)
}

//------------------------------------------------------------------------------
// Overview
//------------------------------------------------------------------------------

type overviewView struct {
	Network     networkView
	Convergence convergenceView

	// Expiring is the renewal work queue: active certificates already past the
	// midpoint of their lifetime. Not "expiring within 30 days" — the agent
	// renews at the midpoint, so anything past it is a renewal that has already
	// failed at least once, and that is the signal, hours or days before an
	// expiry that would show up in a naive countdown.
	Expiring []expiringView

	Replicas []replicaView
	Push     pushView

	CAs []caView
	// RotationInProgress is true when more than one CA is still distributed,
	// which is the whole of a rotation's visible state.
	RotationInProgress bool
}

type expiringView struct {
	HostID     string
	HostName   string
	Short      string
	RenewAt    time.Time
	NotAfter   time.Time
	LastSeenAt *time.Time
	Badge      badge
}

type replicaView struct {
	HostID     string
	Addr       string
	AgentPort  int
	LastSeenAt time.Time
}

// pushView describes the epoch push path.
//
// Push being down is not an outage — agents fall back to polling and converge
// correctly, an order of magnitude slower — but it is the difference between a
// revocation landing in seconds and landing in minutes, and that is worth
// knowing before someone stands watching a convergence number that is not going
// to move as fast as they expect.
type pushView struct {
	Configured bool
	Watchers   int
	Badge      badge
	Detail     string
}

const (
	// overviewLagging bounds the "who is behind" list on the overview. It is a
	// summary; the convergence page carries the full one.
	overviewLagging = 10
	// overviewExpiring bounds the renewal queue for the same reason.
	overviewExpiring = 10
)

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) error {
	networkID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}

	now := time.Now()
	var (
		net   *store.Network
		conv  *store.Convergence
		due   []store.Certificate
		names map[uuid.UUID]*store.Host
		live  []store.ControlPlane
		cas   []store.CA
		certs map[uuid.UUID]int
	)
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if net, err = tx.GetNetwork(ctx, networkID); err != nil {
			return err
		}
		if conv, err = tx.Convergence(ctx, networkID, overviewLagging); err != nil {
			return err
		}
		if due, err = tx.CertificatesDueForRenewal(ctx, networkID, now, overviewExpiring); err != nil {
			return err
		}
		// One host lookup per overdue certificate, bounded by overviewExpiring.
		// The same tradeoff internal/api makes on the expiring endpoint, and for
		// the same reason: a fingerprint with no host name sends the reader
		// somewhere else for every row.
		names = map[uuid.UUID]*store.Host{}
		for _, c := range due {
			if _, seen := names[c.HostID]; seen {
				continue
			}
			h, err := tx.GetHost(ctx, c.HostID)
			if err != nil {
				return err
			}
			names[c.HostID] = h
		}

		// The same staleness bound agents are handed in EnrollResponse, not a
		// second opinion: an operator asking which replicas are live must get the
		// answer the fleet is already acting on.
		if live, err = tx.LiveControlPlanes(ctx, networkID,
			now.Add(-enroll.DefaultControlPlaneStaleAfter)); err != nil {
			return err
		}

		if cas, err = tx.ListCAs(ctx, networkID); err != nil {
			return err
		}
		certs = map[uuid.UUID]int{}
		for i := range cas {
			n, err := tx.ActiveCertificateCount(ctx, cas[i].ID)
			if err != nil {
				return err
			}
			certs[cas[i].ID] = n
		}
		return nil
	})
	if err != nil {
		return err
	}

	v := overviewView{
		Network:     newNetworkView(net),
		Convergence: newConvergenceView(conv, overviewLagging),
		Push:        s.pushStatus(networkID),
	}

	for _, c := range due {
		h := names[c.HostID]
		e := expiringView{
			HostID:   c.HostID.String(),
			Short:    shortFingerprint(c.Fingerprint),
			RenewAt:  c.RenewAt(),
			NotAfter: c.NotAfter,
		}
		if h != nil {
			e.HostName = h.Name
			e.LastSeenAt = h.LastSeenAt
		}
		if now.After(c.NotAfter) {
			e.Badge = badgeBad("expired")
		} else {
			e.Badge = badgeOverdue
		}
		v.Expiring = append(v.Expiring, e)
	}

	for _, cp := range live {
		v.Replicas = append(v.Replicas, replicaView{
			HostID:     cp.HostID.String(),
			Addr:       cp.Addr.String(),
			AgentPort:  cp.AgentPort,
			LastSeenAt: cp.LastSeenAt,
		})
	}

	distributed := 0
	for i := range cas {
		v.CAs = append(v.CAs, newCAView(&cas[i], certs[cas[i].ID], now))
		if cas[i].State != store.CARetired {
			distributed++
		}
	}
	v.RotationInProgress = distributed > 1

	p := s.newPage(r, net.Name)
	if err := s.withNav(r.Context(), p, net.ID.String()); err != nil {
		return err
	}
	p.LiveNetwork = net.ID.String()
	p.Data = v
	return s.render(w, r, "overview.html", http.StatusOK, p)
}

// pushStatus reports the epoch push path's state.
//
// Three states, not two, and the third is the one worth being here for: a
// notifier that is configured but whose LISTEN connection is down right now.
// Nothing else on this page changes when that happens — epochs still advance,
// convergence still climbs — so an operator watching a revocation land sees
// only that it is taking far longer than it should, with no indication why.
//
// This used to report configured-ness alone, because notify only exposed
// Ready(), which means "established at least once" and stays true across a drop
// and a reconnect. Notifier.Up() reports the live state, so the down case is
// now sayable.
func (s *Server) pushStatus(networkID uuid.UUID) pushView {
	if s.cfg.Notifier == nil {
		return pushView{
			Badge: badgeWarn("polling only"),
			Detail: "Push is not enabled on this replica, so agents learn about changes " +
				"on their next poll. Correct, but roughly an order of magnitude slower " +
				"to converge — which is felt most while watching a revocation land.",
		}
	}
	if !s.cfg.Notifier.Up() {
		// Configured is deliberately left false: the watcher count would still
		// be non-zero, since agents stay parked on a notifier that cannot hear
		// anything, and printing "12 agents waiting for a change" next to a
		// listener that will never deliver one reads as reassurance.
		return pushView{
			Badge: badgeWarn("push down"),
			Detail: "Push is enabled but the Postgres notification listener is not " +
				"connected, so every agent has silently fallen back to its poll " +
				"interval. It reconnects on its own; if this persists, the control " +
				"plane cannot hold a connection to the database.",
		}
	}
	return pushView{
		Configured: true,
		Watchers:   s.cfg.Notifier.Subscribers(networkID),
		Badge:      badgeOK("push enabled"),
		Detail: "Agents are woken by a Postgres notification when an epoch advances " +
			"rather than waiting for their next poll.",
	}
}

//------------------------------------------------------------------------------
// Convergence, live
//------------------------------------------------------------------------------

// convergenceLagging is the full lagging list's cap.
//
// A hundred names is already more than anyone reads; past that the answer is
// "this network has one problem, not four hundred", which is what the truncation
// notice says.
const convergenceLagging = 100

func (s *Server) handleConvergence(w http.ResponseWriter, r *http.Request) error {
	networkID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}

	var (
		net  *store.Network
		conv *store.Convergence
	)
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if net, err = tx.GetNetwork(ctx, networkID); err != nil {
			return err
		}
		conv, err = tx.Convergence(ctx, networkID, convergenceLagging)
		return err
	})
	if err != nil {
		return err
	}

	p := s.newPage(r, "Convergence — "+net.Name)
	if err := s.withNav(r.Context(), p, net.ID.String()); err != nil {
		return err
	}
	p.LiveNetwork = net.ID.String()
	p.Data = struct {
		Network     networkView
		Convergence convergenceView
	}{
		Network:     newNetworkView(net),
		Convergence: newConvergenceView(conv, convergenceLagging),
	}
	return s.render(w, r, "convergence.html", http.StatusOK, p)
}
