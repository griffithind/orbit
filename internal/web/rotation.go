package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
)

// CA rotation, as a wizard whose state is derived from the database.
//
// NEVER FROM CLIENT STATE. There is no step number in a URL, no hidden field
// carrying "you are on step 3", and no session key remembering where someone
// was. Every time this page loads it re-reads the CAs, their states, and how
// many live certificates each has signed, and works out from that alone which
// step the rotation is on.
//
// That is not tidiness. A rotation takes hours or days — it waits for the fleet
// to renew — and in that window the browser tab gets closed, the operator goes
// home, a colleague picks it up on a different machine, the control plane is
// restarted, and another replica does half the work. Any of those invalidates
// remembered client state, and the failure mode of acting on stale step state
// here is retiring a CA whose certificates are still in use, which drops every
// host still holding one off the mesh. Derived state cannot be stale: it is a
// description of what is true right now.
//
// CA CREATION IS NOT HERE, deliberately. signer_ref names a location on the
// SERVER — a file path, a KMS key, a PKCS#11 URI — and a browser form that asks
// an operator to type a path into a machine they are not standing at is a
// footgun with an audit entry. That step stays in orbitd and the CLI, and this
// page says so and shows the command.

type caView struct {
	ID          string
	Name        string
	Fingerprint string
	Short       string
	State       string
	Badge       badge
	NotBefore   time.Time
	NotAfter    time.Time
	CreatedAt   time.Time
	// SignerRef is shown because "which key signs this" is the question a
	// rotation is about. It is a locator, never key material — internal/ca is
	// explicit that it holds none.
	SignerRef string

	ActiveCertificates int
	Expired            bool

	// CanRetire is the store's own precondition, evaluated here so the button is
	// absent rather than present-and-refused. RetireCA is still the authority:
	// this only decides whether to offer the control.
	CanRetire bool
}

func newCAView(c *store.CA, activeCerts int, now time.Time) caView {
	v := caView{
		ID:                 c.ID.String(),
		Name:               c.Name,
		Fingerprint:        c.Fingerprint,
		Short:              shortFingerprint(c.Fingerprint),
		State:              c.State,
		Badge:              caStateBadge(c.State),
		NotBefore:          c.NotBefore,
		NotAfter:           c.NotAfter,
		CreatedAt:          c.CreatedAt,
		SignerRef:          c.SignerRef,
		ActiveCertificates: activeCerts,
		Expired:            now.After(c.NotAfter),
	}
	v.CanRetire = c.State == store.CARetiring && activeCerts == 0
	return v
}

// rotationStep is which of the four steps a network is on. Derived, always.
type rotationStep int

const (
	// stepPrepare: exactly one CA, and it is the signer. Nothing to rotate onto.
	stepPrepare rotationStep = iota
	// stepDistribute: a pending CA exists. It is already in every trust bundle;
	// what remains is for the fleet to have applied the generation that carries
	// it.
	stepDistribute
	// stepRenew: the new CA is signing and the old one is retiring with live
	// certificates still out there.
	stepRenew
	// stepRetire: the old CA has no live certificates and can be dropped.
	stepRetire
	// stepDone: one distributed CA, and it is not the one we started with.
	stepDone
)

type rotationView struct {
	Network     networkView
	CAs         []caView
	Convergence convergenceView

	Step  rotationStep
	Steps []rotationStepView

	// Pending is the CA awaiting promotion, nil when there is none.
	Pending *caView
	// Active is the current signer, nil when the network has none at all.
	Active *caView
	// Retiring are the old CAs still in the trust bundle.
	Retiring []caView

	// Converged reports whether promoting now would cut anyone off. It is the
	// same comparison handleActivateCA gates on, so the button's state and the
	// server's answer cannot disagree.
	Converged bool
	CutOff    int
}

type rotationStepView struct {
	N       int
	Title   string
	State   string // done | current | todo
	Detail  string
	Command string
}

func (s *Server) handleRotation(w http.ResponseWriter, r *http.Request) error {
	networkID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}

	now := time.Now()
	var (
		net    *store.Network
		cas    []store.CA
		counts map[uuid.UUID]int
		conv   *store.Convergence
	)
	err = s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if net, err = tx.GetNetwork(ctx, networkID); err != nil {
			return err
		}
		if cas, err = tx.ListCAs(ctx, networkID); err != nil {
			return err
		}
		counts = map[uuid.UUID]int{}
		for i := range cas {
			n, err := tx.ActiveCertificateCount(ctx, cas[i].ID)
			if err != nil {
				return err
			}
			counts[cas[i].ID] = n
		}
		conv, err = tx.Convergence(ctx, networkID, overviewLagging)
		return err
	})
	if err != nil {
		return err
	}

	v := rotationView{
		Network:     newNetworkView(net),
		Convergence: newConvergenceView(conv, overviewLagging),
		Converged:   conv.MembershipsTotal == 0 || conv.ConfigApplied >= conv.MembershipsTotal,
		CutOff:      conv.MembershipsTotal - conv.ConfigApplied,
	}
	for i := range cas {
		cv := newCAView(&cas[i], counts[cas[i].ID], now)
		v.CAs = append(v.CAs, cv)
		switch cas[i].State {
		case store.CAPending:
			if v.Pending == nil {
				v.Pending = &cv
			}
		case store.CAActive:
			v.Active = &cv
		case store.CARetiring:
			v.Retiring = append(v.Retiring, cv)
		}
	}

	v.Step = rotationStepFor(v)
	v.Steps = rotationSteps(v, net.Slug)

	p := s.newPage(r, "CA rotation — "+net.Name)
	if err := s.withNav(r.Context(), p, net.ID.String()); err != nil {
		return err
	}
	p.LiveNetwork = net.ID.String()
	p.Data = v
	return s.render(w, r, "rotation.html", http.StatusOK, p)
}

// rotationStepFor reads the step off the database state.
//
// The order of these tests is the order of the rotation, and each one is a fact
// about rows rather than about what anyone clicked.
func rotationStepFor(v rotationView) rotationStep {
	switch {
	case v.Pending != nil:
		return stepDistribute
	case len(v.Retiring) > 0:
		for _, c := range v.Retiring {
			if c.ActiveCertificates > 0 {
				return stepRenew
			}
		}
		return stepRetire
	default:
		return stepPrepare
	}
}

func rotationSteps(v rotationView, slug string) []rotationStepView {
	state := func(step rotationStep) string {
		switch {
		case v.Step > step:
			return "done"
		case v.Step == step:
			return "current"
		default:
			return "todo"
		}
	}

	create := rotationStepView{
		N: 1, Title: "Create the replacement CA", State: state(stepDistribute),
		Detail: "A new CA is created on the control plane, where its signing key can " +
			"be written. That is why this step is not a button here: signer_ref names " +
			"a path, a KMS key, or a PKCS#11 URI on the SERVER, and a form that asked " +
			"you to type one would be asking about a machine you are not at.",
		Command: "orbit ca create -network " + slug + " -name <new-ca> -days 90",
	}
	if v.Step > stepDistribute || v.Pending != nil {
		create.State = "done"
	}

	distribute := rotationStepView{
		N: 2, Title: "Wait for every host to trust it", State: state(stepDistribute),
		Detail: "A new CA joins every host's trust bundle as soon as it is created, " +
			"before it signs anything. Promoting it before the fleet has applied that " +
			"generation is what partitions a network: the straggler does not trust the " +
			"new CA, and its next certificate will be signed by it.",
	}

	promote := rotationStepView{
		N: 3, Title: "Promote it to signer", State: state(stepRenew),
		Detail: "The new CA starts signing and the old one moves to 'retiring': still " +
			"trusted by every host, no longer issuing. Memberships move across as they renew, " +
			"which happens at the midpoint of each certificate's lifetime.",
	}

	retire := rotationStepView{
		N: 4, Title: "Retire the old CA", State: state(stepRetire),
		Detail: "Retiring drops a CA from every trust bundle. It is refused while any " +
			"certificate it signed is still active — that check is the difference " +
			"between finishing a rotation and silently invalidating whichever hosts " +
			"had not yet renewed.",
	}
	if v.Step == stepPrepare && v.Pending == nil && len(v.Retiring) == 0 {
		retire.State = "todo"
	}

	return []rotationStepView{create, distribute, promote, retire}
}

//------------------------------------------------------------------------------
// The two actions
//------------------------------------------------------------------------------

// handleActivateCA promotes a CA, with the same convergence gate the JSON API
// applies.
//
// The gate is re-evaluated inside the transaction rather than trusted from the
// page that rendered the button. Between the render and the click, a host can
// have fallen behind; a UI that gated on what it drew a minute ago would promote
// past hosts the operator was never shown.
func (s *Server) handleActivateCA(w http.ResponseWriter, r *http.Request) error {
	caID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}
	if err := r.ParseForm(); err != nil {
		return err
	}
	id := identityFrom(r.Context())
	acknowledged := r.PostFormValue("acknowledge_cutoff") != ""

	var (
		row     *store.CA
		cutOff  int
		total   int
		blocked bool
	)
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if row, err = tx.GetCA(ctx, caID); err != nil {
			return err
		}
		if row.State == store.CAActive {
			return nil // idempotent, exactly as the JSON API is
		}

		conv, err := tx.Convergence(ctx, row.NetworkID, overviewLagging)
		if err != nil {
			return err
		}
		total = conv.MembershipsTotal
		cutOff = conv.MembershipsTotal - conv.ConfigApplied
		if cutOff > 0 && !acknowledged {
			blocked = true
			return errNotConverged
		}

		if err := tx.ActivateCA(ctx, row.NetworkID, caID); err != nil {
			return err
		}

		action := store.ActionCAActivated
		if cutOff > 0 {
			// Its own audit action, not a flag in metadata: "which promotion
			// knowingly cut hosts off" is a question an incident review asks with
			// a WHERE clause.
			action = store.ActionCAForceActivated
			s.log.Warn("CA promoted from the operator UI before convergence; unconverged hosts are cut off",
				"ca", caID, "network", row.NetworkID, "cutOff", cutOff,
				"total", total, "actor", id.Display)
		}
		e := s.audit(r, *id, action, "ca", caID.String())
		e.Meta = []byte(fmt.Sprintf(`{"via":"ui","hosts_cut_off":%d,"hosts_total":%d}`, cutOff, total))
		return tx.AppendAudit(ctx, e)
	})
	if err != nil {
		if blocked {
			s.writeStatus(w, r, http.StatusConflict,
				fmt.Sprintf("%d host(s) have not applied this CA yet", cutOff),
				fmt.Sprintf("Promoting %s now would cut them off: they do not trust it, and "+
					"their next certificate would be signed by it. Wait for convergence and "+
					"try again, or — if this is a key compromise, where cutting off "+
					"stragglers is the lesser harm — tick the acknowledgement on the "+
					"rotation page and promote anyway.\n\n"+
					"%d of %d hosts are converged.", row.Name, total-cutOff, total))
			return nil
		}
		return err
	}

	notice := "Promoted " + row.Name + ". Memberships move onto it as they renew."
	if cutOff > 0 {
		notice = fmt.Sprintf("Promoted %s past %d unconverged host(s). They are cut off "+
			"until they apply the new trust bundle.", row.Name, cutOff)
	}
	return s.redirectWithNotice(w, r, "/ui/networks/"+row.NetworkID.String()+"/rotation", notice)
}

var errNotConverged = errors.New("network has not converged on this CA")

func (s *Server) handleRetireCA(w http.ResponseWriter, r *http.Request) error {
	caID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return store.ErrNotFound
	}
	id := identityFrom(r.Context())

	var row *store.CA
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if row, err = tx.GetCA(ctx, caID); err != nil {
			return err
		}
		if err := tx.RetireCA(ctx, caID); err != nil {
			return err
		}
		return tx.AppendAudit(ctx, s.audit(r, *id, store.ActionCARetired, "ca", caID.String()))
	})
	if err != nil {
		if errors.Is(err, store.ErrCAInUse) {
			s.writeStatus(w, r, http.StatusConflict, "that CA is still in use",
				err.Error()+".\n\nRetiring drops it from every host's trust bundle, so a "+
					"host still presenting a certificate it signed would stop verifying "+
					"against its peers. Wait for those certificates to renew.")
			return nil
		}
		return err
	}

	s.log.Info("CA retired from the operator UI",
		"ca", caID, "name", row.Name, "actor", id.Display)
	return s.redirectWithNotice(w, r, "/ui/networks/"+row.NetworkID.String()+"/rotation",
		"Retired "+row.Name+". It is no longer distributed, and the rotation is complete.")
}
