package agent

import (
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/griffithind/orbit/internal/agent/generation"
	"github.com/griffithind/orbit/internal/agent/hostcfg"
	"github.com/griffithind/orbit/internal/wire"
)

// NetworkKeyBytes decodes the pinned network identity public key, or nil.
//
// Nil for "not pinned yet" AND for "unreadable", which callers must treat the
// same way: neither can verify anything. The difference is logged where the
// distinction is actionable, not returned, because a caller that could tell
// them apart would eventually branch on it.
func (s State) NetworkKeyBytes() []byte {
	if s.NetworkKey == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(s.NetworkKey)
	if err != nil {
		return nil
	}
	return key
}

// networkKey returns the pinned network identity public key, or nil.
// VerifiedConfig returns this network's configuration, signature checked.
//
// Exported so callers that only want to READ the configuration — status, diagnostics —
// go through the same verification the reconcilers do, instead of assembling the network
// key and membership id themselves and getting one of them subtly wrong.
func (l *Loop) VerifiedConfig() (string, error) {
	// Guarded because the callers are read-only paths. A loop can be alive with
	// no applier yet — mid-construction, or a network that failed to set up and
	// is being retried — and `orbit status` reporting on it must not be able to
	// take the agent down with it.
	if l == nil || l.Applier == nil {
		return "", errors.New("this network has no configuration yet")
	}
	return l.Applier.VerifiedConfig(l.networkKey(), l.State.MembershipID)
}

func (l *Loop) networkKey() []byte {
	if l.State.NetworkKey == "" {
		return nil
	}
	key, err := base64.StdEncoding.DecodeString(l.State.NetworkKey)
	if err != nil {
		// Unreadable rather than absent, so it must not silently degrade to
		// "unpinned" — that would turn a corrupt state file into a host that
		// accepts anything.
		l.Log.Error("the pinned network key is unreadable; configuration signatures "+
			"cannot be checked until `orbit agent join` is re-run", "error", err)
		return nil
	}
	return key
}

// pinNetworkKey adopts a network key when this host holds none.
//
// ONCE, and never an update. The first pin comes from a response the agent has
// already authenticated — at join, verifyNetwork proves the control plane holds
// the private half of the key its network ID names — so adopting it is keeping
// what that proof established. Accepting a LATER one would discard it.
func (l *Loop) pinNetworkKey(b64 string) {
	if b64 == "" {
		return
	}
	if l.State.NetworkKey != "" {
		if l.State.NetworkKey != b64 {
			// Not fatal here: the signature check is what enforces the pin, and
			// it will fail on its own if this response's material was signed by
			// the other key. Loud, because the only innocent explanation is a
			// network that rotated an identity key it is documented never to
			// rotate.
			l.Log.Error("the control plane presented a different network identity key; " +
				"keeping the one pinned at join. Configuration from this control plane " +
				"will be refused if it was signed by the new key")
		}
		return
	}
	l.State.NetworkKey = b64
	l.Log.Info("pinned this network's identity key; configuration is now verified before it is applied")
}

// checkMaterial is the gate every apply passes through.
//
// Two rules, and the asymmetry between them is the rollout:
//
//   - A host that HAS pinned a key requires a valid signature. No exception, no
//     flag: an agent that can be talked out of verifying has not verified.
//   - A host that has NOT pinned one yet accepts material and says so. This is
//     the only window, it closes at the next renewal — where the response
//     carries the key — and it exists so upgrading the control plane does not
//     strand every host that enrolled before signing existed.
func (l *Loop) checkMaterial(sig *wire.ConfigSignature, config, caBundle string) error {
	key := l.networkKey()
	if key == nil {
		l.Log.Warn("applying configuration without verifying it: no network key is pinned yet. " +
			"This host will pin one at its next renewal and verify from then on")
		return nil
	}
	if err := generation.VerifyMaterial(key, l.State.MembershipID, sig, config, caBundle); err != nil {
		if errors.Is(err, generation.ErrNoSignature) {
			return fmt.Errorf("refusing unsigned configuration: this host has pinned a "+
				"network key, so material must carry a signature. The control plane is "+
				"older than this agent (%w)", err)
		}
		if errors.Is(err, generation.ErrNotForThisMachine) {
			return fmt.Errorf("refusing configuration rendered for another machine: %w", err)
		}
		return fmt.Errorf("refusing configuration: %w", err)
	}
	return nil
}

// checkInstalled compares the configuration on disk against what was signed,
// and self-heals when they differ.
//
// Resetting the known epoch is what makes the fix automatic: the control plane
// answers a poll with material only when the agent says it is behind, so
// declaring this host behind is the whole repair. The next poll re-installs the
// correct generation.
//
// It also makes the FLEET VIEW honest immediately, before any repair lands. The
// agent stops claiming to have applied epoch 47 the moment it discovers it is
// not running epoch 47 — and that number is what gates CA rotation and backs the
// revocation SLO, so a machine lying about it is worse than a machine running an
// edit.
//
// Nebula is not stopped. A running tunnel is not made safer by dropping it, and
// an agent that halts the mesh over an extra newline is an agent that gets
// disabled — after which nothing checks anything.
func (l *Loop) checkInstalled() {
	if l.networkKey() == nil {
		return // not pinned yet; the warning in checkMaterial already says so
	}
	err := l.Applier.VerifyInstalled(l.networkKey(), l.State.MembershipID)
	switch {
	case err == nil:
		return
	case errors.Is(err, generation.ErrNoSignature):
		// This generation predates signing. Expected once per host, and it
		// resolves itself: the next generation is written with a signature.
		l.Log.Debug("the installed generation has no signature; it will get one on the next update")
		return
	}

	l.Log.Error("the installed configuration is not the one the control plane sent; "+
		"re-fetching. Local edits to this file do not take effect — change it through "+
		"the control plane", "error", err, "config", l.Layout.ConfigPath())

	l.State.ConfigEpoch = 0
	l.State.BlocklistEpoch = 0
	if err := WriteState(l.Layout.Dir, l.State); err != nil {
		l.Log.Error("persist agent state failed", "error", err)
	}
}

//------------------------------------------------------------------------------
// What nebula actually loads
//------------------------------------------------------------------------------

// reconcileHost makes the machine's forwarding and NAT match the signed config.
//
// EVERY CYCLE, not only when a generation changes, and that is the whole point
// of it being here rather than in the apply path. Firewall rules live in a
// table other things also write to: somebody flushes nftables, a package
// upgrade reloads a ruleset, an operator experiments. Applying once and trusting
// it would leave a gateway that the control plane believes is forwarding and
// that silently is not.
//
// It is also cheap to be sure: the implementation replaces its own table
// wholesale, so "repair" and "confirm" are the same operation and there is no
// diff to get wrong.
func (l *Loop) reconcileHost() {
	if l.Host == nil {
		return
	}
	yamlCfg, err := l.Applier.VerifiedConfig(l.networkKey(), l.State.MembershipID)
	if err != nil {
		// checkInstalled already reported whatever is wrong with the
		// configuration; saying it twice per cycle would bury it.
		return
	}
	want, err := hostcfg.HostStateFromConfig(yamlCfg)
	if err != nil {
		l.Log.Error("could not read this host's forwarding instructions", "error", err)
		return
	}

	// Before applying, not after. Apply is what installs the default route that
	// captures the fallback path, so a hatch opened afterwards would leave a
	// window — small, but exactly during the change most likely to be the one
	// that needs reverting.
	if l.Client != nil {
		if want.ExitNode {
			l.Client.SetEscapeHatch(l.State.BaseURL, want.SoMark)
		} else {
			l.Client.SetEscapeHatch("", 0)
		}
	}

	// The resolver, before host state for the same reason the escape hatch is:
	// Apply installs the route that changes where this machine's packets go, and
	// a name table that lags that change resolves to answers the routing no
	// longer agrees with.
	if l.DNS != nil {
		if d, err := hostcfg.DNSStateFromConfig(yamlCfg); err != nil {
			l.Log.Error("could not read this network's name table", "error", err)
		} else if err := l.DNS.Apply(d); err != nil {
			// Not fatal: nebula is running and tunnels are unaffected. What is
			// lost is resolving by name, which is a degraded machine rather
			// than a disconnected one.
			l.Log.Error("could not serve the mesh name table", "error", err)
		}
	}

	if err := l.Host.Apply(want); err != nil {
		// Not fatal to the data plane: nebula is already running and tunnels are
		// unaffected. What is affected is everything BEHIND this gateway, so
		// this is an error rather than a warning even though nothing here can
		// fix it.
		l.Log.Error("could not apply this host's forwarding rules; traffic through "+
			"this gateway will not be forwarded", "error", err, "state", want.String(),
			"mechanism", l.Host.Describe())
		return
	}
	if s := want.String(); s != l.lastHostState {
		if want.Empty() {
			l.Log.Info("this host is no longer a gateway; forwarding rules removed",
				"mechanism", l.Host.Describe())
		} else {
			l.Log.Info("gateway forwarding applied", "state", s, "mechanism", l.Host.Describe())
		}
		l.lastHostState = s
	}
}
