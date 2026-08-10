package agent

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"

	"github.com/griffithind/orbit/internal/agent/hostcfg"
	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/wire"
)

// Is the configuration on disk still the one the control plane sent?
//
// Nothing used to ask. The agent fetches material only when its epoch differs
// from the control plane's, and reports back the epoch it RECEIVED — so an
// operator who edits nebula.yml gets a machine running an unrendered config
// while the control plane's convergence view says it converged. The edit is
// invisible while it is live and disappears without trace when a later epoch
// overwrites it. Both halves are wrong, and the second is worse: it means the
// number that gates CA rotation and backs the revocation SLO is a number about
// what was sent, not about what is running.
//
// This does not stop an operator with root from doing whatever they like. It
// makes them unable to do it QUIETLY, which is the achievable half. See
// docs/config-integrity.md §2.

// ErrConfigDiverged means the installed configuration is not the one that was
// signed. Distinct from a bad signature: the material is authentic, the copy on
// disk has been changed since.
var ErrConfigDiverged = errors.New("the installed configuration is not the one the control plane sent")

// ErrNoSignature means this generation was installed without one.
//
// Expected exactly once per host — on a generation installed by a version that
// did not sign — and not otherwise. Separate from a verification failure so the
// two do not report as the same thing while that is still possible.
var ErrNoSignature = errors.New("this generation was installed without a signature")

// VerifyInstalled checks the configuration on disk against the signature stored
// beside it.
//
// networkKey is the network identity public key the agent pinned at join. An
// empty one is a caller that has not pinned yet, and is refused rather than
// skipped: "verified against nothing" must not be reportable as "verified".
//
// Three things are checked, and the third is the one that catches an edit:
//
//  1. the signature over the envelope, under the pinned key
//  2. the digests in the envelope, recomputed from the files
//  3. localize(signed original) == the installed config, byte for byte
//
// The third works because localize is a pure function of the signed bytes and
// this layout — it rewrites exactly pki.ca, pki.cert and pki.key — so
// re-deriving it accounts for every byte of the installed file. There is no
// part of it the check does not cover.
func (a *Applier) VerifyInstalled(networkKey []byte, membershipID string) error {
	if len(networkKey) == 0 {
		return errors.New("no network key is pinned, so the installed configuration " +
			"cannot be verified; re-run `orbit agent join`")
	}

	signed, err := os.ReadFile(a.Layout.SignedConfigPath())
	if errors.Is(err, os.ErrNotExist) {
		return ErrNoSignature
	} else if err != nil {
		return fmt.Errorf("read the signed configuration: %w", err)
	}

	sigJSON, err := os.ReadFile(a.Layout.SigPath())
	if errors.Is(err, os.ErrNotExist) {
		return ErrNoSignature
	} else if err != nil {
		return fmt.Errorf("read the configuration signature: %w", err)
	}

	var sig wire.ConfigSignature
	if err := json.Unmarshal(sigJSON, &sig); err != nil {
		return fmt.Errorf("%w: the signature file is unreadable: %v", ErrConfigDiverged, err)
	}

	bundle, err := os.ReadFile(a.Layout.Paths.CA)
	if err != nil {
		return fmt.Errorf("read the trust bundle: %w", err)
	}

	if err := VerifyMaterial(networkKey, membershipID, &sig, string(signed), string(bundle)); err != nil {
		return err
	}

	installed, err := os.ReadFile(a.Layout.ConfigPath())
	if err != nil {
		return fmt.Errorf("read the installed configuration: %w", err)
	}
	if want := a.localize(string(signed)); want != string(installed) {
		return fmt.Errorf("%w: %s has been edited since it was installed",
			ErrConfigDiverged, a.Layout.ConfigPath())
	}
	return nil
}

// ErrNotForThisMachine means the envelope names a different membership.
var ErrNotForThisMachine = errors.New("this configuration was rendered for a different machine")

// VerifyMaterial checks material that has just arrived, before it is installed.
//
// Separate from VerifyInstalled because it runs at a different moment against
// different inputs: this one has the bytes in memory and no disk to compare
// against, and it is the gate that keeps unsigned or forged material from ever
// being written.
//
// membershipID IS PART OF THE CHECK, not context. Binding the membership into
// the envelope only helps if the verifier confirms the envelope names ITSELF:
// two machines with the same role are handed byte-identical configs, so machine
// A's envelope — genuinely signed, genuinely matching its digests — verifies
// against that config anywhere unless someone asks who it was rendered for.
// An e2e test found exactly that, with the binding already in place and nobody
// reading it.
//
// An empty membershipID skips the comparison, for a caller that genuinely does
// not know yet — the first claim, where the response is what tells this machine
// its membership id. That case is safe because the material and the id come from
// the same authenticated response.
func VerifyMaterial(networkKey []byte, membershipID string, sig *wire.ConfigSignature, config, caBundle string) error {
	if sig == nil {
		return ErrNoSignature
	}
	if membershipID != "" && sig.MembershipID != membershipID {
		return fmt.Errorf("%w: it names membership %s, this machine is %s",
			ErrNotForThisMachine, sig.MembershipID, membershipID)
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Signature)
	if err != nil {
		return fmt.Errorf("%w: the signature is not valid base64: %v", ca.ErrConfigSignature, err)
	}
	return ca.VerifyConfig(networkKey, ca.ConfigEnvelope{
		NetworkID:      sig.NetworkID,
		MembershipID:   sig.MembershipID,
		ConfigEpoch:    sig.ConfigEpoch,
		BlocklistEpoch: sig.BlocklistEpoch,
		ConfigSHA256:   sig.ConfigSHA256,
		CABundleSHA256: sig.CABundleSHA256,
	}, raw, config, caBundle)
}

//------------------------------------------------------------------------------
// The loop's side: pinning, and the gate before every apply
//------------------------------------------------------------------------------

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
	if err := VerifyMaterial(key, l.State.MembershipID, sig, config, caBundle); err != nil {
		if errors.Is(err, ErrNoSignature) {
			return fmt.Errorf("refusing unsigned configuration: this host has pinned a "+
				"network key, so material must carry a signature. The control plane is "+
				"older than this agent (%w)", err)
		}
		if errors.Is(err, ErrNotForThisMachine) {
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
	case errors.Is(err, ErrNoSignature):
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

// VerifiedConfig returns the configuration nebula should run, from the signed
// original, with the certificate material inlined.
//
// THIS IS THE POINT OF THE WHOLE FILE. Verifying a config and then letting
// nebula independently re-read it off disk makes the verification advisory: an
// edit between the check and the read wins, and root can SIGHUP nebula directly
// without the agent involved at all. So nebula is never given a path. It is
// given these bytes, and nebula.yml on disk is a record for people to read.
//
// The material is INLINED — pki.ca, pki.cert and pki.key become PEM rather than
// paths — for the same reason internal/mesh does it for the control plane: a
// path is an instruction to go and read something later, which is exactly the
// second read this exists to remove. What is left on disk is the key, because
// nebula needs it across restarts and it must match the certificate; a key file
// is a real exposure, and a different one from this.
//
// An unsigned generation is refused outright. A host that has not pinned a
// network key yet is the one exception, and it is the same window checkMaterial
// allows — it closes at that host's first renewal.
func (a *Applier) VerifiedConfig(networkKey []byte, membershipID string) (string, error) {
	signed, err := os.ReadFile(a.Layout.SignedConfigPath())
	if err != nil {
		return "", fmt.Errorf("read the signed configuration: %w", err)
	}
	bundle, err := os.ReadFile(a.Layout.Paths.CA)
	if err != nil {
		return "", fmt.Errorf("read the trust bundle: %w", err)
	}

	if len(networkKey) == 0 {
		a.Log.Warn("running a configuration without verifying it: no network key is " +
			"pinned yet. This host will pin one at its next renewal")
	} else {
		sigJSON, err := os.ReadFile(a.Layout.SigPath())
		if err != nil {
			return "", fmt.Errorf("read the configuration signature: %w", err)
		}
		var sig wire.ConfigSignature
		if err := json.Unmarshal(sigJSON, &sig); err != nil {
			return "", fmt.Errorf("%w: the signature file is unreadable: %v", ErrConfigDiverged, err)
		}
		if err := VerifyMaterial(networkKey, membershipID, &sig, string(signed), string(bundle)); err != nil {
			return "", fmt.Errorf("refusing to run this configuration: %w", err)
		}
	}

	cert, err := os.ReadFile(a.Layout.Paths.Cert)
	if err != nil {
		return "", fmt.Errorf("read the certificate: %w", err)
	}
	key, err := os.ReadFile(a.Layout.Paths.Key)
	if err != nil {
		return "", fmt.Errorf("read the private key: %w", err)
	}
	return inlineMaterial(string(signed), string(bundle), string(cert), string(key))
}

// inlineMaterial replaces the pki path references with the material itself.
//
// Nebula accepts either a path or PEM for pki.ca, pki.cert and pki.key, which is
// what makes this possible without a fork — and what makes localize unnecessary
// on this path, since there are no paths left to rewrite.
func inlineMaterial(rendered, caBundle, certPEM, keyPEM string) (string, error) {
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(rendered), &doc); err != nil {
		return "", fmt.Errorf("parse the signed configuration: %w", err)
	}
	pki, ok := doc["pki"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("the signed configuration has no pki section")
	}
	pki["ca"], pki["cert"], pki["key"] = caBundle, certPEM, keyPEM

	out, err := yaml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("re-marshal the configuration: %w", err)
	}
	return string(out), nil
}

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
