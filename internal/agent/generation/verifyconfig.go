package generation

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"

	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/wire"
)

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
