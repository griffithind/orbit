//go:build cgo && pkcs11

package device

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"math/big"

	"github.com/slackhq/nebula/pkclient"
)

// A device identity whose private half lives on a token.
//
// THIS ONE WORKS ON A TPM, and the mesh key does not. The difference is the
// operation, not the hardware: a device key only ever SIGNS, while a mesh key
// has to perform the Noise handshake's Diffie-Hellman. tpm2-pkcs11 implements
// CKM_ECDSA_SHA256 and does not implement CKM_ECDH1_DERIVE (tested — see
// docs/credential-model.md §7), so the same TPM that cannot hold a nebula host
// key can hold this one.
//
// That matters more than it might look. The device key is the thing Orbit's
// identity model rests on: joining is a signature over it, no secret travels,
// and a machine whose certificate expired still gets back in because that key
// never expires. Moving it into a chip means a stolen disk image is no longer a
// stolen identity.
//
// The session is opened PER SIGNATURE rather than held. A device key signs at
// join, at claim, and at renewal — single digits per day — so the latency is
// irrelevant, and a long-running agent holding a PKCS#11 session open for
// months is a bigger liability than opening one three times.

func openToken(uri string) (signer, []byte, error) {
	// Opened once here to read the public half and to fail early: a bad URI, a
	// missing object or a wrong PIN should stop `orbit agent install` while an
	// operator is watching, not surface at the first join.
	client, err := pkclient.FromUrl(uri)
	if err != nil {
		return nil, nil, fmt.Errorf("open pkcs11 token: %w", err)
	}
	defer client.Close()

	raw, err := client.GetPubKey()
	if err != nil {
		return nil, nil, fmt.Errorf("read public key from token: %w", err)
	}
	spki, err := spkiFromECPoint(raw)
	if err != nil {
		return nil, nil, err
	}
	return tokenSigner{uri: uri}, spki, nil
}

// spkiFromECPoint converts a PKCS#11 EC point into the SPKI this package uses.
//
// The two are not interchangeable and the conversion has to happen somewhere: a
// token returns the raw uncompressed point (0x04 || X || Y), while a device's
// public key is SPKI everywhere else in Orbit — because a fingerprint is taken
// over SPKI, and a device certificate's subject is SPKI. Fingerprinting the raw
// point instead would give one machine two different device identities
// depending on where its key lived.
func spkiFromECPoint(raw []byte) ([]byte, error) {
	if len(raw) != 65 || raw[0] != 0x04 {
		return nil, fmt.Errorf(
			"token returned a %d byte key; want a 65 byte uncompressed P-256 point "+
				"(is the object an EC P-256 key?)", len(raw))
	}
	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(raw[1:33]),
		Y:     new(big.Int).SetBytes(raw[33:]),
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("the token's public key is not a point on P-256")
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal the token's public key: %w", err)
	}
	return spki, nil
}

// tokenSigner signs on the token. It holds a URI, not a session.
type tokenSigner struct{ uri string }

func (t tokenSigner) signMessage(msg []byte) ([]byte, error) {
	client, err := pkclient.FromUrl(t.uri)
	if err != nil {
		return nil, fmt.Errorf("open pkcs11 token to sign: %w", err)
	}
	defer client.Close()

	// The MESSAGE, not a digest. SignASN1 uses CKM_ECDSA_SHA256, so the token
	// hashes it — and returns ASN.1, which is what Verify already accepts.
	sig, err := client.SignASN1(msg)
	if err != nil {
		return nil, fmt.Errorf("sign on the token: %w", err)
	}
	return sig, nil
}
