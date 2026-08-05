//go:build cgo && pkcs11

package agent

import (
	"encoding/base64"
	"fmt"

	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/pkclient"
)

// tokenPublicKey reads the public half of a token-resident key.
//
// Deliberately nebula's own pkclient rather than a PKCS#11 binding of our own.
// The agent runs nebula in-process, so the token is opened by nebula's code
// during the handshake regardless; using a second library to read the same
// object would mean two sets of assumptions about slots, PINs and object
// attributes, and only one of them would be the one that matters.
//
// The curve is not read from the token, it is asserted: nebula's pki.go returns
// cert.Curve_P256 unconditionally for a pkcs11 key, so a token holding anything
// else produces a certificate nebula will refuse to load. Better to be
// consistent with nebula here than to be independently right.
func tokenPublicKey(uri string) (*Keypair, error) {
	client, err := pkclient.FromUrl(uri)
	if err != nil {
		return nil, fmt.Errorf("open pkcs11 token: %w", err)
	}
	defer client.Close()

	pub, err := client.GetPubKey()
	if err != nil {
		return nil, fmt.Errorf("read public key from token: %w", err)
	}
	// nebula's DeriveNoise wants a 65-byte uncompressed P-256 point, and
	// enrollment validates the same shape server-side. Checking here turns a
	// misconfigured token — wrong object, wrong key type — into an error at
	// enrollment rather than a certificate that can never complete a handshake.
	if len(pub) != 65 || pub[0] != 0x04 {
		return nil, fmt.Errorf(
			"token returned a %d byte key; want a 65 byte uncompressed P-256 point "+
				"(is the object an EC P-256 key with CKA_DERIVE set?)", len(pub))
	}

	return &Keypair{
		Curve:     cert.Curve_P256,
		PublicB64: base64.StdEncoding.EncodeToString(pub),
		// No PrivatePEM: the private half is on the token and stays there.
	}, nil
}
