//go:build !cgo || !pkcs11

package agent

// tokenPublicKey without PKCS#11 support compiled in.
//
// Refusing here rather than letting nebula's own stub fail later is the whole
// reason this file exists. Nebula's pkclient stub returns "not implemented"
// from inside DeriveNoise, which runs during the Noise handshake — so a binary
// built without the tags enrolls successfully, writes a config that looks
// correct, starts nebula without complaint, and then never establishes a
// tunnel. The failure surfaces as silence.
//
// Failing at the point where the operator asked for a token instead means the
// error arrives with the flag that caused it still on screen.
func tokenPublicKey(string) (*Keypair, error) {
	return nil, ErrPKCS11Unsupported
}
