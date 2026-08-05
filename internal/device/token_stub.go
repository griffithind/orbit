//go:build !cgo || !pkcs11

package device

import "errors"

// Without cgo and the pkcs11 build tag there is no token support compiled in.
//
// A refusal rather than a silent fall back to a file. An operator who asked for
// a hardware-backed device key and got a file on disk has the opposite of what
// they asked for, and no way to tell — the fingerprint looks the same and every
// later operation succeeds. Failing here, naming the build, is the only honest
// answer this binary can give.
func openToken(uri string) (signer, []byte, error) {
	return nil, nil, errors.New(
		"this build has no PKCS#11 support, so it cannot use a token-resident device key: " +
			"install the -pkcs11 build (scripts/install.sh --pkcs11), which is cgo and " +
			"Linux only")
}
