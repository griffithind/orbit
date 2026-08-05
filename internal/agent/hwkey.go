package agent

import (
	"errors"
	"strings"
)

// Hardware-backed host keys.
//
// A host's static key is the thing that makes its identity unforgeable, and by
// default it is a file: readable by root, copyable off a disk image, present in
// every backup and snapshot. A key held in a TPM or a Secure Enclave is not —
// the private half never exists outside the chip, and the certificate that
// names it becomes useless on any other machine.
//
// NOT A TPM, THOUGH. Tested: `tpm2-pkcs11` 1.9.0 does not implement
// CKM_ECDH1_DERIVE — it is absent from the module's mechanism list and
// C_DeriveKey returns CKR_MECHANISM_INVALID — so nebula cannot perform the
// handshake DH on a TPM through it. The TPM itself reports TPM2_CC_ECDH_ZGen
// and P-256; the gap is the PKCS#11 bridge, and closing it is upstream work.
// A token that DOES implement the mechanism (YubiKey ykcs11, SoftHSM, an HSM)
// works today. See docs/credential-model.md §7.
//
// Nebula already supports this. A `pki.key` beginning `pkcs11:` makes nebula
// perform the Noise handshake's Diffie-Hellman ON the token
// (CKM_ECDH1_DERIVE with CKD_NULL), so the private key is never in this
// process's memory. Orbit's part is small: read the PUBLIC half at enrollment
// so the control plane can sign a certificate for it, write the URI into the
// config instead of a path, and never stage a key file.
//
// Two constraints inherited from nebula, both hard:
//
//   - P-256 only. `pki.go` forces cert.Curve_P256 for any pkcs11 key, because
//     no TPM 2.0 implements Curve25519 and Apple's Secure Enclave is P-256
//     only. Every Orbit network is P-256 (migration 0021), so this constraint
//     is now satisfied by construction rather than by an operator's choice.
//   - cgo and the `pkcs11` build tag. Nebula's pkclient is a cgo binding, so a
//     binary without both silently gets a stub whose every method returns "not
//     implemented". This package refuses at the seam instead, with a message
//     that names the build, because a runtime failure inside the handshake is
//     invisible until a tunnel does not come up.

// ErrPKCS11Unsupported means this binary cannot talk to a PKCS#11 token.
//
// Distinct from "the token rejected us": the difference is a rebuild versus a
// configuration fix, and an operator holding a working token deserves to be
// told which.
var ErrPKCS11Unsupported = errors.New(
	"this orbit binary was built without PKCS#11 support (needs cgo and -tags pkcs11)")

// TokenURIScheme is the prefix nebula uses to recognise a token-resident key.
const TokenURIScheme = "pkcs11:"

// IsTokenRef reports whether a key reference names a PKCS#11 token rather than
// a file on disk. Matches nebula's own test in pki.go.
func IsTokenRef(ref string) bool {
	return strings.HasPrefix(ref, TokenURIScheme)
}

// keyBacking describes where a host's private key lives, for logs.
//
// Worth a log field because it is otherwise invisible and it is the single
// most consequential property of a host's identity: "file" means a copy of
// this machine's identity exists in every backup and disk image.
func keyBacking(ref string) string {
	if IsTokenRef(ref) {
		return "token"
	}
	return "file"
}

// KeypairFromToken reads the public half of a token-resident key.
//
// Returns a Keypair with an empty PrivatePEM: there is no private half to
// carry, which is the entire point. Callers must treat an empty PrivatePEM as
// "do not write a key file" rather than as an error — Applier already does,
// because renewal without key rotation has always produced one.
func KeypairFromToken(uri string) (*Keypair, error) {
	if !IsTokenRef(uri) {
		return nil, errors.New("not a pkcs11 URI: " + uri)
	}
	return tokenPublicKey(uri)
}
