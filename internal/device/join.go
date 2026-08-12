package device

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Proof of possession for a join.
//
// A join tells the control plane "this public key would like to be a member of
// that network". Without a signature, anyone who has ever seen a device's
// public key — it is public, and it appears in the CLI, in logs, and in the
// admin UI — can lodge that request on the device's behalf. They cannot USE the
// resulting membership, because every credential issued for it is bound to the
// key they do not hold. What they can do is fill the pending queue with rows an
// operator has to reason about, and take the names those rows claim.
//
// So the joining machine signs. The signature proves the request came from
// something holding the private half, which is the only claim a join needs to
// make.

// JoinStatementV1 is the version tag. Signed as the first line so a future
// scheme cannot be confused with this one — a verifier that reads the tag it
// expects can never be tricked into accepting a signature made over a different
// meaning by the same key.
const JoinStatementV1 = "orbit-join-v1"

// JoinFreshness bounds how far a join's timestamp may be from the control
// plane's clock, in either direction.
//
// Both directions, because a host with a clock five minutes fast is a real
// machine and not an attack — and rejecting only the past would make the error
// depend on which way the drift went.
//
// REPLAY IS NOT WHAT THIS DEFENDS AGAINST, and it is worth being exact about
// why, because "5 minutes" invites the assumption that it is. Replaying a join
// achieves nothing: store.Tx.JoinNetwork is idempotent, so a captured request
// resent produces the same membership row it produced the first time. The
// window exists to stop a captured request from being useful INDEFINITELY —
// after a membership is deleted, a year-old recording should not silently
// recreate it.
const JoinFreshness = 5 * time.Minute

// JoinStatement is the exact byte string a joining device signs.
//
// Every field that scopes the request is in here. The network so a signature
// for one network cannot join another; the name so it cannot be redirected onto
// a different membership; the fingerprint so the statement names the key that
// signed it; the timestamp for the bound above.
//
// LENGTH-PREFIXED, and that is the point of the function.
//
// The obvious encoding is to join the fields with a separator, and it is wrong
// unless no field can contain that separator. A membership name is operator
// input; the rule that forbids a newline in one lives in a different package,
// and a signing scheme whose soundness depends on a validator somewhere else is
// a signing scheme that breaks the day the validator relaxes. With
// "<len>:<field>" per field, `("a\nb", "fp")` and `("a", "b\nfp")` encode
// differently no matter what the fields contain, so one signature can never
// cover two meanings. See TestJoinStatementIsUnambiguous, which caught exactly
// this in the separator version.
func JoinStatement(networkRef, name, fingerprint string, at time.Time) []byte {
	var b strings.Builder
	for _, f := range []string{
		JoinStatementV1,
		networkRef,
		name,
		fingerprint,
		strconv.FormatInt(at.Unix(), 10),
	} {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return []byte(b.String())
}

// SignJoin produces the signature for a join request.
func (i *Identity) SignJoin(networkRef, name string, at time.Time) ([]byte, error) {
	return i.Sign(JoinStatement(networkRef, name, i.Fingerprint(), at))
}

// ErrStaleJoin is returned when a join's timestamp is outside JoinFreshness.
//
// Distinct because it is the one join failure with an obvious remedy the
// operator can act on — fix the machine's clock — and a generic "signature
// rejected" would send them looking at keys instead.
var ErrStaleJoin = errors.New("join timestamp is outside the accepted window")

// VerifyJoin checks a join signature against the presented public key.
//
// The public key is the one the request carried, which looks circular and is
// not: the signature proves the sender holds that key's private half, and the
// key's FINGERPRINT is what the control plane then recognises or does not. An
// unknown key is a new device, which is the normal case on first join; a known
// one resolves to a device row that may be blocked. Neither decision is this
// function's, and keeping it out of here is why the same call serves both.
func VerifyJoin(spki []byte, networkRef, name string, at, now time.Time, sig []byte) error {
	if d := now.Sub(at); d > JoinFreshness || d < -JoinFreshness {
		return fmt.Errorf("%w: off by %s", ErrStaleJoin, d.Round(time.Second))
	}
	return Verify(spki, JoinStatement(networkRef, name, Fingerprint(spki), at), sig)
}

// ClaimStatementV1 is the version tag for a claim: the request an authorized
// device makes to collect the credential its membership entitles it to.
//
// A separate tag from JoinStatementV1, and that is the point of having tags. The
// two statements share every field except one, so without a distinguishing
// prefix a captured join signature would be a valid claim signature — an
// attacker replaying a join could collect the certificate meant for the machine
// that joined.
const ClaimStatementV1 = "orbit-claim-v1"

// ClaimStatement is the byte string an authorized device signs to collect its
// membership credential.
//
// It binds the MESH public key, which is the field that matters and the reason
// this cannot just be a repeat of the join. The device key is permanent; the
// nebula key is generated fresh and is what the certificate will be issued
// over. Signing it is the device saying "issue to THIS key" — without that, an
// attacker who could reach the endpoint could have a certificate minted over a
// key they control, for a membership somebody else's machine was authorized for.
//
// Same length-prefixed encoding as JoinStatement, for the same reason.
func ClaimStatement(membershipID, fingerprint, meshPublicKey string, at time.Time) []byte {
	var b strings.Builder
	for _, f := range []string{
		ClaimStatementV1,
		membershipID,
		fingerprint,
		meshPublicKey,
		strconv.FormatInt(at.Unix(), 10),
	} {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return []byte(b.String())
}

// SignClaim produces the signature for a claim request. meshPublicKey is the
// base64 the request carries, signed exactly as sent so there is no encoding
// step between what was signed and what is verified.
func (i *Identity) SignClaim(membershipID, meshPublicKey string, at time.Time) ([]byte, error) {
	return i.Sign(ClaimStatement(membershipID, i.Fingerprint(), meshPublicKey, at))
}

// VerifyClaim checks a claim signature against the device's stored public key.
//
// Unlike VerifyJoin, the key here comes from the DATABASE rather than the
// request: the membership already names a device, and the question is whether
// the caller holds that device's key. A caller-supplied key would make the check
// vacuous.
func VerifyClaim(spki []byte, membershipID, meshPublicKey string, at, now time.Time, sig []byte) error {
	if d := now.Sub(at); d > JoinFreshness || d < -JoinFreshness {
		return fmt.Errorf("%w: off by %s", ErrStaleJoin, d.Round(time.Second))
	}
	return Verify(spki, ClaimStatement(membershipID, Fingerprint(spki), meshPublicKey, at), sig)
}
