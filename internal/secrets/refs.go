package secrets

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Signer refs for stored secrets.
//
// `db://<uuid>` sits alongside `file://<path>` in the same opaque-locator scheme
// orbit.ca.signer_ref has always used, which is the point: a CA whose key is in
// the vault and one whose key is on disk differ by a string, and every layer
// above the resolver is unchanged. That is what lets a deployment move without
// a migration of its own — and what keeps `file://` a first-class answer for the
// single VM that already works.

const dbScheme = "db://"

// Ref renders a stored secret's id as a signer ref.
func Ref(id uuid.UUID) string { return dbScheme + id.String() }

// IsRef reports whether a signer ref names the vault.
func IsRef(ref string) bool { return strings.HasPrefix(ref, dbScheme) }

// ParseRef extracts the secret id from a `db://` ref.
func ParseRef(ref string) (uuid.UUID, error) {
	rest, ok := strings.CutPrefix(ref, dbScheme)
	if !ok {
		return uuid.Nil, fmt.Errorf("%q is not a %s reference", ref, dbScheme)
	}
	id, err := uuid.Parse(rest)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%q does not name a secret: %w", ref, err)
	}
	return id, nil
}
