package secrets

import (
	"testing"

	"github.com/google/uuid"
)

func TestRefRoundTrip(t *testing.T) {
	id := uuid.New()
	ref := Ref(id)
	if !IsRef(ref) {
		t.Fatalf("%q is not recognised as a vault ref", ref)
	}
	got, err := ParseRef(ref)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got != id {
		t.Fatalf("round trip gave %s, want %s", got, id)
	}
}

// TestRefIsDistinguishableFromAFileRef.
//
// The two schemes coexist in one column and one resolver, so a ref that could be
// read as either would resolve differently depending on the order the resolver
// happened to try them.
func TestRefIsDistinguishableFromAFileRef(t *testing.T) {
	for _, ref := range []string{
		"file:///var/lib/orbit/ca.key",
		"awskms://eu-west-1/abc",
		"pkcs11:token=orbit",
		"",
	} {
		if IsRef(ref) {
			t.Errorf("%q was read as a vault ref", ref)
		}
		if _, err := ParseRef(ref); err == nil {
			t.Errorf("%q parsed as a vault ref", ref)
		}
	}
	// A db:// ref that is not a uuid is malformed, not a different scheme.
	if _, err := ParseRef("db://not-a-uuid"); err == nil {
		t.Error("db://not-a-uuid parsed")
	}
}
