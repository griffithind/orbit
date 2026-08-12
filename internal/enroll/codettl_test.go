package enroll

import (
	"testing"
	"time"
)

// Reserve took its TTL from the request body and only floored it, so a caller
// could ask for a year. A reservation auto-authorises on redemption, which
// makes it an unattended admission credential — and DefaultCodeTTL's own
// comment names the failure an arbitrary lifetime produces: "a long-lived join
// token sitting in a configuration management repository is the usual way a
// fleet's trust boundary is lost". See ADR-0024.
func TestCodeTTLIsClampedAtBothEnds(t *testing.T) {
	for _, c := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{"zero takes the default", 0, DefaultCodeTTL},
		{"negative takes the default", -time.Hour, DefaultCodeTTL},
		{"a reasonable ask is honoured", 2 * time.Hour, 2 * time.Hour},
		{"the ceiling exactly", MaxCodeTTL, MaxCodeTTL},
		{"a year is refused down to the ceiling", 365 * 24 * time.Hour, MaxCodeTTL},
	} {
		if got := clampCodeTTL(c.in); got != c.want {
			t.Errorf("%s: clampCodeTTL(%s) = %s, want %s", c.name, c.in, got, c.want)
		}
	}
}

// The ceiling has to leave the case it exists for possible: an image baked
// today and booted tomorrow. A ceiling below the default would also be a
// ceiling that silently shortens every ordinary code.
func TestTheCeilingIsAboveTheDefaultAndCoversOvernight(t *testing.T) {
	if MaxCodeTTL <= DefaultCodeTTL {
		t.Fatalf("MaxCodeTTL %s is not above DefaultCodeTTL %s", MaxCodeTTL, DefaultCodeTTL)
	}
	if MaxCodeTTL < 12*time.Hour {
		t.Errorf("MaxCodeTTL %s does not cover an overnight provisioning window", MaxCodeTTL)
	}
}
