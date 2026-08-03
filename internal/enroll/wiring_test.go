package enroll

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/policy"
	"github.com/griffithind/orbit/internal/store"
)

// The policy source has to be the DEFAULT, not something a caller supplies.
//
// The failure these guard against is a policy document that is stored, switched
// on, and reported in force by /v1/networks/{ref}/policy, by the CLI, and by
// convergence — while no host has received a single compiled rule. An operator
// reads "in force" and is wrong about their firewall.
//
// It is reachable because enroll.Config is built from a struct literal in ten
// places, one of them production and nine of them test harnesses. A field
// omitted from a literal is silent, and a harness that omits it is exactly why
// no test would notice production omitting it too. So the guard is not a test
// that reads main.go — it is that the safe value is what a zero Config gets.

// TestProductionWiringTakesTheDefault reads cmd/orbitd's own literal.
//
// The unit tests below prove the default exists; this proves production gets
// it. Reading the source is crude, but the alternative — booting orbitd and
// exercising a policy end to end — is what e2e does, and what did NOT catch
// this, because e2e builds its own service. A test that inspects the one call
// site nobody else exercises is the honest shape here.
func TestProductionWiringTakesTheDefault(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "orbitd", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(src), "enroll.NewService(")
	if i < 0 {
		t.Fatal("cmd/orbitd no longer calls enroll.NewService; this test needs rewriting")
	}
	// The literal must either take the default or say why it does not. Naming
	// DisablePolicy is a deliberate choice and fine; silence is the bug.
	lit := string(src[i:])
	if end := strings.Index(lit, "\n\t})"); end > 0 {
		lit = lit[:end]
	}
	if strings.Contains(lit, "DisablePolicy") && !strings.Contains(lit, "DisablePolicy: false") {
		t.Error("cmd/orbitd disables policy; if that is intended, delete this test and say why")
	}
}

func TestPolicyDefaultsOnRatherThanOff(t *testing.T) {
	// The zero Config is what every caller that has not thought about policy
	// passes, including cmd/orbitd.
	s := NewService(nil, nil, nil, Config{})
	if s.cfg.Policy == nil {
		t.Fatal("a Config that does not mention Policy got no policy source.\n" +
			"That is the state where a document is stored, switched on, reported\n" +
			"in force by every endpoint, and rendered by nothing.")
	}
}

// TestPolicyCanBeDisabledDeliberately. The default must not be impossible to
// opt out of — a test that wants to prove the per-role path in isolation needs
// to, and "I forgot" and "I meant to" must not look the same in the source.
func TestPolicyCanBeDisabledDeliberately(t *testing.T) {
	s := NewService(nil, nil, nil, Config{DisablePolicy: true})
	if s.cfg.Policy != nil {
		t.Error("DisablePolicy did not disable it")
	}
}

// TestAnExplicitPolicySourceWins. Defaulting must not overwrite a caller that
// supplied one; e2e/policy_enforcement_test.go passes its own to drive the
// compiler without going through firewall_source.
func TestAnExplicitPolicySourceWins(t *testing.T) {
	called := false
	var src PolicySource = func(_ context.Context, _ *store.Tx, _ uuid.UUID) ([]byte, []policy.Host, error) {
		called = true
		return nil, nil, nil
	}
	s := NewService(nil, nil, nil, Config{Policy: src})
	if s.cfg.Policy == nil {
		t.Fatal("an explicitly supplied policy source was dropped")
	}
	_, _, _ = s.cfg.Policy(context.Background(), nil, uuid.Nil)
	if !called {
		t.Error("the configured source was replaced by the default")
	}
}
