package hostcfg

import "testing"

// The election must be the same on every run, or ownership moves on a restart
// for no reason an operator can see.
func TestOwnershipGoesToTheLowestSlugAndStaysThere(t *testing.T) {
	reset := func() { owner.mu.Lock(); owner.slug = ""; owner.mu.Unlock() }

	t.Run("first claimant takes it", func(t *testing.T) {
		reset()
		if ok, held := claimHostState("prod"); !ok || held != "prod" {
			t.Fatalf("claim = %v, %q; want true, prod", ok, held)
		}
	})

	t.Run("a higher slug is refused and told who holds it", func(t *testing.T) {
		reset()
		claimHostState("prod")
		ok, held := claimHostState("staging")
		if ok {
			t.Error("two networks both own the one nftables table, which is how they " +
				"destroy each other's rules once per reconcile")
		}
		if held != "prod" {
			t.Errorf("refusal named %q as the owner, want prod", held)
		}
	})

	t.Run("a lower slug takes over, so the outcome does not depend on order", func(t *testing.T) {
		reset()
		claimHostState("staging")
		if ok, _ := claimHostState("prod"); !ok {
			t.Error("a lower slug did not take over; the winner would then depend on " +
				"which goroutine started first, and could differ across restarts")
		}
		// And the previous holder now loses it, from either direction.
		if ok, held := claimHostState("staging"); ok || held != "prod" {
			t.Errorf("after takeover: claim = %v, holder = %q; want false, prod", ok, held)
		}
	})

	t.Run("order does not matter", func(t *testing.T) {
		for _, order := range [][]string{{"a", "b", "c"}, {"c", "b", "a"}, {"b", "c", "a"}} {
			reset()
			for _, s := range order {
				claimHostState(s)
			}
			owner.mu.Lock()
			got := owner.slug
			owner.mu.Unlock()
			if got != "a" {
				t.Errorf("claims in order %v elected %q, want a", order, got)
			}
		}
	})

	t.Run("releasing lets another network take over", func(t *testing.T) {
		reset()
		claimHostState("prod")
		releaseHostState("prod")
		if ok, _ := claimHostState("staging"); !ok {
			t.Error("a network that stopped being a gateway kept the claim, so nothing " +
				"else can ever configure host state on this machine")
		}
	})

	t.Run("releasing a claim you do not hold does nothing", func(t *testing.T) {
		reset()
		claimHostState("prod")
		releaseHostState("staging")
		if ok, held := claimHostState("zzz"); ok || held != "prod" {
			t.Errorf("a non-owner's release dropped the real owner's claim: %v, %q", ok, held)
		}
	})
}
