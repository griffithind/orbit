package hostcfg

import (
	"sync"
)

// Host-global objects have exactly one owning network.
//
// A host can join several networks, and each gets its own Loop, its own
// HostConfigurer and its own Resolver. The RESOURCES those manage are not per
// network: the nftables table is named `orbit`, the route table and ip rule are
// both 4242, the macOS global resolver is one scutil key. Apply does not merge —
// it opens with `destroy table inet orbit` and rebuilds from one network's state
// — so two networks that both configure host state destroyed and rebuilt each
// other's rules once per reconcile, forever, and nothing reported it. Each Apply
// succeeded; from where it stood it did exactly what it was asked.
//
// WarnInstanceCollisions was written for this class of problem and checks
// listen.port and tun.dev — the two resources that CANNOT thrash silently,
// because a second nebula fails loudly to bind or create them.
//
// Ownership rather than namespacing, for now. Namespacing (an `orbit-<slug>`
// table, a per-slug route table and rule priority) is what makes two gateways on
// one host actually work, and it is a larger change into a small shared number
// space. This removes the silent failure and does not foreclose it.
// See docs/adr/0020-one-network-owns-the-host.md.
var owner struct {
	mu   sync.Mutex
	slug string
}

// claimHostState decides whether this network may write host-global objects.
//
// Lowest slug wins, so the choice is the same on every run and after every
// restart rather than depending on which goroutine got there first. A network
// that wants host state and does not hold it is told, by its caller — the
// current failure is invisible, and a silent refusal is only better than a
// silent wrong answer if somebody can see it.
func claimHostState(slug string) (ok bool, held string) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.slug == "" || owner.slug == slug || slug < owner.slug {
		owner.slug = slug
		return true, slug
	}
	return false, owner.slug
}

// releaseHostState gives ownership up, so a network that stops being a gateway
// lets another one take over rather than holding a claim it no longer uses.
func releaseHostState(slug string) {
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.slug == slug {
		owner.slug = ""
	}
}
