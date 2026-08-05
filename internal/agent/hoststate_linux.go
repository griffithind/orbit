//go:build linux

package agent

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// The Linux gateway: one nftables table, owned whole.
//
// TableName is the ownership boundary and the reason this is safe to run on a
// machine somebody else also configures. Everything Orbit adds lives inside it;
// nothing Orbit adds goes into a chain anybody else writes to. Removal is
// `nft destroy table inet orbit`, which needs no knowledge of the contents and
// works whether or not the rules are what we left.
//
// Rules are replaced rather than diffed. `nft -f` with a `delete table` followed
// by the whole desired table is atomic: nftables applies the file as one
// transaction, so there is no window in which forwarding is enabled and the NAT
// rule is missing — which would be a gateway leaking un-NATed overlay addresses
// onto somebody's LAN.
//
// WHY SHELLING OUT. `nft` is inspectable: an operator debugging a gateway runs
// `nft list table inet orbit` and sees exactly what Orbit did, in the syntax
// every reference and every answer on the internet uses. A netlink
// implementation would be faster and completely opaque to the person who needs
// to understand it at 2am. Speed is not the constraint here — this runs when a
// configuration changes, which is rarely.
// nftFamily is inet rather than ip so one table covers v4 and v6, which matters
// the day a network is dual stack and nobody remembers there were two tables.
const nftFamily = "inet"

type nftConfigurer struct{ log logger }

type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}

// NewHostConfigurer returns the Linux implementation.
func NewHostConfigurer(log logger) HostConfigurer { return &nftConfigurer{log: log} }

func (n *nftConfigurer) Describe() string { return "nftables table " + nftFamily + " " + TableName }

func (n *nftConfigurer) Apply(h HostState) error {
	if h.Empty() {
		// Not a gateway (any more). Removing is the correct response rather
		// than doing nothing: a machine that stops advertising a route must
		// stop forwarding for it, and leaving the rules would keep a path open
		// that the control plane believes is closed.
		return n.Remove()
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("this host is a route gateway but has no nft binary: "+
			"install nftables (it is the default firewall backend on every current "+
			"distribution, including where iptables is a wrapper over it): %w", err)
	}

	if h.Forward {
		if err := setForwarding(true); err != nil {
			return err
		}
	}

	// One transaction. `destroy` rather than `delete` so a first run, where the
	// table does not exist, is not an error — and so the whole thing is
	// idempotent without a probe first.
	var b bytes.Buffer
	fmt.Fprintf(&b, "destroy table %s %s\n", nftFamily, TableName)
	fmt.Fprintf(&b, "table %s %s {\n", nftFamily, TableName)

	if len(h.Masquerade) > 0 {
		// priority srcnat (100) is where NAT belongs in the postrouting hook;
		// anything else either runs before the routing decision is final or
		// after something else has already rewritten the packet.
		fmt.Fprintf(&b, "  chain postrouting {\n")
		fmt.Fprintf(&b, "    type nat hook postrouting priority srcnat; policy accept;\n")
		for _, p := range h.Masquerade {
			fam := "ip"
			if p.Addr().Is6() {
				fam = "ip6"
			}
			// Scoped to traffic that ARRIVED on the overlay. Without iifname a
			// gateway would masquerade its own LAN's traffic to the same
			// destination, which is somebody else's network silently changing
			// behaviour because Orbit was installed.
			fmt.Fprintf(&b, "    iifname %q %s daddr %s counter masquerade comment \"orbit route %s\"\n",
				h.TunDev, fam, p.String(), p.String())
		}
		fmt.Fprintf(&b, "  }\n")
	}
	fmt.Fprintf(&b, "}\n")

	return n.run(b.String())
}

func (n *nftConfigurer) Remove() error {
	if _, err := exec.LookPath("nft"); err != nil {
		// Nothing to remove and no tool to remove it with. Not an error: a host
		// that never had nft never had a table.
		return nil
	}
	// destroy is idempotent — no error when the table is absent — which is what
	// makes uninstall safe to run twice and safe to run on a machine that was
	// never a gateway.
	return n.run(fmt.Sprintf("destroy table %s %s\n", nftFamily, TableName))
}

func (n *nftConfigurer) run(script string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// The script goes in the error. nft's own messages name a line number,
		// which is useless without the lines.
		return fmt.Errorf("nft: %w: %s\n--- script ---\n%s",
			err, strings.TrimSpace(stderr.String()), script)
	}
	return nil
}

// setForwarding turns on IP forwarding.
//
// Written, not merely checked, and deliberately not restored on Remove. Another
// thing on the machine may want forwarding — a container runtime almost
// certainly does — and turning it off on uninstall would break something Orbit
// did not set up. Leaving it on is the conservative direction: it is a kernel
// setting many things enable, not a hole Orbit opened alone.
func setForwarding(on bool) error {
	v := []byte("0\n")
	if on {
		v = []byte("1\n")
	}
	for _, p := range []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv6/conf/all/forwarding",
	} {
		if err := os.WriteFile(p, v, 0o644); err != nil {
			// v6 may genuinely be absent on a v4-only kernel. v4 may not.
			if strings.Contains(p, "ipv6") && os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("enable forwarding (%s): %w", p, err)
		}
	}
	return nil
}
