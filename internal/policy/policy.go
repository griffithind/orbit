// Package policy compiles a network-wide reachability document into the
// per-host nebula firewall rules that enforce it.
//
// # Why the entries are called allowances, and not grants
//
// A "grant" is Tailscale's word, and it carries Tailscale's claim: the grants
// document is the COMPLETE statement of what is permitted on that network, so
// anything not granted is denied, everywhere, by construction. Orbit can only
// make that claim in ModeAuthoritative, where it writes the single file nebula
// reads. In ModeFragment nebula merges a config directory with
// mergo.WithAppendSlice and firewall lists CONCATENATE, so Orbit's rules are
// added to whatever an operator wrote and Orbit can neither see nor remove
// theirs. The same document is a complete policy in one mode and a lower bound
// in the other.
//
// So the entries are ALLOWANCES: each one states traffic that is permitted.
// That is true in both modes. What is denied is a property of the mode, not of
// the document, and the name should not quietly assert otherwise.
//
// # Why it compiles to addresses and not to groups
//
// The obvious compilation target is `groups:`, because nebula matches groups
// out of the peer's certificate and a group feels like the identity-shaped
// thing. It is the wrong target, and the reason is that `cidr:` is not weaker.
//
// Before any rule is consulted, Firewall.Drop validates the peer's claimed
// source address against the networks in its verified certificate and returns
// ErrInvalidRemoteIP when it does not match (firewall.go, Drop). h.networks is
// built from the certificate at handshake. A `cidr:` selector is therefore
// bound to a signed certificate exactly as strongly as a `groups:` selector is;
// it is not a spoofable header.
//
// Given that, the two differ only in WHERE the change lives. Groups live inside
// the signed certificate, so editing a group-based policy means reissuing
// certificates fleet-wide and waiting for every host to renew before the change
// is in force. Orbit owns address assignment, so it can resolve a selector to
// its members' addresses on the server and emit `cidr:` rules — and then a
// policy edit is config-only, hot, sub-second, and requires zero certificate
// reissuance. Tailscale's coordination server resolves tag: and group: to node
// IPs and ships an IP-keyed filter for the same reason; identity never reaches
// the node's packet filter there either.
//
// # Why both directions are emitted
//
// Outbound rules are enforced on the SENDER against the DESTINATION's
// certificate: inside.go calls Drop(..., incoming=false, hostinfo, ...) down the
// same peerCert path the inbound side uses, and the rule matches p.RemoteAddr,
// which parseV4/parseV6 set to the destination address when incoming is false.
// src and dst are symmetric. One allowance therefore compiles to an inbound
// rule on every dst host AND an outbound rule on every src host. That is
// defence in depth nebula offers and Tailscale's model does not: the flow stays
// closed if either end is misconfigured.
//
// # What is refused, permanently
//
// A nebula certificate identifies a DEVICE: Name, Networks, UnsafeNetworks,
// Groups. There is no user identity in the handshake and nothing in
// FirewallRule.match that could consume one. Accepting a user selector and
// enforcing a device rule would be a lie in the permissive direction, so user
// selectors, autogroups, app capabilities, posture and via/svc are refused with
// an error that says why. See refusals.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Version is the only document version that exists. It is required rather than
// defaulted: a document with no version is one nobody has to think about when
// the shape changes, and the shape will change.
const Version = 1

var (
	// ErrUnknownField is an unrecognised key. Nebula silently ignores unknown
	// configuration keys, which is what turns a typo into a materially
	// different posture with nothing in any log; internal/nebulacfg/validate.go
	// exists for that reason and this document is held to the same bar.
	ErrUnknownField = errors.New("unknown field in policy document")

	// ErrInvalid is a document that parses but does not mean anything.
	ErrInvalid = errors.New("invalid policy document")

	// ErrRefused is a selector Orbit will never support, as opposed to one it
	// has not implemented. The distinction matters to the reader: no future
	// release makes these work, because nothing in a nebula certificate could
	// carry them.
	ErrRefused = errors.New("selector refused")
)

// Document is a network's reachability policy. It round-trips through JSON
// unchanged: what an operator wrote is what is stored and what is shown back.
type Document struct {
	Version int `json:"version"`

	// Allow is ordered for the reader's benefit only. Compilation sorts its
	// output, so reordering entries does not change a single rendered byte.
	Allow []Entry `json:"allow"`
}

// Entry is one allowance: this traffic, from these sources, to these
// destinations, is permitted.
type Entry struct {
	Src []Selector `json:"src"`
	Dst []Selector `json:"dst"`

	// Proto is any, tcp, udp or icmp — nebula supports no others. There is no
	// SCTP and no numeric protocol number.
	Proto string `json:"proto"`

	// Ports is required for tcp, udp and any, and must be absent for icmp,
	// where nebula ignores the port and logs that it did.
	Ports []string `json:"ports,omitempty"`

	// Note is carried through to nobody: it exists so the document explains
	// itself where it is read, which is more often than it is edited.
	Note string `json:"note,omitempty"`
}

// Selector names a set of hosts. The forms are:
//
//	"*"              every host in this network
//	host:<name>      one host, by the name in its certificate
//	id:<uuid>        one host, by its Orbit id
//	tag:<tag>        every host carrying the tag
//	role:<name>      every host holding the role
//	cidr:<prefix>    every address in the prefix
//
// A bare token is not a selector. Requiring the prefix costs one word and buys
// the property that a selector's meaning cannot change because somebody named a
// host "web" after a tag of the same name.
type Selector string

// Validate reports whether raw is a usable policy document.
//
// Strict: an unknown field is an error and the message names it.
func Validate(raw []byte) error {
	_, err := Parse(raw)
	return err
}

// Parse decodes and fully validates a policy document.
//
// Parse validates rather than merely decoding, so that holding a Document is
// proof it is well-formed and Compile never has to re-check. Validate is Parse
// with the result discarded.
func Parse(raw []byte) (Document, error) {
	var doc Document

	// Two stages so the error can say WHERE. A single strict decode names the
	// offending key but not the entry it was in, and "unknown field
	// \"protocol\"" is a much cheaper thing to act on when it comes with
	// "allow[7]".
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return doc, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	for k := range top {
		if k != "version" && k != "allow" {
			return doc, fmt.Errorf("%w: %q (want \"version\" or \"allow\")", ErrUnknownField, k)
		}
	}

	if _, ok := top["version"]; !ok {
		return doc, fmt.Errorf("%w: version is required (the only version is %d)", ErrInvalid, Version)
	}
	if err := json.Unmarshal(top["version"], &doc.Version); err != nil {
		return doc, fmt.Errorf("%w: version: %v", ErrInvalid, err)
	}
	if doc.Version != Version {
		return doc, fmt.Errorf("%w: unknown version %d (the only version is %d)",
			ErrInvalid, doc.Version, Version)
	}

	if body, ok := top["allow"]; ok {
		var raws []json.RawMessage
		if err := json.Unmarshal(body, &raws); err != nil {
			return doc, fmt.Errorf("%w: allow must be a list of entries: %v", ErrInvalid, err)
		}
		doc.Allow = make([]Entry, 0, len(raws))
		for i, re := range raws {
			e, err := parseEntry(re)
			if err != nil {
				return Document{}, fmt.Errorf("allow[%d]: %w", i, err)
			}
			doc.Allow = append(doc.Allow, e)
		}
	}
	if doc.Allow == nil {
		// An empty document is legal and means "nothing is permitted". In
		// authoritative mode that is a real, sometimes intended, posture; it
		// should not require a caller to distinguish nil from empty.
		doc.Allow = []Entry{}
	}
	return doc, nil
}

func parseEntry(raw json.RawMessage) (Entry, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var e Entry
	if err := dec.Decode(&e); err != nil {
		return e, fmt.Errorf("%w: %v", ErrUnknownField, err)
	}

	if len(e.Src) == 0 {
		return e, fmt.Errorf("%w: src is required (use \"*\" for every host)", ErrInvalid)
	}
	if len(e.Dst) == 0 {
		return e, fmt.Errorf("%w: dst is required (use \"*\" for every host)", ErrInvalid)
	}
	for _, side := range []struct {
		name string
		sels []Selector
	}{{"src", e.Src}, {"dst", e.Dst}} {
		for _, s := range side.sels {
			if _, err := parseSelector(s); err != nil {
				return e, fmt.Errorf("%s %q: %w", side.name, s, err)
			}
		}
	}

	switch e.Proto {
	case "":
		return e, fmt.Errorf("%w: proto is required (any, tcp, udp, icmp)", ErrInvalid)
	case "any", "tcp", "udp":
		if len(e.Ports) == 0 {
			return e, fmt.Errorf("%w: ports is required for proto %q (use [\"any\"] for every port)",
				ErrInvalid, e.Proto)
		}
		for _, p := range e.Ports {
			if err := validatePort(p); err != nil {
				return e, err
			}
		}
	case "icmp":
		if len(e.Ports) != 0 {
			// Nebula parses the rule, warns, and throws the port away. A rule
			// whose author believes it is narrower than it is should not exist.
			return e, fmt.Errorf("%w: proto icmp takes no ports; nebula ignores them", ErrInvalid)
		}
	case "sctp", "esp", "gre", "ah":
		return e, fmt.Errorf("%w: proto %q: nebula matches only any, tcp, udp and icmp",
			ErrInvalid, e.Proto)
	default:
		if _, err := strconv.Atoi(e.Proto); err == nil {
			return e, fmt.Errorf("%w: proto %q: nebula takes a name, not a protocol number, "+
				"and only any, tcp, udp and icmp", ErrInvalid, e.Proto)
		}
		return e, fmt.Errorf("%w: unknown proto %q (any, tcp, udp, icmp)", ErrInvalid, e.Proto)
	}

	return e, nil
}

// maxPortSpan bounds how wide a single port range may be.
//
// This is not a style preference. firewallPort.addRule materialises ONE MAP
// ENTRY PER PORT in the range (firewall.go), so "1-65535" builds 65535
// FirewallCA structs per rule, per direction, on every host that carries it.
// The full range is rewritten to "any" during compilation, which costs one
// entry. Anything else this wide is far more likely to be a mistake than a
// requirement, and the operator who genuinely wants it can say "any" or split
// the range and see the cost.
const maxPortSpan = 1024

func validatePort(p string) error {
	if p == "any" {
		return nil
	}
	if p == "fragment" {
		// A real nebula feature, but not a reachability statement: it is about
		// packet fragments, not about who may talk to whom. Role firewall rules
		// still reach it.
		return fmt.Errorf("%w: port \"fragment\" is a packet-level nebula setting, "+
			"not a reachability statement; set it through a role's firewall rules", ErrInvalid)
	}

	lo, hi, isRange := strings.Cut(p, "-")
	l, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return fmt.Errorf("%w: port %q is not a number, a range, or \"any\"", ErrInvalid, p)
	}
	if !isRange {
		return portInRange(l, p)
	}
	h, err := strconv.Atoi(strings.TrimSpace(hi))
	if err != nil {
		return fmt.Errorf("%w: port range end %q is not a number", ErrInvalid, hi)
	}
	if err := portInRange(l, p); err != nil {
		return err
	}
	if err := portInRange(h, p); err != nil {
		return err
	}
	if l > h {
		return fmt.Errorf("%w: port range %q is inverted", ErrInvalid, p)
	}
	if isFullPortRange(l, h) {
		return nil // compiled to "any"
	}
	if h-l+1 > maxPortSpan {
		return fmt.Errorf("%w: port range %q spans %d ports; nebula builds one firewall "+
			"entry per port, so use \"any\" or a range of at most %d",
			ErrInvalid, p, h-l+1, maxPortSpan)
	}
	return nil
}

func portInRange(n int, orig string) error {
	if n < 0 || n > 65535 {
		return fmt.Errorf("%w: port %q is outside 0-65535", ErrInvalid, orig)
	}
	return nil
}

// isFullPortRange reports whether lo-hi covers every port. Nebula's parsePort
// treats 0 as PortAny, so both 0 and 1 are plausible lower bounds for "all".
func isFullPortRange(lo, hi int) bool { return lo <= 1 && hi >= 65535 }

// refusals are the selector namespaces Orbit will never support, each with the
// reason. They are refused rather than ignored: a document that says
// "user:alice may reach the database" and compiles to a rule matching every
// device alice might be sitting at is wrong in the permissive direction, which
// is the only direction that matters.
var refusals = map[string]string{
	"user":       "a nebula certificate identifies a device, not a person; there is no user identity in the handshake and nothing in FirewallRule.match that could consume one",
	"localpart":  "a nebula certificate identifies a device, not a person",
	"group":      "groups live inside the SIGNED certificate, so a group-based rule cannot change without reissuing certificates fleet-wide; use role: or tag:, which Orbit resolves to addresses server-side",
	"groups":     "groups live inside the SIGNED certificate; use role: or tag:",
	"autogroup":  "autogroups classify users, sessions and internet egress, none of which a nebula certificate carries",
	"via":        "routing a flow through a chosen peer is not something a nebula firewall rule can express; the packet filter sees a peer's certificate, not a path",
	"svc":        "there is no service registry in the handshake; name the hosts, or tag them",
	"app":        "application capabilities are enforced by an application, and nebula's filter sees IP, port and protocol",
	"posture":    "nebula's handshake carries no device posture and never checks one",
	"srcposture": "nebula's handshake carries no device posture and never checks one",
	"ipset":      "there is no named address set in nebula; write the prefix with cidr:",
}

type selectorKind int

const (
	selAll selectorKind = iota
	selHost
	selID
	selTag
	selRole
	selCIDR
)

type selector struct {
	kind   selectorKind
	value  string
	prefix netip.Prefix // set only for selCIDR
}

func parseSelector(s Selector) (selector, error) {
	raw := string(s)
	if raw == "*" {
		return selector{kind: selAll}, nil
	}
	if raw == "" {
		return selector{}, fmt.Errorf("%w: empty selector", ErrInvalid)
	}

	kind, value, ok := strings.Cut(raw, ":")
	if !ok {
		if strings.Contains(raw, "@") {
			return selector{}, fmt.Errorf("%w: %s", ErrRefused, refusals["user"])
		}
		if strings.Contains(raw, "/") {
			return selector{}, fmt.Errorf("%w: %q looks like a prefix; write cidr:%s",
				ErrInvalid, raw, raw)
		}
		return selector{}, fmt.Errorf("%w: %q has no kind; write host:%s, tag:%s, role:%s, "+
			"id:%s, a cidr:, or \"*\"", ErrInvalid, raw, raw, raw, raw, raw)
	}
	// autogroup:internet, autogroup:member, autogroup:self — one namespace,
	// refused whole.
	if why, refused := refusals[strings.ToLower(kind)]; refused {
		return selector{}, fmt.Errorf("%w: %s: %s", ErrRefused, raw, why)
	}
	if value == "" {
		return selector{}, fmt.Errorf("%w: %q names nothing after the colon", ErrInvalid, raw)
	}

	switch kind {
	case "host":
		return selector{kind: selHost, value: value}, nil
	case "id":
		return selector{kind: selID, value: value}, nil
	case "tag":
		return selector{kind: selTag, value: value}, nil
	case "role":
		return selector{kind: selRole, value: value}, nil
	case "cidr":
		p, err := netip.ParsePrefix(value)
		if err != nil {
			return selector{}, fmt.Errorf("%w: cidr %q: %v", ErrInvalid, value, err)
		}
		if p.Addr() != p.Masked().Addr() {
			return selector{}, fmt.Errorf("%w: cidr %q has bits set below the prefix length; "+
				"write %s", ErrInvalid, value, p.Masked())
		}
		return selector{kind: selCIDR, value: value, prefix: p}, nil
	}

	if strings.Contains(value, "@") {
		return selector{}, fmt.Errorf("%w: %s", ErrRefused, refusals["user"])
	}
	return selector{}, fmt.Errorf("%w: unknown selector kind %q in %q "+
		"(host, id, tag, role, cidr, or \"*\")", ErrInvalid, kind, raw)
}
