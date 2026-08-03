package nebulacfg

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Firewall rule validation.
//
// The reason this exists: nebula's convertRule (firewall.go) reads only the
// keys it knows and silently ignores everything else. A role that says
//
//	{"port": "22", "proto": "tcp", "groupss": ["ssh"]}
//
// does not fail. It produces a rule with no group constraint at all, which is a
// materially different security posture from the one the author wrote, applied
// to every host carrying that role, with nothing in any log to suggest it.
//
// Catching that at the moment a role is written is the single highest-value
// check Orbit can add over raw nebula configuration.

var (
	ErrUnknownField = errors.New("unknown field in firewall rule")
	ErrInvalidRule  = errors.New("invalid firewall rule")
)

// knownProtos mirrors nebula's firewall.go proto handling.
var knownProtos = map[string]bool{
	"any": true, "tcp": true, "udp": true, "icmp": true,
}

// ValidateFirewall checks a role's rules before they are stored.
//
// Decoding is strict: an unknown key is an error rather than a shrug. That is
// deliberately stricter than nebula itself, because nebula's leniency is what
// makes the typo silent.
func ValidateFirewall(raw []byte) error {
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return nil
	}

	// Reject unknown top-level keys too: "inbounds" is as easy to typo as
	// "groups", and just as silent.
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRule, err)
	}
	for k := range top {
		if k != "inbound" && k != "outbound" {
			return fmt.Errorf("%w: %q (want \"inbound\" or \"outbound\")", ErrUnknownField, k)
		}
	}

	for _, dir := range []string{"inbound", "outbound"} {
		body, ok := top[dir]
		if !ok {
			continue
		}
		var rules []json.RawMessage
		if err := json.Unmarshal(body, &rules); err != nil {
			return fmt.Errorf("%w: %s must be a list of rules: %v", ErrInvalidRule, dir, err)
		}
		for i, rr := range rules {
			if err := validateRule(rr); err != nil {
				return fmt.Errorf("%s rule %d: %w", dir, i, err)
			}
		}
	}
	return nil
}

func validateRule(raw json.RawMessage) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()

	var r Rule
	if err := dec.Decode(&r); err != nil {
		// DisallowUnknownFields produces a message naming the offending key,
		// which is exactly what the author needs to see.
		return fmt.Errorf("%w: %v", ErrUnknownField, err)
	}

	// port and proto are ANDed into every rule and have no useful default, so
	// nebula treats an omitted one as the empty string and the rule matches
	// nothing. Requiring them turns a dead rule into an error.
	if r.Port == "" {
		return fmt.Errorf("%w: port is required (a number, \"22-80\", \"any\", or \"fragment\")", ErrInvalidRule)
	}
	if r.Proto == "" {
		return fmt.Errorf("%w: proto is required (any, tcp, udp, icmp)", ErrInvalidRule)
	}
	if !knownProtos[r.Proto] {
		return fmt.Errorf("%w: unknown proto %q", ErrInvalidRule, r.Proto)
	}
	if err := validatePort(r.Port); err != nil {
		return err
	}

	// Nebula rejects a rule carrying both; catching it here names the rule.
	if r.Group != "" && len(r.Groups) > 0 {
		return fmt.Errorf("%w: set either group or groups, not both", ErrInvalidRule)
	}

	for _, c := range []struct{ name, val string }{
		{"cidr", r.CIDR}, {"local_cidr", r.LocalCIDR},
	} {
		if c.val == "" {
			continue
		}
		if _, err := netip.ParsePrefix(c.val); err != nil {
			return fmt.Errorf("%w: %s %q is not a CIDR prefix: %v", ErrInvalidRule, c.name, c.val, err)
		}
	}

	// A rule with no host, group, cidr, or ca constraint matches every peer.
	// That is legal and sometimes intended, but it should be written
	// explicitly as host: any rather than arrived at by omission — the two look
	// identical to nebula and very different to a reviewer.
	if r.Host == "" && r.Group == "" && len(r.Groups) == 0 &&
		r.CIDR == "" && r.CAName == "" && r.CASha == "" {
		return fmt.Errorf("%w: rule constrains nothing; write host: any if that is intended", ErrInvalidRule)
	}

	return nil
}

// validatePort mirrors nebula's parsePort.
func validatePort(p string) error {
	switch p {
	case "any", "fragment":
		return nil
	}

	if lo, hi, found := strings.Cut(p, "-"); found {
		l, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return fmt.Errorf("%w: port range start %q is not a number", ErrInvalidRule, lo)
		}
		h, err := strconv.Atoi(strings.TrimSpace(hi))
		if err != nil {
			return fmt.Errorf("%w: port range end %q is not a number", ErrInvalidRule, hi)
		}
		if l > h {
			return fmt.Errorf("%w: port range %q is inverted", ErrInvalidRule, p)
		}
		return portInRange(l, p)
	}

	n, err := strconv.Atoi(p)
	if err != nil {
		return fmt.Errorf("%w: port %q is not a number, a range, \"any\", or \"fragment\"", ErrInvalidRule, p)
	}
	return portInRange(n, p)
}

func portInRange(n int, orig string) error {
	if n < 0 || n > 65535 {
		return fmt.Errorf("%w: port %q is outside 0-65535", ErrInvalidRule, orig)
	}
	return nil
}
