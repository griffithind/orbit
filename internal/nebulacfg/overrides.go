package nebulacfg

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The escape hatch, and its limits.
//
// Orbit models the settings that make a mesh work and deliberately does not
// model every setting nebula has. An operator who needs a smaller MTU, a
// different log level, or an odd punchy delay must have somewhere to put it, or
// authoritative mode is not usable and they fall back to fragment mode — which
// costs exactly the property authoritative mode exists to provide.
//
// So: a free-form map, merged last, over everything Orbit rendered.
//
// WHAT IT MAY NOT REACH, and why refusing is right.
//
// The keys below are the ones whose entire value is that Orbit controls them.
// Authoritative mode exists so that what Orbit says about a host's firewall,
// its trust material, and its place in the topology is the WHOLE truth rather
// than a lower bound. An override that could rewrite firewall.inbound would
// reintroduce precisely the divergence this mode removes — and it would be
// worse than fragment mode, because the resulting file still looks
// authoritative to anyone reading it, and the policy view would still claim to
// be complete.
//
// pki.* is the same argument with sharper edges: the trust bundle, the
// certificate, and the blocklist are the mechanism by which a revocation takes
// effect, and an override pointing pki.blocklist somewhere else is a host that
// silently stops honouring revocations. static_host_map and the lighthouse and
// relay flags decide who a host talks to and who it forwards for, which is
// Orbit's answer to "what is the topology" — an override there makes that answer
// wrong for one host with nothing to indicate it.
//
// listen.port and tun.dev are refused for a narrower and more practical reason:
// they are already first-class fields, allocated per (host, network) so that two
// nebula processes on one machine do not collide. A second way to set them is a
// second source of truth, and the API would then report a port the host is not
// listening on.
//
// Refusal happens at the API when the value is written AND here when it is
// rendered. Validating only at the API would leave a value that predates the
// rule rendering silently; validating only here would surface an operator's typo
// as a failed config push on a host rather than as a 400 on the request that
// made it.
//
// Parents cover their children: "pki" refuses pki.blocklist and
// pki.disconnect_invalid without listing them, because walkOverride visits every
// path INCLUDING the parents on the way down. Listing a child as well would be a
// second place to keep in step for no additional protection.
var protectedOverrides = map[string]string{
	"pki":                      "Orbit owns the trust material and the blocklist; an override here can silently stop a host honouring revocations",
	"firewall":                 "the firewall comes from the host's role, and authoritative mode's whole purpose is that the rendered rules are the complete policy",
	"static_host_map":          "Orbit owns the topology; an override here makes the control plane's view of who a host can reach wrong for that host alone",
	"lighthouse.am_lighthouse": "whether a host is a lighthouse is a control-plane role, not a local setting; set it on the host",
	"lighthouse.hosts":         "the lighthouse list is derived from the network's topology",
	"relay.am_relay":           "whether a host relays is a control-plane role; set it on the host",
	"relay.use_relays":         "derived from whether this host is itself a relay",
	"relay.relays":             "the relay list is derived from the network's topology",
	"listen.port":              "the listen port is allocated per host and network so two nebula processes on one machine do not collide; set it on the host or the network",
	"tun.dev":                  "the tun device is allocated per host and network for the same reason; set it on the host or the network",
	"tun.disabled":             "derived from the host's roles: a lighthouse that is not a relay needs no tun device",

	// Orbit's OWN section — the one part of this file that is definitionally
	// not nebula's — was reachable by an override until ADR-0033. Overrides are
	// merged last and the result is THEN signed, so the agent's signature check
	// provides no protection here: the control plane vouches for whatever was
	// injected. `orbit.dns.hosts` mints name-to-address mappings, and mesh names
	// are free text (ADR-0029), so that included mappings for public names.
	"orbit": "the orbit section is what Orbit renders about itself — DNS names, the resolver's address, the exit-node and forwarding flags; an override here rewrites the control plane's own output and is then signed as if the control plane meant it",

	// A second, unmanaged DNS server on a managed host. lighthouse.dns.host
	// defaults to the empty string, which is every interface
	// (third_party/nebula/dns_server.go:452).
	"lighthouse.serve_dns": "Orbit runs the mesh resolver itself; nebula's hostmap-backed one would be a second unmanaged DNS server, bound to every interface by default",
	"lighthouse.dns":       "same reason as lighthouse.serve_dns",

	// The other half of the socket listen.port is protected for. Note that
	// listen.host has no first-class field yet, so protecting it removes the
	// only lever an operator had — which ADR-0033 accepts, because an override
	// that is the SUPPORTED path for a rendered key is a hole shaped exactly
	// like the rule it is meant to protect.
	"listen.host": "the listen address is Orbit's to choose, for the same reason as listen.port; it is currently always \"::\" and wants a field of its own rather than an override",
}

// ValidateOverrides refuses an override that would rewrite a key Orbit owns.
//
// The error names the exact path and says why, because "invalid overrides" sends
// an operator to read source code and the reason is the part that stops them
// retrying.
func ValidateOverrides(ov map[string]any) error {
	var bad []string
	walkOverride(ov, nil, func(path string) {
		if reason, ok := protectedOverrides[path]; ok {
			bad = append(bad, fmt.Sprintf("%s: %s", path, reason))
		}
	})
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("config overrides may not set keys Orbit owns:\n  %s",
		strings.Join(bad, "\n  "))
}

// ParseOverrides decodes the stored jsonb form.
//
// An empty document is not an error and yields nil: "{}" is what the column
// defaults to, and every host has one.
func ParseOverrides(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || string(raw) == "{}" || string(raw) == "null" {
		return nil, nil
	}
	var ov map[string]any
	if err := json.Unmarshal(raw, &ov); err != nil {
		return nil, fmt.Errorf("parse config overrides: %w", err)
	}
	return ov, nil
}

// MergeOverrides layers host overrides over network ones.
//
// Deep for maps and replacing for everything else, which matches how an operator
// reads it: setting tun.mtu on a host must not discard the network's
// logging.level, but setting a list replaces the list rather than appending to
// it — a merge that appended would make "remove this entry" inexpressible, the
// same reason a role's firewall rules replace rather than merge.
func MergeOverrides(base, over map[string]any) map[string]any {
	if len(base) == 0 {
		return over
	}
	if len(over) == 0 {
		return base
	}
	out := make(map[string]any, len(base)+len(over))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range over {
		bm, bok := out[k].(map[string]any)
		om, ook := v.(map[string]any)
		if bok && ook {
			out[k] = MergeOverrides(bm, om)
			continue
		}
		out[k] = v
	}
	return out
}

// walkOverride visits every path in an override map, parents included, so a
// protected parent catches an override of any child.
func walkOverride(m map[string]any, prefix []string, visit func(path string)) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		p := append(append([]string(nil), prefix...), k)
		visit(strings.Join(p, "."))
		if child, ok := m[k].(map[string]any); ok {
			walkOverride(child, p, visit)
		}
	}
}

// applyOverrides merges ov into a rendered document tree.
//
// Recursive into mappings so an override adds to a section rather than replacing
// it; anything else replaces. Keys are visited in sorted order and encoded with
// encodeValue, so two renders of the same input produce the same bytes even
// though the override arrived as a Go map with no order at all.
func applyOverrides(node *yaml.Node, ov map[string]any) error {
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return fmt.Errorf("empty document")
		}
		return applyOverrides(node.Content[0], ov)
	}
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("cannot apply overrides to a %v", node.Kind)
	}

	keys := make([]string, 0, len(ov))
	for k := range ov {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		v := ov[k]
		idx := mappingIndex(node, k)

		if child, ok := v.(map[string]any); ok && idx >= 0 &&
			node.Content[idx+1].Kind == yaml.MappingNode {
			if err := applyOverrides(node.Content[idx+1], child); err != nil {
				return err
			}
			continue
		}

		encoded, err := encodeValue(v)
		if err != nil {
			return fmt.Errorf("override %s: %w", k, err)
		}
		if idx >= 0 {
			node.Content[idx+1] = encoded
			continue
		}
		node.Content = append(node.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, encoded)
	}
	return nil
}

// mappingIndex returns the position of a key node in a mapping's Content, or -1.
func mappingIndex(node *yaml.Node, key string) int {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return i
		}
	}
	return -1
}

// encodeValue turns a decoded JSON value into a yaml node with sorted map keys.
//
// yaml.Node.Encode would do this in one line and would iterate a Go map in
// random order, which is fine for a config file and fatal for a hash the agent
// compares against the last one it applied: the same overrides would render
// differently on every poll and every host would see a change that is not one.
func encodeValue(v any) (*yaml.Node, error) {
	switch t := v.(type) {
	case map[string]any:
		node := &yaml.Node{Kind: yaml.MappingNode}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			child, err := encodeValue(t[k])
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}, child)
		}
		return node, nil
	case []any:
		node := &yaml.Node{Kind: yaml.SequenceNode}
		for _, e := range t {
			child, err := encodeValue(e)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, child)
		}
		return node, nil
	default:
		var node yaml.Node
		if err := node.Encode(v); err != nil {
			return nil, err
		}
		return &node, nil
	}
}
