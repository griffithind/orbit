package status

import "github.com/griffithind/orbit/internal/fwmatch"

// ExplainRequest is what the caller asked.
type ExplainRequest struct {
	// Peer is an overlay address, or the name of a peer this host currently has
	// a tunnel with. A name is only resolvable through the hostmap, so a peer
	// that has never connected must be named by address — which is exactly the
	// case somebody is usually asking about.
	Peer  string
	Proto string
	Port  string
}

// Explanation is the whole answer, in the three layers that fail independently.
type Explanation struct {
	Network string `json:"network"`
	Peer    string `json:"peer"`
	Proto   string `json:"proto"`
	Port    string `json:"port"`

	// Identity.
	Certificate  *CertStatus `json:"certificate,omitempty"`
	CertExpired  bool        `json:"cert_expired,omitempty"`
	PeerResolved string      `json:"peer_resolved,omitempty"`
	PeerName     string      `json:"peer_name,omitempty"`
	PeerGroups   []string    `json:"peer_groups,omitempty"`
	PeerKnown    bool        `json:"peer_known"`

	// Path.
	Running       bool     `json:"running"`
	Detail        string   `json:"detail,omitempty"`
	TunnelUp      bool     `json:"tunnel_up"`
	Handshaking   bool     `json:"handshaking,omitempty"`
	CurrentRemote string   `json:"current_remote,omitempty"`
	RelaysToMe    []string `json:"relays_to_me,omitempty"`

	// Policy, for the two directions this host can actually answer for.
	Outbound fwmatch.Decision `json:"outbound"`
	Inbound  fwmatch.Decision `json:"inbound"`
}
