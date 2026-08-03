package nebulacfg_test

import (
	"errors"
	"testing"

	"github.com/griffithind/orbit/internal/nebulacfg"
)

func TestValidateFirewall(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{
			name: "valid rules",
			raw: `{"inbound":[{"port":"22","proto":"tcp","groups":["ssh"]},
			                  {"port":"any","proto":"icmp","host":"any"}],
			       "outbound":[{"port":"any","proto":"any","host":"any"}]}`,
		},
		{name: "empty", raw: `{}`},
		{name: "port range", raw: `{"inbound":[{"port":"8000-9000","proto":"tcp","host":"any"}]}`},
		{name: "fragment", raw: `{"inbound":[{"port":"fragment","proto":"any","host":"any"}]}`},
		{name: "cidr", raw: `{"inbound":[{"port":"any","proto":"any","cidr":"10.42.0.0/16"}]}`},

		// The headline case. Nebula accepts this and produces a rule with NO
		// group constraint; every host with the role would accept SSH from any
		// peer, silently.
		{
			name:    "typo in groups is caught",
			raw:     `{"inbound":[{"port":"22","proto":"tcp","groupss":["ssh"]}]}`,
			wantErr: nebulacfg.ErrUnknownField,
		},
		{
			name:    "typo in direction is caught",
			raw:     `{"inbounds":[{"port":"22","proto":"tcp","host":"any"}]}`,
			wantErr: nebulacfg.ErrUnknownField,
		},
		{
			name:    "unknown rule key",
			raw:     `{"inbound":[{"port":"22","proto":"tcp","host":"any","allow":true}]}`,
			wantErr: nebulacfg.ErrUnknownField,
		},

		{
			name:    "missing port",
			raw:     `{"inbound":[{"proto":"tcp","host":"any"}]}`,
			wantErr: nebulacfg.ErrInvalidRule,
		},
		{
			name:    "missing proto",
			raw:     `{"inbound":[{"port":"22","host":"any"}]}`,
			wantErr: nebulacfg.ErrInvalidRule,
		},
		{
			name:    "unknown proto",
			raw:     `{"inbound":[{"port":"22","proto":"sctp","host":"any"}]}`,
			wantErr: nebulacfg.ErrInvalidRule,
		},
		{
			name:    "port not a number",
			raw:     `{"inbound":[{"port":"http","proto":"tcp","host":"any"}]}`,
			wantErr: nebulacfg.ErrInvalidRule,
		},
		{
			name:    "port out of range",
			raw:     `{"inbound":[{"port":"70000","proto":"tcp","host":"any"}]}`,
			wantErr: nebulacfg.ErrInvalidRule,
		},
		{
			name:    "inverted range",
			raw:     `{"inbound":[{"port":"9000-8000","proto":"tcp","host":"any"}]}`,
			wantErr: nebulacfg.ErrInvalidRule,
		},
		{
			name:    "group and groups together",
			raw:     `{"inbound":[{"port":"22","proto":"tcp","group":"a","groups":["b"]}]}`,
			wantErr: nebulacfg.ErrInvalidRule,
		},
		{
			name:    "bad cidr",
			raw:     `{"inbound":[{"port":"any","proto":"any","cidr":"10.42.0.1"}]}`,
			wantErr: nebulacfg.ErrInvalidRule,
		},
		{
			// Legal in nebula, but "matches every peer" should be written, not
			// arrived at by leaving every constraint out.
			name:    "rule constrains nothing",
			raw:     `{"inbound":[{"port":"22","proto":"tcp"}]}`,
			wantErr: nebulacfg.ErrInvalidRule,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := nebulacfg.ValidateFirewall([]byte(tc.raw))
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("ValidateFirewall = %v, want nil", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ValidateFirewall = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestValidatedRulesStillRender confirms validation and rendering agree: a rule
// that validates must also survive ParseFirewall and reach nebula.
func TestValidatedRulesStillRender(t *testing.T) {
	raw := []byte(`{"inbound":[{"port":"22","proto":"tcp","groups":["ssh"]},
	                           {"port":"any","proto":"icmp","host":"any","code":"0"}],
	                "outbound":[{"port":"any","proto":"any","host":"any"}]}`)

	if err := nebulacfg.ValidateFirewall(raw); err != nil {
		t.Fatalf("ValidateFirewall: %v", err)
	}
	fw, err := nebulacfg.ParseFirewall(raw)
	if err != nil {
		t.Fatalf("ParseFirewall: %v", err)
	}
	if len(fw.Inbound) != 2 || len(fw.Outbound) != 1 {
		t.Fatalf("parsed %d inbound and %d outbound rules", len(fw.Inbound), len(fw.Outbound))
	}
}
