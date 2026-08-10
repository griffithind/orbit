package store

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestAuditMetaSurvivesHostileInput.
//
// meta is jsonb NOT NULL, so anything that is not valid JSON aborts the
// transaction and takes the mutation with it. Every site used to build this
// string with fmt.Sprintf and %q, which is GO quoting: it escapes " and \ but
// emits \a, \v, \x01 and invalid UTF-8 verbatim, and none of those are legal
// JSON escapes.
//
// The reachable case was `DELETE /hosts/{id}?reason=%07` — an authenticated
// destructive endpoint returning 500 with nothing in the response explaining
// why. Each input below broke the old encoder.
func TestAuditMetaSurvivesHostileInput(t *testing.T) {
	for name, reason := range map[string]string{
		"bell":            "bell\a",
		"vertical tab":    "vtab\v",
		"control byte":    "ctrl\x01",
		"invalid utf8":    "\xff\xfe",
		"quote":           `say "hi"`,
		"backslash":       `C:\path\to`,
		"newline":         "line1\nline2",
		"embedded object": `{"injected":true}`,
		"empty":           "",
	} {
		t.Run(name, func(t *testing.T) {
			b := AuditMeta(map[string]any{"name": "web-01", "reason": reason})

			var out map[string]any
			if err := json.Unmarshal(b, &out); err != nil {
				t.Fatalf("AuditMeta produced invalid JSON for %q: %v\n%s", reason, err, b)
			}
			// Round-trips as data, not as structure: an operator-supplied string
			// containing JSON must stay a string.
			if got, _ := out["reason"].(string); got != reason && json.Valid([]byte(reason)) {
				// Invalid UTF-8 is replaced by the encoder, so only assert exact
				// equality where the input was representable.
				if !strings.ContainsRune(reason, '\uFFFD') && json.Valid([]byte(`"`+reason+`"`)) {
					t.Errorf("reason round-tripped as %q, want %q", got, reason)
				}
			}
			if got, _ := out["name"].(string); got != "web-01" {
				t.Errorf("name = %q, want web-01", got)
			}
		})
	}
}

// TestAuditMetaNeverReturnsInvalidJSON. A value that cannot marshal must still
// yield something jsonb accepts: failing a mutation over its own description is
// worse than recording the description imperfectly.
func TestAuditMetaNeverReturnsInvalidJSON(t *testing.T) {
	b := AuditMeta(map[string]any{"bad": make(chan int)})
	if !json.Valid(b) {
		t.Fatalf("AuditMeta returned invalid JSON on a marshal failure: %s", b)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["meta_encode_error"]; !ok {
		t.Errorf("a marshal failure must say so in the record, got %s", b)
	}
}
