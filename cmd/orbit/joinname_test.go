package main

import "testing"

// A membership name is one DNS label; a hostname routinely is not. Every Mac
// reports something.local and plenty of Linux hosts report a full FQDN, so
// refusing at the server would have broken `orbit join` with no flag on most of
// the machines people actually have — which is how this was found, by the e2e
// suite failing on the developer's own hostname, ik-m4.local.
func TestLabelFromHostname(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"ik-m4.local", "ik-m4"},
		{"web01.corp.example.com", "web01"},
		{"PLAIN", "plain"},
		{"host_with_underscores", "hostwithunderscores"},
		{"-leading-and-trailing-", "leading-and-trailing"},
		{"  spaced.local  ", "spaced"},
		{"", ""},
		{".local", ""},
		{"...", ""},
		{"!!!", ""},
	} {
		if got := labelFromHostname(c.in); got != c.want {
			t.Errorf("labelFromHostname(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestALongHostnameIsTruncatedNotRefused. A machine whose hostname exceeds a
// DNS label is still a machine somebody has to enrol.
func TestALongHostnameIsTruncatedNotRefused(t *testing.T) {
	long := ""
	for range 100 {
		long += "a"
	}
	got := labelFromHostname(long + ".example.com")
	if len(got) != 63 {
		t.Errorf("length = %d, want 63", len(got))
	}
	// And never left ending in a hyphen, which is not a valid label.
	if got != "" && got[len(got)-1] == '-' {
		t.Error("truncation left a trailing hyphen, which is not a valid label")
	}
}
