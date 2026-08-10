package posture

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The probes run against a synthetic /proc and /sys.
//
// Without that these tests would assert whatever the machine running them
// happens to be — nothing on a developer laptop, something else in CI — which is
// the same as asserting nothing. The property that actually matters here is the
// tri-state: unknown must never collapse into false.

// fakeSys builds a root and points the probes at it for one test.
func fakeSys(t *testing.T, files map[string]string) {
	t.Helper()
	root := t.TempDir()
	for name, content := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	old := sysRoot
	sysRoot = root
	t.Cleanup(func() { sysRoot = old })
}

func want(t *testing.T, what string, got *bool, expect *bool) {
	t.Helper()
	switch {
	case got == nil && expect == nil:
	case got == nil || expect == nil:
		t.Errorf("%s = %s, want %s", what, show(got), show(expect))
	case *got != *expect:
		t.Errorf("%s = %s, want %s", what, show(got), show(expect))
	}
}

func show(b *bool) string {
	if b == nil {
		return "unknown"
	}
	if *b {
		return "true"
	}
	return "false"
}

func TestDiskEncrypted(t *testing.T) {
	t.Run("dm-crypt present", func(t *testing.T) {
		fakeSys(t, map[string]string{
			"/sys/block/dm-0/dm/uuid": "CRYPT-LUKS2-abc123-root\n",
		})
		want(t, "diskEncrypted", diskEncrypted(), boolp(true))
	})

	// An LVM mapping is a device mapper target and is NOT encryption. Matching
	// on "dm-" alone rather than the CRYPT- prefix would report a plain LVM
	// machine as encrypted, which is the failure that makes a compliance report
	// worse than having none.
	t.Run("lvm is not encryption", func(t *testing.T) {
		fakeSys(t, map[string]string{
			"/sys/block/dm-0/dm/uuid": "LVM-xyz789\n",
		})
		want(t, "diskEncrypted", diskEncrypted(), boolp(false))
	})

	// No /sys/block at all is unknown, not false: this is a container or a
	// platform without sysfs, and it has told us nothing.
	t.Run("no sysfs is unknown", func(t *testing.T) {
		fakeSys(t, nil)
		want(t, "diskEncrypted", diskEncrypted(), nil)
	})
}

func TestSecureBoot(t *testing.T) {
	const efivar = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

	t.Run("enabled", func(t *testing.T) {
		fakeSys(t, map[string]string{efivar: "\x06\x00\x00\x00\x01"})
		want(t, "secureBoot", secureBoot(), boolp(true))
	})
	t.Run("disabled", func(t *testing.T) {
		fakeSys(t, map[string]string{efivar: "\x06\x00\x00\x00\x00"})
		want(t, "secureBoot", secureBoot(), boolp(false))
	})

	// A legacy BIOS machine has no such variable. That is unknown — the
	// question does not apply — and NOT false, which would file it alongside a
	// UEFI machine that has the feature switched off.
	t.Run("no efivars is unknown", func(t *testing.T) {
		fakeSys(t, nil)
		want(t, "secureBoot", secureBoot(), nil)
	})

	// A truncated read must not index past the end.
	t.Run("truncated is unknown", func(t *testing.T) {
		fakeSys(t, map[string]string{efivar: "\x06\x00"})
		want(t, "secureBoot", secureBoot(), nil)
	})
}

func TestFirewallEnabled(t *testing.T) {
	t.Run("tables populated", func(t *testing.T) {
		fakeSys(t, map[string]string{"/proc/net/ip_tables_names": "filter\nnat\n"})
		want(t, "firewallEnabled", firewallEnabled(), boolp(true))
	})
	t.Run("tables empty", func(t *testing.T) {
		fakeSys(t, map[string]string{"/proc/net/ip_tables_names": "\n"})
		want(t, "firewallEnabled", firewallEnabled(), boolp(false))
	})
	t.Run("no netfilter is unknown", func(t *testing.T) {
		fakeSys(t, nil)
		want(t, "firewallEnabled", firewallEnabled(), nil)
	})
}

func TestTPMPresent(t *testing.T) {
	t.Run("device node", func(t *testing.T) {
		fakeSys(t, map[string]string{"/dev/tpmrm0": ""})
		want(t, "tpmPresent", tpmPresent(), boolp(true))
	})

	// A kernel with TPM support and no chip: /sys/class/tpm exists and is
	// empty. That is a genuine false.
	t.Run("empty class dir is false", func(t *testing.T) {
		fakeSys(t, nil)
		if err := os.MkdirAll(filepath.Join(sysRoot, "sys/class/tpm"), 0o755); err != nil {
			t.Fatal(err)
		}
		want(t, "tpmPresent", tpmPresent(), boolp(false))
	})

	t.Run("no tpm subsystem is unknown", func(t *testing.T) {
		fakeSys(t, nil)
		want(t, "tpmPresent", tpmPresent(), nil)
	})
}

func TestFacts(t *testing.T) {
	fakeSys(t, map[string]string{
		"/etc/os-release":            "NAME=\"Fedora Linux\"\nPRETTY_NAME=\"Fedora Linux 42 (Silverblue)\"\nID=fedora\n",
		"/proc/sys/kernel/osrelease": "6.14.0-63.fc42.x86_64\n",
	})
	f := Facts("v1.11.0")
	// The fake /etc/os-release only reaches the platforms that read one. Darwin
	// asks sw_vers, which is the real machine and not something a test should
	// pin — so this asserts the shape it must never have: an empty string, which
	// is what every Mac reported before posture_darwin.go existed and what made
	// a fleet look like it had agents that were not reporting.
	if runtime.GOOS == "darwin" {
		if f.OSVersion == "" {
			t.Error("OSVersion is empty on darwin; sw_vers should name the machine")
		}
	} else if f.OSVersion != "Fedora Linux 42 (Silverblue)" {
		t.Errorf("OSVersion = %q", f.OSVersion)
	}
	if f.Kernel != "6.14.0-63.fc42.x86_64" {
		t.Errorf("Kernel = %q", f.Kernel)
	}
	if f.NebulaVersion != "v1.11.0" {
		t.Errorf("NebulaVersion = %q", f.NebulaVersion)
	}
	if f.OS == "" || f.Arch == "" {
		t.Error("OS and Arch come from the compiler and must never be empty")
	}
}

// TestFactsToleratesAMachineThatSaysNothing.
//
// A minimal container has no /etc/os-release and no /proc. Facts must still
// return what the compiler knows rather than failing, because the agent reports
// on every cycle and a probe that errors would take the epoch report with it.
func TestFactsToleratesAMachineThatSaysNothing(t *testing.T) {
	fakeSys(t, nil)
	f := Facts("")
	if f == nil {
		t.Fatal("Facts returned nil")
	}
	if f.OS == "" {
		t.Error("OS is empty; it comes from runtime.GOOS and cannot be")
	}
}
