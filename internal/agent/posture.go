package agent

import (
	"os"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/griffithind/orbit/internal/wire"
)

// Reading the machine.
//
// NATIVE READS, NO OSQUERY, and that is a deliberate scope decision rather than
// a stopgap. osquery answers vastly more than this does, and the cost is a
// second daemon, a second update cadence, and a second thing an operator has to
// have working before Orbit can say anything about a fleet. The signals below
// are the ones policy will actually gate on; each is a file read.
//
// EVERY PROBE RETURNS nil WHEN IT CANNOT TELL, and nothing here ever guesses
// false. A machine whose disk encryption could not be read is not a machine with
// an unencrypted disk. Conflating them would make a broken probe look like a
// non-compliant fleet, and the correct response to those two is opposite.
//
// The probes are Linux-shaped and say so by returning nil elsewhere, which is
// the honest answer: this reads /proc, /sys and /dev, and on a platform without
// them it knows nothing.

// Facts describes this machine.
//
// nebulaVersion is passed in rather than read here so a caller running an
// external nebula can report what it actually launched. Empty falls back to the
// embedded module's version, which is the right answer for the default build.
func Facts(nebulaVersion string) *wire.DeviceFacts {
	if nebulaVersion == "" {
		nebulaVersion = EmbeddedNebulaVersion()
	}
	f := &wire.DeviceFacts{
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		AgentVersion:  Version,
		NebulaVersion: nebulaVersion,
	}
	f.OSVersion = osRelease()
	f.Kernel = kernelRelease()
	return f
}

// EmbeddedNebulaVersion reports the nebula the agent has linked in.
//
// Read from the build info rather than declared as a constant, because a
// constant is a second place to update on every dependency bump and the one
// that gets forgotten — leaving a fleet report that confidently names the
// version from two releases ago. Empty in a test binary built without module
// info, which is honest: the caller stores nothing rather than a guess.
func EmbeddedNebulaVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, d := range info.Deps {
		if d.Path == "github.com/slackhq/nebula" {
			return d.Version
		}
	}
	return ""
}

// Posture reads this machine's security configuration.
func Posture() *wire.DevicePosture {
	return &wire.DevicePosture{
		DiskEncrypted:   diskEncrypted(),
		SecureBoot:      secureBoot(),
		FirewallEnabled: firewallEnabled(),
		TPMPresent:      tpmPresent(),
	}
}

func boolp(b bool) *bool { return &b }

// sysRoot prefixes every path these probes read.
//
// Empty in production, so the paths are the absolute ones they appear to be. A
// test sets it to a directory holding a synthetic /proc and /sys, which is the
// only way to assert what these functions do — the alternative is a package
// whose entire behaviour depends on the machine running the suite, and which
// therefore asserts nothing on a developer laptop and something different in CI.
var sysRoot string

func sysPath(p string) string { return sysRoot + p }

func kernelRelease() string {
	b, err := os.ReadFile(sysPath("/proc/sys/kernel/osrelease"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// diskEncrypted reports whether any dm-crypt mapping exists.
//
// ANY, not "the root filesystem is encrypted", and the gap is worth stating
// rather than hiding behind a boolean: this returns true for a machine whose
// root is plaintext and which happens to have one encrypted volume attached.
// Establishing that the ROOT is encrypted means resolving / through the device
// mapper, which is a materially larger piece of work and belongs with the
// attestation story rather than here.
//
// It is still the right signal to ship first. On a bootc fleet — which is the
// deployment this is being built for — the root is either encrypted at install
// or it is not, so the two readings coincide in practice, and a machine with no
// dm-crypt at all is unambiguous.
func diskEncrypted() *bool {
	entries, err := os.ReadDir(sysPath("/sys/block"))
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "dm-") {
			continue
		}
		// The UUID of a dm-crypt mapping is prefixed CRYPT-. Other device
		// mapper targets — LVM, multipath — have their own prefixes, so this
		// distinguishes an encrypted volume from a merely mapped one.
		b, err := os.ReadFile(sysPath("/sys/block/" + e.Name() + "/dm/uuid"))
		if err != nil {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(string(b)), "CRYPT-") {
			return boolp(true)
		}
	}
	// Reaching here means /sys/block was readable and held no encrypted
	// mapping, which is a genuine false rather than an unknown.
	return boolp(false)
}

// secureBoot reads the UEFI SecureBoot variable.
//
// The efivars encoding is four bytes of attributes followed by the value, so the
// flag is the fifth byte. A machine booted in legacy BIOS mode has no such
// variable at all, which is unknown rather than false: the question does not
// apply, and answering "not secure booted" would put it in the same bucket as a
// UEFI machine with the feature switched off.
func secureBoot() *bool {
	const path = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
	b, err := os.ReadFile(sysPath(path))
	if err != nil || len(b) < 5 {
		return nil
	}
	return boolp(b[4] == 1)
}

// firewallEnabled reports whether the kernel holds any netfilter hooks.
//
// /proc/net/nf_conntrack existing is not the test — conntrack loads for reasons
// unrelated to a firewall. The presence of the nf_tables or ip_tables modules is
// closer, but the honest signal available without shelling out to nft is
// /proc/net/ip_tables_names, which is non-empty only when a table has been
// populated.
//
// This is the weakest probe here, and the reason it is included anyway is that
// "no firewall tables at all" is a real and detectable state that an operator
// should see. It cannot distinguish a permissive ruleset from a strict one, and
// a policy that treats true as "protected" is over-reading it.
func firewallEnabled() *bool {
	for _, p := range []string{"/proc/net/ip_tables_names", "/proc/net/nf_tables"} {
		b, err := os.ReadFile(sysPath(p))
		if err != nil {
			continue
		}
		if len(strings.TrimSpace(string(b))) > 0 {
			return boolp(true)
		}
		return boolp(false)
	}
	// Neither file readable: on a machine without netfilter compiled in, or a
	// container without the host's /proc. Unknown, not false.
	return nil
}

// tpmPresent reports whether a TPM device node exists.
//
// Presence only. It says nothing about whether the TPM is usable, whether it
// holds an endorsement certificate, or whether anything is sealed to it —
// none of which a file check can answer. It is inventory, reported alongside
// secure boot and disk encryption: knowing which machines in a fleet have one
// is worth recording even though Orbit does not use it.
func tpmPresent() *bool {
	for _, p := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
		if _, err := os.Stat(sysPath(p)); err == nil {
			return boolp(true)
		}
	}
	// /sys/class/tpm exists on any kernel with TPM support compiled in, so an
	// empty directory is a genuine "no TPM" and a missing one is unknown.
	entries, err := os.ReadDir(sysPath("/sys/class/tpm"))
	if err != nil {
		return nil
	}
	return boolp(len(entries) > 0)
}
