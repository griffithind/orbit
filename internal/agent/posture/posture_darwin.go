package posture

import (
	"os/exec"
	"strings"
)

// osRelease names this Mac.
//
// /etc/os-release does not exist on darwin, so the generic reader returned nothing and
// `orbit device ls` showed a blank OS for every Mac in the fleet while Linux hosts
// reported themselves fine — which reads as an agent that is not reporting rather than a
// file that is not there.
//
// sw_vers rather than a plist or a syscall: it is the interface Apple documents, it is on
// every Mac, and its output is what a person would say the machine is running.
func osRelease() string {
	name := swVers("productName")
	version := swVers("productVersion")
	switch {
	case name != "" && version != "":
		return name + " " + version
	case name != "":
		return name
	case version != "":
		// A version with no name is still more than nothing, and macOS is the
		// only thing sw_vers runs on.
		return "macOS " + version
	}
	return ""
}

func swVers(field string) string {
	out, err := exec.Command("sw_vers", "-"+field).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
