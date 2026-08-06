//go:build !darwin

package agent

import (
	"bufio"
	"os"
	"strings"
)

// osRelease reads PRETTY_NAME from /etc/os-release.
//
// The file is specified by systemd and present on every distribution worth
// supporting, which is why this is a read rather than a shell out to lsb_release
// — a binary that is frequently absent on minimal and container images.
func osRelease() string {
	f, err := os.Open(sysPath("/etc/os-release"))
	if err != nil {
		return ""
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if ok && k == "PRETTY_NAME" {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}
