package agent

import (
	"log/slog"
	"os"
	"path/filepath"

	"github.com/griffithind/orbit/internal/agent/paths"
	"go.yaml.in/yaml/v3"
)

// WarnInstanceCollisions reports settings that are global to the host but
// rendered per network.
//
// listen.port and tun.dev belong to the machine, not to a network, but they are
// chosen by a control plane that can only see its own network. Two networks on
// one host — possibly served by two control planes that will never learn of
// each other — can therefore both pick 4242, or both pick "nebula1", and nobody
// upstream is in a position to notice.
//
// The agent is. It is the only component that can see the other networks'
// directories, because they are siblings under the same root. So it looks, once
// at startup, and says so.
//
// A warning and not an error: the sibling directory may belong to a network
// that is enrolled but not running, the collision may be about to be fixed on
// the other side, and refusing to start would turn a misconfiguration into an
// outage for a network that was working. Nebula will fail to bind loudly enough
// if it is real; this exists so the reason is already in the log when it does.
func WarnInstanceCollisions(l paths.Layout, log *slog.Logger) {
	root := filepath.Dir(l.Dir)
	entries, err := os.ReadDir(root)
	if err != nil {
		return // not a shared root, or unreadable; nothing to compare against
	}

	mine, ok := readHostSettings(l.ConfigPath())
	if !ok {
		return
	}

	for _, e := range entries {
		if !e.IsDir() || filepath.Join(root, e.Name()) == l.Dir {
			continue
		}
		peerDir := filepath.Join(root, e.Name())
		theirs, ok := readHostSettings(paths.DefaultLayout(peerDir).ConfigPath())
		if !ok {
			continue
		}
		if mine.port != 0 && mine.port == theirs.port {
			log.Warn("another network on this host listens on the same UDP port; "+
				"only one of the two nebula processes will bind it",
				"network", l.Network, "otherNetwork", e.Name(), "port", mine.port)
		}
		if mine.dev != "" && mine.dev == theirs.dev {
			log.Warn("another network on this host uses the same tun device name; "+
				"only one of the two nebula processes will create it",
				"network", l.Network, "otherNetwork", e.Name(), "device", mine.dev)
		}
	}
}

type membershipSettings struct {
	port int
	dev  string
}

func readHostSettings(path string) (membershipSettings, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return membershipSettings{}, false
	}
	var doc struct {
		Listen struct {
			Port int `yaml:"port"`
		} `yaml:"listen"`
		Tun struct {
			Dev string `yaml:"dev"`
		} `yaml:"tun"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return membershipSettings{}, false
	}
	// Port 0 means "any", which cannot collide.
	return membershipSettings{port: doc.Listen.Port, dev: doc.Tun.Dev}, true
}
