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

		// The resources that actually thrash.
		//
		// The two checks above are for port and device, which CANNOT collide
		// silently: a second nebula fails loudly to bind or create them. Host
		// state is the opposite — the nftables table, the route table and the ip
		// rule are named once per machine, so two networks that both want them
		// used to overwrite each other once per reconcile with both Apply calls
		// reporting success. One of them now refuses instead (see
		// hostcfg/owner.go); warning at startup is how an operator learns why
		// before wondering where their forwarding went.
		if mine.hostState && theirs.hostState {
			log.Warn("another network on this host also configures host state; "+
				"only one of them will, because the nftables table and the policy "+
				"route are named once per machine",
				"network", l.Network, "otherNetwork", e.Name())
		}
	}
}

type membershipSettings struct {
	port int
	dev  string

	// hostState is whether this network asks for anything host-global —
	// forwarding, masquerade, or an exit route. Read from the rendered config
	// rather than from what was applied, because the warning is for startup,
	// before anything has been applied.
	hostState bool
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
		Orbit struct {
			Forward  bool `yaml:"forward"`
			ExitNode bool `yaml:"exit_node"`
			Serves   []struct {
				Masquerade bool `yaml:"masquerade"`
			} `yaml:"serves"`
		} `yaml:"orbit"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return membershipSettings{}, false
	}
	// The same predicate HostState.Empty uses, read from the rendered document:
	// a network wants host state when it forwards, when it consumes an exit
	// route, or when it masquerades for anything.
	hostState := doc.Orbit.Forward || doc.Orbit.ExitNode
	for _, sv := range doc.Orbit.Serves {
		if sv.Masquerade {
			hostState = true
		}
	}
	// Port 0 means "any", which cannot collide.
	return membershipSettings{port: doc.Listen.Port, dev: doc.Tun.Dev, hostState: hostState}, true
}
