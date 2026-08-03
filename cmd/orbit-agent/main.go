// Command orbit-agent enrolls a host into ONE network and keeps its nebula
// configuration current.
//
// One agent process per network. Everything the agent owns for that network
// lives in one per-network directory — /var/lib/orbit/<slug> by convention —
// and a host joined to two networks runs two agents over two directories with
// nothing shared. See internal/agent/layout.go.
//
// It supervises the stock nebula binary: it writes the configuration and the
// certificate material, then signals a reload, or restarts nebula and verifies
// the restart took when the change is one nebula cannot hot-load. It never
// embeds nebula, and it never restarts nebula merely because the process died —
// the service manager owns that — so an agent failure cannot take down the data
// plane.
//
// Why -dir and not -network:
//
// The directory is the single knob, and it is total: every path the agent
// touches is under it. Deriving the directory from a slug and a compiled-in
// root would put a filesystem policy inside the binary, where a test, a
// container, a second stack on one box, or a distribution with different
// conventions cannot change it — and the e2e suite alone enrolls into a
// temporary directory hundreds of times. systemd's StateDirectory=orbit/%i
// already creates the per-network directory with the right ownership, so the
// unit file states the layout once and the flag agrees with it by construction.
// -network below is a convenience that expands to the default root; it never
// becomes a second source of truth.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/version"
)

// dirFlags registers the -dir/-network pair shared by every subcommand.
//
// Exactly one of them decides the directory. Accepting both would create two
// ways to spell the same thing that can disagree, which on this particular knob
// means an agent renewing certificates into a directory nebula is not reading.
type dirFlags struct {
	dir     *string
	network *string
	mode    *string
}

func addDirFlags(fs *flag.FlagSet) *dirFlags {
	return &dirFlags{
		dir:     fs.String("dir", "", "per-network directory the agent owns: config, certificate, key, state, rollback copy (default "+agent.DefaultRoot+"/<network>)"),
		network: fs.String("network", "", "network slug; shorthand for -dir "+agent.DefaultRoot+"/<slug>"),
		mode: fs.String("mode", "authoritative",
			`"authoritative" writes one complete nebula.yml that nebula is pointed at directly; `+
				`"fragment" writes config.d/50-orbit.yml for nebula to merge with operator files`),
	}
}

func (d *dirFlags) layout() (agent.Layout, error) {
	mode, err := agent.ParseConfigMode(*d.mode)
	if err != nil {
		return agent.Layout{}, err
	}
	switch {
	case *d.dir != "" && *d.network != "":
		// Only an error when they disagree: a unit that passes both for
		// readability is fine, one that passes two different things is not.
		if filepath.Clean(*d.dir) != agent.DirFor(*d.network) {
			return agent.Layout{}, fmt.Errorf("-dir %q and -network %q disagree; pass one or the other", *d.dir, *d.network)
		}
	case *d.network != "":
		if err := agent.ValidateNetwork(*d.network); err != nil {
			return agent.Layout{}, err
		}
		*d.dir = agent.DirFor(*d.network)
	case *d.dir == "":
		return agent.Layout{}, errors.New("one of -dir or -network is required; " +
			"an agent manages exactly one network and has no default")
	}
	return agent.LayoutFor(filepath.Clean(*d.dir), mode), nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "enroll":
		err = enrollCmd(os.Args[2:])
	case "run":
		err = runCmd(os.Args[2:])
	case "recover":
		err = recoverCmd(os.Args[2:])
	case "version", "-version", "--version":
		fmt.Println(version.Version)
		return
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "orbit-agent:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `orbit-agent <command> [flags]

  enroll   join a network using an enrollment code
  run      poll for updates and apply them
  recover  re-obtain a certificate after this host's expired while offline
  version  print the build version

Every command manages exactly ONE network and needs -dir (or -network, which is
shorthand for `+agent.DefaultRoot+`/<slug>). A host on two networks runs two
agents over two directories.

Run "orbit-agent <command> -h" for flags.
`)
}

func describeSupervisor(s agent.Supervisor) string {
	if s == nil {
		return "none"
	}
	return s.Describe()
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	if os.Getenv("ORBIT_DEBUG") != "" {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func enrollCmd(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	var (
		url    = fs.String("url", "", "control plane base URL")
		code   = fs.String("code", "", "enrollment code (or ORBIT_ENROLL_CODE)")
		reload = fs.String("reload", "", `how to reload nebula: "pid:/run/nebula.pid", a command, or empty for none`)
		curve  = fs.String("curve", "CURVE25519", "key curve; must match the network")
	)
	df := addDirFlags(fs)
	_ = fs.Parse(args)

	layout, err := df.layout()
	if err != nil {
		return err
	}
	dir := &layout.Dir

	if *code == "" {
		*code = os.Getenv("ORBIT_ENROLL_CODE")
	}
	if *url == "" || *code == "" {
		return errors.New("-url and -code are required")
	}

	log := newLogger()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	c, err := parseCurve(*curve)
	if err != nil {
		return err
	}

	// The keypair is generated here, on the host. The private half is written
	// to disk by the applier and is never transmitted.
	kp, err := agent.GenerateKeypair(c)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	client := agent.NewClient(*url)
	resp, err := client.Enroll(ctx, *code, kp, version.Version)
	if err != nil {
		var apiErr *agent.APIError
		if errors.As(err, &apiErr) && !apiErr.Retryable() {
			// A spent or expired code is not worth retrying, and a retry loop
			// against an enrollment endpoint looks exactly like an attack.
			return fmt.Errorf("enrollment rejected: %s", apiErr.Message)
		}
		return fmt.Errorf("enroll: %w", err)
	}

	applier := &agent.Applier{
		Layout:   layout,
		Reloader: agent.ParseReloader(*reload),
		Log:      log,
	}
	if err := applier.Apply(ctx, agent.MaterialFromEnroll(resp, kp.PrivatePEM)); err != nil {
		return err
	}

	log.Info("enrolled",
		"host", resp.HostName, "hostId", resp.HostID, "layout", layout.Describe(),
		"configEpoch", resp.ConfigEpoch, "renewAfter", resp.RenewAfter)

	if len(resp.AgentEndpoints) > 0 {
		log.Info("control plane reachable over the overlay; "+
			"steady-state traffic will use it and no credential is stored",
			"endpoints", resp.AgentEndpoints)
	} else {
		log.Warn("control plane advertised no overlay endpoints; the agent will " +
			"keep using the public URL and has no replica to fail over to")
	}

	if err := agent.WriteState(*dir, agent.State{
		BaseURL:        *url,
		AgentURLs:      resp.AgentEndpoints,
		ConfigEpoch:    resp.ConfigEpoch,
		BlocklistEpoch: resp.BlocklistEpoch,
		HostID:         resp.HostID,
	}); err != nil {
		return err
	}

	fmt.Printf("enrolled as %s (%s)\ncertificate expires %s\nrenew after %s\n",
		resp.HostName, resp.HostID,
		resp.NotAfter.Format(time.RFC3339), resp.RenewAfter.Format(time.RFC3339))
	return nil
}

func runCmd(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var (
		reload  = fs.String("reload", "", `how to reload nebula: "pid:/run/nebula.pid", a command, or empty`)
		restart = fs.String("restart", "",
			`how to restart nebula: "unit:nebula@<network>", a command, or empty. `+
				`Required to apply a changed overlay address, and the only way the agent can `+
				`tell whether nebula is running at all`)
		verifyURL = fs.String("verify-url", "", "URL polled over the overlay after an apply; empty disables verification and rollback")
		interval  = fs.Duration("interval", time.Minute, "poll interval")
		curve     = fs.String("curve", "CURVE25519", "key curve; must match the network")
		reuseKey  = fs.Bool("reuse-key", false, "keep the existing private key across renewals (for hardware-backed keys)")
		once      = fs.Bool("once", false, "run one iteration and exit")
	)
	df := addDirFlags(fs)
	_ = fs.Parse(args)

	log := newLogger()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	layout, err := df.layout()
	if err != nil {
		return err
	}
	st, err := agent.ReadState(layout.Dir)
	if err != nil {
		return fmt.Errorf("read agent state (has this host enrolled?): %w", err)
	}
	c, err := parseCurve(*curve)
	if err != nil {
		return err
	}

	applier := &agent.Applier{
		Layout:   layout,
		Reloader: agent.ParseReloader(*reload),
		Log:      log,
	}
	// The pidfile comes from -reload rather than a flag of its own: a host that
	// reloads by pidfile has exactly one, and naming it twice is one more thing
	// to get out of step.
	applier.Supervisor = agent.ParseSupervisor(*restart, agent.PidFileFromReloadSpec(*reload))
	if applier.Supervisor == nil {
		// Two distinct losses, both silent, so name both. Without a supervisor
		// an address change is refused outright rather than applied, and a
		// nebula that is not running is invisible to this host and to the
		// control plane.
		log.Warn("no -restart configured: a changed overlay address will be REFUSED rather " +
			"than applied, and the agent cannot tell whether nebula is running")
	}
	if *verifyURL != "" {
		applier.Verifier = agent.NewReachabilityVerifier(*verifyURL)
	} else {
		// Worth saying out loud: without verification the rollback path never
		// runs, so a generation that breaks connectivity stays installed.
		log.Warn("post-apply verification disabled: set -verify-url to an overlay " +
			"address so a broken generation is rolled back automatically")
	}

	loop := &agent.Loop{
		Client:   agent.NewClient(st.ControlURL()),
		Applier:  applier,
		Policy:   agent.DefaultRenewalPolicy(),
		Layout:   layout,
		Curve:    c,
		ReuseKey: *reuseKey,
		State:    st,
		Log:      log,
	}

	if nb, na, err := loop.CurrentWindow(); err == nil {
		log.Info("agent started",
			"host", st.HostID,
			"network", layout.Network,
			"layout", layout.Describe(),
			"controlPlane", st.ControlURL(),
			"replicas", len(st.AgentURLs),
			"notAfter", na,
			"renewAt", loop.Policy.RenewAt(nb, na, st.HostID),
			"reload", applier.Reloader.Describe(),
			"restart", describeSupervisor(applier.Supervisor))
	}

	// A host on several networks renders listen.port and tun.dev per network,
	// and no control plane can see what another one chose. Say so once at
	// startup rather than leaving it as an intermittent bind failure inside
	// nebula's logs.
	agent.WarnInstanceCollisions(layout, log)

	run := func() {
		if err := loop.Tick(ctx); err != nil {
			log.Warn("tick failed, keeping current configuration", "error", err)
		}
	}

	run()
	if *once {
		return nil
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			run()
		}
	}
}

func parseCurve(name string) (cert.Curve, error) {
	switch name {
	case "CURVE25519", "25519":
		return cert.Curve_CURVE25519, nil
	case "P256":
		return cert.Curve_P256, nil
	default:
		return 0, fmt.Errorf("unknown curve %q", name)
	}
}

// recoverCmd re-obtains a certificate for a host whose own expired while it was
// offline.
//
// Such a host cannot reach the overlay, so the normal renewal path is closed to
// it. This falls back to the public endpoint and proves possession of the key
// whose certificate expired — that key must still be on disk, which is why the
// agent never deletes it.
func recoverCmd(args []string) error {
	fs := flag.NewFlagSet("recover", flag.ExitOnError)
	var (
		url     = fs.String("url", "", "public control plane URL (defaults to the one recorded at enrollment)")
		reload  = fs.String("reload", "", `how to reload nebula: "pid:/run/nebula.pid", a command, or empty`)
		restart = fs.String("restart", "", `how to restart nebula: "unit:nebula@<network>", a command, or empty`)
		curve   = fs.String("curve", "CURVE25519", "key curve; must match the network")
	)
	df := addDirFlags(fs)
	_ = fs.Parse(args)

	log := newLogger()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	layout, err := df.layout()
	if err != nil {
		return err
	}
	dir := &layout.Dir

	st, err := agent.ReadState(*dir)
	if err != nil {
		return fmt.Errorf("read agent state (has this host enrolled?): %w", err)
	}
	if st.HostID == "" {
		return errors.New("agent state has no host id; this host must re-enroll")
	}

	// Recovery always uses the public endpoint. The overlay one is unreachable
	// by definition: that is why this command exists.
	base := *url
	if base == "" {
		base = st.BaseURL
	}
	client := agent.NewClient(base)

	c, err := parseCurve(*curve)
	if err != nil {
		return err
	}

	ch, err := client.RecoveryChallenge(ctx, st.HostID)
	if err != nil {
		return fmt.Errorf("request recovery challenge: %w", err)
	}

	// A fresh keypair, as at enrollment. The old one proved identity and is
	// then done with.
	kp, err := agent.GenerateKeypair(c)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	resp, err := client.Recover(ctx, st.HostID, layout.Paths.Key, ch, kp)
	if err != nil {
		var apiErr *agent.APIError
		if errors.As(err, &apiErr) && !apiErr.Retryable() {
			return fmt.Errorf("recovery denied: %s\n\n"+
				"This host may be blocked, past the recovery window, or holding a key "+
				"that does not match its last certificate. Re-enroll it instead.", apiErr.Message)
		}
		return fmt.Errorf("recover: %w", err)
	}

	applier := &agent.Applier{
		Layout:   layout,
		Reloader: agent.ParseReloader(*reload),
		// Recovery re-keys the host, and a recovered certificate can carry a
		// different overlay address than the expired one. That is a restart, not
		// a reload, so this path needs a supervisor as much as `run` does.
		Supervisor: agent.ParseSupervisor(*restart, agent.PidFileFromReloadSpec(*reload)),
		Log:        log,
	}
	if err := applier.Apply(ctx, agent.MaterialFromEnroll(resp, kp.PrivatePEM)); err != nil {
		return err
	}

	st.ConfigEpoch = resp.ConfigEpoch
	st.BlocklistEpoch = resp.BlocklistEpoch
	st.SetAgentURLs(resp.AgentEndpoints)
	if err := agent.WriteState(*dir, st); err != nil {
		return err
	}

	log.Warn("recovered after certificate expiry; renewal was not working for this host " +
		"and is worth investigating")
	fmt.Printf("recovered as %s (%s)\ncertificate expires %s\n",
		resp.HostName, resp.HostID, resp.NotAfter.Format(time.RFC3339))
	return nil
}
