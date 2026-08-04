package main

// The agent: enrolls a host into ONE network and keeps its nebula configuration
// current.
//
// A subcommand group rather than its own binary. `orbit` is the client-side
// binary — one artifact for a laptop and for a managed host — and the agent is
// what it does on a host. The two shared a release and a version already;
// shipping them apart only meant two downloads and two things to keep in step.
//
// One process, every network. Everything the agent owns for a network lives in
// one per-network directory — /var/lib/orbit/<slug> by convention — and a host
// joined to two networks keeps two directories with nothing shared, served by
// one process under one service unit. See internal/agent/layout.go.
//
// It runs nebula in-process, one instance per joined network: it writes the
// configuration and the certificate material, then reloads or restarts the
// instance depending on whether the change is one nebula can hot-load. Agent
// liveness and tunnel liveness are therefore the same liveness, which is the
// cost of the arrangement; a control-plane outage still leaves every overlay
// running, because nebula needs nothing from the control plane to forward
// packets.
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

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
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

// explicit reports whether the caller named a single network, which means "run
// exactly this one" rather than "run everything joined on this host".
func (d *dirFlags) explicit() bool {
	return *d.dir != "" || *d.network != ""
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

const agentVerbs = "install, uninstall, enroll, run, recover"

func agentCmd(_ context.Context, args []string) error {
	if len(args) == 0 {
		return agentUsage()
	}
	switch args[0] {
	case "install":
		return installCmd(args[1:])
	case "uninstall":
		return uninstallCmd(args[1:])
	case "enroll":
		return enrollCmd(args[1:])
	case "run":
		return runCmd(args[1:])
	case "recover":
		return recoverCmd(args[1:])
	case "-h", "--help", "help":
		return agentUsage()
	default:
		return unknownSub("agent", args[0], agentVerbs)
	}
}

func agentUsage() error {
	fmt.Fprint(errOut, `orbit agent <command> [flags]

  install    enroll into a network and set this host up as a service
  uninstall  leave a network and remove its local state
  enroll     join a network using an enrollment code
  run        serve every joined network: poll, apply, renew
  recover    re-obtain a certificate after this host's expired while offline

A host can join SEVERAL networks, including ones run by different control
planes that have never heard of each other. Each keeps its own directory under
`+agent.DefaultRoot+`, its own certificate, and its own
nebula instance — two overlays cannot share a UDP port or a tun device — but
they are served by one process under one service.

So `+"`run`"+` takes no -dir: it runs everything joined under -root. The other
commands act on one network and take -network (or -dir).

None of these need an admin token. They are what runs ON a managed host; every
other orbit command is what an operator runs about one.

Run "orbit agent <command> -h" for flags.
`)
	// No message: the listing above is the message, matching subUsage.
	return &exitError{code: exitUsage}
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
		url   = fs.String("url", "", "control plane base URL")
		code  = fs.String("code", "", "enrollment code (or ORBIT_ENROLL_CODE)")
		curve = fs.String("curve", "CURVE25519", "key curve; must match the network")
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

	// No engine here: enrolling writes the first generation, and `orbit agent
	// run` is what starts nebula on it. Reloading something that is not running
	// yet is the one case there is nothing useful to do about.
	applier := &agent.Applier{
		Layout:            layout,
		Reloader:          agent.NoopReloader{},
		DisableValidation: true,
		Log:               log,
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
		verifyURL = fs.String("verify-url", "", "URL polled over the overlay after an apply; empty disables verification and rollback")
		interval  = fs.Duration("interval", time.Minute, "poll interval")
		curve     = fs.String("curve", "CURVE25519", "key curve; must match the network")
		reuseKey  = fs.Bool("reuse-key", false, "keep the existing private key across renewals (for hardware-backed keys)")
		once      = fs.Bool("once", false, "run one iteration and exit")
		root      = fs.String("root", agent.DefaultRoot, "directory holding one subdirectory per joined network")
	)
	df := addDirFlags(fs)
	_ = fs.Parse(args)

	log := newLogger()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	c, err := parseCurve(*curve)
	if err != nil {
		return err
	}

	// Every joined network, in one process.
	//
	// A host can belong to several networks, possibly run by different control
	// planes that have never heard of each other. Each keeps its own directory,
	// its own certificate, and its own nebula instance — two overlays cannot
	// share a UDP port or a tun device, so the instances are irreducible — but
	// they no longer need a process and a unit each.
	dirs, err := networksToRun(df, *root)
	if err != nil {
		return err
	}
	if len(dirs) == 0 {
		return fmt.Errorf("no joined networks under %s: enroll one with `orbit agent install`", *root)
	}

	slots := make([]*netSlot, len(dirs))
	for i, dir := range dirs {
		slots[i] = &netSlot{dir: dir}
	}

	var wg sync.WaitGroup
	for _, s := range slots {
		wg.Add(1)
		go func(s *netSlot) {
			defer wg.Done()
			serveNetwork(ctx, s, c, *verifyURL, *reuseKey, *interval, *once, log)
		}(s)
	}

	// The status socket, which `orbit status` reads.
	//
	// Not under -once: that is a single pass for a test or a cron, and binding
	// a socket for the length of one tick would only leave a path for the next
	// invocation to trip over.
	//
	// A failure to serve it is logged and nothing more. Diagnostics are worth
	// having; they are not worth taking a host's overlays down for.
	if !*once {
		srv := &agent.StatusServer{
			Path:   agent.SocketPath(socketRoot(df, *root)),
			Log:    log,
			Report: func(ctx context.Context) agent.Report { return report(ctx, *root, slots) },
		}
		go func() {
			if err := srv.Serve(ctx); err != nil {
				log.Error("status socket unavailable; `orbit status` will not work on this host",
					"path", srv.Path, "error", err)
			}
		}()
	}

	log.Info("agent running", "networks", len(dirs), "root", *root)

	wg.Wait()
	return nil
}

// socketRoot is the directory the status socket lives in.
//
// Normally the agent root, the one directory shared by every network this
// process serves. An explicit -dir means the caller has put a network somewhere
// of its own — a test, a container, a second stack on one box — and the socket
// belongs beside it rather than in a /var/lib/orbit that may not exist and may
// not be writable.
func socketRoot(df *dirFlags, root string) string {
	if df.explicit() {
		if layout, err := df.layout(); err == nil {
			return filepath.Dir(layout.Dir)
		}
	}
	return root
}

// netSlot is one network's current status: published by the goroutine that owns
// the network, read by the status socket.
//
// One slot per directory, created before any of them starts, so a network that
// never finishes setup still appears in the report and carries the reason. That
// is the case the command exists for, and a registry populated only on success
// would omit exactly it.
type netSlot struct {
	dir string

	mu  sync.Mutex
	nl  *networkLoop
	err error
}

func (s *netSlot) setLoop(nl *networkLoop) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nl, s.err = nl, nil
}

func (s *netSlot) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nl, s.err = nil, err
}

func (s *netSlot) status(ctx context.Context) agent.NetworkStatus {
	s.mu.Lock()
	nl, err := s.nl, s.err
	s.mu.Unlock()

	if nl != nil {
		return nl.status(ctx)
	}
	st := agent.NetworkStatus{Network: filepath.Base(s.dir), Dir: s.dir}
	if err != nil {
		st.Error = err.Error()
	}
	return st
}

func report(ctx context.Context, root string, slots []*netSlot) agent.Report {
	rep := agent.Report{
		Version:  version.Version,
		Root:     root,
		PID:      os.Getpid(),
		Started:  processStart,
		Networks: make([]agent.NetworkStatus, 0, len(slots)),
	}
	for _, s := range slots {
		rep.Networks = append(rep.Networks, s.status(ctx))
	}
	return rep
}

// processStart is when this agent came up, reported so an operator can tell a
// host that has been healthy for a week from one that restarted a minute ago.
var processStart = time.Now()

// setupBackoff bounds how fast a network that cannot be set up is retried.
//
// Retried at all, which it was not: a network whose state file was unreadable
// at startup used to be skipped for the life of the process, so a transient
// problem — a disk not yet mounted, a directory being written by an install
// running concurrently — became permanent until somebody noticed and restarted
// the agent.
const (
	setupBackoffMin = 5 * time.Second
	setupBackoffMax = 5 * time.Minute
)

// serveNetwork keeps one network running for as long as the process does.
//
// Setup is retried rather than attempted once, and the poll loop below heals
// nebula on every tick. Between them, the states a host can get stuck in are
// the ones where the control plane itself has nothing to offer.
func serveNetwork(ctx context.Context, slot *netSlot, c cert.Curve, verifyURL string, reuseKey bool, interval time.Duration, once bool, log *slog.Logger) {
	dir := slot.dir
	backoff := setupBackoffMin
	for {
		nl, err := newNetworkLoop(ctx, dir, c, verifyURL, reuseKey, log)
		if err == nil {
			slot.setLoop(nl)
			defer func() { _ = nl.engine.Close() }()
			nl.run(ctx, interval, once)
			return
		}
		slot.setError(err)

		// One network failing must not stop the others: a host on three
		// networks losing all three because one directory is unreadable is
		// what the per-network layout exists to prevent.
		log.Error("network not ready; retrying", "dir", dir, "error", err, "in", backoff)
		if once {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, setupBackoffMax)
	}
}

// networksToRun resolves which networks this process serves.
//
// An explicit -dir or -network means exactly that one, which is what a test, a
// container, or a host with an unconventional layout needs. Otherwise every
// subdirectory of the root that holds agent state is a joined network — the
// directory IS the enrolment record, so discovering them is reading it rather
// than keeping a second list that can disagree.
func networksToRun(df *dirFlags, root string) ([]string, error) {
	if df.explicit() {
		layout, err := df.layout()
		if err != nil {
			return nil, err
		}
		return []string{layout.Dir}, nil
	}

	slugs, err := agent.EnabledInstances(root, "")
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", root, err)
	}
	dirs := make([]string, 0, len(slugs))
	for _, s := range slugs {
		dirs = append(dirs, filepath.Join(root, s))
	}
	return dirs, nil
}

// networkLoop is one network's worth of agent: its own nebula, its own poll
// loop, its own control plane.
type networkLoop struct {
	loop   *agent.Loop
	engine *agent.Embedded
	log    *slog.Logger

	// mu guards the tick's own record of itself. Loop's state is NOT read
	// through here — see status.
	mu       sync.Mutex
	lastPoll time.Time
	lastErr  error
}

// status is this network as the socket reports it.
//
// The persisted state is re-read from disk rather than taken from
// loop.State, which the tick goroutine mutates: reading that field from the
// socket's goroutine is a data race, and holding a lock across a tick would
// make a slow control plane block the diagnostic command that exists to
// report on it. Reading the file is also the more honest answer — it is what
// survives a restart, and it is what the control plane was last told.
func (n *networkLoop) status(ctx context.Context) agent.NetworkStatus {
	n.mu.Lock()
	lastPoll, lastErr := n.lastPoll, n.lastErr
	n.mu.Unlock()

	layout := n.loop.Layout
	out := agent.NetworkStatus{
		Network:  layout.Network,
		Dir:      layout.Dir,
		Ready:    true,
		LastPoll: lastPoll,
	}
	if lastErr != nil {
		out.LastPollError = lastErr.Error()
	}

	if st, err := agent.ReadState(layout.Dir); err == nil {
		out.HostID = st.HostID
		out.ControlURL = st.ControlURL()
		out.Replicas = len(st.AgentURLs)
		out.ConfigEpoch = st.ConfigEpoch
		out.BlocklistEpoch = st.BlocklistEpoch
		out.DataPlaneDownSince = st.DataPlaneDownSince
		out.UnconfirmedSince = st.UnconfirmedSince
		// Only while it is still in force. A quarantine that lapsed an hour ago
		// is not a reason to tell an operator this host is refusing a config.
		if time.Now().Before(st.QuarantinedUntil) {
			out.QuarantinedEpoch = st.QuarantinedConfigEpoch
		}
	}

	if s, err := n.engine.Status(ctx); err == nil {
		out.Nebula = agent.NebulaStatus{Known: s.Known, Running: s.Running, Instance: s.Instance}
	}
	if cs, err := agent.ReadCertStatus(layout.Paths.Cert); err == nil {
		out.Certificate = cs
	}
	return out
}

func newNetworkLoop(ctx context.Context, dir string, c cert.Curve, verifyURL string, reuseKey bool, log *slog.Logger) (*networkLoop, error) {
	layout := agent.DefaultLayout(dir)
	st, err := agent.ReadState(dir)
	if err != nil {
		return nil, fmt.Errorf("read agent state (has this host enrolled?): %w", err)
	}
	nlog := log.With("network", layout.Network)

	engine := &agent.Embedded{ConfigArg: layout.NebulaConfigArg(), Log: nlog}
	applier := &agent.Applier{
		Layout:   layout,
		Reloader: engine,
		// The linked copy IS the copy that will run it, so validating in
		// process is exact rather than a guess about a host binary's version.
		DisableValidation: true,
		Log:               nlog,
	}
	applier.Supervisor = engine

	if verifyURL != "" {
		applier.Verifier = agent.NewReachabilityVerifier(verifyURL)
	} else {
		nlog.Warn("post-apply verification disabled: set -verify-url to an overlay " +
			"address so a broken generation is rolled back automatically")
	}

	if err := engine.Start(ctx); err != nil {
		// Not fatal. The agent's job is to fetch a generation that works and
		// apply it, and refusing to run because the CURRENT configuration is
		// bad is how a host stays broken: the fix is on the control plane, and
		// reaching it is what the loop does.
		nlog.Error("nebula did not start on the existing configuration; "+
			"continuing so a new generation can replace it", "error", err)
	}

	loop := &agent.Loop{
		Client:   agent.NewClient(st.ControlURL()),
		Applier:  applier,
		Policy:   agent.DefaultRenewalPolicy(),
		Layout:   layout,
		Curve:    c,
		ReuseKey: reuseKey,
		State:    st,
		Log:      nlog,
	}

	if nb, na, err := loop.CurrentWindow(); err == nil {
		nlog.Info("network joined",
			"host", st.HostID,
			"layout", layout.Describe(),
			"controlPlane", st.ControlURL(),
			"replicas", len(st.AgentURLs),
			"notAfter", na,
			"renewAt", loop.Policy.RenewAt(nb, na, st.HostID))
	}

	// Two networks render listen.port and tun.dev independently, and no control
	// plane can see what another one chose. In one process that collision is a
	// bind failure inside one engine while the others carry on, so say it once
	// at startup rather than leaving it in nebula's logs.
	agent.WarnInstanceCollisions(layout, nlog)

	return &networkLoop{loop: loop, engine: engine, log: nlog}, nil
}

func (n *networkLoop) run(ctx context.Context, interval time.Duration, once bool) {
	tick := func() {
		// Nebula first. It may have failed to start at boot, or died since —
		// a fatal reader error stops it without stopping this process — and
		// without this it would stay down until a NEW generation happened to
		// arrive, which on a settled network is never.
		//
		// Before the poll rather than after, so that a host whose data plane is
		// down spends the tick getting it back rather than talking to a control
		// plane it may not be able to reach without it.
		if started, err := n.engine.Ensure(ctx); err != nil {
			n.log.Error("nebula is down and will not start", "error", err)
		} else if started {
			n.log.Info("nebula restarted")
		}

		err := n.loop.Tick(ctx)
		if err != nil {
			n.log.Warn("tick failed, keeping current configuration", "error", err)
		}

		// Recorded whether or not it failed. "Last polled 40 minutes ago with
		// no error" is a different diagnosis from "polled a second ago and
		// failed", and the epochs alone tell neither.
		n.mu.Lock()
		n.lastPoll, n.lastErr = time.Now(), err
		n.mu.Unlock()
	}

	tick()
	if once {
		return
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			tick()
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
		url = fs.String("url", "", "public control plane URL (defaults to the one recorded at enrollment)")

		curve = fs.String("curve", "CURVE25519", "key curve; must match the network")
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

	// Recovery re-keys the host, and a recovered certificate can carry a
	// different overlay address than the expired one — a restart, not a reload.
	// The engine is both.
	engine := &agent.Embedded{ConfigArg: layout.NebulaConfigArg(), Log: log}
	defer func() { _ = engine.Close() }()

	applier := &agent.Applier{
		Layout:            layout,
		Reloader:          engine,
		Supervisor:        engine,
		DisableValidation: true,
		Log:               log,
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

// installCmd is enrollment plus everything an operator would otherwise do by
// hand afterwards: write the service definition, enable it, start it.
//
// It exists because the manual sequence is six steps on Linux and seven on
// macOS, every one of them a place to mistype a path — and a deployment that
// followed the written version hit four separate failures before reaching
// anything Orbit does.
func installCmd(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	var (
		url       = fs.String("url", "", "control plane base URL")
		code      = fs.String("code", "", "enrollment code (or ORBIT_ENROLL_CODE)")
		curve     = fs.String("curve", "CURVE25519", "key curve; must match the network")
		verifyURL = fs.String("verify-url", "", "URL polled over the overlay after an apply; empty disables verification and rollback")
		dryRun    = fs.Bool("dry-run", false, "print what would be written and installed, and change nothing")
		noStart   = fs.Bool("no-start", false, "write the service definition but do not enable or start it")
	)
	df := addDirFlags(fs)
	_ = fs.Parse(args)

	layout, err := df.layout()
	if err != nil {
		return err
	}

	// The binary's own path, resolved before anything is written. A unit that
	// names a path the binary is not at starts once — from the shell that
	// installed it — and never again after a reboot.
	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve this binary's path: %w", err)
	}
	if binary, err = filepath.EvalSymlinks(binary); err != nil {
		return fmt.Errorf("resolve this binary's path: %w", err)
	}

	plan, err := agent.PlanService(agent.DefaultRoot, binary, *verifyURL)
	if err != nil {
		return err
	}

	if *dryRun {
		fmt.Fprintf(errOut, "would enroll into %s\nwould write %s (%s)\nwould run: %s\n\n",
			layout.Dir, plan.Path, plan.Manager, strings.Join(plan.Start, " "))
		fmt.Fprintln(out, plan.Contents)
		return nil
	}

	// Enroll FIRST. Writing a service definition for a host that then fails to
	// enroll leaves a unit pointing at an empty directory, and a service
	// manager restarting it forever.
	if err := enrollCmd([]string{
		"-url", *url, "-code", *code, "-curve", *curve, "-dir", layout.Dir,
	}); err != nil {
		return err
	}

	if err := plan.Write(); err != nil {
		return err
	}
	fmt.Fprintf(errOut, "wrote %s\n", plan.Path)

	if *noStart {
		fmt.Fprintf(errOut, "\nNot started. When you are ready:\n\n  %s\n",
			strings.Join(plan.Start, " "))
		return nil
	}

	if err := plan.Enable(); err != nil {
		return fmt.Errorf("%w\n\nThe host IS enrolled and %s is written; only starting the "+
			"service failed. Fix that and run:\n\n  %s",
			err, plan.Path, strings.Join(plan.Start, " "))
	}

	fmt.Fprintf(errOut, `
%s is running. This host is on the mesh and will renew on its own.

  %s
`, plan.Name, strings.Join(plan.Status, " "))
	return nil
}

// uninstallCmd takes this host off the mesh and leaves nothing behind.
//
// It is the inverse of install, and it exists for the same reason: the manual
// version is stop, disable, remove a unit, reload, delete a directory — and the
// consequence of getting it half right is a host that still holds a valid
// certificate and is no longer being told about revocations.
func uninstallCmd(args []string) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	var (
		keepDir = fs.Bool("keep-dir", false, "leave the per-network directory, including the certificate and key")
		yes     = fs.Bool("y", false, "do not ask")
	)
	df := addDirFlags(fs)
	_ = fs.Parse(args)

	layout, err := df.layout()
	if err != nil {
		return err
	}
	slug := filepath.Base(layout.Dir)

	binary, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve this binary's path: %w", err)
	}
	plan, err := agent.PlanService(agent.DefaultRoot, binary, "")
	if err != nil {
		return err
	}

	// Other networks on this host share the template unit, so say so before
	// touching it rather than after.
	others, err := agent.EnabledInstances(agent.DefaultRoot, slug)
	if err != nil {
		return err
	}

	fmt.Fprintf(errOut, "About to remove %s from this host:\n\n  service   %s\n  directory %s\n",
		slug, plan.Name, layout.Dir)
	if *keepDir {
		fmt.Fprintln(errOut, "  (keeping the directory: -keep-dir)")
	}
	if len(others) > 0 {
		fmt.Fprintf(errOut, "\n  %s also uses the shared unit file, which will be left in place.\n",
			strings.Join(others, ", "))
	}
	fmt.Fprintln(errOut)

	if !*yes {
		// Irreversible: the private key is generated on this host and exists
		// nowhere else, so removing the directory means re-enrolling rather
		// than restarting.
		if err := confirmUninstall(slug, *keepDir); err != nil {
			return err
		}
	}

	if err := plan.Disable(); err != nil {
		return err
	}
	fmt.Fprintf(errOut, "stopped %s\n", plan.Name)

	removed, err := plan.RemoveUnit(len(others) > 0)
	if err != nil {
		return err
	}
	if removed {
		fmt.Fprintf(errOut, "removed %s\n", plan.Path)
	} else {
		fmt.Fprintf(errOut, "left %s in place\n", plan.Path)
	}

	if !*keepDir {
		if err := os.RemoveAll(layout.Dir); err != nil {
			return fmt.Errorf("remove %s: %w", layout.Dir, err)
		}
		fmt.Fprintf(errOut, "removed %s\n", layout.Dir)
	}

	fmt.Fprintf(errOut, `
This host is off the mesh locally. Its RECORD on the control plane is untouched,
and its certificate stays valid until it expires — a host that is merely gone is
not a host that has been revoked. To close that:

  orbit host block %s
`, slug)
	return nil
}

func confirmUninstall(slug string, keepDir bool) error {
	what := "the private key, certificate, and enrollment state"
	if keepDir {
		what = "the service"
	}
	var o options
	o.yes = false
	return o.confirm(fmt.Sprintf(
		"Remove %s for %q? The key was generated on this host and exists nowhere "+
			"else, so this host re-enrols rather than restarts.", what, slug))
}
