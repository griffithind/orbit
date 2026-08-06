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
	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/device"
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
}

func addDirFlags(fs *flag.FlagSet) *dirFlags {
	return &dirFlags{
		dir:     fs.String("dir", "", "per-network directory the agent owns: config, certificate, key, state, rollback copy (default "+agent.DefaultRoot+"/<network>)"),
		network: fs.String("network", "", "network slug; shorthand for -dir "+agent.DefaultRoot+"/<slug>"),
	}
}

// explicit reports whether the caller named a single network, which means "run
// exactly this one" rather than "run everything joined on this host".
func (d *dirFlags) explicit() bool {
	return *d.dir != "" || *d.network != ""
}

// networkRef is the network the caller named, for passing on to a subcommand.
//
// The slug when they gave one, otherwise the directory's base name — which is
// what LayoutFor already treats as the network's name, so the two agree by
// construction rather than by a caller remembering to keep them in step.
func (d *dirFlags) networkRef() string {
	if *d.network != "" {
		return *d.network
	}
	if *d.dir != "" {
		return filepath.Base(filepath.Clean(*d.dir))
	}
	return ""
}

func (d *dirFlags) layout() (agent.Layout, error) {
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
	return agent.DefaultLayout(filepath.Clean(*d.dir)), nil
}

const agentVerbs = "install, uninstall, join, enroll, run"

func agentCmd(_ context.Context, args []string) error {
	if len(args) == 0 {
		return agentUsage()
	}
	switch args[0] {
	case "install":
		return installCmd(args[1:])
	case "uninstall":
		return uninstallCmd(args[1:])
	case "join":
		return joinCmd(args[1:])
	case "enroll":
		return enrollCmd(args[1:])
	case "run":
		return runCmd(args[1:])
	case "-h", "--help", "help":
		return agentUsage()
	default:
		return unknownSub("agent", args[0], agentVerbs)
	}
}

func agentUsage() error {
	fmt.Fprint(errOut, `orbit agent <command> [flags]

  install    set THIS MACHINE up: generate its device identity, install the service
  uninstall  leave a network and remove its local state
  join       join a network — repeat once per network
  enroll     re-enrol an existing membership with a code
  run        serve every joined network: poll, apply, renew

Install once per MACHINE, join once per NETWORK. That split is the model: a
machine has one agent, one service and one device identity however many networks
it joins, and a membership is what belongs to a network. The service rescans its
root, so a join lands without a restart.

A machine can join SEVERAL networks, including ones run by different control
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
		url  = fs.String("url", "", "control plane base URL")
		code = fs.String("code", "", "enrollment code (or ORBIT_ENROLL_CODE)")
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

	// P-256, always: one constant across both halves rather than a flag on each
	// that can disagree. See cmd/orbitd bootstrap for why there is only one
	// defensible answer, and why the two defaults used to differ.
	c := cert.Curve_P256

	// The private half is generated here and never transmitted: only the public
	// half goes to the control plane, which signs a certificate over it.
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
		"host", resp.MembershipName, "membershipId", resp.MembershipID, "layout", layout.Describe(),
		"configEpoch", resp.ConfigEpoch, "renewAfter", resp.RenewAfter)

	if len(resp.AgentEndpoints) > 0 {
		log.Info("control plane reachable over the overlay; "+
			"steady-state traffic will use it and no credential is stored",
			"endpoints", resp.AgentEndpoints)
	} else {
		log.Warn("control plane advertised no overlay endpoints; the agent will " +
			"keep using the public URL and has no replica to fail over to")
	}

	// The network key comes from the enrollment response here rather than from a
	// join proof: a machine that enrolled with a code never called
	// /enroll/v1/join and has never seen one. That is trust on first use —
	// weaker than a key checked against a network ID given out of band, and
	// still enough to make every LATER generation verifiable, which is what this
	// is for. Hosts that join by network ID get the stronger form.
	if err := agent.WriteState(*dir, agent.State{
		BaseURL:        *url,
		AgentURLs:      resp.AgentEndpoints,
		ConfigEpoch:    resp.ConfigEpoch,
		BlocklistEpoch: resp.BlocklistEpoch,
		MembershipID:   resp.MembershipID,
		NetworkKey:     resp.NetworkKey,
	}); err != nil {
		return err
	}

	fmt.Printf("enrolled as %s (%s)\ncertificate expires %s\nrenew after %s\n",
		resp.MembershipName, resp.MembershipID,
		resp.NotAfter.Format(time.RFC3339), resp.RenewAfter.Format(time.RFC3339))
	return nil
}

func runCmd(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var (
		verifyURL = fs.String("verify-url", "", "URL polled over the overlay after an apply; empty disables verification and rollback")
		interval  = fs.Duration("interval", time.Minute, "poll interval")
		once      = fs.Bool("once", false, "run one iteration and exit")
		root      = fs.String("root", agent.DefaultRoot, "directory holding one subdirectory per joined network")
	)
	df := addDirFlags(fs)
	_ = fs.Parse(args)

	log := newLogger()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	c := cert.Curve_P256

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
	if len(dirs) == 0 && *once {
		// -once is a single pass for a test or a cron. Nothing to do and no
		// later chance to do it, so say so rather than exiting 0 silently.
		return fmt.Errorf("no joined networks under %s: join one with `orbit agent join`", *root)
	}

	// The set of networks is DISCOVERED and REDISCOVERED, not fixed at startup.
	//
	// This is what lets `orbit agent install` be a device-level action and
	// `orbit agent join` a per-network one. The service is installed once, and
	// starts before this machine belongs to anything; each join drops a
	// directory under -root and this loop picks it up on the next pass, with no
	// restart and nothing to remember to do.
	//
	// Zero networks is therefore a normal running state, not an error. A freshly
	// installed machine idles here until somebody joins it, which is exactly
	// what a newly provisioned laptop should do.
	sup := &supervisor{
		root: *root, df: df, curve: c,
		verifyURL: *verifyURL,
		interval:  *interval, once: *once, log: log,
		running: map[string]*netSlot{},
	}

	var wg sync.WaitGroup
	sup.start(ctx, &wg, dirs)

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
			Report: func(ctx context.Context) agent.Report { return report(ctx, *root, sup.slots()) },
			Peers: func(ctx context.Context, network string) (agent.PeerReport, error) {
				return peerReport(ctx, network, sup.slots())
			},
			Explain: func(ctx context.Context, network string, req agent.ExplainRequest) (agent.Explanation, error) {
				return explain(network, req, sup.slots())
			},
		}
		go func() {
			if err := srv.Serve(ctx); err != nil {
				log.Error("status socket unavailable; `orbit status` will not work on this host",
					"path", srv.Path, "error", err)
			}
		}()
	}

	log.Info("agent running", "networks", len(dirs), "root", *root)

	// Watch for networks joined after this process started. Not under -once,
	// and not when the caller named a single network with -dir or -network:
	// both mean "exactly this", and rescanning would contradict it.
	if !*once && !df.explicit() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sup.watch(ctx, &wg)
		}()
	}

	wg.Wait()
	return nil
}

// supervisor owns the set of networks this process serves.
//
// It exists because that set is not fixed: `orbit agent join` writes a new
// directory under the agent root at any moment, and the service should pick it
// up without an operator remembering to restart anything. A restart would also
// drop every OTHER network's tunnels, which is a poor price for adding one.
type supervisor struct {
	root      string
	df        *dirFlags
	curve     cert.Curve
	verifyURL string
	interval  time.Duration
	once      bool
	log       *slog.Logger

	mu      sync.Mutex
	running map[string]*netSlot
}

// slots is the current set, for the status socket.
//
// A copy under the lock. The socket's goroutine and the watcher run
// concurrently, and handing out the live map would be a data race on every
// `orbit status`.
func (s *supervisor) slots() []*netSlot {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*netSlot, 0, len(s.running))
	for _, sl := range s.running {
		out = append(out, sl)
	}
	return out
}

// start serves any of dirs that are not already running.
func (s *supervisor) start(ctx context.Context, wg *sync.WaitGroup, dirs []string) {
	s.mu.Lock()
	fresh := make([]*netSlot, 0, len(dirs))
	for _, dir := range dirs {
		if _, ok := s.running[dir]; ok {
			continue
		}
		slot := &netSlot{dir: dir}
		s.running[dir] = slot
		fresh = append(fresh, slot)
	}
	s.mu.Unlock()

	for _, slot := range fresh {
		wg.Add(1)
		go func(slot *netSlot) {
			defer wg.Done()
			serveNetwork(ctx, slot, s.curve, s.verifyURL, s.interval, s.once, s.log)
		}(slot)
	}
}

// watch rescans the agent root and starts anything new.
//
// A poll rather than an inotify watch, deliberately. The event this is looking
// for happens when a human runs a command, so latency of up to one interval is
// invisible; inotify would add a platform-specific dependency and a class of
// failure (watch limits, a root that does not exist yet) to save nothing.
//
// It never STOPS a network. A directory disappearing is `orbit agent uninstall`,
// which stops the service itself, or it is a mistake — and tearing down a live
// overlay because a directory read failed once would turn a transient disk
// problem into an outage.
func (s *supervisor) watch(ctx context.Context, wg *sync.WaitGroup) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		dirs, err := networksToRun(s.df, s.root)
		if err != nil {
			s.log.Warn("could not rescan for newly joined networks", "root", s.root, "error", err)
			continue
		}
		before := len(s.slots())
		s.start(ctx, wg, dirs)
		if after := len(s.slots()); after > before {
			s.log.Info("picked up a newly joined network without a restart",
				"networks", after, "root", s.root)
		}
	}
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

// peerReport answers for one network, matched by slug.
//
// A network that exists but has not come up answers with Running false rather
// than 404: the host HAS joined it, and telling an operator it does not exist
// would send them looking for a typo instead of at the reason it is down.
func peerReport(ctx context.Context, network string, slots []*netSlot) (agent.PeerReport, error) {
	for _, s := range slots {
		if filepath.Base(s.dir) != network {
			continue
		}
		s.mu.Lock()
		nl := s.nl
		s.mu.Unlock()

		rep := agent.PeerReport{Network: network, Established: []agent.Peer{}}
		if nl == nil {
			rep.Detail = "this network has not started"
			return rep, nil
		}

		established, pending, err := nl.engine.Peers()
		if err != nil {
			// Not an error to the caller. "nebula is not running" is the
			// answer, and returning a 500 would make the command fail on
			// exactly the host it is most useful on.
			rep.Detail = err.Error()
			if st, sErr := nl.engine.Status(ctx); sErr == nil && st.Detail != "" {
				rep.Detail = st.Detail
			}
			return rep, nil
		}
		rep.Running = true
		rep.Established, rep.Pending = established, pending
		return rep, nil
	}
	return agent.PeerReport{}, fmt.Errorf("%w: %s", agent.ErrUnknownNetwork, network)
}

// explain answers a reachability question for one network.
func explain(network string, req agent.ExplainRequest, slots []*netSlot) (agent.Explanation, error) {
	for _, s := range slots {
		if filepath.Base(s.dir) != network {
			continue
		}
		s.mu.Lock()
		nl := s.nl
		s.mu.Unlock()

		if nl == nil {
			// Joined but not started. Not a 404 — the network exists — and not
			// an explanation either, because the rules that would answer it are
			// whatever the unreadable directory holds.
			return agent.Explanation{Network: network},
				fmt.Errorf("%s has not started; `orbit status` has the reason", network)
		}
		return agent.Explain(nl.engine, nl.loop.Layout, req)
	}
	return agent.Explanation{}, fmt.Errorf("%w: %s", agent.ErrUnknownNetwork, network)
}

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
func serveNetwork(ctx context.Context, slot *netSlot, c cert.Curve, verifyURL string, interval time.Duration, once bool, log *slog.Logger) {
	dir := slot.dir
	backoff := setupBackoffMin
	for {
		nl, err := newNetworkLoop(ctx, dir, c, verifyURL, log)
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
		out.MembershipID = st.MembershipID
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
		out.Nebula = agent.NebulaStatus{
			Known: s.Known, Running: s.Running, Instance: s.Instance, Detail: s.Detail,
		}
	}
	if cs, err := agent.ReadCertStatus(layout.Paths.Cert); err == nil {
		out.Certificate = cs
	}

	// From the VERIFIED bytes, like everything else that reads this
	// configuration. Status showing instructions that failed verification would
	// tell an operator the machine was told something it will never act on.
	if cfg, err := n.loop.VerifiedConfig(); err == nil {
		if hs, err := agent.HostStatusFromConfig(cfg); err == nil && !hs.Empty() {
			out.Host = &hs
		}
	}
	return out
}

func newNetworkLoop(ctx context.Context, dir string, c cert.Curve, verifyURL string, log *slog.Logger) (*networkLoop, error) {
	layout := agent.DefaultLayout(dir)
	st, err := agent.ReadState(dir)
	if err != nil {
		return nil, fmt.Errorf("read agent state (has this host enrolled?): %w", err)
	}
	nlog := log.With("network", layout.Network)

	engine := &agent.Embedded{Log: nlog}
	applier := &agent.Applier{
		Layout:   layout,
		Reloader: engine,
		// The linked copy IS the copy that will run it, so validating in
		// process is exact rather than a guess about a host binary's version.
		DisableValidation: true,
		Log:               nlog,
	}
	applier.Supervisor = engine

	// The knot tied: nebula's configuration comes from the applier, verified on
	// every start and every reload, rather than from a path nebula would read
	// for itself. Set after the applier exists because the two refer to each
	// other — the applier reloads the engine, the engine asks the applier what
	// to run.
	engine.Config = func() (string, error) {
		return applier.VerifiedConfig(st.NetworkKeyBytes(), st.MembershipID)
	}

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
		Client:  agent.NewClient(st.ControlURL()),
		Applier: applier,
		Host:    agent.NewHostConfigurer(nlog),
		DNS:     agent.NewResolver(nlog),
		Policy:  agent.DefaultRenewalPolicy(),
		Layout:  layout,
		Curve:   c,
		State:   st,
		Log:     nlog,
	}

	if nb, na, err := loop.CurrentWindow(); err == nil {
		nlog.Info("network joined",
			"host", st.MembershipID,
			"layout", layout.Describe(),
			"controlPlane", st.ControlURL(),
			"replicas", len(st.AgentURLs),
			"notAfter", na,
			"renewAt", loop.Policy.RenewAt(nb, na, st.MembershipID))
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

func parseCurve(name string) (cert.Curve, error) { return ca.ParseCurve(name) }

// installCmd sets this MACHINE up: a device identity, a service, nothing else.
//
// Device-level, not network-level, and the split is the model showing through.
// A machine has one agent, one service and one device key however many networks
// it joins; a membership is per network. Install used to do both, which meant a
// machine on three networks ran it three times and rewrote the same unit three
// times.
//
// So: install once, then `orbit agent join <network>` per network. The service
// rescans its root, so a join lands without a restart — and without dropping the
// tunnels of every other network a restart would have taken with it.
func installCmd(args []string) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	var (
		root      = fs.String("root", agent.DefaultRoot, "directory holding this machine's device key and one subdirectory per joined network")
		verifyURL = fs.String("verify-url", "", "URL polled over the overlay after an apply; empty disables verification and rollback")
		dryRun    = fs.Bool("dry-run", false, "print what would be written and installed, and change nothing")
		noStart   = fs.Bool("no-start", false, "write the service definition but do not enable or start it")
	)
	_ = fs.Parse(args)

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

	plan, err := agent.PlanService(*root, binary, *verifyURL)
	if err != nil {
		return err
	}

	if *dryRun {
		fmt.Fprintf(errOut, "would write the device key under %s\nwould write %s (%s)\nwould run: %s\n\n",
			*root, plan.Path, plan.Manager, strings.Join(plan.Start, " "))
		fmt.Fprintln(out, plan.Contents)
		return nil
	}

	// The device key FIRST, and this is the one thing install cannot leave to
	// the service. It is this machine's identity: generated here, never issued,
	// never expiring, and the same key for every network it will ever join. An
	// operator can read the fingerprint off this output and recognise the
	// machine in the authorization queue before it has joined anything.
	id, err := device.LoadOrCreate(agent.DeviceKeyPath(*root))
	if err != nil {
		return fmt.Errorf("device key: %w", err)
	}

	if err := plan.Write(); err != nil {
		return err
	}
	fmt.Fprintf(errOut, "wrote %s\n", plan.Path)

	fmt.Printf("device %s\n", id.Fingerprint())

	if *noStart {
		fmt.Fprintf(errOut, "\nNot started. When you are ready:\n\n  %s\n",
			strings.Join(plan.Start, " "))
	} else if err := plan.Enable(); err != nil {
		return fmt.Errorf("%w\n\nThe device key and %s are written; only starting the "+
			"service failed. Fix that and run:\n\n  %s",
			err, plan.Path, strings.Join(plan.Start, " "))
	}

	// The commands for THIS platform, because every piece of guidance around
	// this one said systemctl and a Mac does not have it. The plan already
	// computed them; printing them is the difference between an operator
	// knowing the next command and translating one.
	fmt.Fprintf(errOut, "\nManage it with (%s):\n\n  %s\n  %s\n",
		plan.Manager, strings.Join(plan.Restart, " "), strings.Join(plan.Status, " "))

	// The service is running and serving nothing, which is correct and worth
	// saying — otherwise the obvious reading of "installed" is "done".
	fmt.Fprintf(errOut, "\nThis machine belongs to no network yet. Join one:\n\n"+
		"  sudo orbit agent join -url https://<control-plane> -network <slug>\n\n"+
		"Add -code <reservation> to skip the authorization queue. The service picks\n"+
		"up each network as it is joined; there is nothing to restart.\n")
	return nil
}

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

	// The forwarding rules, if this host was a gateway.
	//
	// BEFORE the directory goes, and without consulting it: Remove destroys the
	// whole nftables table by name, so it does not need to know what was in it
	// and works even if somebody edited the rules. A machine that had rules
	// left behind here would keep forwarding for a network it is no longer part
	// of, which is the one uninstall failure with a security consequence.
	if err := agent.NewHostConfigurer(newLogger()).Remove(); err != nil {
		// Reported, not fatal. The rest of the uninstall is still worth doing,
		// and stopping here would leave a machine half-removed with no obvious
		// way forward.
		fmt.Fprintf(errOut, "WARNING: could not remove forwarding rules: %v\n"+
			"Remove them by hand with: nft destroy table inet %s\n", err, agent.TableName)
	} else {
		fmt.Fprintf(errOut, "removed any forwarding rules (nft table inet %s)\n", agent.TableName)
	}

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
