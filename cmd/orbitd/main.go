// Command orbitd is the Orbit control plane.
//
// Subcommands:
//
//	serve      run the HTTP surfaces
//	bootstrap  create a network, CA, role, and admin token
//
// bootstrap exists because a control plane with no admin token has no way to
// authenticate the request that would create one. It is the one operation that
// has to happen out of band.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/api"
	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/device"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/mesh"
	"github.com/griffithind/orbit/internal/metrics"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/notify"
	"github.com/griffithind/orbit/internal/sched"
	"github.com/griffithind/orbit/internal/secrets"
	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/vault"
	"github.com/griffithind/orbit/internal/version"
	"github.com/griffithind/orbit/internal/web"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "bootstrap":
		err = bootstrap(os.Args[2:])
	case "doctor":
		err = doctorCmd(os.Args[2:])
	case "migrate":
		err = migrateCmd(os.Args[2:])
	case "token":
		err = tokenCmd(os.Args[2:])
	case "kek":
		err = kekCmd(os.Args[2:])
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
		fmt.Fprintln(os.Stderr, "orbitd:", err)
		os.Exit(1)
	}
}

// The UDP ports a control plane's nebula instances use.
//
// One port per network, because nebula cannot share one (see meshSpecs). A
// contiguous range is what lets a firewall rule and a cloud security group be
// written once, at install, without knowing how many networks this control
// plane will end up serving.
//
// SIXTEEN. The number is a judgement, so here is the reasoning: 4242 stays the
// first, so a single-network deployment is unchanged and every existing
// document stays correct. Sixteen covers what a self-hosted control plane
// plausibly runs — prod, staging, dev, and a handful per-customer or
// per-tenant — while staying small enough to state as one rule and to open
// without feeling like a wildcard. Past that, run a second instance over a
// disjoint subset of networks, which is the scaling story anyway.
//
// Opening a port is not listening on it: only the networks actually passed to
// -mesh bind anything, and the rest are closed at the socket layer regardless
// of the firewall.
const (
	DefaultNebulaPort    = 4242
	DefaultNebulaPortMax = 4257
)

// meshSpecs is a repeatable -mesh flag: <network-uuid>=<overlay-addr>[:port]
//
// Joining is explicit per instance rather than implied by the network existing,
// so scaling past a few hundred networks is a matter of running more instances
// over disjoint subsets. `orbitd bootstrap` prints the exact flag.
//
// THE PORT IS PER NETWORK, and it has to be. Nebula's v1 header carries no
// network identifier — 16 bytes of version, type, subtype, reserved, remote
// index and message counter — and the remote index is an index into ONE
// interface's hostmap. A received packet cannot be attributed to a network, so
// one UDP socket is one network, and N networks need N ports.
//
// Omitting it takes -nebula-port, which is right for the single-network case
// that is nearly everyone. Two networks that both omit it are refused by
// checkMeshPorts rather than silently colliding: the second nebula would fail
// with "address already in use" from inside a library, which is a long way from
// the flag that caused it.
type meshSpecs []mesh.Config

func (m *meshSpecs) String() string { return fmt.Sprintf("%d networks", len(*m)) }

func (m *meshSpecs) Set(v string) error {
	idAndAddr := strings.SplitN(v, "=", 2)
	if len(idAndAddr) != 2 {
		return fmt.Errorf("want <network-uuid>=<overlay-addr>[:port], got %q", v)
	}
	networkID, err := uuid.Parse(idAndAddr[0])
	if err != nil {
		return fmt.Errorf("network id: %w", err)
	}

	// AddrPort first, then a bare address. The order matters and the two cannot
	// be told apart by looking for a colon: an IPv6 overlay address is full of
	// them. netip's own rule is the one to follow — a port means brackets, so
	// "[fd00::1]:4242" parses here and "fd00::1" falls through to the bare form.
	var cfg mesh.Config
	if ap, err := netip.ParseAddrPort(idAndAddr[1]); err == nil {
		if ap.Port() == 0 {
			return fmt.Errorf("port 0 in %q: a lighthouse must be reachable at a "+
				"known port, so this has to be a real one", v)
		}
		cfg = mesh.Config{NetworkID: networkID, Addr: ap.Addr(), ListenPort: int(ap.Port())}
	} else {
		addr, err := netip.ParseAddr(idAndAddr[1])
		if err != nil {
			return fmt.Errorf("overlay address: %w (an IPv6 address with a port "+
				"needs brackets: [fd00::1]:4242)", err)
		}
		cfg = mesh.Config{NetworkID: networkID, Addr: addr}
	}
	*m = append(*m, cfg)
	return nil
}

// checkMeshPorts refuses two networks on one UDP port.
//
// Caught HERE, before anything binds, because the alternative is discovering it
// halfway through startup: the first network comes up, the second fails inside
// nebula with "address already in use", and the operator is looking at a
// library error rather than at the two flags that collided. Reporting both
// network ids and the fix is the whole value of the check.
func checkMeshPorts(meshes meshSpecs, defaultPort int) error {
	byPort := map[int]uuid.UUID{}
	for _, mc := range meshes {
		port := mc.ListenPort
		if port == 0 {
			port = defaultPort
		}
		if other, taken := byPort[port]; taken {
			return fmt.Errorf(
				"networks %s and %s are both on UDP port %d, and nebula cannot "+
					"share a port between networks: its wire header carries no "+
					"network identifier, so one socket is one network.\n\n"+
					"Give one of them its own port:\n"+
					"  -mesh %s=<overlay-addr>:%d\n\n"+
					"Ports %d-%d are the range Orbit's firewall guidance opens.",
				other, mc.NetworkID, port,
				mc.NetworkID, port+1, DefaultNebulaPort, DefaultNebulaPortMax)
		}
		byPort[port] = mc.NetworkID
	}
	return nil
}

func usage() {
	fmt.Fprint(os.Stderr, `orbitd <command> [flags]

  serve      run the control plane
  bootstrap  create the first network, CA, role, and admin token
  doctor     preflight: listen addresses, mesh ports, database, migration state
  migrate    apply database migrations (needs the admin DSN, not the app one)
  token      manage API tokens offline (break-glass; see docs/deployment.md)
  kek        rotate the key encryption key, re-sealing every stored secret
  version    print the build version

Run "orbitd <command> -h" for flags.
`)
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	if os.Getenv("ORBIT_DEBUG") != "" {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func openStore(ctx context.Context, dsn string) (*store.Store, error) {
	if dsn == "" {
		dsn = os.Getenv("ORBIT_DSN")
	}
	if dsn == "" {
		return nil, errors.New("-dsn is required (or set ORBIT_DSN); " +
			"connect as orbit_app, never as the migration role: the application must not be able to alter the schema")
	}
	return store.Open(ctx, dsn)
}

//------------------------------------------------------------------------------
// serve
//------------------------------------------------------------------------------

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	var (
		dsn        = fs.String("dsn", "", "postgres DSN for the orbit_app role (or ORBIT_DSN)")
		addr       = fs.String("addr", ":8080", "listen address")
		enrollURL  = fs.String("enroll-url", "", "public enroll URL handed to agents")
		agentPort  = fs.Int("agent-port", 8443, "port the agent API listens on, on each overlay")
		listenPort = fs.Int("nebula-port", DefaultNebulaPort,
			"default nebula UDP port: what a -mesh without one takes, and what "+
				"rendered configs use when neither the membership nor the network sets it")
		trustXFF   = fs.Bool("trust-forwarded-for", false, "read the client address from X-Forwarded-For (only behind a trusted proxy)")
		maxWatch   = fs.Int("max-watchers", 5000, "cap on concurrent long-poll connections per network")
		noPush     = fs.Bool("no-push", false, "disable push updates; agents fall back to polling")
		lighthouse = fs.String("lighthouse", "", "seed: public host:port entries to advertise as a lighthouse, applied only when this control plane's host record is first created (comma separated)")
		relay      = fs.Bool("relay", false, "seed: act as a relay, applied only when this control plane's host record is first created")
		maintEvery = fs.Duration("maintenance-interval", 15*time.Minute, "how often to prune and report")
		noMaint    = fs.Bool("no-maintenance", false, "disable periodic maintenance on this instance")
		uiAddr     = fs.String("ui-addr", "",
			"web UI listen address; empty disables it. A bare port or \":port\" binds loopback")
		uiURL = fs.String("ui-url", "",
			"external URL the UI is reached at; required when -ui-addr is not loopback")
		uiMaxStreams = fs.Int("ui-max-streams", web.DefaultMaxStreams,
			"cap on concurrent UI event streams")
		deviceKeyPath = fs.String("device-key", paths.DeviceKeyPath(""),
			"this control plane's own device identity key; generated on first use. It is a machine on its own network like any other, and this is the key that says which one")
		metricsAddr = fs.String("metrics-addr", "127.0.0.1:9464",
			"Prometheus exposition address; empty disables it. Bind to localhost or the overlay: the output is fleet inventory")
		meshes meshSpecs
	)
	fs.Var(&meshes, "mesh", fmt.Sprintf(
		"join a network: <network-uuid>=<overlay-addr>[:port] (repeatable). "+
			"One UDP port per network — nebula cannot share one. Omit it for "+
			"-nebula-port; ports %d-%d are the documented range",
		DefaultNebulaPort, DefaultNebulaPortMax))
	_ = fs.Parse(args)

	log := newLogger()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Checked before anything is opened or joined. A refusal that arrives after
	// the store is up and the mesh is joined has already done work, and the
	// operator has to unpick it to act on the message.
	if err := checkMeshPorts(meshes, *listenPort); err != nil {
		return err
	}
	*uiAddr = web.NormalizeAddr(*uiAddr)
	if err := web.CheckExposure(*uiAddr, *uiURL); err != nil {
		return err
	}

	st, err := openStore(ctx, *dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	// The vault. Required, not optional: every private key this control plane
	// holds is in it, so a deployment without one cannot sign anything.
	//
	// The passphrase is checked HERE, at startup, against a verifier stored at
	// bootstrap. A replica with a mistyped passphrase that started cleanly would
	// fail on its first signing operation — while somebody is adding a machine,
	// days after the mistake, with nothing connecting the two.
	if err := secrets.ConfigureKDF(); err != nil {
		return err
	}
	vlt, err := vault.Open(ctx, st)
	if err != nil {
		if errors.Is(err, store.ErrNoKEK) {
			return fmt.Errorf("%w\n\nThis database has never been bootstrapped, or was "+
				"bootstrapped by a version that stored keys in files. Run `orbitd bootstrap`", err)
		}
		return fmt.Errorf("open the key vault: %w", err)
	}
	log.Info("key vault open; private keys are stored encrypted in the database")

	registry := ca.NewRegistry(vlt.SignerFactory())
	defer registry.Close()

	enrollCfg := enroll.Config{
		Paths:      nebulacfg.DefaultPaths(),
		ListenPort: *listenPort,
		EnrollURL:  *enrollURL,
		Log:        log.With("component", "enroll"),

		// Policy is deliberately not set: NewService defaults it to
		// store.NetworkPolicy. Naming it here would suggest a caller that omits
		// it gets something else, which is exactly the assumption that left this
		// path inert once already.
	}
	enrollCfg.NetworkIdentity = vlt.NetworkIdentity
	svc := enroll.NewService(st, registry, enrollCfg)

	// Metrics. Built before anything that reports into it, and served on its
	// own listener: /metrics enumerates network names and host counts, which is
	// inventory that has no business on the public enrollment listener.
	var mx *metrics.Metrics
	if *metricsAddr != "" {
		mx = metrics.New()
		if err := mx.RegisterDB(st, log.With("component", "metrics")); err != nil {
			return fmt.Errorf("register metrics collector: %w", err)
		}
		go func() {
			if err := mx.ServeMetrics(ctx, *metricsAddr, log.With("component", "metrics")); err != nil {
				log.Error("metrics listener stopped", "error", err)
			}
		}()
	} else {
		log.Warn("metrics disabled; convergence and log lines are the only signals")
	}

	apiCfg := api.Config{
		TrustForwardedFor: *trustXFF,
		MaxWatchers:       *maxWatch,
		SignerFactory:     vlt.SignerFactory(),
		SealNetworkIdentity: func(ctx context.Context, tx *store.Tx, plaintext []byte) (string, error) {
			return vlt.PutTx(ctx, tx, secrets.KindNetworkIdentity, nil, plaintext)
		},
		SealCAKey: func(ctx context.Context, tx *store.Tx, networkID uuid.UUID, plaintext []byte) (string, error) {
			return vlt.PutTx(ctx, tx, secrets.KindCASigning, &networkID, plaintext)
		},
		Metrics: mx,
	}

	// Push. The notifier holds a dedicated connection listening for epoch
	// changes and wakes parked watchers; without it every agent falls back to
	// its poll interval, which is correct but roughly an order of magnitude
	// slower to converge. Say which mode we are in at startup rather than
	// letting an operator discover it from a latency graph.
	var notifier *notify.Notifier
	if !*noPush {
		notifier = notify.New(st.Pool(), log).Observe(mx)
		go func() {
			if err := notifier.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("epoch notifier stopped", "error", err)
			}
		}()
		readyCtx, cancelReady := context.WithTimeout(ctx, 10*time.Second)
		if err := notifier.Ready(readyCtx); err != nil {
			cancelReady()
			return fmt.Errorf("epoch notifier did not start: %w", err)
		}
		cancelReady()

		apiCfg.Notifier = notifier
		log.Info("push updates enabled", "maxWatchersPerNetwork", *maxWatch)
	} else {
		log.Warn("push updates disabled; agents will poll, converging an order of magnitude slower")
	}

	// The web UI, on its own listener. Not the public one — that is where
	// unenrolled hosts enroll, and this serves a Block button for the whole
	// fleet. Not the overlay one either: the mesh being broken is precisely when
	// someone needs this, and a console reachable only over the mesh is
	// unreachable exactly then.
	if *uiAddr != "" {
		// Derived from the KEK, so every replica computes the same key and a
		// form rendered by one can be submitted to another. Per-process keys
		// made the console the one surface that could not sit behind the load
		// balancer docs/design.md tells operators to use.
		csrfKey, cerr := vlt.DeriveKey("orbit ui csrf form token v1", 32)
		if cerr != nil {
			return fmt.Errorf("derive the ui csrf key: %w", cerr)
		}

		ui, uerr := web.New(st, svc, web.StoreSessions(st), web.Config{
			BaseURL:    *uiURL,
			Notifier:   notifier,
			MaxStreams: *uiMaxStreams,
			CSRFKey:    csrfKey,
		}, log.With("component", "ui"))
		if uerr != nil {
			return fmt.Errorf("build the web ui: %w", uerr)
		}

		uiSrv := &http.Server{
			Addr:              *uiAddr,
			Handler:           api.Observe(log.With("component", "ui"), ui.Handler()),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       15 * time.Second,
			// No WriteTimeout: /ui/events is a long-lived SSE stream, and a
			// write deadline would sever it on a schedule. Same reasoning as
			// the overlay listener's long poll.
			IdleTimeout: 2 * time.Minute,
		}
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = uiSrv.Shutdown(shutdown)
		}()
		go func() {
			log.Info("web ui listening", "addr", *uiAddr, "url", *uiURL)
			if err := uiSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("web ui listener stopped", "error", err)
			}
		}()
	}

	// Periodic maintenance: prune the blocklist and spent credentials, and
	// report certificates whose agents have stopped renewing. Idempotent and
	// safe to run on every replica; no leader election needed.
	if !*noMaint {
		runner := sched.New(st, sched.Config{Interval: *maintEvery}, log.With("component", "maintenance"))
		runner.OnSuccess(mx.MaintenanceSucceeded)
		go func() {
			if err := runner.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("maintenance runner stopped", "error", err)
			}
		}()
		log.Info("maintenance enabled", "interval", *maintEvery)
	} else {
		log.Warn("maintenance disabled: the blocklist and expired enrollment " +
			"credentials will grow without bound unless another instance runs it")
	}

	server := api.New(st, svc, apiCfg, log)

	// One overlay listener per network. The agent API lives ONLY here: it is
	// never mounted on the public listener, so it is not merely authenticated
	// but unroutable from outside the mesh.
	// This control plane's own device identity, loaded once and shared by every
	// mesh node. One process is one machine, so one key: reading it per node
	// would make a single control plane present several identities and would
	// undo the thing the device noun is for.
	var selfDevice *device.Identity
	if len(meshes) > 0 {
		var err error
		selfDevice, err = device.LoadOrCreate(*deviceKeyPath)
		if err != nil {
			return fmt.Errorf("control plane device key: %w", err)
		}
		log.Info("control plane device identity",
			"fingerprint", selfDevice.Fingerprint(), "path", *deviceKeyPath)
	}

	for _, mc := range meshes {
		// Every field of mesh.Config, explicitly. Zero means different things
		// per field — a safe default for Heartbeat, an unreachable lighthouse
		// for ListenPort — and the difference is invisible at a struct literal
		// that simply omits one. See cmd/orbitd/wiring_test.go.
		mc.AgentPort = *agentPort
		// AgentPort is shared across networks on purpose and ListenPort cannot
		// be: the agent API listens on each network's own gvisor netstack, so
		// the same number on two overlays is two independent listeners, while
		// ListenPort is a real host UDP socket.
		if mc.ListenPort == 0 {
			mc.ListenPort = *listenPort
		}
		mc.LighthouseAddrs = splitCSV(*lighthouse)
		mc.Relay = *relay
		mc.Heartbeat = mesh.DefaultHeartbeat
		mc.DeviceKey = selfDevice.PublicKey()
		node, err := mesh.Join(ctx, svc, mc, log)
		if err != nil {
			return err
		}
		defer node.Close()

		ln, err := node.Listen(*agentPort)
		if err != nil {
			return err
		}

		mux := http.NewServeMux()
		// AgentRoutes only. Admin and enroll are deliberately absent: an
		// operator API reachable from every managed host is a lateral movement
		// path, and enrollment over the overlay is meaningless since a host
		// must already be enrolled to get here.
		nodeCfg := apiCfg
		nodeCfg.Agent = &api.AgentListener{NetworkID: node.NetworkID()}
		nodeSrv := api.New(st, svc, nodeCfg, log)
		nodeSrv.AgentRoutes(mux)
		// Health on the overlay too, and not redundantly: this is a separate
		// socket that fails separately. A replica can serve the public port
		// perfectly while its agent port is a black hole, and agents keep
		// rotating onto it from AgentEndpoints. Exposure costs nothing here —
		// only certificate-verified peers can reach it.
		nodeSrv.HealthRoutes(mux)

		// Advertise this replica so agents can discover and fail over to it.
		if err := node.Announce(ctx, st); err != nil {
			return err
		}

		// Keep the control plane's own nebula current. It is a mesh member, so
		// a stale configuration means a stale trust bundle and a stale
		// blocklist: it would reject hosts that renewed onto a rotated CA and
		// keep trusting ones that have been blocked. It also renews its own
		// certificate here — nothing else does, and without it the control
		// plane drops off the overlay one lifetime after it started.
		var changes <-chan struct{}
		if notifier != nil {
			ch := make(chan struct{}, 1)
			events, release := notifier.Subscribe(node.NetworkID())
			defer release()
			go func() {
				for range events {
					select {
					case ch <- struct{}{}:
					default: // a pending wake already covers this change
					}
				}
			}()
			changes = ch
		}
		go node.Maintain(ctx, changes, *maintEvery)

		// Fewer timeouts than the public listener, because /agent/v1/watch parks
		// for up to api.MaxWatchHold:
		//
		//   - No WriteTimeout. Its deadline is armed before the handler runs, so
		//     a hold longer than the timeout means the response write fails and
		//     the agent sees a dropped connection — indistinguishable from a
		//     control plane failure, on the path the whole fleet depends on.
		//   - No ReadTimeout either. net/http does clear the read deadline once
		//     a request body is consumed, so it would survive a parked GET
		//     today, but that is an implementation detail to bet the watch loop
		//     on and it buys little here: this listener is reachable only from
		//     inside the mesh, by certificate-verified peers, and slow headers
		//     are already covered below.
		//   - IdleTimeout is safe at any value: it applies between requests, not
		//     to one in flight, so two minutes does not cap a five minute hold.
		//     It is what reaps agents that vanished without closing.
		overlaySrv := &http.Server{
			Handler:           api.Observe(log, mux),
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
		}
		go func() {
			if err := overlaySrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("overlay agent listener stopped", "error", err)
			}
		}()
		go func() {
			<-ctx.Done()
			_ = overlaySrv.Close()
		}()

		// Report the roles actually in force, which come from the host record
		// rather than from the flags. Logging the flags would be a lie the
		// moment someone changed a role through the API.
		roles, err := node.Roles(ctx)
		if err != nil {
			return err
		}
		log.Info("agent API listening on the overlay",
			"network", node.NetworkID(), "endpoint", node.AgentEndpoint(*agentPort),
			"lighthouse", roles.IsLighthouse, "relay", roles.IsRelay)

		if roles.IsRelay {
			// A relay forwards other hosts' traffic, on the machine holding the
			// mesh's root CA key, and restarting it drops that traffic rather
			// than merely delaying a handshake.
			log.Warn("control plane is a relay: it is in the data path, " +
				"and restarts will interrupt traffic it is forwarding")
		}
		if (*lighthouse != "" || *relay) && !roles.SeededThisStart {
			log.Warn("-lighthouse/-relay are seeds and were ignored: this control plane "+
				"already has a host record. Change its roles with "+
				"PATCH /v1/memberships/{id} instead; it will pick them up without a restart",
				"lighthouse", roles.IsLighthouse, "relay", roles.IsRelay)
		}
	}

	if len(meshes) == 0 {
		log.Warn("no -mesh configured: the agent API is unavailable, so enrolled hosts " +
			"cannot poll, renew, or receive revocations. Agents can enroll and nothing more.")
	}

	// Public listener: enrollment and admin only.
	publicMux := http.NewServeMux()
	server.EnrollRoutes(publicMux)
	server.AdminRoutes(publicMux)
	// Where a proxy, systemd, or a container orchestrator looks. Without it the
	// only unauthenticated request here is a POST to /enroll/v1, so a probe's
	// signal is a TCP connect — which stays green through a total database
	// outage.
	server.HealthRoutes(publicMux)

	// Full timeouts, which this listener can afford because nothing it serves is
	// long-lived: enrollment and admin are request/response, and the request
	// bodies are capped at 1 MiB. The write budget is generous on purpose —
	// enrollment does a password hash and a signing operation — but bounded, so
	// a stalled client cannot hold a connection open indefinitely on the one
	// surface that is exposed to the internet.
	srv := &http.Server{
		Addr:              *addr,
		Handler:           api.Observe(log, publicMux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	log.Info("public listener (enroll + admin) starting", "addr", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

//------------------------------------------------------------------------------
// bootstrap
//------------------------------------------------------------------------------

func bootstrap(args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	var (
		dsn     = fs.String("dsn", "", "postgres DSN for the orbit_app role (or ORBIT_DSN)")
		netName = fs.String("network", "default", "network display name; may be renamed later")
		netSlug = fs.String("slug", "", "immutable network identifier: the directory name on every managed host and what `orbit -network` takes (default: derived from -network)")
		cidr    = fs.String("cidr", "10.42.0.0/16", "overlay network prefix")
		caName  = fs.String("ca-name", "", "CA name (defaults to the network name)")
		caDays  = fs.Int("ca-days", 90, "CA lifetime in days")
		certTTL = fs.Duration("cert-ttl", 24*time.Hour, "host certificate lifetime; this is the revocation SLA for a partitioned host")

		// Separate from -ca-key because they have different lifetimes and
		// different jobs. The CA key rotates; this one never does, because
		// rotating it would change the network's ID. Writing them to one file
		// would make rotating the first mean touching the second.
		groupsCS = fs.String("groups", "default", "comma separated groups the CA may delegate")

		// Explicit and never defaulted. A CA that quietly permitted a range
		// would grant routing authority nobody asked for — and it cannot be
		// narrowed afterwards any more than it can be widened, because the
		// constraint is signed into the certificate.
		unsafeCS = fs.String("unsafe-networks", "",
			"comma separated external prefixes gateways under this CA may route "+
				"(e.g. 192.168.88.0/24). Empty permits none. PERMANENT: widening "+
				"this later is a new CA and a rotation")

		// Writing the unit is opt-in rather than the default: bootstrap is also
		// run inside a container and from a laptop against a remote database,
		// where writing to /etc/systemd would be wrong and surprising.
		writeUnit   = fs.Bool("write-unit", false, "write /etc/orbit/orbit.env and a systemd unit filled in from this bootstrap")
		overlayAddr = fs.String("overlay-addr", "", "the control plane's own overlay address, written into -write-unit's -mesh flag")
		lighthouse  = fs.String("lighthouse", "", "public host:port to advertise as a lighthouse, written into -write-unit")
		enrollURL   = fs.String("enroll-url", "", "public enroll URL handed to agents, written into -write-unit")
	)
	_ = fs.Parse(args)

	ctx := context.Background()
	log := newLogger()

	prefix, err := netip.ParsePrefix(*cidr)
	if err != nil {
		return fmt.Errorf("-cidr: %w", err)
	}
	if *caName == "" {
		*caName = *netName
	}
	groups := splitCSV(*groupsCS)

	// P-256, and there is no flag.
	//
	// A network's curve is PERMANENT — nebula refuses a certificate whose curve
	// differs from its signer's, and nothing updates it — so the wrong answer
	// here means building a new network and re-enrolling every machine. That is
	// a bad thing to leave as a choice, and there is only one defensible answer.
	//
	// P-256 because it is what every other ecosystem standardises on for ECDSA,
	// and because the choice is nearly free either way.
	//
	// What it costs is nothing that reaches the data plane. The curve selects
	// only the Noise handshake's DH function (pki.go newCipherSuite); the AEAD
	// and hash come from the separate `cipher` setting, so every packet after
	// the handshake is identical either way. Measured, P-256 costs ~10% on the
	// handshake DH and ~24% on a certificate verify — on the order of 10-20µs,
	// once per peer pair.
	//
	// It also removes a class of bug: bootstrap defaulted to P256 while every
	// `orbit agent` path defaulted to CURVE25519, so a machine following the
	// documented steps failed its claim with a curve mismatch. Neither default
	// was wrong alone, which is exactly why it survived. One constant cannot
	// disagree with itself.
	const curve = cert.Curve_P256

	st, err := openStore(ctx, *dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	// Both keys go into the vault, sealed under this deployment's KEK. There is
	// no file option: two custody paths meant two sets of failure modes, two
	// things to document, and a second replica that worked or did not depending
	// on which one a network happened to use. See docs/key-custody.md.
	caPub, caPriv, err := ca.GenerateCAKey(curve)
	if err != nil {
		return err
	}
	caPEMBytes := cert.MarshalSigningPrivateKeyToPEM(curve, caPriv)

	// Ed25519 regardless of -curve: the identity key never signs a certificate,
	// so nebula's "a certificate's curve must match its signer's" rule does not
	// reach it. A P-256 network and a Curve25519 network get the same kind.
	identityPub, identityPriv, err := ca.GenerateNetworkIdentity()
	if err != nil {
		return err
	}
	identityPEMBytes := ca.MarshalNetworkIdentityPEM(identityPriv)

	signer := ca.NewMemorySigner(curve, caPub, caPriv)

	now := time.Now()
	unsafeNets, err := store.ParsePrefixes(splitCSV(*unsafeCS))
	if err != nil {
		return fmt.Errorf("-unsafe-networks: %w", err)
	}

	caCert, err := ca.CreateCA(ctx, signer, ca.CAParams{
		Name:           *caName,
		Networks:       []netip.Prefix{prefix},
		UnsafeNetworks: unsafeNets,
		Groups:         groups,
		NotBefore:      now.Add(-time.Minute),
		NotAfter:       now.AddDate(0, 0, *caDays),
	})
	if err != nil {
		return fmt.Errorf("create ca: %w", err)
	}
	caPEM, err := caCert.MarshalPEM()
	if err != nil {
		return err
	}
	fingerprint, err := caCert.Fingerprint()
	if err != nil {
		return err
	}

	token, tokenHash, err := store.NewAPIToken()
	if err != nil {
		return err
	}

	var (
		networkID    uuid.UUID
		verifiableID string
		roleID       uuid.UUID
	)
	slug := *netSlug
	if slug == "" {
		slug = store.Slugify(*netName)
	}

	if err := secrets.ConfigureKDF(); err != nil {
		return err
	}
	// The vault. Initialised before the transaction so a missing passphrase
	// fails before anything is written, rather than leaving a half-created
	// network behind.
	vlt, err := vault.Init(ctx, st)
	if err != nil {
		return fmt.Errorf("initialise the key vault: %w\n\n"+
			"Generate one and keep it somewhere your database backups are not:\n"+
			"  head -c 32 /dev/urandom | base64", err)
	}
	var caRef, identityRef string

	err = st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		// Sealed inside the same transaction as the rows that reference them. A
		// key stored in a transaction that then rolled back would be ciphertext
		// nothing points at; a network stored without its key would be a network
		// that cannot sign.
		if identityRef, err = vlt.PutTx(ctx, tx, secrets.KindNetworkIdentity, nil, identityPEMBytes); err != nil {
			return err
		}

		net := store.Network{
			Name:              *netName,
			Slug:              slug,
			CIDRs:             []netip.Prefix{prefix},
			CertVer:           int16(cert.Version2),
			Curve:             curve.String(),
			CertTTL:           *certTTL,
			IdentityPublicKey: identityPub,
			IdentitySignerRef: identityRef,
		}
		if err := tx.CreateNetwork(ctx, &net); err != nil {
			return err
		}
		networkID = net.ID
		verifiableID = net.NetworkID

		if caRef, err = vlt.PutTx(ctx, tx, secrets.KindCASigning, &net.ID, caPEMBytes); err != nil {
			return err
		}

		caRow := store.CA{
			NetworkID:   net.ID,
			Name:        *caName,
			Fingerprint: fingerprint,
			CertPEM:     string(caPEM),
			SignerRef:   caRef,
			Curve:       curve.String(),
			// The readable copy of what was signed. splitCSV rather than the
			// parsed prefixes so the stored text is what the operator typed.
			UnsafeNetworks: splitCSV(*unsafeCS),
			NotBefore:      caCert.NotBefore(),
			NotAfter:       caCert.NotAfter(),
		}
		if err := tx.CreateCA(ctx, &caRow); err != nil {
			return err
		}
		if err := tx.ActivateCA(ctx, net.ID, caRow.ID); err != nil {
			return err
		}

		// A default role that permits ICMP inbound and everything outbound.
		// Deliberately not "allow any inbound": a host that is reachable by
		// accident is an invisible misconfiguration.
		role := store.Role{
			NetworkID: net.ID,
			Name:      "default",
			Groups:    groups,
			FirewallRules: []byte(`{
				"inbound":  [{"port":"any","proto":"icmp","host":"any"}],
				"outbound": [{"port":"any","proto":"any","host":"any"}]
			}`),
		}
		if err := tx.CreateRole(ctx, &role); err != nil {
			return err
		}
		roleID = role.ID

		_, err := tx.CreateAPIToken(ctx, "bootstrap", tokenHash, []string{"*"}, nil)
		if err != nil {
			return err
		}
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: "system", Action: store.ActionNetworkCreated,
			TargetType: "network", TargetID: net.ID.String(),
		})
	})
	if err != nil {
		return err
	}

	log.Info("bootstrap complete")
	fmt.Printf(`
network    %s  (%s)
network id %s  ← what machines join by, and can verify
slug       %s  ← the directory name on every managed host; immutable
role       %s  (default)
ca         %s  fingerprint %s
ca key     %s
identity   %s

Admin token (shown once):

  %s

Export it:

  export ORBIT_TOKEN=%s
  export ORBIT_NETWORK=%s

Join the overlay so agents can poll, renew, and receive revocations
(pick any free address inside %s):

  orbitd serve -mesh %s=<overlay-addr>

Add a machine — the network id is what it joins by, and unlike a uuid it is
something the machine can CHECK. A machine given this id will refuse any
control plane that cannot prove it holds the matching key, so a mistyped or
hostile URL fails instead of quietly enrolling into somebody else's mesh:

  orbit membership reserve -name web-01 -role default    # prints a code
  sudo orbit agent install                               # on the machine
  sudo orbit join -url <this control plane> -network %s -code <code>

The network identity key names this network. It cannot mint a certificate, so
it is not the CA key; but anyone holding it can convince a JOINING machine that
their control plane is this network, so it gets the same custody. If it is ever
compromised, bootstrap a new network id and change the -network argument
wherever machines join — they keep their memberships, addresses and
certificates, because those are keyed on the device.

%s`, *netName, networkID, verifiableID, slug, roleID, *caName, fingerprint[:16], caRef,
		identityRef, token, token, networkID, prefix, networkID, verifiableID, custodyNote(caRef))

	if *writeUnit {
		if *enrollURL == "" {
			return fmt.Errorf("-write-unit needs -enroll-url: it is the address agents " +
				"are told to enroll against, and a unit with an empty one enrolls nobody")
		}
		if *overlayAddr == "" {
			// Not fatal, and worth saying rather than silently producing a unit
			// with no -mesh: without it the agent API does not exist, so hosts
			// can enroll and nothing more.
			fmt.Fprintln(os.Stderr,
				"\nwarning: no -overlay-addr, so the unit joins no network. Agents will be "+
					"able to enroll but not poll, renew, or receive revocations.")
		}
		plan := planControlPlane(networkID.String(), *dsn,
			*enrollURL, *overlayAddr, *lighthouse, caRef)
		if err := plan.write(); err != nil {
			return err
		}
		fmt.Println()
		fmt.Println(plan.describe())
	}
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// custodyNote says where the CA key ended up and what that obliges.
//
// Two paragraphs rather than one, because the obligations genuinely differ. The
// earlier version printed "the CA private key is on local disk" unconditionally,
// which after this change was false for the default path — and a bootstrap that
// tells an operator to `chmod 600` a file that does not exist is worse than
// silence: they go looking, find nothing, and stop trusting the rest of it.
func custodyNote(caRef string) string {
	const shared = "Nebula has no intermediate CAs, so this key is a root of trust for the\n" +
		"entire mesh: anyone who reads it can mint any identity this CA's constraints\n" +
		"allow. Rotate on a schedule you have rehearsed — docs/design.md section 6.\n"

	if strings.HasPrefix(caRef, "file://") {
		return "\nThe CA private key is on local disk. Keep it encrypted (see \"orbitd ca\n" +
			"encrypt\") and mode 0600. " + shared
	}
	return "\nThe CA private key is in the database, encrypted under your KEK passphrase.\n" +
		"The database never sees that passphrase, so a leaked dump is ciphertext — and\n" +
		"losing it makes every stored key unreadable. Escrow it somewhere the database\n" +
		"backups are not: docs/deployment.md section 5.\n\n" + shared
}
