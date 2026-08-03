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
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/api"
	"github.com/griffithind/orbit/internal/ca"
	"github.com/griffithind/orbit/internal/enroll"
	"github.com/griffithind/orbit/internal/mesh"
	"github.com/griffithind/orbit/internal/metrics"
	"github.com/griffithind/orbit/internal/nebulacfg"
	"github.com/griffithind/orbit/internal/notify"
	"github.com/griffithind/orbit/internal/sched"
	"github.com/griffithind/orbit/internal/store"
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
	case "ca":
		err = caCmd(os.Args[2:])
	case "token":
		err = tokenCmd(os.Args[2:])
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

// meshSpecs is a repeatable -mesh flag: <network-uuid>=<overlay-addr>
//
// Joining is explicit per instance rather than implied by the network existing,
// so scaling past a few hundred networks is a matter of running more instances
// over disjoint subsets. `orbitd bootstrap` prints the exact flag.
type meshSpecs []mesh.Config

func (m *meshSpecs) String() string { return fmt.Sprintf("%d networks", len(*m)) }

func (m *meshSpecs) Set(v string) error {
	idAndAddr := strings.SplitN(v, "=", 2)
	if len(idAndAddr) != 2 {
		return fmt.Errorf("want <network-uuid>=<overlay-addr>, got %q", v)
	}
	networkID, err := uuid.Parse(idAndAddr[0])
	if err != nil {
		return fmt.Errorf("network id: %w", err)
	}
	addr, err := netip.ParseAddr(idAndAddr[1])
	if err != nil {
		return fmt.Errorf("overlay address: %w", err)
	}

	*m = append(*m, mesh.Config{NetworkID: networkID, Addr: addr})
	return nil
}

func usage() {
	fmt.Fprint(os.Stderr, `orbitd <command> [flags]

  serve      run the control plane
  bootstrap  create the first network, CA, role, and admin token
  token      manage API tokens offline (break-glass; see docs/deployment.md)
  ca         encrypt a CA signing key at rest
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

// pepper loads the enrollment credential pepper.
//
// Required, and deliberately without a default. A hardcoded fallback would mean
// every deployment that forgot to set one shared the same value, which defeats
// the purpose of having a pepper at all.
func pepper() ([]byte, error) {
	raw := os.Getenv("ORBIT_ENROLL_PEPPER")
	if raw == "" {
		return nil, errors.New("ORBIT_ENROLL_PEPPER is required (32+ random bytes, base64); " +
			"generate one with: head -c 32 /dev/urandom | base64")
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("ORBIT_ENROLL_PEPPER is not valid base64: %w", err)
	}
	return b, nil
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
		listenPort = fs.Int("nebula-port", 4242, "nebula UDP port written into rendered configs")
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
		metricsAddr = fs.String("metrics-addr", "127.0.0.1:9464",
			"Prometheus exposition address; empty disables it. Bind to localhost or the overlay: the output is fleet inventory")
		meshes meshSpecs
	)
	fs.Var(&meshes, "mesh", "join a network: <network-uuid>=<overlay-addr> (repeatable)")
	_ = fs.Parse(args)

	log := newLogger()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pep, err := pepper()
	if err != nil {
		return err
	}
	hasher, err := enroll.NewHasher(pep)
	if err != nil {
		return err
	}

	// Checked before anything is opened or joined. A refusal that arrives after
	// the store is up and the mesh is joined has already done work, and the
	// operator has to unpick it to act on the message.
	*uiAddr = web.NormalizeAddr(*uiAddr)
	if err := web.CheckExposure(*uiAddr, *uiURL); err != nil {
		return err
	}

	st, err := openStore(ctx, *dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	registry := ca.NewRegistry(ca.FileSignerFactory)
	defer registry.Close()

	svc := enroll.NewService(st, registry, hasher, enroll.Config{
		Paths:      nebulacfg.DefaultPaths(),
		ListenPort: *listenPort,
		EnrollURL:  *enrollURL,
		Log:        log.With("component", "enroll"),

		// Policy is deliberately not set: NewService defaults it to
		// store.NetworkPolicy. Naming it here would suggest a caller that omits
		// it gets something else, which is exactly the assumption that left this
		// path inert once already.
	})

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
		SignerFactory:     ca.FileSignerFactory,
		Metrics:           mx,
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
		ui, uerr := web.New(st, svc, web.StoreSessions(st), web.Config{
			BaseURL:    *uiURL,
			Notifier:   notifier,
			MaxStreams: *uiMaxStreams,
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
	for _, mc := range meshes {
		mc.AgentPort = *agentPort
		mc.LighthouseAddrs = splitCSV(*lighthouse)
		mc.Relay = *relay
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
				"PATCH /v1/hosts/{id} instead; it will pick them up without a restart",
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
		dsn      = fs.String("dsn", "", "postgres DSN for the orbit_app role (or ORBIT_DSN)")
		netName  = fs.String("network", "default", "network display name; may be renamed later")
		netSlug  = fs.String("slug", "", "immutable network identifier: the directory name on every managed host and what `orbit -network` takes (default: derived from -network)")
		cidr     = fs.String("cidr", "10.42.0.0/16", "overlay network prefix")
		caName   = fs.String("ca-name", "", "CA name (defaults to the network name)")
		caDays   = fs.Int("ca-days", 90, "CA lifetime in days")
		certTTL  = fs.Duration("cert-ttl", 24*time.Hour, "host certificate lifetime; this is the revocation SLA for a partitioned host")
		keyPath  = fs.String("ca-key", "ca.key", "where to write the CA signing key; encrypted automatically when a passphrase is available")
		groupsCS = fs.String("groups", "default", "comma separated groups the CA may delegate")
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

	st, err := openStore(ctx, *dsn)
	if err != nil {
		return err
	}
	defer st.Close()

	// Generate the CA key and write it to disk, encrypted if a passphrase is
	// available. Nebula has no intermediate CAs, so this key is a root of trust
	// for the whole mesh; encryption is what makes a disk snapshot, a backup,
	// or a stolen volume useless on its own.
	caPub, caPriv, err := ca.GenerateCAKey(cert.Curve_CURVE25519)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*keyPath, cert.MarshalSigningPrivateKeyToPEM(cert.Curve_CURVE25519, caPriv), 0o600); err != nil {
		return fmt.Errorf("write ca key: %w", err)
	}

	passphrase, err := ca.CAKeyPassphrase()
	if err != nil {
		return err
	}
	if len(passphrase) > 0 {
		if err := ca.EncryptKeyFile(*keyPath, passphrase); err != nil {
			return fmt.Errorf("encrypt ca key: %w", err)
		}
		log.Info("CA key written encrypted", "path", *keyPath)
	} else {
		// Loud, because the failure is invisible: everything works, and the
		// key sits in plaintext in every snapshot and backup of this machine.
		log.Warn("CA key written UNENCRYPTED: set ORBIT_CA_KEY_PASSPHRASE_FILE "+
			"(or ORBIT_CA_KEY_PASSPHRASE) and re-run `orbitd ca encrypt` — "+
			"a disk snapshot or backup of this host currently yields the mesh's root key",
			"path", *keyPath)
	}

	signer := ca.NewMemorySigner(cert.Curve_CURVE25519, caPub, caPriv)

	now := time.Now()
	caCert, err := ca.CreateCA(ctx, signer, ca.CAParams{
		Name:      *caName,
		Networks:  []netip.Prefix{prefix},
		Groups:    groups,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.AddDate(0, 0, *caDays),
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

	absKey, err := filepath.Abs(*keyPath)
	if err != nil {
		return err
	}

	token, tokenHash, err := store.NewAPIToken()
	if err != nil {
		return err
	}

	var (
		networkID uuid.UUID
		roleID    uuid.UUID
	)
	slug := *netSlug
	if slug == "" {
		slug = store.Slugify(*netName)
	}

	err = st.Tx(ctx, func(ctx context.Context, tx *store.Tx) error {
		net := store.Network{
			Name:    *netName,
			Slug:    slug,
			CIDRs:   []netip.Prefix{prefix},
			CertVer: int16(cert.Version2),
			Curve:   cert.Curve_CURVE25519.String(),
			CertTTL: *certTTL,
		}
		if err := tx.CreateNetwork(ctx, &net); err != nil {
			return err
		}
		networkID = net.ID

		caRow := store.CA{
			NetworkID:   net.ID,
			Name:        *caName,
			Fingerprint: fingerprint,
			CertPEM:     string(caPEM),
			SignerRef:   "file://" + absKey,
			Curve:       cert.Curve_CURVE25519.String(),
			NotBefore:   caCert.NotBefore(),
			NotAfter:    caCert.NotAfter(),
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
slug       %s  ← the directory name on every managed host; immutable
role       %s  (default)
ca         %s  fingerprint %s
ca key     %s

Admin token (shown once):

  %s

Export it:

  export ORBIT_TOKEN=%s
  export ORBIT_NETWORK=%s

Join the overlay so agents can poll, renew, and receive revocations
(pick any free address inside %s):

  orbitd serve -mesh %s=<overlay-addr>

The CA private key is on local disk and is a root of trust for this entire
mesh: nebula has no intermediate CAs, so anyone who reads it can mint any
identity this CA's constraints allow. Keep it encrypted (see "orbitd ca
encrypt"), mode 0600, and rotate on a schedule you have rehearsed —
docs/design.md section 6.
`, *netName, networkID, slug, roleID, *caName, fingerprint[:16], absKey,
		token, token, networkID, prefix, networkID)
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

// caCmd holds maintenance on the CA key file.
func caCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: orbitd ca encrypt -key <path>")
	}

	switch args[0] {
	case "encrypt":
		fs := flag.NewFlagSet("ca encrypt", flag.ExitOnError)
		keyPath := fs.String("key", "ca.key", "path to the CA signing key")
		_ = fs.Parse(args[1:])

		passphrase, err := ca.CAKeyPassphrase()
		if err != nil {
			return err
		}
		if len(passphrase) == 0 {
			return errors.New("set ORBIT_CA_KEY_PASSPHRASE_FILE or ORBIT_CA_KEY_PASSPHRASE first.\n\n" +
				"On systemd, the file form pairs with LoadCredentialEncrypted= so the\n" +
				"passphrase is sealed to this machine's TPM and a stolen disk image is\n" +
				"useless without it.")
		}

		if err := ca.EncryptKeyFile(*keyPath, passphrase); err != nil {
			return err
		}
		fmt.Printf("%s is encrypted.\n\nThe same passphrase must be available to orbitd at startup, "+
			"or it cannot sign.\n", *keyPath)
		return nil

	default:
		return fmt.Errorf("unknown ca subcommand %q (want: encrypt)", args[0])
	}
}
