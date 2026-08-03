// Command orbit-agent enrolls a host and keeps its nebula configuration current.
//
// It supervises the stock nebula binary: it writes config.d/50-orbit.yml and
// the certificate material, then signals a reload. It never starts, stops, or
// embeds nebula itself, so the operator keeps control of the process and an
// agent failure cannot take down the data plane.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/nebulacfg"
)

const version = "0.1.0"

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

Run "orbit-agent <command> -h" for flags.
`)
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
		dir    = fs.String("dir", nebulacfg.DefaultDir, "directory the agent owns: certificate, key, rendered config, rollback copy")
		reload = fs.String("reload", "", `how to reload nebula: "pid:/run/nebula.pid", a command, or empty for none`)
		curve  = fs.String("curve", "CURVE25519", "key curve; must match the network")
	)
	_ = fs.Parse(args)

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
	resp, err := client.Enroll(ctx, *code, kp, version)
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
		Layout:   agent.DefaultLayout(*dir),
		Reloader: agent.ParseReloader(*reload),
		Log:      log,
	}
	if err := applier.Apply(ctx, agent.MaterialFromEnroll(resp, kp.PrivatePEM)); err != nil {
		return err
	}

	log.Info("enrolled",
		"host", resp.HostName, "hostId", resp.HostID,
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
		dirFlag   = fs.String("dir", nebulacfg.DefaultDir, "directory the agent owns: certificate, key, rendered config, rollback copy")
		reload    = fs.String("reload", "", `how to reload nebula: "pid:/run/nebula.pid", a command, or empty`)
		restart   = fs.String("restart", "", "how to restart nebula; required to apply a changed overlay address")
		verifyURL = fs.String("verify-url", "", "URL polled over the overlay after an apply; empty disables verification and rollback")
		interval  = fs.Duration("interval", time.Minute, "poll interval")
		curve     = fs.String("curve", "CURVE25519", "key curve; must match the network")
		reuseKey  = fs.Bool("reuse-key", false, "keep the existing private key across renewals (for hardware-backed keys)")
		once      = fs.Bool("once", false, "run one iteration and exit")
	)
	_ = fs.Parse(args)

	log := newLogger()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	st, err := agent.ReadState(*dirFlag)
	if err != nil {
		return fmt.Errorf("read agent state (has this host enrolled?): %w", err)
	}
	c, err := parseCurve(*curve)
	if err != nil {
		return err
	}

	layout := agent.DefaultLayout(*dirFlag)
	applier := &agent.Applier{
		Layout:   layout,
		Reloader: agent.ParseReloader(*reload),
		Log:      log,
	}
	if *restart != "" {
		applier.Restarter = agent.ParseReloader(*restart)
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
			"controlPlane", st.ControlURL(),
			"replicas", len(st.AgentURLs),
			"notAfter", na,
			"renewAt", loop.Policy.RenewAt(nb, na, st.HostID),
			"reload", applier.Reloader.Describe())
	}

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
		dir    = fs.String("dir", nebulacfg.DefaultDir, "directory the agent owns: certificate, key, rendered config, rollback copy")
		url    = fs.String("url", "", "public control plane URL (defaults to the one recorded at enrollment)")
		reload = fs.String("reload", "", `how to reload nebula: "pid:/run/nebula.pid", a command, or empty`)
		curve  = fs.String("curve", "CURVE25519", "key curve; must match the network")
	)
	_ = fs.Parse(args)

	log := newLogger()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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
	layout := agent.DefaultLayout(*dir)

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
		Log:      log,
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
