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
	"github.com/griffithind/orbit/internal/device"
	"github.com/griffithind/orbit/internal/version"
)

// orbit agent join — the machine asks to be admitted, and waits.
//
// The difference from `enroll`, and the reason both exist: enroll carries a
// SECRET to the machine, and a secret that has to travel is one that can be
// copied out of a provisioning repository. Join carries nothing. The machine
// proves it holds the key it generated at first start, an operator says yes,
// and the machine comes back for its certificate.
//
// The cost is that somebody has to watch a queue, which does not suit
// unattended provisioning — which is why enroll stays. See
// docs/design-device-identity.md §3.

func joinCmd(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	var (
		url     = fs.String("url", "", "control plane base URL")
		network = fs.String("network", "", "network to join, as a uuid or a slug")
		name    = fs.String("name", "", "membership name, unique within the network (default: this machine's hostname)")
		curve   = fs.String("curve", "CURVE25519", "mesh key curve; must match the network")
		root    = fs.String("root", agent.DefaultRoot, "directory holding this machine's device key and one subdirectory per joined network")

		// Waiting is the default because it is what the operator running this
		// almost always wants: they are about to go and approve it. -wait=0
		// returns as soon as the join is lodged, which is what a provisioning
		// script wants.
		wait = fs.Duration("wait", 30*time.Minute, "how long to wait for an operator to authorize; 0 returns immediately after joining")
		poll = fs.Duration("poll", 5*time.Second, "how often to check whether the join has been authorized")

		code = fs.String("code", "", "reservation code (or ORBIT_ENROLL_CODE). A valid one is pre-authorization: the membership is created with the name, address and role the operator reserved, instead of landing in the queue")

		// A token URI rather than a boolean, for the reason `enroll` takes one:
		// which object on which token is not something the agent can guess, and
		// getting it wrong must fail here rather than at the first handshake.
		keyRef = fs.String("key", "", "PKCS#11 URI of a token-resident mesh key, e.g. pkcs11:token=orbit;object=host-key. Implies P-256, which the network must also use; requires a binary built with -tags pkcs11")
	)
	dirFlag := fs.String("dir", "", "per-network directory (default "+agent.DefaultRoot+"/<network slug>)")
	_ = fs.Parse(args)

	if *code == "" {
		*code = os.Getenv("ORBIT_ENROLL_CODE")
	}

	if *url == "" || *network == "" {
		return errors.New("-url and -network are required")
	}
	if *name == "" {
		h, err := os.Hostname()
		if err != nil || h == "" {
			return errors.New("-name is required: this machine's hostname could not be read")
		}
		*name = h
	}

	c, err := parseCurve(*curve)
	if err != nil {
		return err
	}

	log := newLogger()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// The device key, generated on first use and never again. Everything after
	// this point is the same key no matter which network is being joined or
	// which control plane is being talked to.
	id, err := device.LoadOrCreate(agent.DeviceKeyPath(*root))
	if err != nil {
		return fmt.Errorf("device key: %w", err)
	}
	hostname, _ := os.Hostname()

	// The device key's backing is what this machine CLAIMS about where its
	// device key lives. It is always a file today: -key names the MESH key, and
	// the two are different keys with different jobs — nebula needs CKA_DERIVE,
	// an identity needs CKA_SIGN, and one object cannot be both.
	client := agent.NewClient(*url)
	joined, err := client.JoinWithCode(ctx, id, *network, *name, hostname, "", *code, time.Now())
	if err != nil {
		var apiErr *agent.APIError
		if errors.As(err, &apiErr) && !apiErr.Retryable() {
			return fmt.Errorf("join rejected: %s", apiErr.Message)
		}
		return fmt.Errorf("join: %w", err)
	}

	log.Info("joined",
		"membership", joined.MembershipID, "device", joined.DeviceID,
		"fingerprint", id.Fingerprint(), "state", joined.State)

	fmt.Printf("joined %s as %q\n  membership %s\n  device     %s\n  fingerprint %s\n",
		*network, *name, joined.MembershipID, joined.DeviceID, id.Fingerprint())

	if *wait == 0 {
		fmt.Printf("\nawaiting authorization. An operator runs:\n  orbit host authorize %s\n",
			joined.MembershipID)
		return nil
	}

	// Resolve the per-network directory only now. Doing it before the join
	// would create a directory for a network that might not exist and a
	// membership that might be refused.
	dir := *dirFlag
	if dir == "" {
		dir = agent.DirFor(*network)
	}

	fmt.Printf("\nwaiting for an operator to authorize (up to %s). Meanwhile, they run:\n"+
		"  orbit host authorize %s\n\n", *wait, joined.MembershipID)

	return awaitAuthorization(ctx, client, id, joined.MembershipID, dir, c, *keyRef, *wait, *poll, log)
}

// awaitAuthorization polls the claim endpoint until the membership is approved,
// then writes the first generation.
//
// A 409 is the EXPECTED answer here and not an error: it means a human has not
// looked yet. Treating it as a failure is the mistake this loop exists to avoid
// — an agent that gave up on the first 409 would need approval to land inside
// one polling interval of the join.
func awaitAuthorization(ctx context.Context, client *agent.Client, id *device.Identity,
	membershipID, dir string, c cert.Curve, keyRef string, wait, poll time.Duration, log *slog.Logger) error {

	// One mesh keypair for the whole wait, re-signed on each attempt.
	//
	// The claim signature covers the mesh public key AND a timestamp, so a new
	// signature is needed per attempt regardless — but a new KEY per attempt
	// would mean the private half that ends up on disk depends on which poll
	// happened to succeed, and a run that was interrupted between issuance and
	// write would leave a certificate for a key this host no longer has.
	// Either way the private half stays on this machine and is never
	// transmitted. The difference is how strong that guarantee is: a file can be
	// copied off a disk image, a token key cannot leave the chip.
	var kp *agent.Keypair
	var err error
	if keyRef != "" {
		if !agent.IsTokenRef(keyRef) {
			return fmt.Errorf("-key must be a pkcs11: URI, got %q", keyRef)
		}
		kp, err = agent.KeypairFromToken(keyRef)
		if err != nil {
			return fmt.Errorf("read public key from token: %w", err)
		}
	} else if kp, err = agent.GenerateKeypair(c); err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	deadline := time.Now().Add(wait)
	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	for {
		resp, err := client.Claim(ctx, id, membershipID, kp, version.Version, time.Now())
		switch {
		case err == nil:
			layout := agent.DefaultLayout(dir)
			applier := &agent.Applier{
				Layout:            layout,
				Reloader:          agent.NoopReloader{},
				DisableValidation: true,
				KeyRef:            keyRef,
				Log:               log,
			}
			if err := applier.Apply(ctx, agent.MaterialFromEnroll(resp, kp.PrivatePEM)); err != nil {
				return err
			}
			if err := agent.WriteState(dir, agent.State{
				BaseURL:        client.BaseURL,
				AgentURLs:      resp.AgentEndpoints,
				ConfigEpoch:    resp.ConfigEpoch,
				BlocklistEpoch: resp.BlocklistEpoch,
				MembershipID:   resp.MembershipID,
				KeyRef:         keyRef,
			}); err != nil {
				return err
			}
			fmt.Printf("authorized as %s (%s)\ncertificate expires %s\nrenew after %s\n",
				resp.MembershipName, resp.MembershipID,
				resp.NotAfter.Format(time.RFC3339), resp.RenewAfter.Format(time.RFC3339))
			return nil

		case agent.IsPendingAuthorization(err):
			// Still in the queue. Say nothing on stdout — a line every five
			// seconds would bury the instruction printed above it.
			log.Debug("still awaiting authorization", "membership", membershipID)

		default:
			var apiErr *agent.APIError
			if errors.As(err, &apiErr) && !apiErr.Retryable() {
				return fmt.Errorf("claim rejected: %s", apiErr.Message)
			}
			log.Warn("claim failed, will retry", "error", err)
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("membership %s was not authorized within %s; "+
				"it is still pending, so re-running this command will pick it up",
				membershipID, wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}
