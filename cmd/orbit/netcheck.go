package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/griffithind/orbit/internal/agent"
	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/agent/status"
)

// `orbit netcheck` — can this machine do the things it needs to do?
//
// The gap `orbit status` leaves. Status reports what the AGENT believes: its
// epochs, its certificate, whether nebula is running. It cannot answer the
// question an operator actually has when none of that is working, which is
// whether this machine can reach the control plane at all, whether TLS
// verifies, and whether the clock is close enough for a certificate to be
// valid.
//
// Deliberately usable with no token, no agent and no overlay. That is the
// state a host is in when somebody runs this, and a diagnostic that needs the
// system to be working is not a diagnostic.
//
// Clock skew is the check that earns this command on its own. Certificates
// default to a 24h lifetime, and nebula rejects one whose NotBefore is in the
// future — so a machine whose clock is wrong fails to enroll, fails to renew,
// and reports nothing anywhere that says "your clock is wrong". It shows up as
// a certificate error, which sends people to the CA.

type checkResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	// Advice is what to do about it, and is only set when OK is false.
	Advice string `json:"advice,omitempty"`

	// Info marks a check whose failure is context rather than a fault, so it
	// does not affect the exit status.
	//
	// The agent is the case: netcheck is documented as usable before a host has
	// been set up, and it is most useful precisely then — so "no agent" must not
	// be the thing that makes `orbit netcheck` non-zero, or the command reports a
	// problem to every machine that has not joined yet.
	Info bool `json:"info,omitempty"`
}

type netcheckReport struct {
	URL     string        `json:"url,omitempty"`
	Checks  []checkResult `json:"checks"`
	Healthy bool          `json:"healthy"`
}

func netcheckCmd(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("netcheck", flag.ContinueOnError)
	fl := bindNetcheckCmd(fs)
	if err := parseLeaf(fs, args); err != nil {
		return err
	}

	rep := netcheckReport{Healthy: true}
	add := func(c checkResult) {
		if !c.OK && !c.Info {
			rep.Healthy = false
		}
		rep.Checks = append(rep.Checks, c)
	}

	// The agent socket first, because it is also where the control plane URL
	// comes from when one was not given. Its absence is not a failure: netcheck
	// is meant to work before an agent exists.
	sockPath := status.SocketPath(*fl.root)
	statusCtx, cancel := context.WithTimeout(ctx, *fl.timeout)
	status, statusErr := status.Fetch(statusCtx, sockPath)
	cancel()
	switch {
	case statusErr == nil:
		add(checkResult{Name: "agent", OK: true,
			Detail: fmt.Sprintf("running, %d network(s) joined", len(status.Networks))})
	default:
		advice := "this is fine if the host has not been set up yet"
		if _, statusCmd := agent.ServiceCommands(); statusCmd != "" {
			// Named for the platform this is running on, not for whichever one
			// the docs were written against.
			advice += "; otherwise check it with: " + statusCmd
		}
		add(checkResult{Name: "agent", OK: false, Info: true,
			Detail: "not running or not answering on " + sockPath,
			Advice: advice})
	}

	target := *fl.rawURL
	if target == "" && statusErr == nil {
		for _, n := range status.Networks {
			if n.ControlURL != "" {
				target = n.ControlURL
				break
			}
		}
	}
	if target == "" {
		add(checkResult{Name: "control plane", OK: false,
			Detail: "no URL to test",
			Advice: "pass --url, or run this on a host that has joined a network"})
		return emitNetcheck(rep, *fl.asJSON)
	}
	rep.URL = target

	u, err := url.Parse(target)
	if err != nil {
		add(checkResult{Name: "control plane", OK: false,
			Detail: fmt.Sprintf("%s is not a URL: %v", target, err)})
		return emitNetcheck(rep, *fl.asJSON)
	}

	// DNS, TCP and TLS reported separately, because they fail for different
	// reasons and send an operator to different places: a name that does not
	// resolve is DNS, a connection refused is a firewall or a dead process, and
	// a certificate error is neither.
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	resolveCtx, cancel := context.WithTimeout(ctx, *fl.timeout)
	addrs, err := net.DefaultResolver.LookupHost(resolveCtx, host)
	cancel()
	if err != nil {
		add(checkResult{Name: "dns", OK: false, Detail: err.Error(),
			Advice: "check /etc/resolv.conf. If this host is an exit node or uses " +
				"mesh DNS, its resolver may itself be behind the overlay"})
	} else {
		add(checkResult{Name: "dns", OK: true,
			Detail: fmt.Sprintf("%s -> %s", host, strings.Join(addrs, ", "))})
	}

	dialCtx, cancel := context.WithTimeout(ctx, *fl.timeout)
	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, port))
	rtt := time.Since(start)
	cancel()
	if err != nil {
		add(checkResult{Name: "tcp", OK: false, Detail: err.Error(),
			Advice: "nothing is listening, or a firewall is dropping it. This is not " +
				"an authentication failure"})
		return emitNetcheck(rep, *fl.asJSON)
	}
	_ = conn.Close()
	add(checkResult{Name: "tcp", OK: true,
		Detail: fmt.Sprintf("connected to %s in %s", net.JoinHostPort(host, port), rtt.Round(time.Millisecond))})

	if u.Scheme == "https" {
		tlsCtx, cancel := context.WithTimeout(ctx, *fl.timeout)
		tconn, err := (&tls.Dialer{}).DialContext(tlsCtx, "tcp", net.JoinHostPort(host, port))
		cancel()
		if err != nil {
			add(checkResult{Name: "tls", OK: false, Detail: err.Error(),
				Advice: "the chain does not verify from this host. A private CA has to " +
					"be in the system trust store"})
		} else {
			cs := tconn.(*tls.Conn).ConnectionState()
			detail := tls.VersionName(cs.Version)
			if len(cs.PeerCertificates) > 0 {
				leaf := cs.PeerCertificates[0]
				detail += fmt.Sprintf(", %s, expires %s",
					leaf.Subject.CommonName, leaf.NotAfter.UTC().Format(time.RFC3339))
			}
			add(checkResult{Name: "tls", OK: true, Detail: detail})
			_ = tconn.Close()
		}
	}

	// Clock skew, from the server's own Date header.
	//
	// Measured against the control plane rather than against NTP, because the
	// control plane is the thing that will refuse this host's certificate, and
	// its opinion of the time is the one that matters.
	skewCtx, cancel := context.WithTimeout(ctx, *fl.timeout)
	add(clockCheck(skewCtx, target))
	cancel()

	return emitNetcheck(rep, *fl.asJSON)
}

// maxSkew is the point at which a wrong clock starts breaking things.
//
// Certificates are minute-granular and issuance applies a one-minute backdate
// (enroll passes a skew allowance to ca.ValidityFor), so a minute is tolerable
// and two is not: past that, a freshly issued certificate can have a NotBefore
// this host considers to be in the future, and nebula refuses it.
const maxSkew = 2 * time.Minute

func clockCheck(ctx context.Context, target string) checkResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return checkResult{Name: "clock", OK: false, Detail: err.Error()}
	}
	local := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return checkResult{Name: "clock", OK: false,
			Detail: "could not read the server's time: " + err.Error()}
	}
	defer resp.Body.Close()

	served, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return checkResult{Name: "clock", OK: false,
			Detail: "the control plane sent no usable Date header, so skew is unknown"}
	}

	skew := local.Sub(served)
	abs := time.Duration(math.Abs(float64(skew)))
	if abs <= maxSkew {
		return checkResult{Name: "clock", OK: true,
			Detail: fmt.Sprintf("within %s of the control plane", abs.Round(time.Second))}
	}
	dir := "ahead of"
	if skew < 0 {
		dir = "behind"
	}
	return checkResult{Name: "clock", OK: false,
		Detail: fmt.Sprintf("this host is %s %s the control plane", abs.Round(time.Second), dir),
		Advice: "certificates last 24h by default and nebula refuses one whose " +
			"NotBefore is in the future, so this breaks enrolment and renewal and " +
			"reports itself as a certificate error. Fix NTP"}
}

func emitNetcheck(rep netcheckReport, asJSON bool) error {
	if asJSON {
		b, err := json.MarshalIndent(rep, "", "  ")
		if err != nil {
			return err
		}
		return emitJSON(b)
	}

	if rep.URL != "" {
		fmt.Fprintf(out, "control plane  %s\n\n", rep.URL)
	}
	for _, c := range rep.Checks {
		mark := "ok  "
		switch {
		case c.OK:
		case c.Info:
			mark = "--  "
		default:
			mark = "FAIL"
		}
		fmt.Fprintf(out, "%-4s %-14s %s\n", mark, c.Name, c.Detail)
		if c.Advice != "" {
			fmt.Fprintf(out, "     %-14s %s\n", "", c.Advice)
		}
	}

	// Non-zero when something is wrong, so `orbit netcheck` is usable as a
	// health check without parsing it. The same reason `tailscale status` exits
	// 1 when the backend is not running.
	if !rep.Healthy {
		return &exitError{code: exitFailure}
	}
	return nil
}

// netcheckCmdFlags are the flags of `orbit netcheckCmd`, declared here so the
// command tree can register them: completion offers exactly the set the
// command parses, because there is only one declaration of it.
type netcheckCmdFlags struct {
	root    *string
	rawURL  *string
	asJSON  *bool
	timeout *time.Duration
}

func bindNetcheckCmd(fs *flag.FlagSet) netcheckCmdFlags {
	return netcheckCmdFlags{
		root:    fs.String("root", paths.DefaultRoot, "directory holding one subdirectory per joined network"),
		rawURL:  fs.String("url", "", "control plane URL to test; defaults to what this host enrolled against"),
		asJSON:  fs.Bool("json", false, "emit the report as JSON"),
		timeout: fs.Duration("timeout", 5*time.Second, "per-check timeout"),
	}
}
