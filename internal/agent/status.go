package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/slackhq/nebula/cert"
)

// The agent's local status socket.
//
// One socket for the whole process, at <root>/agent.sock, because one process
// serves every joined network — the same reason there is one service unit. The
// network is a field in the answer, not a socket of its own.
//
// HTTP over a unix socket rather than a bespoke protocol: net/http is already
// linked, the paths carry a version, and `curl --unix-socket` works on it
// without any tooling of ours.
//
// Read-only. nebula's Control also offers CloseTunnel, SetRemoteForTunnel and
// CloseAllTunnels, and none of them are reachable here. Keeping the surface
// read-only means the blast radius of a permissions mistake is disclosure
// rather than control of the data plane.

// SocketName is the socket's name inside the agent root.
const SocketName = "agent.sock"

// SocketPath is where the agent listens for status requests.
func SocketPath(root string) string { return filepath.Join(root, SocketName) }

// SocketMode is 0600: root only.
//
// The report names every network this host has joined, its control plane, and
// its certificate. On a shared machine that is a map of the estate, and root is
// already required to run the agent at all — so restricting it costs nothing
// today. Widening it to a group is a deliberate flag, not a default.
const SocketMode os.FileMode = 0o600

// Report is the whole of GET /v1/status.
type Report struct {
	Version  string          `json:"version"`
	Root     string          `json:"root"`
	PID      int             `json:"pid"`
	Started  time.Time       `json:"started"`
	Networks []NetworkStatus `json:"networks"`
}

// NetworkStatus is one joined network.
type NetworkStatus struct {
	Network string `json:"network"`
	Dir     string `json:"dir"`

	// Ready is false when this network could not be set up at all — an
	// unreadable state file, a directory half-written by a concurrent install.
	// Such a network is retried forever in the background, so reporting it as
	// absent would hide the single most useful fact about a broken host.
	Ready bool   `json:"ready"`
	Error string `json:"error,omitempty"`

	HostID     string `json:"host_id,omitempty"`
	ControlURL string `json:"control_url,omitempty"`
	Replicas   int    `json:"replicas,omitempty"`

	Nebula      NebulaStatus `json:"nebula"`
	Certificate *CertStatus  `json:"certificate,omitempty"`

	ConfigEpoch    int64 `json:"config_epoch"`
	BlocklistEpoch int64 `json:"blocklist_epoch"`

	// LastPoll is when the agent last completed a tick, and LastPollError what
	// it failed with. Together they separate "the control plane is unreachable"
	// from "the control plane has nothing new", which look identical from the
	// epochs alone.
	LastPoll      time.Time `json:"last_poll,omitempty"`
	LastPollError string    `json:"last_poll_error,omitempty"`

	// The three states a host can be stuck in, each carried explicitly rather
	// than left to be inferred from the epochs.
	DataPlaneDownSince time.Time `json:"data_plane_down_since,omitempty"`
	UnconfirmedSince   time.Time `json:"unconfirmed_since,omitempty"`
	QuarantinedEpoch   int64     `json:"quarantined_config_epoch,omitempty"`
}

// NebulaStatus is the embedded data plane.
type NebulaStatus struct {
	// Known is false when the supervisor cannot observe the process. It is not
	// the same as "not running", and reporting it as such would call every
	// unobservable host down.
	Known    bool   `json:"known"`
	Running  bool   `json:"running"`
	Instance string `json:"instance,omitempty"`
}

// CertStatus is the certificate as currently on disk.
type CertStatus struct {
	Name        string    `json:"name"`
	Groups      []string  `json:"groups,omitempty"`
	Networks    []string  `json:"networks,omitempty"`
	NotBefore   time.Time `json:"not_before"`
	NotAfter    time.Time `json:"not_after"`
	Fingerprint string    `json:"fingerprint,omitempty"`
}

// ReadCertStatus loads the certificate a network is running.
//
// Read from disk on every request rather than cached from the last renewal: the
// point of the command is to diagnose a host whose in-memory view may be the
// thing that is wrong.
func ReadCertStatus(path string) (*CertStatus, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, _, err := cert.UnmarshalCertificateFromPEM(b)
	if err != nil {
		return nil, err
	}
	cs := &CertStatus{
		Name:      c.Name(),
		Groups:    c.Groups(),
		NotBefore: c.NotBefore(),
		NotAfter:  c.NotAfter(),
	}
	for _, n := range c.Networks() {
		cs.Networks = append(cs.Networks, n.String())
	}
	if fp, err := c.Fingerprint(); err == nil {
		cs.Fingerprint = fp
	}
	return cs, nil
}

// Expired reports whether the certificate is outside its validity window.
func (c CertStatus) Expired(now time.Time) bool {
	return now.Before(c.NotBefore) || now.After(c.NotAfter)
}

// StatusServer serves the socket.
type StatusServer struct {
	// Path is the socket. Empty disables the server entirely.
	Path string
	Log  *slog.Logger

	// Report produces the current answer. Called per request so the report is
	// never staler than the request that asked for it.
	Report func(context.Context) Report
}

// Serve listens until ctx is cancelled.
//
// A failure here must never stop the agent: diagnostics going missing is worse
// than not having them, but it is not worth taking a host's overlays down for.
// Callers log the error and carry on — see cmd/orbit/agent.go.
func (s *StatusServer) Serve(ctx context.Context) error {
	if s.Path == "" {
		return nil
	}

	ln, err := listenUnix(s.Path)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(s.Path) }()

	// After Listen, not before: the socket does not exist until then, and a
	// umask of 0022 would otherwise leave it group- and world-readable.
	if err := os.Chmod(s.Path, SocketMode); err != nil {
		_ = ln.Close()
		return fmt.Errorf("chmod %s: %w", s.Path, err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) {
		writeStatusJSON(w, s.Report(r.Context()))
	})

	srv := &http.Server{
		Handler: mux,
		// A local reader that stops reading must not pin a goroutine forever.
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	err = srv.Serve(ln)
	<-done
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// listenUnix binds the socket, clearing a stale one but never a live one.
//
// The dance matters. Unlinking unconditionally would let a second agent steal
// the socket from a running first one: the bind succeeds, both processes look
// healthy, and every status request goes to whichever won — while the other
// keeps serving networks nobody can see. So connect first: a successful connect
// means somebody is listening and this is a genuine conflict, and only a
// refused connection proves the path is a leftover.
func listenUnix(path string) (net.Listener, error) {
	if _, err := os.Stat(path); err == nil {
		c, err := net.DialTimeout("unix", path, time.Second)
		if err == nil {
			_ = c.Close()
			return nil, fmt.Errorf("another agent is already listening on %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %s: %w", path, err)
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	return ln, nil
}

func writeStatusJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// ErrNoAgent is returned when nothing is listening on the socket.
//
// A distinct error because it is the answer to the most common question this
// command is asked — "why is nothing working" — and the caller should say "the
// agent is not running" rather than surface a dial error about a path.
var ErrNoAgent = errors.New("the orbit agent is not running")

// FetchStatus reads the report from a running agent.
//
// The only client of the socket, so the wire format has exactly one
// implementation on each side and the CLI does not hand-roll a unix transport.
func FetchStatus(ctx context.Context, path string) (Report, error) {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
		Timeout: 10 * time.Second,
	}

	// The host in the URL is ignored by the dialer above but must be present
	// and valid for net/http to accept the request at all.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent/v1/status", nil)
	if err != nil {
		return Report{}, err
	}

	resp, err := client.Do(req)
	if err != nil {
		// Nothing there, or something there that will not talk: both mean no
		// agent from the caller's point of view. Permission is different — the
		// agent may be running perfectly well and the caller simply is not
		// root — so that one keeps its own error.
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
			return Report{}, ErrNoAgent
		}
		if errors.Is(err, os.ErrPermission) {
			return Report{}, fmt.Errorf("cannot read %s: %w (run as root)", path, os.ErrPermission)
		}
		return Report{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return Report{}, fmt.Errorf("agent returned %s", resp.Status)
	}

	var rep Report
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		return Report{}, fmt.Errorf("parse agent response: %w", err)
	}
	return rep, nil
}
