package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/slackhq/nebula/cert"

	"github.com/griffithind/orbit/internal/agent/generation"
	"github.com/griffithind/orbit/internal/agent/hostcfg"
	"github.com/griffithind/orbit/internal/agent/paths"
	"github.com/griffithind/orbit/internal/agent/posture"
	"github.com/griffithind/orbit/internal/version"
	"github.com/griffithind/orbit/internal/wire"
)

// State is what the agent remembers between invocations.
//
// Deliberately minimal. The control plane is the source of truth for everything
// else, and anything cached here is something that can go stale and disagree
// with reality. The epochs exist only so a steady-state poll can say "I already
// have N" and get an empty response; the certificate's own validity window is
// read back from the certificate on disk rather than stored, so the two can
// never disagree.
type State struct {
	// BaseURL is the public endpoint this host enrolled against. It is the
	// BOOTSTRAP endpoint, and it is used until the first response names the
	// overlay replicas — ControlURL returns it only while AgentURLs is empty.
	//
	// It is NOT a steady-state fallback, and this comment used to say it was.
	// The public listener mounts the enroll, admin and health routes and not
	// the agent routes (cmd/orbitd/main.go), so there is no /agent/v1 there to
	// fall back TO — and putting one there would expose an API whose identity is
	// the caller's source address to the internet, where that means nothing.
	// The same listener deliberately refuses the mirror image, keeping the
	// admin API off the overlay.
	//
	// So when every advertised overlay endpoint is unreachable, the agent fails
	// static on the configuration it already has and keeps trying. Recovery is
	// re-enrolment against this endpoint with a fresh code — `orbit agent
	// enroll` — which reaches the enroll routes that ARE mounted there.
	BaseURL string `json:"base_url"`

	// BaseAddrs are the addresses BaseURL was last seen at, refreshed while the
	// overlay is healthy and used by the escape hatch when it is not.
	//
	// Persisted because the case it exists for is a host whose exit route has
	// broken: the resolver's own packets carry no mark, so a lookup then goes
	// into the tunnel and fails, and a hatch that resolves at dial time is dead
	// exactly when it is needed. See ADR-0016.
	BaseAddrs []string `json:"base_addrs,omitempty"`

	// AgentURLs are the control plane's overlay addresses, one per live
	// replica, learned at enrollment and refreshed on every response. Once
	// populated, all steady-state traffic goes here and the host holds no
	// credential at all: identity is the source address, which nebula's
	// firewall verifies on every packet.
	//
	// A list, and rotated on failure. An agent pinned to one replica loses
	// renewal and revocation the moment that replica goes away.
	//
	// No special dialer is needed. The agent's own nebula routes overlay
	// traffic through the tun device, so this is an ordinary HTTP request.
	AgentURLs []string `json:"agent_urls,omitempty"`

	// Preferred indexes AgentURLs. Persisted so a restart does not send every
	// agent back to the first replica at once.
	Preferred int `json:"preferred,omitempty"`

	MembershipID   string `json:"membership_id"`
	ConfigEpoch    int64  `json:"config_epoch"`
	BlocklistEpoch int64  `json:"blocklist_epoch"`

	// NetworkKey is the network's identity public key, base64 — the anchor
	// every configuration signature is checked against.
	//
	// WRITE-ONCE. Adopted from an enrollment or renewal response when this host
	// holds none, and never replaced afterwards. A key a response can overwrite
	// is not a trust anchor: a control plane that could hand out a new one could
	// hand out its own, and the signature check would pass on anything it sent.
	//
	// The value is already established out of band at join, where verifyNetwork
	// checks it hashes to the network ID and that the proof verifies under it
	// before anything else is acted on. This just keeps what that step proved.
	NetworkKey string `json:"network_key,omitempty"`

	// UnconfirmedSince is when the currently-installed generation was applied
	// without the control plane having been reachable since. Zero means the
	// current generation is confirmed working.
	//
	// Persisted so the guard survives an agent restart: a crash right after a
	// bad apply must not clear the evidence that the apply was never confirmed.
	UnconfirmedSince time.Time `json:"unconfirmed_since,omitempty"`

	// ConfirmAfter is the earliest a successful control-plane call may count as
	// confirmation. A reload is asynchronous, so a request completing
	// milliseconds after SIGHUP proves nothing about the new configuration.
	ConfirmAfter time.Time `json:"confirm_after,omitempty"`

	// PrevConfigEpoch and PrevBlocklistEpoch are what the previous generation
	// was at, so a revert can put the reported epochs back rather than leaving
	// the control plane believing this host converged on a config it no longer
	// runs.
	PrevConfigEpoch    int64 `json:"prev_config_epoch,omitempty"`
	PrevBlocklistEpoch int64 `json:"prev_blocklist_epoch,omitempty"`

	// QuarantinedConfigEpoch is a generation that already broke this host.
	//
	// Without this, revert is a loop: the agent reverts, immediately polls, is
	// handed the same generation, applies it, breaks again. Refusing to
	// re-apply the specific epoch that failed, for a while, is what makes
	// automatic rollback safe rather than a way to flap forever.
	// QuarantinedBlocklistEpoch is the OTHER half of the key, and it is what
	// keeps the guard from swallowing revocations. Blocking a host advances the
	// blocklist epoch and — before ADR-0022 — nothing else, so a revocation
	// arrived carrying the same config epoch the guard was refusing and was
	// refused with it, for the full quarantine window. The revert made it worse
	// by rolling the installed blocklist back to its pre-revocation value.
	//
	// A generation is the one that broke this host only if BOTH epochs match.
	// See docs/adr/0025-quarantine-does-not-gate-revocation.md.
	QuarantinedConfigEpoch    int64     `json:"quarantined_config_epoch,omitempty"`
	QuarantinedBlocklistEpoch int64     `json:"quarantined_blocklist_epoch,omitempty"`
	QuarantinedUntil          time.Time `json:"quarantined_until,omitempty"`

	// PendingRevertFromConfigEpoch and PendingRevertFromBlocklistEpoch are the
	// epochs a revert moved away from, held until the control plane has been
	// told.
	//
	// Persisted, and retried on the next successful control-plane call, because
	// this is the report most likely to be lost and the one that matters most: the
	// guard fires precisely because the control plane was unreachable, and a
	// reload is asynchronous, so the report immediately following a revert goes
	// out over a data plane that may not be back yet. Losing it leaves the control
	// plane counting this host as converged on a generation it threw away, and
	// while the quarantine holds the agent applies nothing — so there is no later
	// report to correct the record.
	//
	// Zero once reported, and cleared by the next apply, which supersedes the
	// revert entirely.
	PendingRevertFromConfigEpoch    int64 `json:"pending_revert_from_config_epoch,omitempty"`
	PendingRevertFromBlocklistEpoch int64 `json:"pending_revert_from_blocklist_epoch,omitempty"`

	// DataPlaneDownSince is when the agent first observed that nebula was not
	// running on this network, or zero when it is running (or unobservable).
	//
	// Persisted so the outage is not forgotten by an agent restart, and so the
	// duration reported to the control plane is the real one rather than "since
	// the last time the agent started". Held on the agent, not inferred by the
	// server from missing reports, because the two are different facts: an agent
	// that stops reporting may have lost its own connectivity, while this says
	// the agent is fine and the data plane is not.
	DataPlaneDownSince time.Time `json:"data_plane_down_since,omitempty"`

	// RestartedForEpoch is the control plane's restart-required epoch that this
	// host has already restarted for.
	//
	// This is what stops a restart from repeating. The server sends the epoch on
	// EVERY poll, not only while the agent is behind — a steady-state poll
	// carries no configuration, and an agent that missed the one response naming
	// it would never learn it must restart. That makes the flag durable and
	// therefore repeatable, so the agent has to remember which one it acted on.
	// Without this the agent would drop every tunnel on the network once per
	// poll interval, forever, and each drop would look like progress.
	RestartedForEpoch int64 `json:"restarted_for_epoch,omitempty"`
}

// ControlURL is the endpoint the agent should talk to for steady-state work.
func (s State) ControlURL() string {
	if len(s.AgentURLs) == 0 {
		return s.BaseURL
	}
	return s.AgentURLs[s.Preferred%len(s.AgentURLs)]
}

// NextControlURL rotates to the next replica after a failure and reports the
// new endpoint.
//
// Rotation happens on the agent, not the control plane, so failover needs no
// load balancer, no virtual address, and no coordination between replicas. The
// cost is that a host may take one failed request to notice, which is the right
// trade for infrastructure that must keep working while the control plane is
// partly down.
func (s *State) NextControlURL() string {
	if len(s.AgentURLs) <= 1 {
		return s.ControlURL()
	}
	s.Preferred = (s.Preferred + 1) % len(s.AgentURLs)
	return s.ControlURL()
}

// SetAgentURLs updates the known replicas, preserving which one is in use where
// possible.
//
// Preserving it matters: re-pinning every agent to index 0 whenever the list
// changes would herd the entire fleet onto one replica after any membership
// change, which is the opposite of what the list is for.
func (s *State) SetAgentURLs(urls []string) bool {
	if len(urls) == 0 || equalStrings(s.AgentURLs, urls) {
		return false
	}
	current := ""
	if len(s.AgentURLs) > 0 {
		current = s.AgentURLs[s.Preferred%len(s.AgentURLs)]
	}
	s.AgentURLs = urls
	s.Preferred = 0
	for i, u := range urls {
		if u == current {
			s.Preferred = i
			break
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// StatePath is the agent's state file inside a per-network directory.
func StatePath(dir string) string { return filepath.Join(dir, paths.StateFileName) }

func WriteState(dir string, s State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Through a temp file and a rename: a crash mid-write would otherwise leave
	// an unparseable state file, and the agent would look unenrolled.
	tmp := StatePath(dir) + ".new"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("write agent state: %w", err)
	}
	return os.Rename(tmp, StatePath(dir))
}

func ReadState(dir string) (State, error) {
	var s State
	b, err := os.ReadFile(StatePath(dir))
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("parse agent state: %w", err)
	}
	if s.BaseURL == "" {
		return s, fmt.Errorf("agent state at %s has no control plane URL", StatePath(dir))
	}
	return s, nil
}

// Loop drives one managed host: renew the certificate when due, and apply
// configuration changes when the control plane has any.
type Loop struct {
	Client  *Client
	Applier *generation.Applier
	Policy  RenewalPolicy
	Layout  paths.Layout

	// Curve for newly generated keys. Must match the network.
	Curve cert.Curve

	State State
	Log   *slog.Logger

	// Guard configures the unreachable-revert behaviour. The zero value is
	// filled in with DefaultGuard.
	Guard GuardPolicy

	// Host applies forwarding and NAT for a gateway. Nil on a machine that is
	// not one, and on any platform that cannot be one.
	Host hostcfg.HostConfigurer

	// DNS serves the network's name table on this host's overlay address. Nil
	// disables it, which is what every test and every platform that cannot read
	// its own resolver configuration gets.
	DNS *hostcfg.Resolver

	// lastHostState is the last state successfully applied, so a reconcile that
	// changes nothing does not log every cycle.
	lastHostState string

	// lastRenewAttempt throttles retries after a failure so a persistent
	// problem does not become a hot loop against the control plane.
	lastRenewAttempt time.Time

	// serverRenewAfter is the control plane's view of when this host should
	// renew, refreshed from every poll and watch response.
	//
	// In memory only, and deliberately not in State: it is a hint the very next
	// response restates, and persisting it would add exactly the kind of cached
	// value State's documentation exists to warn about — one that can outlive the
	// certificate it describes and disagree with what is on disk. Losing it
	// across a restart costs one poll interval.
	serverRenewAfter time.Time

	// clockWarned is the last thing checkClock said, so it says it on a
	// transition rather than on every poll.
	clockWarned bool

	// baseAddrsAt is when the public endpoint was last resolved, so a poll every
	// minute does not become a lookup every minute.
	baseAddrsAt time.Time

	// pollMu guards lastPoll and lastPollErr, which the status socket reads from
	// its own goroutine while the loop writes them from the tick goroutine.
	pollMu      sync.Mutex
	lastPoll    time.Time
	lastPollErr error

	// now is injectable for tests.
	now func() time.Time
}

func (l *Loop) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// SetClock replaces the loop's time source.
//
// For tests, and the reason it is exported: every guard decision is a deadline
// comparison, so a test that drives them with the real clock is really
// asserting the machine is fast enough. It then fails under -race or on a
// loaded CI runner and passes on a laptop, which is the worst signal a test can
// give. Drive the clock instead.
func (l *Loop) SetClock(fn func() time.Time) { l.now = fn }

// GuardPolicy configures the unreachable-revert guard.
type GuardPolicy struct {
	// ConfirmWithin is how long a freshly applied generation may go without a
	// successful control-plane call before it is treated as having broken this
	// host, and reverted.
	//
	// Must comfortably exceed the poll interval and a nebula handshake, or a
	// healthy host on a slow link reverts good configuration. Too long and a
	// severed fleet stays severed. Ten minutes is a deliberate compromise, and
	// it is the number design.md 9 refers to.
	ConfirmWithin time.Duration

	// MinConfirm is how long after an apply a successful call starts counting
	// as confirmation. Nebula reloads asynchronously, so a request that
	// completes immediately after SIGHUP may still be running on the old
	// configuration.
	//
	// Zero means "use the default", not "confirm immediately". That is
	// deliberate: a caller who forgets this field gets the safe behaviour
	// rather than a guard that can be satisfied by a request already in flight
	// when the apply happened. Pass a small positive value to opt out.
	MinConfirm time.Duration

	// Quarantine is how long a reverted generation is refused. It only needs to
	// outlast the operator noticing; the agent logs loudly throughout.
	Quarantine time.Duration

	// Disabled turns the guard off. Correct only where something else owns
	// recovery, and it means a fleet-severing push has no automatic remedy.
	Disabled bool
}

func DefaultGuard() GuardPolicy {
	return GuardPolicy{
		ConfirmWithin: 10 * time.Minute,
		MinConfirm:    60 * time.Second,
		Quarantine:    30 * time.Minute,
	}
}

func (l *Loop) guard() GuardPolicy {
	g := l.Guard
	if g.ConfirmWithin <= 0 {
		g.ConfirmWithin = DefaultGuard().ConfirmWithin
	}
	if g.MinConfirm <= 0 {
		g.MinConfirm = DefaultGuard().MinConfirm
	}
	if g.Quarantine <= 0 {
		g.Quarantine = DefaultGuard().Quarantine
	}
	return g
}

// markApplied records that a generation is installed but not yet proven.
func (l *Loop) markApplied(prevConfig, prevBlock int64) {
	now := l.clock()
	g := l.guard()
	l.State.PrevConfigEpoch = prevConfig
	l.State.PrevBlocklistEpoch = prevBlock
	l.State.UnconfirmedSince = now
	l.State.ConfirmAfter = now.Add(g.MinConfirm)

	// A newer generation supersedes any revert this host has not yet reported:
	// the epoch it names is no longer what the control plane holds, so retrying
	// it could only describe a state that has since been overtaken.
	l.State.PendingRevertFromConfigEpoch = 0
	l.State.PendingRevertFromBlocklistEpoch = 0
}

// markReachable records a successful control-plane call.
//
// It only clears the guard once ConfirmAfter has passed, so the report that
// immediately follows an apply cannot vouch for the configuration that apply
// installed.
func (l *Loop) markReachable() {
	if l.State.UnconfirmedSince.IsZero() {
		return
	}
	if l.clock().Before(l.State.ConfirmAfter) {
		return
	}
	l.Log.Info("current generation confirmed working",
		"configEpoch", l.State.ConfigEpoch, "blocklistEpoch", l.State.BlocklistEpoch)
	l.State.UnconfirmedSince = time.Time{}
	l.State.ConfirmAfter = time.Time{}
	_ = WriteState(l.Layout.Dir, l.State)
}

// checkGuard reverts if the installed generation has gone unconfirmed too long.
func (l *Loop) checkGuard(ctx context.Context) {
	g := l.guard()
	if g.Disabled || l.State.UnconfirmedSince.IsZero() {
		return
	}
	unconfirmed := l.clock().Sub(l.State.UnconfirmedSince)
	if unconfirmed < g.ConfirmWithin {
		return
	}

	broken, brokenBlock := l.State.ConfigEpoch, l.State.BlocklistEpoch
	l.Log.Error("control plane unreachable since applying a new generation; reverting",
		"unconfirmedFor", unconfirmed.Round(time.Second),
		"configEpoch", broken, "revertingTo", l.State.PrevConfigEpoch)

	if err := l.Applier.Revert(ctx); err != nil {
		// Nothing to revert to, or the revert failed. Either way the host needs
		// a human; say so once per interval rather than silently retrying.
		l.Log.Error("revert failed", "error", err)
		return
	}

	l.State.ConfigEpoch = l.State.PrevConfigEpoch
	l.State.BlocklistEpoch = l.State.PrevBlocklistEpoch
	l.State.UnconfirmedSince = time.Time{}
	l.State.ConfirmAfter = time.Time{}
	l.State.QuarantinedConfigEpoch = broken
	l.State.QuarantinedBlocklistEpoch = brokenBlock
	l.State.QuarantinedUntil = l.clock().Add(g.Quarantine)
	l.State.PendingRevertFromConfigEpoch = broken
	l.State.PendingRevertFromBlocklistEpoch = brokenBlock
	if err := WriteState(l.Layout.Dir, l.State); err != nil {
		l.Log.Error("persist agent state failed", "error", err)
	}

	l.Log.Warn("quarantined the generation that broke connectivity; "+
		"it will not be re-applied until an operator investigates",
		"configEpoch", broken, "until", l.State.QuarantinedUntil)

	// Tell the control plane, best effort and last.
	//
	// Last, because a revert must not depend on anything remote: this call
	// happens precisely when the control plane may be unreachable — that is what
	// triggered the revert — so it is expected to fail about as often as it
	// succeeds, and a failure must not prevent or undo a rollback that has
	// already put a working generation back on disk. The pending marker is on
	// disk before the attempt for the same reason a state file is written before
	// anything remote is touched: a crash here must not lose the fact that this
	// host owes the control plane a correction.
	//
	// Best effort, but not optional: until it lands, the control plane still
	// believes this host converged on a configuration it no longer runs, and the
	// CA rotation gate reads exactly that number. A whole fleet can revert in
	// unison and still show 100% converged.
	l.report(ctx)
}

// quarantineEpoch refuses a generation this host has already failed to deliver.
//
// The same reasoning as the unreachable-guard's quarantine, applied to a
// different failure. A generation that needs a restart this host cannot perform,
// or a restart that did not take, will be offered again by the control plane on
// the very next poll — it has no way to know the host cannot take it. Without a
// quarantine the agent tries again every interval, forever, and in the
// restart-failed case each attempt drops every tunnel on this network. That is
// not a retry loop, it is a rolling outage.
func (l *Loop) quarantineEpoch(epoch, blocklistEpoch int64, cause error) {
	if epoch == 0 {
		return
	}
	l.State.QuarantinedBlocklistEpoch = blocklistEpoch
	g := l.guard()
	l.State.QuarantinedConfigEpoch = epoch
	l.State.QuarantinedUntil = l.clock().Add(g.Quarantine)
	l.Log.Error("refusing this generation until an operator investigates",
		"network", l.Layout.Network, "configEpoch", epoch,
		"until", l.State.QuarantinedUntil, "error", cause)
	if err := WriteState(l.Layout.Dir, l.State); err != nil {
		l.Log.Error("persist agent state failed", "error", err)
	}
}

// undeliverable reports whether an apply failed in a way that will fail
// identically every time it is retried.
func undeliverable(err error) bool {
	return errors.Is(err, generation.ErrRestartRequired) || errors.Is(err, generation.ErrRestartFailed)
}

// checkDataPlane notices that nebula is not running.
//
// It deliberately does NOT restart it. The service manager owns process
// liveness — nebula.service has Restart=always — and an agent that also
// restarted would race it, turning one crash loop into two racing ones and
// making the logs unreadable. The agent's job here is the one systemd cannot
// do: tell the control plane, so a host that cannot start its data plane looks
// different from a host that is merely slow to converge.
//
// Only the restart path in the applier ever starts a process, and only because
// a specific generation requires it.
func (l *Loop) checkDataPlane(ctx context.Context) {
	sup := l.Applier.Supervisor
	if sup == nil {
		return
	}
	st, err := sup.Status(ctx)
	if err != nil {
		l.Log.Warn("could not read nebula status", "network", l.Layout.Network, "error", err)
		return
	}
	if !st.Known {
		return // nothing observable; not the same as "down"
	}

	if st.Running {
		if !l.State.DataPlaneDownSince.IsZero() {
			l.Log.Info("nebula is running again",
				"network", l.Layout.Network,
				"downFor", l.clock().Sub(l.State.DataPlaneDownSince).Round(time.Second),
				"status", st.Detail)
			l.State.DataPlaneDownSince = time.Time{}
			if err := WriteState(l.Layout.Dir, l.State); err != nil {
				l.Log.Error("persist agent state failed", "error", err)
			}
		}
		return
	}

	if l.State.DataPlaneDownSince.IsZero() {
		l.State.DataPlaneDownSince = l.clock()
		if err := WriteState(l.Layout.Dir, l.State); err != nil {
			l.Log.Error("persist agent state failed", "error", err)
		}
	}
	l.Log.Error("nebula is not running; this host has no data plane on this network",
		"network", l.Layout.Network,
		"downFor", l.clock().Sub(l.State.DataPlaneDownSince).Round(time.Second),
		"status", st.Detail, "supervisor", sup.Describe())
}

// restartRequiredEpoch is the control plane's "this generation cannot be
// hot-loaded" marker, or zero.
//
// An epoch rather than a boolean, and the difference is the whole idempotence
// story: the server repeats the value on every poll so a host that missed one
// response still learns of it, which means a boolean would be indistinguishable
// from "restart again now" on the very next tick.
func restartRequiredEpoch(resp *wire.StateResponse) int64 {
	if resp == nil {
		return 0
	}
	return resp.RestartRequiredEpoch
}

// restartRequired reports whether the control plane is asking for a restart
// this host has not already performed.
//
// The comparison, not the flag, is what makes a restart happen once. Everything
// else about a restart — that it drops every tunnel on the network, that it is
// the only way an address change takes effect — argues for doing it exactly as
// often as the control plane asks and no more.
func (l *Loop) restartRequired(resp *wire.StateResponse) bool {
	e := restartRequiredEpoch(resp)
	return e != 0 && e > l.State.RestartedForEpoch
}

// noteRestarted records that this host has satisfied a restart request.
//
// Called only after a successful apply, so a restart that failed and rolled
// back is asked for again rather than being counted as done.
func (l *Loop) noteRestarted(resp *wire.StateResponse) {
	if e := restartRequiredEpoch(resp); e > l.State.RestartedForEpoch {
		l.State.RestartedForEpoch = e
		l.Log.Info("restarted for the generation the control plane flagged",
			"network", l.Layout.Network, "restartRequiredEpoch", e)
	}
}

// quarantinedEpoch is the generation this host is currently refusing, or zero.
//
// Read-only, unlike quarantined(), which expires the quarantine as a side
// effect. Reporting must not be able to change what the guard decides.
func (l *Loop) quarantinedEpoch() int64 {
	if l.State.QuarantinedConfigEpoch == 0 || l.clock().After(l.State.QuarantinedUntil) {
		return 0
	}
	return l.State.QuarantinedConfigEpoch
}

// quarantined reports whether a generation is the one that already broke this
// host.
//
// Both epochs, because a blocklist cannot be the cause of the unreachability the
// guard is reacting to: a blocklist entry can only withdraw trust in a PEER,
// never in this host's own certificate. A generation carrying a newer blocklist
// is therefore not the generation that broke us, whatever its config epoch says.
func (l *Loop) quarantined(configEpoch, blocklistEpoch int64) bool {
	if l.State.QuarantinedConfigEpoch == 0 {
		return false
	}
	if configEpoch != l.State.QuarantinedConfigEpoch ||
		blocklistEpoch != l.State.QuarantinedBlocklistEpoch {
		return false
	}
	if l.clock().After(l.State.QuarantinedUntil) {
		// Expired: let it through, having given an operator time to look.
		l.State.QuarantinedConfigEpoch = 0
		l.State.QuarantinedBlocklistEpoch = 0
		l.State.QuarantinedUntil = time.Time{}
		return false
	}
	return true
}

// failover rotates to another replica after a transport-level failure.
//
// Only for errors that mean "this endpoint is unreachable". An APIError is a
// reply from a working control plane — rotating on a 400 would hide a real
// problem behind an endless tour of replicas that all answer the same way.
func (l *Loop) failover(err error) {
	if err == nil || len(l.State.AgentURLs) <= 1 {
		return
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) && !apiErr.Retryable() {
		return
	}

	next := l.State.NextControlURL()
	l.Log.Warn("control plane endpoint failed, trying another replica",
		"error", err, "next", next)
	l.Client.BaseURL = next
	_ = WriteState(l.Layout.Dir, l.State)
}

// baseAddrsTTL is how often the public endpoint is re-resolved on a healthy
// poll. Long, because the answer changes rarely and the cost of a stale one is
// a failed dial that falls back to the ordinary path.
const baseAddrsTTL = 30 * time.Minute

// refreshBaseAddrs learns where the public endpoint lives, while it still can.
//
// Called from a SUCCESSFUL poll, which is the only moment this is safe to do:
// the overlay is working, so the resolver is answering from somewhere real
// rather than through a tunnel that may be the broken thing. The escape hatch
// then has addresses to use when none of that is true any more.
//
// Non-blocking and best effort. A poll must not wait on a resolver, and a
// lookup that fails leaves the previous answer in place — "could not tell" and
// "there is nowhere to go" are different, and only one of them should erase a
// working recovery path.
func (l *Loop) refreshBaseAddrs() {
	if l.State.BaseURL == "" || l.clock().Before(l.baseAddrsAt.Add(baseAddrsTTL)) {
		return
	}
	l.baseAddrsAt = l.clock()

	u, err := url.Parse(l.State.BaseURL)
	if err != nil || u.Hostname() == "" {
		return
	}
	host := u.Hostname()
	// Already an address: nothing to learn, and nothing that can go stale.
	if _, err := netip.ParseAddr(host); err == nil {
		l.State.BaseAddrs = []string{host}
		return
	}

	// Synchronous, and bounded. The Loop has no lock — its state belongs to one
	// goroutine — so a background lookup writing State would be a data race for
	// the sake of saving a few milliseconds once every half hour, on a poll that
	// has already made a network round trip.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return
	}
	l.State.BaseAddrs = addrs
}

// checkClock names a wrong clock, once, instead of letting it arrive as a
// certificate error.
//
// Nebula validates NotBefore and NotAfter against raw wall time with zero
// leeway, and Orbit backdates issuance by exactly one minute. So a host more
// than a minute slow considers its brand-new certificate not-yet-valid: nebula
// refuses to load it, the apply fails, the loop rolls back and retries forever.
// That failure looks identical to a wrong key, a wrong CA, or a corrupted
// config, and `orbit netcheck`'s own advice text admits it — the check exists
// and is a command an operator runs only AFTER suspecting the problem.
//
// Logged once per transition rather than every poll: a wrong clock does not
// fix itself between polls, and a warning a minute forever is a warning nobody
// reads. See docs/adr/0031-clock-skew-is-measured-not-inferred.md.
func (l *Loop) checkClock() {
	skew, ok := l.Client.Skew()
	if !ok {
		return
	}
	bad := skew > MaxSkew || skew < -MaxSkew
	if bad == l.clockWarned {
		return
	}
	l.clockWarned = bad
	if !bad {
		l.Log.Info("clock is back within tolerance of the control plane",
			"skew", skew.Round(time.Second))
		return
	}
	dir := "ahead of"
	if skew < 0 {
		dir = "behind"
	}
	l.Log.Warn("this machine's clock disagrees with the control plane; "+
		"certificates will be refused and it will look like a certificate problem",
		"skew", skew.Round(time.Second), "direction", dir, "tolerance", MaxSkew,
		"fix", "NTP")
}

// adoptEndpoints records a refreshed replica list.
func (l *Loop) adoptEndpoints(urls []string) {
	if l.State.SetAgentURLs(urls) {
		l.Log.Info("control plane replicas changed",
			"endpoints", urls, "using", l.State.ControlURL())
		l.Client.BaseURL = l.State.ControlURL()
		_ = WriteState(l.Layout.Dir, l.State)
	}
}

// cycle is everything an iteration does except deciding how to wait.
//
// Run and Tick share it so that "what the agent does each time round" has one
// definition. It previously had two, and they had drifted: the daemon called
// Tick, which did neither checkInstalled nor reconcileHost, so config-integrity
// self-healing and host reconciliation were built, tested via Run, and never
// executed in production.
//
// Order matters and is not arbitrary. Ensure first, so a host whose data plane
// is down spends the cycle getting it back rather than talking to a control
// plane it may not be able to reach without it. Renewal before the poll, because
// a renewal response already carries the current configuration and doing it the
// other way round would apply the same generation twice.
func (l *Loop) cycle(ctx context.Context) {
	l.ensureDataPlane(ctx)
	l.checkGuard(ctx)
	l.checkDataPlane(ctx)

	// Every cycle, including the first. The first matters most: the machine may
	// have been edited while the agent was stopped, which is exactly when
	// someone would do it. It is a hash comparison against files already on this
	// disk, so the steady-state cost is nothing.
	l.checkInstalled()

	// And the host's own forwarding rules, which live somewhere other things
	// also write to and therefore have to be re-asserted rather than assumed.
	l.reconcileHost()

	if err := l.maybeRenew(ctx); err != nil {
		// Renewal failure is not fatal. The existing certificate is still valid
		// (that is the point of renewing at half life), and the configuration
		// poll may still have useful work to do.
		l.Log.Warn("renewal failed", "error", err)
	}
}

// ensureDataPlane restarts nebula if it is not running.
//
// Distinct from checkDataPlane, which only observes and records how long the
// data plane has been down. Observing without acting is what left a host that
// failed to start at boot down until the next new generation arrived.
func (l *Loop) ensureDataPlane(ctx context.Context) {
	sup := l.Applier.Supervisor
	if sup == nil {
		return
	}
	started, err := sup.Ensure(ctx)
	if err != nil {
		l.Log.Error("nebula is down and will not start",
			"network", l.Layout.Network, "error", err)
		return
	}
	if started {
		l.Log.Info("nebula restarted", "network", l.Layout.Network)
	}
}

// Tick performs one iteration and returns.
//
// This is the -once path. Run is the long-running one; both go through cycle,
// so they cannot diverge again.
//
// A failure is logged and returned but is never allowed to disturb the running
// data plane: the applier only installs a generation it has already validated,
// and rolls back one that fails verification.
func (l *Loop) Tick(ctx context.Context) error {
	l.cycle(ctx)
	return l.recordPoll(l.poll(ctx))
}

// recordPoll stores the outcome of the most recent poll for the status socket.
//
// "Last polled 40 minutes ago with no error" is a different diagnosis from
// "polled a second ago and failed", and the epochs alone tell neither. Recorded
// here rather than in the daemon so that both loops report it and the status
// socket does not depend on which one is running.
func (l *Loop) recordPoll(err error) error {
	l.pollMu.Lock()
	l.lastPoll, l.lastPollErr = l.clock(), err
	l.pollMu.Unlock()
	return err
}

// LastPoll reports when the loop last completed a poll, and what it returned.
func (l *Loop) LastPoll() (at time.Time, err error) {
	l.pollMu.Lock()
	defer l.pollMu.Unlock()
	return l.lastPoll, l.lastPollErr
}

// CurrentWindow reads the validity window of the certificate on disk.
func (l *Loop) CurrentWindow() (notBefore, notAfter time.Time, err error) {
	b, err := os.ReadFile(l.Layout.Paths.Cert)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return CertificateWindow(string(b))
}

// noteRenewHint records the control plane's view of when this host should renew.
//
// Every state and watch response carries it, so the hint tracks the certificate
// the server currently holds for this host and needs no invalidation of its own:
// once a renewal lands, the next response restates it as the new certificate's
// schedule. That self-correction is why honouring the hint cannot loop.
func (l *Loop) noteRenewHint(resp *wire.StateResponse) {
	l.serverRenewAfter = resp.RenewAfter
}

// maybeRenew renews the certificate if the policy says it is due.
func (l *Loop) maybeRenew(ctx context.Context) error {
	notBefore, notAfter, err := l.CurrentWindow()
	if err != nil {
		return fmt.Errorf("read current certificate: %w", err)
	}

	now := l.clock()
	urgency := l.Policy.AssessWithHint(now, notBefore, notAfter, l.State.MembershipID, l.serverRenewAfter)
	if urgency == NotDue {
		l.Log.Debug("certificate not due for renewal",
			"renewAt", l.Policy.RenewAtWithHint(notBefore, notAfter, l.State.MembershipID, l.serverRenewAfter),
			"notAfter", notAfter)
		return nil
	}

	// Throttle retries. Without this a control plane outage during the renewal
	// window turns every tick into a failed request.
	if !l.lastRenewAttempt.IsZero() && now.Sub(l.lastRenewAttempt) < l.Policy.MinRetry {
		return nil
	}
	l.lastRenewAttempt = now

	switch urgency {
	case Urgent:
		// Worth an operator's attention: renewal has been failing long enough
		// that the remaining margin is thin.
		l.Log.Warn("certificate renewal is overdue",
			"notAfter", notAfter, "remaining", notAfter.Sub(now))
	case Expired:
		// The agent API rides the overlay, which this host can no longer reach.
		// Say so precisely rather than emitting a generic connection error.
		l.Log.Error("certificate has expired; this host cannot renew over the overlay and needs recovery",
			"notAfter", notAfter)
	}

	return l.doRenew(ctx)
}

// RenewNow renews immediately, bypassing the schedule.
//
// Exported for the e2e tests, which drive renewal directly and cannot reach
// doRenew from outside the package. It said it existed for an operator escape
// hatch, "orbit agent renew", and no such command has ever existed — the
// justification on its deadcode-allow entry was describing something imagined.
//
// It still goes through the full apply path, so a renewal that breaks the host
// is rolled back exactly as a scheduled one would be.
func (l *Loop) RenewNow(ctx context.Context) error {
	l.lastRenewAttempt = l.clock()
	return l.doRenew(ctx)
}

func (l *Loop) doRenew(ctx context.Context) error {
	// A FRESH keypair on every renewal, with no way to opt out.
	//
	// Rotating the key is what makes a renewal worth more than a longer
	// certificate: a key that never changes is one a past compromise keeps
	// paying out on, for as long as the machine lives. Generating one costs
	// microseconds and the private half never leaves this host either way.
	kp, err := GenerateKeypair(l.Curve)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	resp, err := l.Client.Renew(ctx, kp)
	if err != nil {
		l.failover(err)
		var apiErr *APIError
		if errors.As(err, &apiErr) && !apiErr.Retryable() {
			return fmt.Errorf("renewal rejected, will not retry until the next window: %w", err)
		}
		return err
	}

	// The renewal response is where a host that has never pinned a network key
	// gets one, so this runs before the gate below rather than after it.
	l.pinNetworkKey(resp.NetworkKey)
	if err := l.checkMaterial(resp.ConfigSig, resp.Config, resp.CABundle); err != nil {
		return err
	}

	material := generation.Material{
		Config:      resp.Config,
		CABundle:    resp.CABundle,
		Certificate: resp.Certificate,
		ConfigSig:   resp.ConfigSig,
	}
	material.PrivateKey = kp.PrivatePEM

	if err := l.Applier.Apply(ctx, material); err != nil {
		return fmt.Errorf("apply renewed certificate: %w", err)
	}

	prevConfig, prevBlock := l.State.ConfigEpoch, l.State.BlocklistEpoch
	l.State.ConfigEpoch = resp.ConfigEpoch
	l.State.BlocklistEpoch = resp.BlocklistEpoch
	l.markApplied(prevConfig, prevBlock)
	if err := WriteState(l.Layout.Dir, l.State); err != nil {
		l.Log.Error("persist agent state failed", "error", err)
	}

	// Adopt the new certificate's schedule immediately rather than waiting for
	// the next poll to restate it. A pull-forward hint that outlived the
	// certificate it was about would say "renew now" about a certificate just
	// issued, and the only thing standing between that and a renewal loop would
	// be MinRetry.
	l.serverRenewAfter = resp.RenewAfter

	l.adoptEndpoints(resp.AgentEndpoints)
	l.Log.Info("certificate renewed",
		"notAfter", resp.NotAfter, "renewAfter", resp.RenewAfter)

	l.report(ctx)
	return nil
}

// poll fetches and applies any configuration change.
func (l *Loop) poll(ctx context.Context) error {
	resp, err := l.Client.State(ctx, l.State.ConfigEpoch, l.State.BlocklistEpoch)
	if err != nil {
		// A control plane outage must never disturb a working data plane. Log
		// and keep the current configuration; the mesh is unaffected.
		l.failover(err)
		return fmt.Errorf("poll: %w", err)
	}

	l.markReachable()
	l.noteRenewHint(resp)
	l.retryPendingRevert(ctx)

	if resp.Config == "" {
		l.Log.Debug("no configuration change",
			"configEpoch", resp.ConfigEpoch, "blocklistEpoch", resp.BlocklistEpoch)
		return nil
	}
	// Before the quarantine gate and before any early return: the replica list
	// is how this host reaches a control plane at all, and a host refusing a
	// generation is exactly a host that may need to reach a different one.
	l.adoptEndpoints(resp.AgentEndpoints)
	l.checkClock()
	l.refreshBaseAddrs()

	if l.quarantined(resp.ConfigEpoch, resp.BlocklistEpoch) {
		l.Log.Warn("refusing a quarantined generation",
			"configEpoch", resp.ConfigEpoch, "until", l.State.QuarantinedUntil)
		return nil
	}

	prevConfig, prevBlock := l.State.ConfigEpoch, l.State.BlocklistEpoch
	l.Log.Info("applying configuration update",
		"configEpoch", resp.ConfigEpoch, "blocklistEpoch", resp.BlocklistEpoch)

	if err := l.checkMaterial(resp.ConfigSig, resp.Config, resp.CABundle); err != nil {
		return err
	}

	if err := l.Applier.Apply(ctx, generation.Material{
		Config:          resp.Config,
		CABundle:        resp.CABundle,
		Certificate:     resp.Certificate,
		RequiresRestart: l.restartRequired(resp),
		ConfigSig:       resp.ConfigSig,
	}); err != nil {
		if undeliverable(err) {
			l.quarantineEpoch(resp.ConfigEpoch, resp.BlocklistEpoch, err)
		}
		return fmt.Errorf("apply configuration: %w", err)
	}

	l.noteRestarted(resp)
	l.State.ConfigEpoch = resp.ConfigEpoch
	l.State.BlocklistEpoch = resp.BlocklistEpoch
	l.markApplied(prevConfig, prevBlock)
	if err := WriteState(l.Layout.Dir, l.State); err != nil {
		l.Log.Error("persist agent state failed", "error", err)
	}

	l.report(ctx)
	return nil
}

// report tells the control plane what this host has applied.
//
// Sent after a successful apply — never after a fetch, which is what makes the
// control plane's convergence figure mean "in effect" rather than "downloaded" —
// and after a revert, which is the same statement in the other direction. A
// failure is logged but not propagated: the host is correctly configured either
// way, and the next tick reports again.
func (l *Loop) report(ctx context.Context) {
	req := l.reportRequest()
	revert := req.RevertedFromConfigEpoch != 0 || req.RevertedFromBlocklistEpoch != 0

	if err := l.Client.Report(ctx, req); err != nil {
		if revert {
			// Louder than an ordinary failed report: this is the one whose loss
			// leaves the control plane counting a reverted host as converged. It
			// stays pending and goes out again on the next call that gets through.
			l.Log.Error("could not tell the control plane about the revert; "+
				"it may still count this host as converged on the reverted generation",
				"error", err, "revertedFrom", req.RevertedFromConfigEpoch,
				"nowAt", l.State.ConfigEpoch)
			return
		}
		l.Log.Warn("report failed", "error", err)
		return
	}

	if revert {
		// The server accepted the report. Whether it actually lowered anything is
		// its decision — a duplicate that no longer matches what it holds is a
		// no-op there — so a delivered report is exactly the right condition for
		// dropping the marker, and it is what stops a lost response from making
		// the agent retry forever.
		l.Log.Info("reported the revert to the control plane",
			"revertedFrom", req.RevertedFromConfigEpoch, "nowAt", l.State.ConfigEpoch)
		l.State.PendingRevertFromConfigEpoch = 0
		l.State.PendingRevertFromBlocklistEpoch = 0
		if err := WriteState(l.Layout.Dir, l.State); err != nil {
			l.Log.Error("persist agent state failed", "error", err)
		}
	}
}

// reportRequest describes this host's current state to the control plane.
//
// The reverted-from epochs are what let the server accept a lower number at all:
// it requires them to match what it currently holds, so a duplicate of this
// report cannot lower anything a second time, and a report that merely carries a
// smaller number cannot lower anything at all.
func (l *Loop) reportRequest() wire.ReportRequest {
	req := l.baseReportRequest()
	// A host whose nebula is not running is converged on paper and off the mesh
	// in fact. Reporting it is what stops the two from looking the same.
	reportDataPlaneDown(&req, !l.State.DataPlaneDownSince.IsZero())

	// Facts and posture describe the MACHINE, and are sent on every report
	// rather than only when they change.
	//
	// Sending unconditionally is the point rather than an oversight. Posture is
	// only worth anything if it is FRESH — CISA's maturity ladder turns on
	// continuously verified rather than verified once, and the well-documented
	// failure of Entra's device-compliance signal is that it is stale by
	// construction. A change-detection scheme would mean a machine whose
	// encryption was switched off between reports keeps reading as compliant
	// until something notices, and "something notices" is the part that does
	// not exist. Four file reads per cycle is not a cost worth optimising.
	//
	// A host on three networks sends this three times; the control plane records
	// it once, against the device. See docs/model.md §3.
	req.Facts = posture.Facts("")
	req.Posture = posture.Posture()
	return req
}

// reportDataPlaneDown marks a report as coming from a host whose data plane is
// down.
//
// Split out so wiring the wire field is a one-line change: it becomes
//
//	req.DataPlaneDown = down
//
// once wire.ReportRequest carries it. Until then the condition is logged at
// Error on every tick and is not visible to the control plane, which is the gap
// this names.
func reportDataPlaneDown(req *wire.ReportRequest, down bool) {
	req.DataPlaneDown = down
}

func (l *Loop) baseReportRequest() wire.ReportRequest {
	return wire.ReportRequest{
		ConfigEpoch:                l.State.ConfigEpoch,
		BlocklistEpoch:             l.State.BlocklistEpoch,
		AgentVersion:               version.Version,
		RevertedFromConfigEpoch:    l.State.PendingRevertFromConfigEpoch,
		RevertedFromBlocklistEpoch: l.State.PendingRevertFromBlocklistEpoch,
		// Sent on every report, not only after a revert. A quarantine is
		// otherwise invisible server-side: a host refusing a generation and a
		// host that is merely slow are the same observation — an applied epoch
		// that is behind — and an operator needs opposite responses to them.
		QuarantinedConfigEpoch: l.quarantinedEpoch(),
	}
}

// retryPendingRevert re-sends a revert report the control plane never received.
//
// Called from the poll and watch paths rather than only after an apply, because
// a quarantined host applies nothing: without this the single attempt made at
// revert time — over a data plane that had just been reloaded and may not have
// been back yet — would be the only one this host ever makes.
func (l *Loop) retryPendingRevert(ctx context.Context) {
	if l.State.PendingRevertFromConfigEpoch == 0 && l.State.PendingRevertFromBlocklistEpoch == 0 {
		return
	}
	l.report(ctx)
}

// RunOptions configures the long-running agent.
type RunOptions struct {
	// Push enables long-polling. When the server has no notifier it answers
	// 503 and the loop falls back to Interval polling on its own.
	Push bool

	// Hold is how long a watch request may block server-side.
	Hold time.Duration

	// Interval is the poll cadence when push is unavailable.
	Interval time.Duration

	// Jitter is the fraction of Interval to randomise by. Mandatory in
	// practice: a fleet enrolled together polls together forever without it,
	// turning a steady load into a periodic spike.
	Jitter float64
}

func DefaultRunOptions() RunOptions {
	return RunOptions{Push: true, Hold: 30 * time.Second, Interval: time.Minute, Jitter: 0.2}
}

// Run drives the agent until ctx ends.
//
// Renewal is checked on every iteration rather than on its own timer. With push
// enabled a watch returns at least every Hold, so the check runs often enough;
// without it, Interval bounds the same thing. One loop is easier to reason
// about than two, and renewal is cheap when not due (it reads one file).
func (l *Loop) Run(ctx context.Context, opts RunOptions) error {
	if opts.Hold <= 0 {
		opts.Hold = 30 * time.Second
	}
	if opts.Interval <= 0 {
		opts.Interval = time.Minute
	}

	push := opts.Push
	for ctx.Err() == nil {
		l.cycle(ctx)

		if push {
			outcome, err := l.watchOnce(ctx, opts.Hold)
			if err != nil {
				var apiErr *APIError
				if errors.As(err, &apiErr) && apiErr.Status == 503 {
					// The server has no notifier, or is shedding watchers.
					// Falling back is expected, not an error condition.
					l.Log.Info("push unavailable, falling back to polling",
						"interval", opts.Interval)
					push = false
					continue
				}
				l.Log.Warn("watch failed, retrying", "error", err)
				l.sleep(ctx, opts.Interval, opts.Jitter)
				continue
			}

			// Only watchIdle may reconnect immediately: the server held that
			// request for the full hold period, so the loop is paced by the
			// server and the next watch costs one connection per hold.
			//
			// watchRefused must not. The server answers a watch the moment this
			// host's known epoch is behind, and refusing a generation is what
			// keeps it behind — for the entire quarantine window. Reconnecting
			// straight away turns that window into a hot loop: watch, instant
			// answer, refuse, watch, at full speed, per host, fleet-wide, costing
			// the server a notifier subscribe and a full state read every pass.
			// Backing off to the poll interval is the same throttle
			// lastRenewAttempt applies to a failing renewal, for the same reason:
			// a condition the control plane cannot resolve by answering faster is
			// not worth asking about faster.
			if outcome == watchRefused {
				l.sleep(ctx, opts.Interval, opts.Jitter)
			}
			continue
		}

		if err := l.recordPoll(l.poll(ctx)); err != nil {
			l.Log.Warn("poll failed, keeping current configuration", "error", err)
		}
		l.sleep(ctx, opts.Interval, opts.Jitter)
	}
	return ctx.Err()
}

// watchOutcome is what a completed watch actually did.
//
// Three states, not a bool: "nothing was offered" and "something was offered and
// refused" look identical to a caller holding only "did I apply anything", and
// they need opposite pacing. Conflating them is what made a quarantined host spin
// against the control plane at full speed.
type watchOutcome int

const (
	// watchIdle means the hold expired with nothing new. The server paced this
	// request; reconnecting immediately is correct.
	watchIdle watchOutcome = iota
	// watchApplied means a new generation was installed.
	watchApplied
	// watchRefused means the server offered a generation this host will not
	// apply. The server will keep offering it, immediately, for as long as the
	// refusal stands, so the agent must pace itself.
	watchRefused
)

// watchOnce performs one long poll and applies whatever it returns.
func (l *Loop) watchOnce(ctx context.Context, hold time.Duration) (watchOutcome, error) {
	resp, err := l.Client.Watch(ctx, l.State.ConfigEpoch, l.State.BlocklistEpoch, hold)
	if err != nil {
		l.failover(err)
		return watchIdle, err
	}
	l.markReachable()
	l.noteRenewHint(resp)
	l.retryPendingRevert(ctx)

	if resp.Config == "" {
		return watchIdle, nil // hold expired with nothing new
	}
	l.adoptEndpoints(resp.AgentEndpoints)

	if l.quarantined(resp.ConfigEpoch, resp.BlocklistEpoch) {
		l.Log.Warn("refusing a quarantined generation",
			"configEpoch", resp.ConfigEpoch, "until", l.State.QuarantinedUntil)
		return watchRefused, nil
	}

	prevConfig, prevBlock := l.State.ConfigEpoch, l.State.BlocklistEpoch
	l.Log.Info("applying pushed update",
		"configEpoch", resp.ConfigEpoch, "blocklistEpoch", resp.BlocklistEpoch)

	if err := l.checkMaterial(resp.ConfigSig, resp.Config, resp.CABundle); err != nil {
		return watchIdle, err
	}

	if err := l.Applier.Apply(ctx, generation.Material{
		Config:          resp.Config,
		CABundle:        resp.CABundle,
		Certificate:     resp.Certificate,
		RequiresRestart: l.restartRequired(resp),
		ConfigSig:       resp.ConfigSig,
	}); err != nil {
		if undeliverable(err) {
			// Quarantined, so the next watch is refused rather than retried —
			// and refused is what paces the loop. Returning watchIdle here would
			// reconnect immediately against a server that answers immediately.
			l.quarantineEpoch(resp.ConfigEpoch, resp.BlocklistEpoch, err)
			return watchRefused, nil
		}
		return watchIdle, fmt.Errorf("apply pushed update: %w", err)
	}

	l.noteRestarted(resp)
	l.State.ConfigEpoch = resp.ConfigEpoch
	l.State.BlocklistEpoch = resp.BlocklistEpoch
	l.markApplied(prevConfig, prevBlock)
	if err := WriteState(l.Layout.Dir, l.State); err != nil {
		l.Log.Error("persist agent state failed", "error", err)
	}
	l.report(ctx)
	return watchApplied, nil
}

// sleep waits for d, randomised by ±jitter, or until ctx ends.
func (l *Loop) sleep(ctx context.Context, d time.Duration, jitter float64) {
	if jitter > 0 {
		delta := float64(d) * jitter
		d = time.Duration(float64(d) - delta + rand.Float64()*2*delta)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}
