package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// What a guard revert does to the control plane's idea of convergence.
//
// Reported epochs are monotonic, and have to be: a replayed or reordered report
// that could lower a recorded epoch would make a network look less converged
// than it is and stall a CA rotation on a number that keeps regressing. But an
// automatic revert is the one case where a lower epoch is the truth, and
// discarding it means a push that severed the fleet still reads as fully
// converged — to the very gate whose purpose is stopping a CA rotation from
// partitioning that fleet.
//
// The exception is therefore explicit and narrow: the agent must name the epoch
// it reverted FROM, and that name must match what the server currently holds.

// reportAs applies an agent report directly, the way the agent report handler
// does. Direct rather than over HTTP because the interesting behaviour is the
// store's, and a test that went through the handler would be pinning the
// handler's field copying instead.
func (h *harness) reportAs(t *testing.T, hostID uuid.UUID, r store.AgentReport) {
	t.Helper()
	err := h.store.Tx(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		return tx.RecordAgentReport(ctx, hostID, r)
	})
	if err != nil {
		t.Fatalf("record agent report: %v", err)
	}
}

func (h *harness) appliedEpochs(t *testing.T, hostID uuid.UUID) (int64, int64) {
	t.Helper()
	var cfg, blk int64
	err := h.store.Read(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		host, err := tx.GetHost(ctx, hostID)
		if err != nil {
			return err
		}
		cfg, blk = host.AppliedConfigEpoch, host.AppliedBlocklistEpoch
		return nil
	})
	if err != nil {
		t.Fatalf("read host: %v", err)
	}
	return cfg, blk
}

// TestRevertLowersTheRecordedEpochOnlyWhenNamed is the whole contract in one
// test: nothing else may lower an epoch, and a matched revert must.
func TestRevertLowersTheRecordedEpochOnlyWhenNamed(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "reverter", "10.42.60.5", false, false, nil)
	hostID := uuid.MustParse(host.id)

	h.reportAs(t, hostID, store.AgentReport{ConfigEpoch: 5, BlocklistEpoch: 3, AgentVersion: "e2e"})
	if cfg, blk := h.appliedEpochs(t, hostID); cfg != 5 || blk != 3 {
		t.Fatalf("applied epochs = (%d, %d), want (5, 3)", cfg, blk)
	}

	// A plain lower report: a replay, or two reports that arrived out of order.
	// Unchanged behaviour, and the reason the default is monotonic.
	h.reportAs(t, hostID, store.AgentReport{ConfigEpoch: 2, BlocklistEpoch: 1})
	if cfg, blk := h.appliedEpochs(t, hostID); cfg != 5 || blk != 3 {
		t.Errorf("a bare lower report regressed the epochs to (%d, %d), want (5, 3)", cfg, blk)
	}

	// A revert that names the wrong epoch. Either the agent is confused or
	// something is forging reports; neither earns a regression.
	h.reportAs(t, hostID, store.AgentReport{
		ConfigEpoch: 4, RevertedFromConfigEpoch: 99,
		BlocklistEpoch: 2, RevertedFromBlocklistEpoch: 99,
	})
	if cfg, blk := h.appliedEpochs(t, hostID); cfg != 5 || blk != 3 {
		t.Errorf("a mismatched revert regressed the epochs to (%d, %d), want (5, 3)", cfg, blk)
	}

	// The real thing: the host reverted from 5 back to 4, and from blocklist 3
	// back to 2, and says so.
	revert := store.AgentReport{
		ConfigEpoch: 4, RevertedFromConfigEpoch: 5,
		BlocklistEpoch: 2, RevertedFromBlocklistEpoch: 3,
		QuarantinedConfigEpoch: 5, AgentVersion: "e2e",
	}
	h.reportAs(t, hostID, revert)
	if cfg, blk := h.appliedEpochs(t, hostID); cfg != 4 || blk != 2 {
		t.Fatalf("after a named revert the epochs are (%d, %d), want (4, 2): the control "+
			"plane still believes this host runs a generation it threw away", cfg, blk)
	}

	// The same report again, as a retry or a replay. The stored epoch no longer
	// matches what it names, so it does nothing — which is what keeps the
	// exception from being a way to walk a host's epoch down.
	h.reportAs(t, hostID, revert)
	if cfg, blk := h.appliedEpochs(t, hostID); cfg != 4 || blk != 2 {
		t.Errorf("a replayed revert moved the epochs to (%d, %d), want (4, 2)", cfg, blk)
	}

	// Forward again afterwards, unimpeded: a revert is not a latch.
	h.reportAs(t, hostID, store.AgentReport{ConfigEpoch: 6, BlocklistEpoch: 4})
	if cfg, blk := h.appliedEpochs(t, hostID); cfg != 6 || blk != 4 {
		t.Errorf("applied epochs = (%d, %d) after reporting 6/4", cfg, blk)
	}
}

// TestRevertIsAudited covers the evidence. An epoch that goes backwards is the
// only regression in this system, and an operator reading a stalled rotation
// needs to find out which push caused it and which generation the host is now
// refusing — neither of which is recoverable from the host row alone.
func TestRevertIsAudited(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "audited-revert", "10.42.60.7", false, false, nil)
	hostID := uuid.MustParse(host.id)

	h.reportAs(t, hostID, store.AgentReport{ConfigEpoch: 5, BlocklistEpoch: 3})
	// A forward report writes no audit entry: only regressions are events.
	h.reportAs(t, hostID, store.AgentReport{ConfigEpoch: 6, BlocklistEpoch: 3})

	revert := store.AgentReport{
		ConfigEpoch: 5, RevertedFromConfigEpoch: 6,
		BlocklistEpoch:         3,
		QuarantinedConfigEpoch: 6, AgentVersion: "e2e",
	}
	h.reportAs(t, hostID, revert)
	h.reportAs(t, hostID, revert) // replayed: no second entry, since nothing regressed

	entries := h.auditFor(t, ts.URL, store.ActionConfigReverted, host.id)
	if len(entries) != 1 {
		t.Fatalf("audit has %d %s entries, want exactly 1", len(entries), store.ActionConfigReverted)
	}
	e := entries[0]
	if e.ActorType != "agent" || e.ActorDisplay != "audited-revert" {
		t.Errorf("audit actor = %s/%s, want agent/audited-revert", e.ActorType, e.ActorDisplay)
	}

	var meta struct {
		WasConfig    int64 `json:"was_config_epoch"`
		Applied      int64 `json:"applied_config_epoch"`
		Quarantined  int64 `json:"quarantined_config_epoch"`
		AgentVersion string
	}
	if err := json.Unmarshal(e.Meta, &meta); err != nil {
		t.Fatalf("audit meta: %v (%s)", err, e.Meta)
	}
	if meta.WasConfig != 6 || meta.Applied != 5 {
		t.Errorf("audit says the epoch went %d -> %d, want 6 -> 5", meta.WasConfig, meta.Applied)
	}
	if meta.Quarantined != 6 {
		t.Errorf("audit quarantined epoch = %d, want 6: without it the entry cannot say "+
			"which push the host is refusing", meta.Quarantined)
	}
}

// TestRevertShowsUpInConvergence is the consequence the fix exists for. Before
// it, a host that reverted still counted toward the figure the CA rotation gate
// reads, so a push that severed the fleet showed as fully converged and the gate
// passed on it.
func TestRevertShowsUpInConvergence(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))
	host := h.createAndEnroll(t, ts, "unconverged", "10.42.60.9", false, false, nil)
	hostID := uuid.MustParse(host.id)

	current, _ := h.appliedEpochs(t, hostID)
	current++ // stand in for a freshly pushed generation

	h.reportAs(t, hostID, store.AgentReport{ConfigEpoch: current})
	if !h.convergedOn(t, ts.URL, hostID, current) {
		t.Fatalf("host is not counted as converged on epoch %d after reporting it", current)
	}

	h.reportAs(t, hostID, store.AgentReport{
		ConfigEpoch: current - 1, RevertedFromConfigEpoch: current,
		QuarantinedConfigEpoch: current,
	})
	if h.convergedOn(t, ts.URL, hostID, current) {
		t.Errorf("host still counts as converged on epoch %d after reverting away from it",
			current)
	}
}

// convergedOn reports whether the control plane counts this host as running the
// given config epoch, read through the same endpoint the rotation gate uses.
func (h *harness) convergedOn(t *testing.T, baseURL string, hostID uuid.UUID, epoch int64) bool {
	t.Helper()
	var conv wire.ConvergenceResponse
	if code := h.adminReq(t, http.MethodGet,
		baseURL+"/v1/networks/"+h.netID.String()+"/convergence", nil, &conv); code != http.StatusOK {
		t.Fatalf("convergence: %d", code)
	}
	for _, l := range conv.Lagging {
		if l.HostID == hostID.String() {
			return l.AppliedConfigEpoch >= epoch
		}
	}
	// Not listed as lagging: either it is at the network's epoch, or the network
	// has moved past the epoch under test.
	return conv.ConfigEpoch >= epoch
}
