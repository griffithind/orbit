package e2e

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// The revert fields have to survive the whole path: agent -> wire.ReportRequest
// -> handleAgentReport -> store.AgentReport -> RecordAgentReport.
//
// This test exists because that chain was broken in exactly one place and every
// other test passed anyway. handleAgentReport built store.AgentReport field by
// field and copied four of them, so an agent could report a revert, the store
// could be perfectly capable of recording it, both halves could be
// independently tested and green, and the epoch would still never move. A
// field-copying handler is invisible to any test that starts on either side of
// it.
//
// So this one deliberately goes over HTTP.

func TestRevertSurvivesTheReportHandler(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "chain", "10.42.11.1", false, false, nil)
	hostID := uuid.MustParse(host.id)
	client := xffClient(t, ts.URL, host.addr)

	// Converge on a generation, the ordinary way.
	if err := client.Report(context.Background(), wire.ReportRequest{
		ConfigEpoch: 40, BlocklistEpoch: 5,
	}); err != nil {
		t.Fatalf("report: %v", err)
	}
	if cfg, _ := h.appliedEpochs(t, hostID); cfg != 40 {
		t.Fatalf("applied config epoch = %d, want 40", cfg)
	}

	// A bare lower number must not move it. This is the property that protects
	// against a replayed or reordered report, and it must hold across the
	// handler too, not only in the store.
	if err := client.Report(context.Background(), wire.ReportRequest{
		ConfigEpoch: 39, BlocklistEpoch: 5,
	}); err != nil {
		t.Fatalf("report: %v", err)
	}
	if cfg, _ := h.appliedEpochs(t, hostID); cfg != 40 {
		t.Errorf("an unnamed lower epoch moved the record to %d; monotonicity is broken", cfg)
	}

	// A named revert must move it. If the handler drops the field, this is the
	// assertion that fails.
	if err := client.Report(context.Background(), wire.ReportRequest{
		ConfigEpoch: 39, BlocklistEpoch: 5,
		RevertedFromConfigEpoch: 40,
		QuarantinedConfigEpoch:  40,
	}); err != nil {
		t.Fatalf("report: %v", err)
	}
	cfg, _ := h.appliedEpochs(t, hostID)
	if cfg != 39 {
		t.Fatalf("named revert did not lower the recorded epoch: got %d, want 39.\n"+
			"The store accepts this; if it failed here the report handler is\n"+
			"dropping RevertedFromConfigEpoch when it builds store.AgentReport.", cfg)
	}

	// And it is audited, because a revert is the signal that a pushed
	// generation severed hosts — the thing convergence alone cannot say.
	var found bool
	if err := h.store.Read(context.Background(), func(ctx context.Context, tx *store.Tx) error {
		recs, err := tx.ListAudit(ctx, store.AuditFilter{
			Action:   store.ActionConfigReverted,
			TargetID: host.id,
		})
		found = len(recs) > 0
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Error("a revert reported over HTTP left no audit entry")
	}
}

// TestReplayedRevertIsANoOp: the guard retries its revert report until one
// lands, so duplicates are expected rather than exceptional. A second delivery
// must not walk the epoch down again.
func TestReplayedRevertIsANoOp(t *testing.T) {
	h := setup(t)
	ts := h.serve(t, freeUDPPort(t))

	host := h.createAndEnroll(t, ts, "replay", "10.42.11.2", false, false, nil)
	hostID := uuid.MustParse(host.id)
	client := xffClient(t, ts.URL, host.addr)

	report := func(r wire.ReportRequest) {
		t.Helper()
		if err := client.Report(context.Background(), r); err != nil {
			t.Fatalf("report: %v", err)
		}
	}

	report(wire.ReportRequest{ConfigEpoch: 20, BlocklistEpoch: 3})
	revert := wire.ReportRequest{
		ConfigEpoch: 19, BlocklistEpoch: 3, RevertedFromConfigEpoch: 20,
	}
	report(revert)
	if cfg, _ := h.appliedEpochs(t, hostID); cfg != 19 {
		t.Fatalf("after revert = %d, want 19", cfg)
	}

	// Same message again. The stored epoch is now 19, which no longer matches
	// RevertedFromConfigEpoch=20, so the condition fails and nothing moves.
	report(revert)
	if cfg, _ := h.appliedEpochs(t, hostID); cfg != 19 {
		t.Errorf("a replayed revert moved the epoch again, to %d", cfg)
	}
}
