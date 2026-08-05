package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/griffithind/orbit/internal/store"
	"github.com/griffithind/orbit/internal/wire"
)

// The device surface.
//
// Devices are NOT scoped to a network — that is the whole reason the noun
// exists — so these routes take no network reference and are not filtered by
// one. A token that can read devices can see every machine this control plane
// knows, which is the correct granularity for the question they answer: "is
// this laptop encrypted" has one answer regardless of how many meshes it is on.

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request) {
	var out wire.DeviceList
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		devices, err := tx.ListDevices(ctx)
		if err != nil {
			return err
		}
		out.Devices = make([]wire.DeviceResponse, 0, len(devices))
		for i := range devices {
			// Memberships deliberately NOT resolved in the listing: it would be
			// a query per device, which is what turns a 500-machine fleet into
			// 501 round trips. GET /v1/devices/{id} carries them.
			out.Devices = append(out.Devices, deviceResponse(&devices[i], nil))
		}
		return nil
	})
	if err != nil {
		s.log.Error("list devices failed", "error", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var out wire.DeviceResponse
	err := s.store.Read(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		d, err := tx.GetDevice(ctx, id)
		if err != nil {
			return err
		}
		hosts, err := tx.DeviceHosts(ctx, id)
		if err != nil {
			return err
		}
		out = deviceResponse(d, hosts)
		return nil
	})
	if err != nil {
		s.notFoundOr(w, err, "device")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleBlockDevice refuses a machine everywhere on this control plane.
//
// Distinct from blocking a HOST, which suspends one membership. Both are useful
// and they are not the same action: a stolen laptop should be refused
// everywhere, and a machine being rebuilt should leave one network. Today only
// the second existed.
//
// Immediate, with no propagation, because there is exactly one enforcement
// point — the process holding this database — and a check there is a lookup it
// is already making. That is what lets a device credential be long-lived at all.
func (s *Server) handleBlockDevice(w http.ResponseWriter, r *http.Request) {
	s.setDeviceBlocked(w, r, true)
}

func (s *Server) handleUnblockDevice(w http.ResponseWriter, r *http.Request) {
	s.setDeviceBlocked(w, r, false)
}

func (s *Server) setDeviceBlocked(w http.ResponseWriter, r *http.Request, blocked bool) {
	identity := identityFrom(r.Context())
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var req wire.BlockDeviceRequest
	if r.ContentLength > 0 && !decode(w, r, &req) {
		return
	}

	action := store.ActionDeviceUnblocked
	if blocked {
		action = store.ActionDeviceBlocked
	}

	var out wire.DeviceResponse
	err := s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		var err error
		if blocked {
			err = tx.BlockDevice(ctx, id, req.Reason)
		} else {
			err = tx.UnblockDevice(ctx, id)
		}
		if err != nil {
			return err
		}
		d, err := tx.GetDevice(ctx, id)
		if err != nil {
			return err
		}
		hosts, err := tx.DeviceHosts(ctx, id)
		if err != nil {
			return err
		}
		out = deviceResponse(d, hosts)

		// The fingerprint goes in the audit meta, not just the uuid. It is what
		// an operator has in front of them on the machine itself, and the row
		// has to stay legible after the device is deleted.
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: identity.Kind, ActorID: identity.Subject, ActorDisplay: identity.Display,
			Action:     action,
			TargetType: "device", TargetID: id.String(),
			Meta: fmtMeta(d.KeyFingerprint, req.Reason),
		})
	})
	if err != nil {
		s.notFoundOr(w, err, "device")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func deviceResponse(d *store.Device, hosts []store.Membership) wire.DeviceResponse {
	out := wire.DeviceResponse{
		ID:             d.ID.String(),
		KeyFingerprint: d.KeyFingerprint,
		KeyBacking:     d.KeyBacking,
		Hostname:       d.Hostname,
		PublicAddrs:    d.PublicAddrs,
		Blocked:        d.Blocked(),
		BlockedAt:      d.BlockedAt,
		BlockedReason:  d.BlockedReason,
		Facts: wire.DeviceFacts{
			OS:            d.Facts.OS,
			OSVersion:     d.Facts.OSVersion,
			Kernel:        d.Facts.Kernel,
			Arch:          d.Facts.Arch,
			AgentVersion:  d.Facts.AgentVersion,
			NebulaVersion: d.Facts.NebulaVersion,
		},
		FactsObservedAt: d.Facts.ObservedAt,
		Posture: wire.DevicePosture{
			DiskEncrypted:   d.Posture.DiskEncrypted,
			SecureBoot:      d.Posture.SecureBoot,
			FirewallEnabled: d.Posture.FirewallEnabled,
			TPMPresent:      d.Posture.TPMPresent,
		},
		PostureObservedAt: d.Posture.ObservedAt,
		FirstSeenAt:       d.FirstSeenAt,
		LastSeenAt:        d.LastSeenAt,
	}
	for i := range hosts {
		h := &hosts[i]
		m := wire.DeviceMembership{
			MembershipID: h.ID.String(),
			NetworkID:    h.NetworkID.String(),
			Name:         h.Name,
			State:        h.State,
		}
		for _, a := range h.Addrs {
			m.OverlayAddrs = append(m.OverlayAddrs, a.String())
		}
		out.Memberships = append(out.Memberships, m)
	}
	return out
}

// fmtMeta builds the audit meta for a device block. Marshalled rather than
// formatted so a reason containing a quote cannot produce invalid json.
func fmtMeta(fingerprint, reason string) []byte {
	b, err := json.Marshal(struct {
		Fingerprint string `json:"fingerprint"`
		Reason      string `json:"reason,omitempty"`
	}{fingerprint, reason})
	if err != nil {
		return nil
	}
	return b
}

// handleSetDeviceAddrs records where a machine is reachable from outside.
//
// A DEVICE endpoint, not a membership one, and that is the whole point of the
// split in migration 0019. A machine has one public address however many
// networks it is a lighthouse for; setting it here fixes all of them in one
// write and bumps every affected network's config epoch.
//
// Before, the address lived on each membership, so a machine serving three
// networks held it three times — and a partial edit left part of the fleet
// dialling somewhere nothing was listening.
func (s *Server) handleSetDeviceAddrs(w http.ResponseWriter, r *http.Request) {
	identity := identityFrom(r.Context())
	id, ok := pathUUID(w, r, "id")
	if !ok {
		return
	}

	var req wire.SetDeviceAddrsRequest
	if !decode(w, r, &req) {
		return
	}
	addrs, err := store.ValidatePublicAddrs(req.PublicAddrs)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	var out wire.DeviceResponse
	err = s.store.Tx(r.Context(), func(ctx context.Context, tx *store.Tx) error {
		if err := tx.SetDevicePublicAddrs(ctx, id, addrs); err != nil {
			return err
		}
		d, err := tx.GetDevice(ctx, id)
		if err != nil {
			return err
		}
		hosts, err := tx.DeviceHosts(ctx, id)
		if err != nil {
			return err
		}
		out = deviceResponse(d, hosts)
		return tx.AppendAudit(ctx, store.AuditEntry{
			ActorType: identity.Kind, ActorID: identity.Subject, ActorDisplay: identity.Display,
			Action:     store.ActionDeviceUpdated,
			TargetType: "device", TargetID: id.String(),
			Meta: fmtAddrsMeta(req.PublicAddrs),
		})
	})
	if err != nil {
		s.notFoundOr(w, err, "device")
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func fmtAddrsMeta(addrs []string) []byte {
	b, err := json.Marshal(struct {
		PublicAddrs []string `json:"public_addrs"`
	}{addrs})
	if err != nil {
		return nil
	}
	return b
}
