package adminclient

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/wire"
)

// Devices: machines, across every network they have joined on this control
// plane. Not network-scoped, which is why none of these take a network.

func (c *Client) ListDevices(ctx context.Context) (Result[wire.DeviceList], error) {
	return send[wire.DeviceList](ctx, c, http.MethodGet, "/v1/devices", nil, nil)
}

func (c *Client) GetDevice(ctx context.Context, id uuid.UUID) (Result[wire.DeviceResponse], error) {
	return send[wire.DeviceResponse](ctx, c, http.MethodGet, "/v1/devices/"+id.String(), nil, nil)
}

// BlockDevice refuses a machine everywhere on this control plane.
//
// Different from BlockHost, which suspends one membership. A stolen laptop wants
// the first; a machine being rebuilt wants the second.
func (c *Client) BlockDevice(ctx context.Context, id uuid.UUID, reason string) (Result[wire.DeviceResponse], error) {
	return send[wire.DeviceResponse](ctx, c, http.MethodPost,
		"/v1/devices/"+id.String()+"/block", nil, wire.BlockDeviceRequest{Reason: reason})
}

func (c *Client) UnblockDevice(ctx context.Context, id uuid.UUID) (Result[wire.DeviceResponse], error) {
	return send[wire.DeviceResponse](ctx, c, http.MethodPost,
		"/v1/devices/"+id.String()+"/unblock", nil, nil)
}

// SetDeviceAddrs records where a machine is reachable from outside.
//
// One call fixes every network the machine is a lighthouse for, because the
// address belongs to the machine and only the port belongs to a membership.
func (c *Client) SetDeviceAddrs(ctx context.Context, id uuid.UUID, addrs []string) (Result[wire.DeviceResponse], error) {
	return send[wire.DeviceResponse](ctx, c, http.MethodPatch,
		"/v1/devices/"+id.String()+"/addrs", nil, wire.SetDeviceAddrsRequest{PublicAddrs: addrs})
}
