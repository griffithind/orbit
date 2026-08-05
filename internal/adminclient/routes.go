package adminclient

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/griffithind/orbit/internal/wire"
)

// ListRoutes returns the prefixes one membership offers.
func (c *Client) ListRoutes(ctx context.Context, membershipID uuid.UUID) (Result[wire.RouteListResponse], error) {
	return send[wire.RouteListResponse](ctx, c, http.MethodGet,
		"/v1/memberships/"+membershipID.String()+"/routes", nil, nil)
}

// AddRoute offers a prefix through a membership.
func (c *Client) AddRoute(ctx context.Context, membershipID uuid.UUID, req wire.CreateRouteRequest) (Result[wire.RouteResponse], error) {
	return send[wire.RouteResponse](ctx, c, http.MethodPost,
		"/v1/memberships/"+membershipID.String()+"/routes", nil, req)
}

// RemoveRoute withdraws one.
func (c *Client) RemoveRoute(ctx context.Context, routeID uuid.UUID) error {
	_, err := send[struct{}](ctx, c, http.MethodDelete,
		"/v1/routes/"+routeID.String(), nil, nil)
	return err
}
