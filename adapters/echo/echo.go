// Package canopyecho mounts Canopy on an Echo router.
//
// Mount registers the Canopy handler at the configured base path. The
// middleware helpers wrap Canopy's net/http middleware with
// echo.WrapMiddleware. Session data stays in the request context, so
// handlers read it with Session or canopy.SessionFromContext.
package canopyecho

import (
	"github.com/labstack/echo/v4"
	"github.com/ssnxd/canopy"
)

// Mount registers the Canopy handler on the router at the base path from
// Config.BasePath. Do not wrap the handler with http.StripPrefix.
func Mount(e *echo.Echo, a *canopy.Auth) {
	h := echo.WrapHandler(a.Handler())
	base := a.API().Config().BasePath
	if base == "/" {
		e.Any("/*", h)
		return
	}
	e.Any(base, h)
	e.Any(base+"/*", h)
}

// OptionalSession returns middleware that adds session data to the request
// context when a valid session is present and continues anonymously
// otherwise.
func OptionalSession(a *canopy.Auth) echo.MiddlewareFunc {
	return echo.WrapMiddleware(a.OptionalSession)
}

// RequireSession returns middleware that adds session data to the request
// context or ends the request with a 401 JSON error.
func RequireSession(a *canopy.Auth) echo.MiddlewareFunc {
	return echo.WrapMiddleware(a.RequireSession)
}

// Session returns the session data that the middleware stored on the
// request context.
func Session(c echo.Context) (*canopy.SessionData, bool) {
	return canopy.SessionFromContext(c.Request().Context())
}
