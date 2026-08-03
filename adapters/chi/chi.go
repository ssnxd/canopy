// Package canopychi mounts Canopy on a chi router.
//
// chi routes standard net/http handlers, so this adapter is a thin
// convenience layer. Mount registers the Canopy handler at the configured
// base path without http.StripPrefix, which Canopy forbids. The session
// middleware helpers return the root Canopy middleware unchanged so the
// call site names the framework consistently.
package canopychi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/ssnxd/canopy"
)

// Mount registers the Canopy handler on the router at the base path from
// Config.BasePath. Do not wrap the handler with http.StripPrefix.
func Mount(r chi.Router, a *canopy.Auth) {
	h := a.Handler()
	base := a.API().Config().BasePath
	if base == "/" {
		r.Handle("/*", h)
		return
	}
	r.Handle(base, h)
	r.Handle(base+"/*", h)
}

// OptionalSession returns middleware that adds session data to the request
// context when a valid session is present and continues anonymously
// otherwise. Read the session with canopy.SessionFromContext.
func OptionalSession(a *canopy.Auth) func(http.Handler) http.Handler {
	return a.OptionalSession
}

// RequireSession returns middleware that adds session data to the request
// context or ends the request with a 401 JSON error.
func RequireSession(a *canopy.Auth) func(http.Handler) http.Handler {
	return a.RequireSession
}
