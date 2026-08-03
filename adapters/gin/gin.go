// Package canopygin mounts Canopy on a Gin router.
//
// Mount registers the Canopy handler at the configured base path. The
// middleware helpers bridge Canopy's net/http middleware into Gin handler
// functions. Session data stays in the request context, so handlers read
// it with Session or canopy.SessionFromContext.
package canopygin

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/ssnxd/canopy"
)

// Mount registers the Canopy handler on the router at the base path from
// Config.BasePath. Do not wrap the handler with http.StripPrefix.
func Mount(r gin.IRouter, a *canopy.Auth) {
	h := gin.WrapH(a.Handler())
	base := a.API().Config().BasePath
	if base == "/" {
		r.Any("/*canopy", h)
		return
	}
	r.Any(base, h)
	r.Any(base+"/*canopy", h)
}

// OptionalSession returns middleware that adds session data to the request
// context when a valid session is present and continues anonymously
// otherwise.
func OptionalSession(a *canopy.Auth) gin.HandlerFunc {
	return wrap(a.OptionalSession)
}

// RequireSession returns middleware that adds session data to the request
// context or ends the request with a 401 JSON error.
func RequireSession(a *canopy.Auth) gin.HandlerFunc {
	return wrap(a.RequireSession)
}

// Session returns the session data that the middleware stored on the
// request context.
func Session(c *gin.Context) (*canopy.SessionData, bool) {
	return canopy.SessionFromContext(c.Request.Context())
}

// wrap converts net/http middleware into a Gin handler function. When the
// middleware does not call its next handler, the chain stops.
func wrap(middleware func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		passed := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			passed = true
			c.Request = r
			c.Next()
		})
		middleware(next).ServeHTTP(c.Writer, c.Request)
		if !passed {
			c.Abort()
		}
	}
}
