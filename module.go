package canopy

import (
	"context"
	"net/http"
)

// Module is an optional feature that plugs into the Canopy handler and
// service. The built-in features implement Module. A third-party plugin
// uses the same seam. New calls Init once for each module.
type Module interface {
	ID() string
	Init(core Core) error
}

// Core is the narrow facade that a module depends on. A module must not
// depend on the concrete Service type.
type Core interface {
	Store() Store
	Config() Config
	IssueSession(ctx context.Context, user User, opt SessionOptions) (*SessionData, string, error)
	Authenticate(r *http.Request) (*SessionData, error)
	Audit(ctx context.Context, event AuditEvent)
}

// RouteModule is a module that mounts HTTP routes under the handler.
// This is an optional capability. The handler discovers it with a type
// assertion.
type RouteModule interface {
	Module
	Routes() []Route
}

// SignInInterceptor is a module that can pause session creation after
// primary authentication. This is an optional capability. The two-factor
// module uses it to require a second step.
type SignInInterceptor interface {
	AfterPrimaryAuth(ctx context.Context, user User) (*StepUpChallenge, error)
}

// Route is one HTTP route that a module mounts.
type Route struct {
	Method  string
	Pattern string
	Handler http.Handler
	// RequireSession makes the handler resolve a session first. The
	// handler returns unauthorized when no session is present. The
	// session is available through SessionFromContext.
	RequireSession bool
}

// SessionOptions carries the values that IssueSession needs. A module
// sets ActiveOrganizationID or ImpersonatedBy when it applies.
type SessionOptions struct {
	RememberMe           *bool
	IPAddress            string
	UserAgent            string
	ActiveOrganizationID string
	ImpersonatedBy       string
}

// StepUpChallenge tells the client that a second authentication step is
// required. Token is opaque and short-lived. Methods lists the accepted
// second factors, for example "totp" or "backup_code".
type StepUpChallenge struct {
	Token   string   `json:"token"`
	Methods []string `json:"methods"`
}
