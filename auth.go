package canopy

import (
	"fmt"
	"net/http"
)

type Auth struct {
	cfg Config
	api *Service
}

func New(config Config) (*Auth, error) {
	config.setDefaults()
	if err := config.validate(); err != nil {
		return nil, err
	}
	a := &Auth{cfg: config}
	a.api = newService(config)
	for _, module := range config.Modules {
		core := moduleCore{Service: a.api, moduleID: module.ID()}
		if err := module.Init(core); err != nil {
			return nil, fmt.Errorf("canopy: module %q: %w", module.ID(), err)
		}
	}
	return a, nil
}

func (a *Auth) API() *Service {
	return a.api
}

func (a *Auth) Handler() http.Handler {
	return newHandler(a.api, a.cfg)
}

// Middleware is a deprecated alias for OptionalSession.
// Deprecated: use OptionalSession or RequireSession to make intent explicit.
func (a *Auth) Middleware(next http.Handler) http.Handler {
	return a.OptionalSession(next)
}

// OptionalSession adds session data to the request context when valid and
// continues anonymously otherwise.
func (a *Auth) OptionalSession(next http.Handler) http.Handler {
	return a.api.OptionalSession(next)
}

// RequireSession adds session data to the request context or returns a 401
// JSON error without calling next.
func (a *Auth) RequireSession(next http.Handler) http.Handler {
	return a.api.RequireSession(next)
}
