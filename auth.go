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

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return a.api.Middleware(next)
}
