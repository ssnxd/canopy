package oauth

import (
	"context"
	"time"

	"golang.org/x/oauth2"
)

type StartOptions struct {
	State        string
	Nonce        string
	PKCEVerifier string
	CallbackURL  string
	Scopes       []string
	// RedirectURL replaces the redirect URL that the provider is configured
	// with. It applies to this authorization request and to the matching
	// token exchange. An empty value keeps the configured redirect URL.
	//
	// A module sets this when its own callback route is not the core OAuth
	// callback route. The value must come from server-side configuration.
	// Never build it from request input.
	//
	// OAuth requires the redirect_uri of the token exchange to match the
	// redirect_uri of the authorization request. A provider that honors this
	// field must also implement RedirectExchanger, so that the caller can
	// send the same value at the exchange.
	RedirectURL string
}

type Profile struct {
	ProviderID            string
	AccountID             string
	Email                 string
	EmailVerified         bool
	Name                  string
	Image                 string
	IDToken               string
	AccessToken           string
	RefreshToken          string
	Scope                 string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
}

type Provider interface {
	ID() string
	Config(ctx context.Context) (*oauth2.Config, error)
	AuthCodeOptions(StartOptions) []oauth2.AuthCodeOption
	Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error)
	Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error)
	Profile(ctx context.Context, token *oauth2.Token, nonce string) (*Profile, error)
}

// RedirectExchanger is an optional provider capability. A provider that
// implements it can exchange an authorization code with a redirect URL that
// replaces the configured one. The value must equal the redirect URL of the
// authorization request, because OAuth requires the two to match.
//
// The built-in providers implement this interface. A caller must type-assert
// it and must fall back to Provider.Exchange when a provider does not
// implement it.
type RedirectExchanger interface {
	ExchangeWithRedirect(ctx context.Context, code string, verifier string, redirectURL string) (*oauth2.Token, error)
}

// Validator is an optional provider capability used by canopy.New to reject
// incomplete provider configuration before serving requests.
type Validator interface {
	Validate() error
}
